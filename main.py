import os
import sys
import logging
from ipaddress import ip_network, ip_address

from flask import Flask, request, Response, render_template
import urllib3

app = Flask(__name__)
env = os.environ

# All requested URLs are eventually routed to to the same load balancer, which
# uses the host header to route requests to the correct application. So as
# long as we pass the application's host header, which urllib3 does
# automatically from the URL, to resolve the IP address of the origin server,
# we can use _any_ hostname that resolves to this load balancer. So if we use
# the _same_ hostname for all requests...
# - we allow onward persistant connections to the load balancer that are
#   reused for all requests;
# - we avoid requests going back through the CDN, which is good for both
#   latency, and (hopefully) debuggability since there are fewer hops.
PoolClass = \
    urllib3.HTTPConnectionPool if env['ORIGIN_PROTO'] == 'http' else \
    urllib3.HTTPSConnectionPool
http = PoolClass(env['ORIGIN_HOSTNAME'], maxsize=1000)

logging.basicConfig(stream=sys.stdout, level=env['LOG_LEVEL'])
logger = logging.getLogger(__name__)


def check_auth(username, password):
    return username == env['BASIC_AUTH_USERNAME'] and password == env['BASIC_AUTH_PASSWORD']


def is_valid_ip(client_ip):

    if not client_ip:
        return False

    if client_ip in env['ALLOWED_IPS']:
        return True

    # ip_addr = ip_address(client_ip)
    # for cidr in app.config['ALLOWED_IP_RANGES']:
    #     if ip_addr in ip_network(cidr):
    #         return True

    return False



def get_client_ip():

    try:
        return request.headers["X-Forwarded-For"].split(',')[int(env['XFF_IP_INDEX'])].strip()
    except (IndexError, KeyError):
        logger.debug(
            'X-Forwarded-For header is missing or does not '
            'contain enough elements to determine the '
            'client\'s ip')
        return None


def render_access_denied(client_ip, forwarded_url):
    return (render_template(
        'access-denied.html',
        client_ip=client_ip,
        email=env['EMAIL'],
        forwarded_url=forwarded_url,
    ), 403)


def basic_auth_check():
    auth = request.authorization

    if not auth or not check_auth(auth.username, auth.password):
        logger.debug('requiring basic auth')
        return Response(
            'Could not verify your access level for that URL.\n'
            'You have to login with proper credentials', 401,
            {'WWW-Authenticate': 'Basic realm="Login Required"'})

    return 'ok'


@app.route('/', methods=['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'])
def handle_request():
    forwarded_url = request.headers.get('X-CF-Forwarded-Url', None)

    if not forwarded_url:
        logger.error('Missing X-CF-Forwarded-Url header')
        return 'Missing X-CF-Forwarded-Url'

    if forwarded_url.endswith('/automated-test-auth'):
        # apply basic auth with 401/Www-Authenticate header to this URL only
        return basic_auth_check()

    client_ip = get_client_ip()

    logger.debug('client ip: %s', client_ip)

    logger.debug(f'Incoming request: forwarded url: {forwarded_url}; method: {request.method}; headers: {request.headers}: cookies: {request.cookies}')   # noqa

    # Shared secret check
    if env.get('SHARED_SECRET'):
        if request.headers.get('X-Shared-Secret', '') != app.config['SHARED_SECRET']:
            logger.debug('Shared secret invalid')
            return 'Forbidden', 403

    # IP and basic auth
    if not client_ip or not is_valid_ip(client_ip):
        logger.debug('invalid client ip: %s', client_ip)
        auth = request.authorization

        if not auth or not check_auth(auth.username, auth.password):
            logger.debug('requiring basic auth')
            return render_access_denied(client_ip, forwarded_url)

    def downstream_data():
        while True:
            contents = request.stream.read(65536)
            if not contents:
                break
            yield contents

    origin_response = http.request(
        request.method,
        forwarded_url,
        headers={
            k: v for k, v in request.headers
            if k not in ('Host', 'X-Cf-Forwarded-Url', 'Connection')
        },
        preload_content=False,
        redirect=False,
        assert_same_host=False,
        body=downstream_data(),
    )

    logger.debug(f'Forwarding request to app: {forwarded_url}; method: {request.method}; headers: {origin_response.headers}')  # noqa

    logger.debug(f'Response from app: status: {origin_response.status}; headers: {origin_response.headers}')   # noqa

    downstream_response = Response(
        origin_response.stream(65536, decode_content=False),
        status=origin_response.status,
        headers=[
            (k, v) for k, v in origin_response.headers.items()
            if k.lower() != 'connection'
        ],
    )
    downstream_response.autocorrect_location_header = False
    downstream_response.call_on_close(origin_response.release_conn)
    return downstream_response
