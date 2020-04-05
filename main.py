import os
import re
import sys
import logging
from ipaddress import IPv4Network, IPv4Address
import urllib.parse
import string

from utils import constant_time_is_equal, normalise_environment

from flask import Flask, request, Response, render_template
from random import choices
import urllib3

app = Flask(__name__)
env = normalise_environment(os.environ)

# All requested URLs are eventually routed to to the same load balancer, which
# uses the host header to route requests to the correct application. So as
# long as we pass the application's host header, which urllib3 does
# automatically from the URL, to resolve the IP address of the origin server,
# we can use _any_ hostname that resolves to this load balancer. So if we use
# the _same_ hostname for all requests...
# - we allow onward persistant connections to the load balancer that are
#   reused for all requests;
# - we avoid requests going back through the CDN, which is good for both
#   latency, and (hopefully) debuggability since there are fewer hops;
# - we avoid routing requests to arbitrary targets on the internet as part of
#   a defense-in-depth/least-privilege strategy.
PoolClass = \
    urllib3.HTTPConnectionPool if env['ORIGIN_PROTO'] == 'http' else \
    urllib3.HTTPSConnectionPool
http = PoolClass(env['ORIGIN_HOSTNAME'], maxsize=1000)

logging.basicConfig(stream=sys.stdout, level=env['LOG_LEVEL'])
logger = logging.getLogger(__name__)

request_id_alphabet = string.ascii_letters + string.digits


def render_access_denied(client_ip, forwarded_url):
    return (render_template(
        'access-denied.html',
        client_ip=client_ip,
        email=env['EMAIL'],
        forwarded_url=forwarded_url,
    ), 403)


@app.route('/', methods=['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'])
def handle_request():
    request_id = ''.join(choices(request_id_alphabet, k=8))
    logger.info('[%s] Start', request_id)

    # Must have X-CF-Forwarded-Url to match route
    try:
        forwarded_url = request.headers['X-CF-Forwarded-Url']
    except KeyError:
        logger.error('[%s] Missing X-CF-Forwarded-Url header', request_id)
        return render_access_denied('Unknown', 'Unknown')

    logger.info('[%s] Forwarded URL: %s', request_id, forwarded_url)
    parsed_url = urllib.parse.urlsplit(forwarded_url)

    # Find x-forwarded-for
    try:
        x_forwarded_for = request.headers['X-Forwarded-For']
    except KeyError:
        logger.error('[%s] X-Forwarded-For header is missing', request_id)
        return render_access_denied('Unknown', forwarded_url)

    logger.debug('[%s] X-Forwarded-For: %s', request_id, x_forwarded_for)
    client_ip = 'Unknown'

    # A request is only rejected only if it matches no routes
    for route in env['ROUTES']:
        if not re.match(route['HOSTNAME_REGEX'], parsed_url.hostname):
            continue

        logger.debug('[%s] Host matches %s', request_id, route['HOSTNAME_REGEX'])

        try:
            client_ip = x_forwarded_for.split(',')[int(route['IP_DETERMINED_BY_X_FORWARDED_FOR_INDEX'])].strip()
        except IndexError:
            logger.debug('[%s] Not enough addresses in x-forwarded-for %s', request_id, x_forwarded_for)
            continue

        logger.debug('[%s] Trusting that the client has IP %s', request_id, client_ip)

        # The client IP must be in an allowed range, which can be 0.0.0.0/0
        if not any(
                IPv4Address(client_ip) in IPv4Network(ip_range) for ip_range in route['IP_RANGES']
        ):
            logger.debug('[%s] IP address %s does not match range', request_id, client_ip)
            continue

        # Must pass a shared secret header check, if specified
        shared_secrets = route.get('SHARED_SECRET_HEADER', [])
        shared_secrets_ok = [
            (
                shared_secret['NAME'] in request.headers
                and constant_time_is_equal(shared_secret['VALUE'].encode(), request.headers[shared_secret['NAME']].encode())
            )
            for shared_secret in shared_secrets
        ]
        if shared_secrets and not any(shared_secrets_ok):
            logger.debug('[%s] Shared secret check failed', request_id)
            continue

        # Must pass a basic auth check, if specified
        basic_auths = route.get('BASIC_AUTH', [])
        basic_auths_ok = [
            (
                request.authorization and
                constant_time_is_equal(basic_auth['USERNAME'].encode(), request.authorization.username.encode()) and 
                constant_time_is_equal(basic_auth['PASSWORD'].encode(), request.authorization.password.encode())
            )
            for basic_auth in basic_auths
        ]
        on_auth_path_and_ok = [
            basic_auths_ok[i]
            for i, basic_auth in enumerate(basic_auths)
            if parsed_url.path == basic_auth['AUTHENTICATE_PATH']
        ]
        # If on authentication path, but have passed no checks for this path, request auth
        if bool(on_auth_path_and_ok) and all(not ok for ok in on_auth_path_and_ok):
            return Response(
                'Could not verify your access level for that URL.\n'
                'You have to login with proper credentials', 401,
                {'WWW-Authenticate': 'Basic realm="Login Required"'})
        # If on authentication path, and have passed any checks for this path, say ok
        if bool(on_auth_path_and_ok) and any(on_auth_path_and_ok):
            return 'ok'
        if basic_auths and not any(basic_auths_ok):
            logger.debug('[%s] Basic auth failed', request_id)
            continue

        break
    else:
        logger.error('[%s] No matching route', request_id)
        return render_access_denied(client_ip, forwarded_url)

    logger.info('[%s] Making request to origin', request_id)

    def downstream_data():
        while True:
            contents = request.stream.read(65536)
            if not contents:
                break
            yield contents

    headers_to_remove = tuple(set(
        shared_secret_header['NAME'].lower()
        for route in env['ROUTES']
        for shared_secret_header in route.get('SHARED_SECRET_HEADER', [])
    )) + ('host', 'x-cf-forwarded-url', 'connection')

    origin_response = http.request(
        request.method,
        forwarded_url,
        headers={
            k: v for k, v in request.headers
            if k.lower() not in headers_to_remove
        },
        preload_content=False,
        redirect=False,
        assert_same_host=False,
        body=downstream_data(),
    )
    logger.info('[%s] Origin response status: %s', request_id, origin_response.status)

    def release_conn():
        origin_response.release_conn()
        logger.info('[%s] End', request_id)

    downstream_response = Response(
        origin_response.stream(65536, decode_content=False),
        status=origin_response.status,
        headers=[
            (k, v) for k, v in origin_response.headers.items()
            if k.lower() != 'connection'
        ],
    )
    downstream_response.autocorrect_location_header = False
    downstream_response.call_on_close(release_conn)

    logger.info('[%s] Starting response to client', request_id)

    return downstream_response
