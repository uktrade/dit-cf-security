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

app = Flask(__name__, template_folder=os.path.dirname(__file__))
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
        email_name=env['EMAIL_NAME'],
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

    def get_client_ip(route):
        try:
            return x_forwarded_for.split(',')[int(route['IP_DETERMINED_BY_X_FORWARDED_FOR_INDEX'])].strip()
        except IndexError:
            logger.debug('[%s] Not enough addresses in x-forwarded-for %s', request_id, x_forwarded_for)

    routes = env['ROUTES']
    hostname_ok = [
        re.match(route['HOSTNAME_REGEX'], parsed_url.hostname)
        for route in routes
    ]
    client_ips = [
        get_client_ip(route)
        for route in routes
    ]
    ip_ok = [
        any(client_ips[i] and IPv4Address(client_ips[i]) in IPv4Network(ip_range) for ip_range in route['IP_RANGES'])
        for i, route in enumerate(routes)
    ]
    shared_secrets = [
        route.get('SHARED_SECRET_HEADER', [])
        for route in routes
    ]
    shared_secret_ok = [
        [
            (
                shared_secret['NAME'] in request.headers
                and constant_time_is_equal(shared_secret['VALUE'].encode(), request.headers[shared_secret['NAME']].encode())
            )
            for shared_secret in shared_secrets[i]
        ]
        for i, _ in enumerate(routes)
    ]

    # In general, any matching basic auth credentials are accepted. However,
    # on authentication paths, only those with that path are accepted, and
    # on failure, a 401 is returned to request the correct credentials
    basic_auths = [
        route.get('BASIC_AUTH', [])
        for route in routes
    ]
    basic_auths_ok = [
        [
            request.authorization and
            constant_time_is_equal(basic_auth['USERNAME'].encode(), request.authorization.username.encode()) and 
            constant_time_is_equal(basic_auth['PASSWORD'].encode(), request.authorization.password.encode())
            for basic_auth in basic_auths[i]
        ]
        for i, _ in enumerate(routes)
    ]
    on_auth_path_and_ok = [
        [
            basic_auths_ok[i][j]
            for j, basic_auth in enumerate(basic_auths[i])
            if parsed_url.path == basic_auth['AUTHENTICATE_PATH']
        ]
        for i, _ in enumerate(routes)
    ]
    any_on_auth_path_and_ok = any([
        any(on_auth_path_and_ok[i])
        for i, _ in enumerate(routes)
    ])
    should_request_auth = not any_on_auth_path_and_ok and any(
        (
            hostname_ok[i] and
            ip_ok[i] and
            (not shared_secrets[i] or any(shared_secret_ok[i])) and
            len(on_auth_path_and_ok[i]) and
            all(not ok for ok in on_auth_path_and_ok[i])
        )
        for i, _ in enumerate(routes)
    )
    should_respond_ok_to_auth_request = any(
        (
            hostname_ok[i] and
            ip_ok[i] and
            (not shared_secrets[i] or any(shared_secret_ok[i])) and
            len(on_auth_path_and_ok[i]) and
            any(on_auth_path_and_ok[i])
        )
        for i, _ in enumerate(routes)
    )

    any_route_with_all_checks_passed = any(
        (
            hostname_ok[i] and
            ip_ok[i] and
            (not shared_secrets[i] or any(shared_secret_ok[i])) and
            (not basic_auths[i] or any(basic_auths_ok[i]))
        )
        for i, _ in enumerate(routes)
    )

    # There is no perfect answer as to which IP to present to the client in
    # the light of multiple routes with different indexes of the
    # x-forwarded-for header. However, in real cases it is likely that if the
    # host matches, then that will be the correct one. If 'Unknown' is then
    # shown to the user, it suggests something has been misconfigured
    client_ip = next(
        (client_ips[i] for i, _ in enumerate(routes) if hostname_ok[i])
    , 'Unknown')

    headers_to_remove = tuple(set(
        shared_secret['NAME'].lower()
        for i, _ in enumerate(routes)
        for shared_secret in shared_secrets[i]
    )) + ('host', 'x-cf-forwarded-url', 'connection')

    if should_request_auth:
        return Response(
            'Could not verify your access level for that URL.\n'
            'You have to login with proper credentials', 401,
            {'WWW-Authenticate': 'Basic realm="Login Required"'})

    if should_respond_ok_to_auth_request:
        return 'ok'

    if not any_route_with_all_checks_passed:
        logger.warning('[%s] No matching route', request_id)
        return render_access_denied(client_ip, forwarded_url)

    logger.info('[%s] Making request to origin', request_id)

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
