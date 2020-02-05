import os
import sys
import logging
from ipaddress import ip_network, ip_address
from urllib.parse import urlparse, urljoin

import requests
from flask import Flask, request, Response, make_response, render_template


class FixedLocationResponse(Response):
    autocorrect_location_header = False


app = Flask(__name__)
app.response_class = FixedLocationResponse


app.config['XFF_IP_INDEX'] = int(os.environ.get('IP_SAFELIST_XFF_IP_INDEX', '-3'))
app.config['ALLOWED_IPS'] = os.environ.get('ALLOWED_IPS', '').split(',')
app.config['ALLOWED_IP_RANGES'] = os.environ.get('ALLOWED_IP_RANGES', '').split(',')
app.config['BASIC_AUTH_USERNAME'] = os.environ.get('BASIC_AUTH_USERNAME')
app.config['BASIC_AUTH_PASSWORD'] = os.environ.get('BASIC_AUTH_PASSWORD')
app.config['SHARED_SECRET'] = os.environ.get('SHARED_SECRET', '')
app.config['EMAIL'] = os.environ.get('EMAIL', 'unspecified')
app.config['LOG_LEVEL'] = os.environ.get('LOG_LEVEL', 'INFO')

logging.basicConfig(stream=sys.stdout, level=app.config['LOG_LEVEL'])
logger = logging.getLogger(__name__)


FORWARDED_URL = 'X-CF-Forwarded-Url'


def check_auth(username, password):
    return username == app.config['BASIC_AUTH_USERNAME'] and password == app.config['BASIC_AUTH_PASSWORD']



def is_valid_ip(client_ip):

    if not client_ip:
        return False

    if client_ip in app.config['ALLOWED_IPS']:
        return True

    # ip_addr = ip_address(client_ip)
    # for cidr in app.config['ALLOWED_IP_RANGES']:
    #     if ip_addr in ip_network(cidr):
    #         return True

    return False



def get_client_ip():

    try:
        return request.headers.get("X-Forwarded-For").split(',')[app.config['XFF_IP_INDEX']].strip()
    except (IndexError, KeyError):
        logger.debug(
            'X-Forwarded-For header is missing or does not '
            'contain enough elements to determine the '
            'client\'s ip')
        return None


def render_access_denied(client_ip):
    return render_template('access-denied.html', client_ip=client_ip, email=app.config['EMAIL'])


def basic_auth_check():
    auth = request.authorization

    if not auth or not check_auth(auth.username, auth.password):
        logger.debug('requiring basic auth')
        return Response(
            'Could not verify your access level for that URL.\n'
            'You have to login with proper credentials', 401,
            {'WWW-Authenticate': 'Basic realm="Login Required"'})

    return 'ok'


@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'])
def handle_request(path):
    forwarded_url = request.headers.get(FORWARDED_URL, None)

    if not forwarded_url:
        logger.error('Missing %s header', FORWARDED_URL)
        return f'Missing {FORWARDED_URL}'

    if forwarded_url.endswith('/automated-test-auth'):
        # apply basic auth with 401/Www-Authenticate header to this URL only
        return basic_auth_check()

    client_ip = get_client_ip()

    logger.debug('client ip: %s', client_ip)

    logger.debug(f'Incoming request: forwarded url: {forwarded_url}; method: {request.method}; headers: {request.headers}: cookies: {request.cookies}')   # noqa

    # Shared secret check
    if app.config['SHARED_SECRET']:
        if request.headers.get('X-Shared-Secret', '') != app.config['SHARED_SECRET']:
            logger.debug('Shared secret invalid')
            return 'Forbidden', 403

    # IP and basic auth
    if not client_ip or not is_valid_ip(client_ip):
        logger.debug('invalid client ip: %s', client_ip)
        auth = request.authorization

        if not auth or not check_auth(auth.username, auth.password):
            logger.debug('requiring basic auth')
            return render_access_denied(client_ip)

    headers = {k: v for k, v in request.headers.items() if k not in ['Host', 'X-Cf-Forwarded-Url']}

    origin_response = requests.request(
        request.method,
        forwarded_url,
        allow_redirects=False,
        headers=headers,
        cookies=request.cookies,
        stream=True,
        data=request.get_data())

    logger.debug(f'Forwarding request to app: {forwarded_url}; method: {request.method}; headers: {headers}; cookies: {request.cookies}')  # noqa

    logger.debug(f'Response from app: status: {origin_response.status_code}; headers: {origin_response.headers}; cookies: {origin_response.cookies}')   # noqa

    headers = origin_response.headers.copy()
    if 'Set-Cookie' in headers:
        del headers['Set-Cookie']

    response = make_response(origin_response.raw.read(), origin_response.status_code, headers.items())

    for cookie in origin_response.cookies:
        response.set_cookie(cookie.name,
                            cookie.value,
                            expires=cookie.expires,
                            path=cookie.path,
                            secure=cookie.secure,
                            domain=cookie.domain,
                            httponly=cookie.has_nonstandard_attr('HttpOnly'))

    return response
