import os
import sys
import logging
from ipaddress import ip_network, ip_address
from urllib.parse import urlparse, urljoin

import requests
from flask import Flask, request, Response


class FixedLocationResponse(Response):
    autocorrect_location_header = False


app = Flask(__name__)
app.response_class = FixedLocationResponse


logging.basicConfig(stream=sys.stdout, level='INFO')
logger = logging.getLogger(__name__)


app.config['XFF_IP_INDEX'] = int(os.environ.get('IP_SAFELIST_XFF_IP_INDEX', '-3'))
app.config['ALLOWED_IPS'] = os.environ.get('ALLOWED_IPS', '').split(',')
app.config['ALLOWED_IP_RANGES'] = os.environ.get('ALLOWED_IP_RANGES', '').split(',')
app.config['BASIC_AUTH_USERNAME'] = os.environ.get('BASIC_AUTH_USERNAME')
app.config['BASIC_AUTH_PASSWORD'] = os.environ.get('BASIC_AUTH_PASSWORD')
app.config['SHARED_SECRET'] = os.environ.get('SHARED_SECRET', '')


FORWARDED_URL = 'X-CF-Forwarded-Url'
PROXY_METADATA = 'X-CF-Proxy-Metadata'
PROXY_SIGNATURE = 'X-CF-Proxy-Signature'


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
        logger.warning(
            'X-Forwarded-For header is missing or does not '
            'contain enough elements to determine the '
            'client\'s ip')
        return None


@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTION', 'HEAD'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTION', 'HEAD'])
def handle_request(path):
    forwarded_url = request.headers.get(FORWARDED_URL, None)

    if not forwarded_url:
        logger.error('Missing %s header', FORWARDED_URL)
        return f'Missing {FORWARDED_URL}'

    client_ip = get_client_ip()

    logger.info('client ip: %s', client_ip)

    logger.info(f'Incoming request: forwarded url: {forwarded_url}; method: {request.method}; headers: {request.headers}: cookies: {request.cookies}')   # noqa

    # Shared secret check
    if app.config['SHARED_SECRET']:
        if request.headers.get('X-Shared-Secret', '') != app.config['SHARED_SECRET']:
            logger.info('Shared secret invalid')
            return 'Forbidden', 403

    # IP and basic auth
    if not client_ip or not is_valid_ip(client_ip):
        logger.info('invalid client ip: %s', client_ip)
        auth = request.authorization

        if not auth or not check_auth(auth.username, auth.password):
            logger.info('requiring basic auth')
            return 'Forbidden', 403

    headers = {k: v for k, v in request.headers.items() if k not in ['Host', 'X-Cf-Forwarded-Url']}

    response = requests.request(
        request.method,
        forwarded_url,
        allow_redirects=False,
        headers=headers,
        cookies=request.cookies,
        stream=True,
        data=request.get_data())

    logger.info(f'Forwarding request to app: {forwarded_url}; method: {request.method}; headers: {headers}; cookies: {request.cookies}')  # noqa

    logger.info(f'Response from app: status: {response.status_code}; headers: {response.headers}; cookies: {response.cookies}')   # noqa

    return response.raw.read(), response.status_code, response.headers.items()
