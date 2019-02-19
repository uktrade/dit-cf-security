import sys
import logging

import requests
from flask import Flask, request, Response

app = Flask(__name__)


logging.basicConfig(stream=sys.stdout, level='INFO')
logger = logging.getLogger(__name__)


FORWARDED_URL = 'X-CF-Forwarded-Url'
PROXY_METADATA = 'X-CF-Proxy-Metadata'
PROXY_SIGNATURE = 'X-CF-Proxy-Signature'


@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def handle_request(path):
    forwarded_url = request.headers.get(FORWARDED_URL, None)

    if not forwarded_url:
        logger.error(f'Missing {FORWARDED_URL} header')
        return f'Missing {FORWARDED_URL}'

    logger.info(f'forwarded url: {forwarded_url}; method: {request.method}; headers: {request.headers}')

    logger.info('incoming request')

    headers = {k: v for k,v in request.headers.items() if k not in ['Host', 'X-Cf-Forwarded-Url']}
    response = requests.request(request.method, forwarded_url, headers=headers)

    logger.info(
        f'forwarding response to url: {forwarded_url}; status: {response.status_code}; headers: {response.headers}')

    return (response.text, response.status_code, response.headers.items())

