import base64
import json
from multiprocessing import (
    Process,
)
import itertools
import os
import signal
import socket
import subprocess
import sys
import time
import unittest
import urllib.parse
import uuid

from flask import (
    Flask,
    Response,
    request,
)
import requests
from werkzeug.routing import (
    Rule,
)


class TestCfSecurity(unittest.TestCase):

    def test_meta_wait_until_connectable_raises(self):
        with self.assertRaises(OSError):
            wait_until_connectable(8080, max_attempts=10)

    def test_method_is_forwarded(self):
        self.addCleanup(create_filter(8080))
        self.addCleanup(create_origin(8081))
        wait_until_connectable(8080)
        wait_until_connectable(8081)

        methods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD']
        echo_methods = [
            requests.request(
                method,
                url='http://127.0.0.1:8080/',
                headers={
                    'x-cf-forwarded-url': 'http://127.0.0.1:8081/',
                    'x-forwarded-for': '1.2.3.4, 1.1.1.1, 1.1.1.1',
                },
            ).headers['x-echo-method']
            for method in methods
        ]
        self.assertEqual(methods, echo_methods)

    def test_host_is_forwarded(self):
        self.addCleanup(create_filter(8080))
        self.addCleanup(create_origin(8081))
        wait_until_connectable(8080)
        wait_until_connectable(8081)

        host = requests.request(
            'GET',
            url='http://127.0.0.1:8080/',
            headers={
                'x-cf-forwarded-url': 'http://127.0.0.1:8081/',
                'x-forwarded-for': '1.2.3.4, 1.1.1.1, 1.1.1.1',
            },
        ).headers['x-echo-header-host']
        self.assertEqual(host, '127.0.0.1:8081')

    def test_path_and_query_is_forwarded(self):
        self.addCleanup(create_filter(8080))
        self.addCleanup(create_origin(8081))
        wait_until_connectable(8080)
        wait_until_connectable(8081)

        path = urllib.parse.quote('/a/£/💾')
        query = urllib.parse.urlencode([
            ('a', 'b'),
            ('🍰', '😃'),
        ])
        raw_uri_expected = f'{path}?{query}'
        raw_uri_received = requests.request(
            'GET',
            url='http://127.0.0.1:8080/',
            headers={
                'x-cf-forwarded-url': f'http://127.0.0.1:8081{raw_uri_expected}',
                'x-forwarded-for': '1.2.3.4, 1.1.1.1, 1.1.1.1',
            },
        ).headers['x-echo-raw-uri']
        self.assertEqual(raw_uri_expected, raw_uri_received)

    def test_body_is_forwarded(self):
        self.addCleanup(create_filter(8080))
        self.addCleanup(create_origin(8081))
        wait_until_connectable(8080)
        wait_until_connectable(8081)

        method_bodies_expected = [
            ('GET', uuid.uuid4().bytes * 1),
            ('POST', uuid.uuid4().bytes * 10),
            ('PUT', uuid.uuid4().bytes * 100),
            ('PATCH', uuid.uuid4().bytes * 1000),
            ('DELETE', uuid.uuid4().bytes * 10000),
            ('OPTIONS', uuid.uuid4().bytes * 100000),
        ]
        method_bodies_received = [
            (method, requests.request(
                method,
                url='http://127.0.0.1:8080/',
                headers={
                    'x-cf-forwarded-url': 'http://127.0.0.1:8081/',
                    'x-forwarded-for': '1.2.3.4, 1.1.1.1, 1.1.1.1',
                },
                data=body,
            ).content)
            for method, body in method_bodies_expected
        ]
        self.assertEqual(method_bodies_expected, method_bodies_received)

    def test_status_is_forwarded(self):
        self.addCleanup(create_filter(8080))
        self.addCleanup(create_origin(8081))
        wait_until_connectable(8080)
        wait_until_connectable(8081)

        method_statuses_expected = list(itertools.product(
            ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'],
            ['200', '201', '401', '403', '500']
        ))
        method_statuses_received = [
            (method, str(requests.request(
                method,
                url='http://127.0.0.1:8080/',
                headers={
                    'x-cf-forwarded-url': 'http://127.0.0.1:8081/',
                    'x-forwarded-for': '1.2.3.4, 1.1.1.1, 1.1.1.1',
                    'x-echo-response-status': status,
                },
            ).status_code))
            for method, status in method_statuses_expected
        ]
        self.assertEqual(method_statuses_expected, method_statuses_received)

    def test_request_header_is_forwarded(self):
        self.addCleanup(create_filter(8080))
        self.addCleanup(create_origin(8081))
        wait_until_connectable(8080)
        wait_until_connectable(8081)

        response_header = requests.request(
            'GET',
            url='http://127.0.0.1:8080/',
            headers={
                'x-cf-forwarded-url': 'http://127.0.0.1:8081/',
                'x-forwarded-for': '1.2.3.4, 1.1.1.1, 1.1.1.1',
                'some-header': 'some-value',
            },
        ).headers['x-echo-header-some-header']
        self.assertEqual(response_header, 'some-value')

    def test_response_header_is_forwarded(self):
        self.addCleanup(create_filter(8080))
        self.addCleanup(create_origin(8081))
        wait_until_connectable(8080)
        wait_until_connectable(8081)

        response_header = requests.request(
            'GET',
            url='http://127.0.0.1:8080/',
            headers={
                'x-cf-forwarded-url': 'http://127.0.0.1:8081/',
                'x-forwarded-for': '1.2.3.4, 1.1.1.1, 1.1.1.1',
                'x-echo-response-header-some-header': 'some-value',
            },
        ).headers['some-header']
        self.assertEqual(response_header, 'some-value')

    def test_head_content_length_is_forwarded(self):
        self.addCleanup(create_filter(8080))
        self.addCleanup(create_origin(8081))
        wait_until_connectable(8080)
        wait_until_connectable(8081)

        content_length = requests.request(
            'HEAD',
            url='http://127.0.0.1:8080/',
            headers={
                'x-cf-forwarded-url': 'http://127.0.0.1:8081/',
                'x-forwarded-for': '1.2.3.4, 1.1.1.1, 1.1.1.1',
                'x-echo-response-header-content-length': '12345678',
            }
        ).headers['content-length']
        # This should probably be 12345678
        self.assertEqual(content_length, '0')

    def test_request_cookie_is_forwarded(self):
        self.addCleanup(create_filter(8080))
        self.addCleanup(create_origin(8081))
        wait_until_connectable(8080)
        wait_until_connectable(8081)

        response_header = requests.request(
            'GET',
            url='http://127.0.0.1:8080/',
            headers={
                'x-cf-forwarded-url': 'http://localtest.me:8081/',
                'x-forwarded-for': '1.2.3.4, 1.1.1.1, 1.1.1.1',
                'cookie': 'my_name=my_value',
            },
        ).headers['x-echo-header-cookie']
        self.assertEqual(response_header, 'my_name=my_value')

    def test_response_cookie_is_forwarded(self):
        self.addCleanup(create_filter(8080))
        self.addCleanup(create_origin(8081))
        wait_until_connectable(8080)
        wait_until_connectable(8081)

        response_header = requests.request(
            'GET',
            url='http://127.0.0.1:8080/',
            headers={
                'x-cf-forwarded-url': 'http://localtest.me:8081/',
                'x-forwarded-for': '1.2.3.4, 1.1.1.1, 1.1.1.1',
                'x-echo-response-header-set-cookie': 'my_name=my_value',
            },
        ).headers['set-cookie']
        # This should probably pass through the set-cookie header unchanged
        self.assertEqual(response_header, 'my_name=my_value; Domain=localtest.me; Path=/')

    def test_multiple_response_cookies_are_forwarded(self):
        self.addCleanup(create_filter(8080))
        self.addCleanup(create_origin(8081))
        wait_until_connectable(8080)
        wait_until_connectable(8081)

        # We make sure we don't depend or are thwarted by magic that an HTTP
        # client in the tests does regarding multiple HTTP headers of the same
        # name, and specifically any handing of multiple Set-Cookie headers
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('127.0.0.1', 8080))
        sock.send(
            b'GET / HTTP/1.1\r\n' \
            b'host:127.0.0.1\r\n' \
            b'x-cf-forwarded-url:http://localtest.me:8081/multiple-cookies\r\n' \
            b'x-forwarded-for:1.2.3.4, 1.1.1.1, 1.1.1.1\r\n' \
            b'x-multiple-cookies:name_a=value_a,name_b=value_b\r\n' \
            b'\r\n'
        )

        response = b''
        while b'\r\n\r\n' not in response:
            response += sock.recv(4096)
        sock.close()

        # This should probably pass through the set-cookie headers unchanged,
        # i.e. without domain and path
        self.assertIn(b'Set-Cookie: name_a=value_a; Domain=localtest.me; Path=/\r\n', response)
        self.assertIn(b'Set-Cookie: name_b=value_b; Domain=localtest.me; Path=/\r\n', response)

    def test_cookie_not_stored(self):
        self.addCleanup(create_filter(8080))
        self.addCleanup(create_origin(8081))
        wait_until_connectable(8080)
        wait_until_connectable(8081)

        # Ensure that the filter itself don't store cookies set by the origin
        cookie_header = 'x-echo-header-cookie'
        set_cookie = requests.request(
            'GET',
            url='http://127.0.0.1:8080/',
            headers={
                'x-cf-forwarded-url': 'http://localtest.me:8081/',
                'x-forwarded-for': '1.2.3.4, 1.1.1.1, 1.1.1.1',
                'x-echo-response-header-set-cookie': 'my_name=my_value_a; Domain=.localtest.me; Path=/path',
            },
        ).headers['set-cookie']
        self.assertEqual(set_cookie, 'my_name=my_value_a; Domain=.localtest.me; Path=/path')
        has_cookie = cookie_header in requests.request(
            'GET',
            url='http://127.0.0.1:8080/',
            headers={
                'x-cf-forwarded-url': 'http://localtest.me:8081/',
                'x-forwarded-for': '1.2.3.4, 1.1.1.1, 1.1.1.1',
            },
        ).headers
        self.assertFalse(has_cookie)

        # Meta test, ensuring that cookie_header is the right header to
        # check for to see if the echo origin received the cookie
        cookie_header_value = requests.request(
            'GET',
            url='http://127.0.0.1:8080/',
            headers={
                'x-cf-forwarded-url': 'http://localtest.me:8081/',
                'x-forwarded-for': '1.2.3.4, 1.1.1.1, 1.1.1.1',
                'cookie': 'my_name=my_value_b',
            },
        ).headers[cookie_header]
        self.assertEqual(cookie_header_value, 'my_name=my_value_b')

    def test_slow_upload(self):
        self.addCleanup(create_filter(8080))
        self.addCleanup(create_origin(8081))
        wait_until_connectable(8080)
        wait_until_connectable(8081)

        num_bytes = 35
        def data():
            for _ in range(0, num_bytes):
                yield b'-'
                time.sleep(1)

        # Testing non-chunked streaming requests
        with requests.Session() as session:
            request = requests.Request(
                'POST',
                'http://127.0.0.1:8080/',
                headers={
                    'x-cf-forwarded-url': 'http://127.0.0.1:8081/',
                    'x-forwarded-for': '1.2.3.4, 1.1.1.1, 1.1.1.1',
                    'x-echo-response-status': '201',
                },
                data=data(),
            )
            prepared_request = session.prepare_request(request)
            del prepared_request.headers['transfer-encoding']
            prepared_request.headers['content-length'] = str(num_bytes)

            # This documents an issue to be fixed
            with self.assertRaises(requests.exceptions.ConnectionError):
                with session.send(prepared_request) as response:
                    pass

    def test_chunked_response(self):
        self.addCleanup(create_filter(8080))
        self.addCleanup(create_origin(8081))
        wait_until_connectable(8080)
        wait_until_connectable(8081)

        response = requests.request(
            'GET',
            url='http://127.0.0.1:8080/',
            headers={
                'x-cf-forwarded-url': 'http://127.0.0.1:8081/chunked',
                'x-forwarded-for': '1.2.3.4, 1.1.1.1, 1.1.1.1',
                'x-chunked-num-bytes': '10000',
            },
        )
        # This is an issue to be fixed: it the server sent chunked, then the
        # client should receive chunked, and not a content-length
        self.assertNotIn('transfer-encoding', response.headers)
        self.assertEqual(response.headers['content-length'], '10000')

        self.assertEqual(response.content, b'-' * 10000)

    def test_missing_x_forwarded_for_returns_403_and_origin_not_called(self):
        # Origin not running: if an attempt was made to connect to it, we
        # would get a 500
        self.addCleanup(create_filter(8080))
        wait_until_connectable(8080)

        status_code = requests.request(
            'GET',
            url='http://127.0.0.1:8080/',
            headers={
                'x-cf-forwarded-url': 'http://127.0.0.1:8081/',
            },
        ).status_code
        self.assertEqual(status_code, 403)

    def test_incorrect_x_forwarded_for_returns_403_and_origin_not_called(self):
        # Origin not running: if an attempt was made to connect to it, we
        # would get a 500
        self.addCleanup(create_filter(8080))
        wait_until_connectable(8080)

        x_forwarded_for_headers = [
            '1.2.3.4, 1.1.1.1, 1.1.1.1, 1.1.1.1',
            '3.3.3.3, 1.1.1.1, 1.1.1.1',
            '1.2.3.4, 1.1.1.1',
            '1.2.3.4',
            '',
        ]
        status_codes = [
            requests.request(
                'GET',
                url='http://127.0.0.1:8080/',
                headers={
                    'x-cf-forwarded-url': 'http://127.0.0.1:8081/',
                    'x-forwarded-for': x_forwarded_for_header,
                },
            ).status_code
            for x_forwarded_for_header in x_forwarded_for_headers
        ]
        self.assertEqual(status_codes, [403] * len(x_forwarded_for_headers))

    def test_not_running_origin_returns_500(self):
        self.addCleanup(create_filter(8080))
        wait_until_connectable(8080)
        status_code = requests.request(
            'GET',
            url='http://127.0.0.1:8080/',
            headers={
                'x-cf-forwarded-url': 'http://127.0.0.1:8081/',
                'x-forwarded-for': '1.2.3.4, 1.1.1.1, 1.1.1.1',
            },
        ).status_code
        self.assertEqual(status_code, 500)

def create_filter(port):
    def stop():
        process.terminate()
        process.wait()

    with open('Procfile', 'r') as f:
        lines = f.readlines()
    for line in lines:
        name, _, command = line.partition(':')
        if name.strip() == 'web':
            break
    process = subprocess.Popen(['bash', '-c', command.strip()], env={
        **os.environ,
        'ALLOWED_IPS': '1.2.3.4',
        'PORT': str(port),
    })

    return stop

def create_origin(port):
    def start():
        # Avoid warning about this not a prod server
        os.environ['FLASK_ENV'] = 'development'
        origin_app = Flask('origin')

        origin_app.endpoint('chunked')(chunked)
        origin_app.url_map.add(Rule('/chunked', endpoint='chunked'))

        origin_app.endpoint('multiple-cookies')(multiple_cookies)
        origin_app.url_map.add(Rule('/multiple-cookies', endpoint='multiple-cookies'))

        origin_app.endpoint('echo')(echo)
        origin_app.url_map.add(Rule('/', endpoint='echo'))
        origin_app.url_map.add(Rule('/<path:path>', endpoint='echo'))

        def _stop(_, __):
            sys.exit()

        signal.signal(signal.SIGTERM, _stop)
        signal.signal(signal.SIGINT, _stop)

        try:
            origin_app.run(host='', port=port, debug=False)
        except SystemExit:
            # origin_app.run doesn't seem to have a good way of killing the
            # server, and need to exit cleanly for code coverage to be saved
            pass

    def chunked():
        num_bytes = int(request.headers['x-chunked-num-bytes'])
        def data():
            chunk = b'-'
            for _ in range(0, num_bytes):
                yield hex(len(chunk))[2:].encode() + b'\r\n' + chunk + b'\r\n'
            yield b'0\r\n\r\n'

        return Response(data(), headers=[
            ('transfer-encoding', 'chunked'),
        ], status=200)

    def multiple_cookies():
        cookies = request.headers['x-multiple-cookies'].split(',')
        return Response(b'', headers=[
            ('set-cookie', cookie)
            for cookie in cookies
        ], status=200)

    def echo(path='/'):
        # Echo via headers to be able to assert more on HEAD requests that
        # have no response body
        response_header_prefix = 'x-echo-response-header-'
        headers = [
            ('x-echo-method', request.method),
            ('x-echo-raw-uri', request.environ['RAW_URI']),
        ] + [
            ('x-echo-header-' + k, v)
            for k, v in request.headers.items()
        ] + [
            (k[len(response_header_prefix):], v)
            for k, v in request.headers.items()
            if k.lower().startswith(response_header_prefix)
        ]
        return Response(
            request.stream.read(),
            headers=headers,
            status=int(request.headers.get('x-echo-response-status', '200')),
        )

    def stop():
        process.terminate()
        process.join()

    process = Process(target=start)
    process.start()

    return stop

def wait_until_connectable(port, max_attempts=1000):
    for i in range(0, max_attempts):
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=0.1):
                break
        except (OSError, ConnectionRefusedError):
            if i == max_attempts - 1:
                raise
            time.sleep(0.01)
