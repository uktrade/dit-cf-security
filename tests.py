import gzip
from multiprocess import (
    Process,
)
from io import (
    BytesIO,
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
from unittest.mock import patch

from flask import (
    abort,
    Flask,
    Response,
    request,
)
import urllib3
from werkzeug.routing import (
    Rule,
)
from werkzeug.serving import (
    WSGIRequestHandler,
)

from config import Environ


class EnvironTestCase(unittest.TestCase):
    def test_missing_key_raises_keyerror(self):
        env = Environ({
            "COPILOT_ENVIRONMENT": "staging",
        })

        with self.assertRaises(KeyError):
            env.get_value("MISSING")

        with self.assertRaises(KeyError):
            env.list("MINSSING")

        with self.assertRaises(KeyError):
            env.bool("MISSING")

        with self.assertRaises(KeyError):
            env.int("MISSING")

    def test_default_values(self):
        env = Environ(
            {
                "COPILOT_ENVIRONMENT": "staging",
            }
        )

        self.assertEqual(env.get_value("MISSING", default="missing"), "missing")
        self.assertEqual(env.bool("MISSING", default=True), True)
        self.assertEqual(env.list("MISSING", default=[]), [])
        self.assertEqual(env.list("MISSING", default=["test"]), ["test"])
        self.assertEqual(env.int("MISSING", default=-1), -1)

    def test_type_conversion_bool(self):
        env = Environ(
            {
                "COPILOT_ENVIRONMENT": "staging",
                "IS_TRUE": "True",
                "IS_FALSE": "False",
            }
        )

        self.assertEqual(env.bool("IS_TRUE"), True)
        self.assertEqual(env.bool("IS_FALSE"), False)

    def test_type_conversion_list(self):
        env = Environ(
            {
                "COPILOT_ENVIRONMENT": "staging",
                "MULTIPLE": "profile1, profile2, profile3",
                "SINGLE_ITEM": "False",
                "EMPTY": "",
            }
        )
        self.assertEqual(
            env.list("MULTIPLE"), ["profile1", "profile2", "profile3"]
        )
        self.assertEqual(env.list("SINGLE_ITEM"), ["False"])
        self.assertEqual(
            env.list("EMPTY"), []
        )

    def test_type_conversion_int(self):
        env = Environ(
            {
                "COPILOT_ENVIRONMENT": "staging",
                "TEST": "-1",
            }
        )
        self.assertEqual(
            env.int("TEST"), -1
        )

    def test_type_with_environment_overrides(self):
        env = Environ(
            {
                "COPILOT_ENVIRONMENT": "staging",
                "RANDOM_FIELD": "base-value",
                "STAGING_RANDOM_FIELD": "environment-override",
            }
        )

        self.assertEqual(env.get_value("RANDOM_FIELD"), "base-value")
        self.assertEqual(env.get_value("RANDOM_FIELD", allow_environment_override=True), "environment-override")


class ConfigurationTestCase(unittest.TestCase):
    """Tests covering the configuration logic"""

    def _setup_environment_and_make_request(self, env=(), request_path="/"):
        default_env = (
            ("ORIGIN_HOSTNAME", "localhost:8081"),
            ("ORIGIN_PROTO", "http"),
        )
        self.addCleanup(create_filter(8080, default_env + env))
        self.addCleanup(create_origin(8081))
        wait_until_connectable(8080)
        wait_until_connectable(8081)

        response = urllib3.PoolManager().request(
            "GET",
            url=f"http://127.0.0.1:8080{request_path}",
            headers={
                "x-forwarded-for": "1.2.3.4, 1.1.1.1, 1.1.1.1",
                "connection": "close",
            },
            body=b"some-data",
        )

        return response

    def test_ipfilter_disabled(self):
        """
        If the IP filter is disabled requests pass through to the origin.
        """
        response = self._setup_environment_and_make_request(
            (
                ("COPILOT_ENVIRONMENT", "staging"),
                ("IPFILTER_ENABLED", "False"),
            )
        )
        self.assertEqual(response.status, 200)
        self.assertNotIn("x-echo-header-connection", response.headers)

    def test_ipfiler_enabled_globally_but_disabled_for_environment(self):
        response = self._setup_environment_and_make_request(
            (
                ("COPILOT_ENVIRONMENT", "staging"),
                ("IPFILTER_ENABLED", "True"),
                ("STAGING_IPFILTER_ENABLED", "False"),
            )
        )

        self.assertEqual(response.status, 200)

    def test_ipfiler_enabled_and_path_is_in_public_paths(self):
        response = self._setup_environment_and_make_request(
            (
                ("COPILOT_ENVIRONMENT", "staging"),
                ("IPFILTER_ENABLED", "True"),
                ("PUBLIC_PATHS", "/public-test"),
            ),
            request_path="/public-test",
        )
        self.assertEqual(response.status, 200)
        self.assertNotIn("x-echo-header-connection", response.headers)

    def test_ipfiler_enabled_and_path_is_not_in_public_paths(self):
        response = self._setup_environment_and_make_request(
            (
                ("COPILOT_ENVIRONMENT", "staging"),
                ("IPFILTER_ENABLED", "True"),
                ("PUBLIC_PATHS", "/public-test"),
            ),
            request_path="/not-public",
        )
        self.assertEqual(response.status, 403)
        self.assertNotIn("x-echo-header-connection", response.headers)

    def test_ipfiler_enabled_and_path_is_in_protected_paths(self):
        response = self._setup_environment_and_make_request(
            (
                ("COPILOT_ENVIRONMENT", "staging"),
                ("IPFILTER_ENABLED", "True"),
                ("PROTECTED_PATHS", "/protected-test"),
            ),
            request_path="/protected-test",
        )
        self.assertEqual(response.status, 403)

    def test_ipfiler_enabled_and_path_is_not_in_protected_paths(self):
        response = self._setup_environment_and_make_request(
            (
                ("COPILOT_ENVIRONMENT", "staging"),
                ("IPFILTER_ENABLED", "True"),
                ("PROTECTED_PATHS", "/protected-test"),
            ),
            request_path="/not-protected",
        )
        self.assertEqual(response.status, 200)
        self.assertNotIn("x-echo-header-connection", response.headers)

    def test_appconfig_agent_with_valid_ip(self):
        self.addCleanup(
            create_appconfig_agent(2772))

        wait_until_connectable(2772)

        response = self._setup_environment_and_make_request(
            (
                ("COPILOT_ENVIRONMENT", "staging"),
                ("IPFILTER_ENABLED", "True"),
                ("APPCONFIG_PROFILES", "testapp:testenv:testconfig"),
            )
        )

        self.assertEqual(response.status, 200)


class ProxyTestCase(unittest.TestCase):
    """Tests that covery the ip filter's proxy functionality"""

    def test_meta_wait_until_connectable_raises(self):
        with self.assertRaises(OSError):
            wait_until_connectable(8080, max_attempts=10)

    def test_method_is_forwarded(self):
        self.addCleanup(create_appconfig_agent(2772))
        self.addCleanup(
            create_filter(
                8080,
                (
                    ("ORIGIN_HOSTNAME", "localhost:8081"),
                    ("ORIGIN_PROTO", "http"),
                    ("COPILOT_ENVIRONMENT", "staging"),
                    ("APPCONFIG_PROFILES", "testapp:testenv:testconfig"),
                ),
            )
        )
        self.addCleanup(create_origin(8081))
        wait_until_connectable(8080)
        wait_until_connectable(8081)
        wait_until_connectable(2772)

        methods = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]
        echo_methods = [
            urllib3.PoolManager()
            .request(
                method,
                url="http://127.0.0.1:8080/",
                headers={
                    "x-forwarded-for": "1.2.3.4, 1.1.1.1, 1.1.1.1",
                },
            )
            .headers["x-echo-method"]
            for method in methods
        ]
        self.assertEqual(methods, echo_methods)

    def test_host_is_forwarded(self):
        self.addCleanup(create_appconfig_agent(2772))
        self.addCleanup(
            create_filter(
                8080,
                (
                    ("ORIGIN_HOSTNAME", "localhost:8081"),
                    ("ORIGIN_PROTO", "http"),
                    ("COPILOT_ENVIRONMENT", "staging"),
                    ("APPCONFIG_PROFILES", "testapp:testenv:testconfig"),
                ),
            )
        )
        self.addCleanup(create_origin(8081))
        wait_until_connectable(8080)
        wait_until_connectable(8081)
        wait_until_connectable(2772)

        host = (
            urllib3.PoolManager()
            .request(
                "GET",
                url="http://127.0.0.1:8080/",
                headers={
                    "host": "somehost.com",
                    "x-forwarded-for": "1.2.3.4, 1.1.1.1, 1.1.1.1",
                },
            )
            .headers["x-echo-header-host"]
        )
        self.assertEqual(host, "somehost.com")

    def test_path_and_query_is_forwarded(self):
        self.addCleanup(create_appconfig_agent(2772))
        self.addCleanup(
            create_filter(
                8080,
                (
                    ("ORIGIN_HOSTNAME", "127.0.0.1:8081"),
                    ("ORIGIN_PROTO", "http"),
                    ("COPILOT_ENVIRONMENT", "staging"),
                    ("APPCONFIG_PROFILES", "testapp:testenv:testconfig")
                ),
            )
        )
        self.addCleanup(create_origin(8081))
        wait_until_connectable(8080)
        wait_until_connectable(8081)
        wait_until_connectable(2772)

        path = urllib.parse.quote("/a/£/💾")
        query = urllib.parse.urlencode(
            [
                ("a", "b"),
                ("🍰", "😃"),
            ]
        )
        raw_uri_expected = f"{path}?{query}"
        response = urllib3.PoolManager().request(
            "GET",
            url=f"http://127.0.0.1:8080/{path}?{query}",
            headers={
                "host": "127.0.0.1:8081",
                "x-forwarded-for": "1.2.3.4, 1.1.1.1, 1.1.1.1",
            },
        )
        raw_uri_received = response.headers["x-echo-raw-uri"]

        self.assertEqual(raw_uri_expected, raw_uri_received)
        self.assertEqual(response.headers["x-echo-header-Host"], "127.0.0.1:8081")

    def test_body_is_forwarded(self):
        self.addCleanup(create_appconfig_agent(2772))
        self.addCleanup(
            create_filter(
                8080,
                (
                    ("ORIGIN_HOSTNAME", "localhost:8081"),
                    ("ORIGIN_PROTO", "http"),
                    ("COPILOT_ENVIRONMENT", "staging"),
                    ("APPCONFIG_PROFILES", "testapp:testenv:testconfig"),
                ),
            )
        )
        self.addCleanup(create_origin(8081))
        wait_until_connectable(8080)
        wait_until_connectable(8081)
        wait_until_connectable(2772)

        method_bodies_expected = [
            ("GET", uuid.uuid4().bytes * 1),
            ("POST", uuid.uuid4().bytes * 10),
            ("PUT", uuid.uuid4().bytes * 100),
            ("PATCH", uuid.uuid4().bytes * 1000),
            ("DELETE", uuid.uuid4().bytes * 10000),
            ("OPTIONS", uuid.uuid4().bytes * 100000),
        ]
        method_bodies_received = [
            (
                method,
                urllib3.PoolManager()
                .request(
                    method,
                    url="http://127.0.0.1:8080/",
                    headers={
                        "x-forwarded-for": "1.2.3.4, 1.1.1.1, 1.1.1.1",
                    },
                    body=body,
                )
                .data,
            )
            for method, body in method_bodies_expected
        ]
        self.assertEqual(method_bodies_expected, method_bodies_received)

    def test_status_is_forwarded(self):
        self.addCleanup(create_appconfig_agent(2772))
        self.addCleanup(
            create_filter(
                8080,
                (
                    ("ORIGIN_HOSTNAME", "localhost:8081"),
                    ("ORIGIN_PROTO", "http"),
                    ("COPILOT_ENVIRONMENT", "staging"),
                    ("APPCONFIG_PROFILES", "testapp:testenv:testconfig"),
                ),
            )
        )
        self.addCleanup(create_origin(8081))
        wait_until_connectable(8080)
        wait_until_connectable(8081)
        wait_until_connectable(8081)

        method_statuses_expected = list(
            itertools.product(
                ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"],
                ["200", "201", "401", "403", "500"],
            )
        )
        method_statuses_received = [
            (
                method,
                str(
                    urllib3.PoolManager()
                    .request(
                        method,
                        url="http://127.0.0.1:8080/",
                        headers={
                            "x-forwarded-for": "1.2.3.4, 1.1.1.1, 1.1.1.1",
                            "x-echo-response-status": status,
                        },
                    )
                    .status
                ),
            )
            for method, status in method_statuses_expected
        ]
        self.assertEqual(method_statuses_expected, method_statuses_received)

    def test_connection_is_not_forwarded(self):
        self.addCleanup(create_appconfig_agent(2772))
        self.addCleanup(
            create_filter(
                8080,
                (
                    ("ORIGIN_HOSTNAME", "localhost:8081"),
                    ("ORIGIN_PROTO", "http"),
                    ("COPILOT_ENVIRONMENT", "staging"),
                    ("APPCONFIG_PROFILES", "testapp:testenv:testconfig"),
                ),
            )
        )
        self.addCleanup(create_origin(8081))
        wait_until_connectable(8080)
        wait_until_connectable(8081)
        wait_until_connectable(2772)

        response = urllib3.PoolManager().request(
            "GET",
            url="http://127.0.0.1:8080/",
            headers={
                "x-forwarded-for": "1.2.3.4, 1.1.1.1, 1.1.1.1",
                "connection": "close",
            },
            body=b"some-data",
        )
        self.assertEqual(response.status, 200)
        self.assertNotIn("x-echo-header-connection", response.headers)

    def test_no_issue_if_origin_restarted(self):
        self.addCleanup(create_appconfig_agent(2772))
        self.addCleanup(
            create_filter(
                8080,
                (
                    ("ORIGIN_HOSTNAME", "localhost:8081"),
                    ("ORIGIN_PROTO", "http"),
                    ("COPILOT_ENVIRONMENT", "staging"),
                    ("APPCONFIG_PROFILES", "testapp:testenv:testconfig"),
                ),
            )
        )
        stop_origin_1 = create_origin(8081)
        self.addCleanup(stop_origin_1)
        wait_until_connectable(8080)
        wait_until_connectable(8081)
        wait_until_connectable(2772)

        response_1 = urllib3.PoolManager().request(
            "GET",
            url="http://127.0.0.1:8080/some-path",
            headers={
                "x-forwarded-for": "1.2.3.4, 1.1.1.1, 1.1.1.1",
            },
            body=b"some-data",
        )
        self.assertEqual(response_1.status, 200)
        self.assertEqual(response_1.data, b"some-data")
        remote_port_1 = response_1.headers["x-echo-remote-port"]

        stop_origin_1()
        stop_origin_2 = create_origin(8081)
        self.addCleanup(stop_origin_2)
        wait_until_connectable(8081)

        response_2 = urllib3.PoolManager().request(
            "GET",
            url="http://127.0.0.1:8080/some-path",
            headers={
                "x-forwarded-for": "1.2.3.4, 1.1.1.1, 1.1.1.1",
            },
            body=b"some-more-data",
        )
        self.assertEqual(response_2.status, 200)
        self.assertEqual(response_2.data, b"some-more-data")
        remote_port_2 = response_2.headers["x-echo-remote-port"]

        # A meta test to ensure that we really have
        # restart the origin server. Hopefully not too flaky.
        self.assertNotEqual(remote_port_1, remote_port_2)

    def test_no_issue_if_request_unfinished(self):
        self.addCleanup(create_appconfig_agent(2772))
        self.addCleanup(
            create_filter(
                8080,
                (
                    ("ORIGIN_HOSTNAME", "localhost:8081"),
                    ("ORIGIN_PROTO", "http"),
                    ("COPILOT_ENVIRONMENT", "staging"),
                    ("APPCONFIG_PROFILES", "testapp:testenv:testconfig"),
                ),
            )
        )
        self.addCleanup(create_origin(8081))
        wait_until_connectable(8080)
        wait_until_connectable(8081)
        wait_until_connectable(2772)

        class BodyException(Exception):
            pass

        def body():
            yield b"-" * 100_000
            time.sleep(1)
            raise BodyException()

        # We only send half of the request
        with self.assertRaises(BodyException):
            urllib3.PoolManager().request(
                "POST",
                "http://127.0.0.1:8080/",
                headers={
                    "content-length": "200000",
                    "x-forwarded-for": "1.2.3.4, 1.1.1.1, 1.1.1.1",
                },
                body=body(),
            )

        response = urllib3.PoolManager().request(
            "GET",
            url="http://127.0.0.1:8080/",
            headers={
                "x-forwarded-for": "1.2.3.4, 1.1.1.1, 1.1.1.1",
            },
            body="some-data",
        )
        self.assertEqual(response.data, b"some-data")

    def test_request_header_is_forwarded(self):
        self.addCleanup(create_appconfig_agent(2772))
        self.addCleanup(
            create_filter(
                8080,
                (
                    ("ORIGIN_HOSTNAME", "localhost:8081"),
                    ("ORIGIN_PROTO", "http"),
                    ("COPILOT_ENVIRONMENT", "staging"),
                    ("APPCONFIG_PROFILES", "testapp:testenv:testconfig"),
                ),
            )
        )
        self.addCleanup(create_origin(8081))
        wait_until_connectable(8080)
        wait_until_connectable(8081)
        wait_until_connectable(2772)

        response_header = (
            urllib3.PoolManager()
            .request(
                "GET",
                url="http://127.0.0.1:8080/",
                headers={
                    "x-forwarded-for": "1.2.3.4, 1.1.1.1, 1.1.1.1",
                    "some-header": "some-value",
                },
            )
            .headers["x-echo-header-some-header"]
        )
        self.assertEqual(response_header, "some-value")

    def test_content_length_is_forwarded(self):
        self.addCleanup(create_appconfig_agent(2772))
        self.addCleanup(
            create_filter(
                8080,
                (
                    ("ORIGIN_HOSTNAME", "localhost:8081"),
                    ("ORIGIN_PROTO", "http"),
                    ("COPILOT_ENVIRONMENT", "staging"),
                    ("APPCONFIG_PROFILES", "testapp:testenv:testconfig"),
                ),
            )
        )
        self.addCleanup(create_origin(8081))
        wait_until_connectable(8080)
        wait_until_connectable(8081)
        wait_until_connectable(2772)

        headers = (
            urllib3.PoolManager()
            .request(
                "GET",
                url="http://127.0.0.1:8080/",
                headers={
                    "x-forwarded-for": "1.2.3.4, 1.1.1.1, 1.1.1.1",
                },
                body=b"some-data",
            )
            .headers
        )
        self.assertEqual(
            headers["x-echo-header-content-length"], str(len(b"some-data"))
        )
        self.assertNotIn("x-echo-header-transfer-encoding", headers)

    def test_response_header_is_forwarded(self):
        self.addCleanup(create_appconfig_agent(2772))
        self.addCleanup(
            create_filter(
                8080,
                (
                    ("ORIGIN_HOSTNAME", "localhost:8081"),
                    ("ORIGIN_PROTO", "http"),
                    ("COPILOT_ENVIRONMENT", "staging"),
                    ("APPCONFIG_PROFILES", "testapp:testenv:testconfig"),
                ),
            )
        )
        self.addCleanup(create_origin(8081))
        wait_until_connectable(8080)
        wait_until_connectable(8081)
        wait_until_connectable(2772)

        response_header = (
            urllib3.PoolManager()
            .request(
                "GET",
                url="http://127.0.0.1:8080/",
                headers={
                    "x-forwarded-for": "1.2.3.4, 1.1.1.1, 1.1.1.1",
                    "x-echo-response-header-some-header": "some-value",
                },
            )
            .headers["some-header"]
        )
        self.assertEqual(response_header, "some-value")

    def test_content_disposition_with_latin_1_character_is_forwarded(self):
        self.addCleanup(create_appconfig_agent(2772))
        self.addCleanup(
            create_filter(
                8080,
                (
                    ("ORIGIN_HOSTNAME", "localhost:8081"),
                    ("ORIGIN_PROTO", "http"),
                    ("COPILOT_ENVIRONMENT", "staging"),
                    ("APPCONFIG_PROFILES", "testapp:testenv:testconfig"),
                ),
            )
        )
        self.addCleanup(create_origin(8081))
        wait_until_connectable(8080)
        wait_until_connectable(8081)
        wait_until_connectable(2772)

        response_header = (
            urllib3.PoolManager()
            .request(
                "GET",
                url="http://127.0.0.1:8080/",
                headers={
                    "x-forwarded-for": "1.2.3.4, 1.1.1.1, 1.1.1.1",
                    "x-echo-response-header-content-disposition": 'attachment; filename="Ö"',
                },
            )
            .headers["content-disposition"]
        )

        self.assertEqual(response_header, 'attachment; filename="Ö"')

    def test_get_content_length_is_forwarded(self):
        self.addCleanup(create_appconfig_agent(2772))
        self.addCleanup(
            create_filter(
                8080,
                (
                    ("ORIGIN_HOSTNAME", "localhost:8081"),
                    ("ORIGIN_PROTO", "http"),
                    ("COPILOT_ENVIRONMENT", "staging"),
                    ("APPCONFIG_PROFILES", "testapp:testenv:testconfig"),
                ),
            )
        )
        self.addCleanup(create_origin(8081))
        wait_until_connectable(8080)
        wait_until_connectable(8081)
        wait_until_connectable(2772)

        content_length = (
            urllib3.PoolManager()
            .request(
                "GET",
                # Make sure test doesn't pass due to "de-chunking" of small bodies
                body=b"Something" * 10000000,
                url="http://127.0.0.1:8080/",
                headers={
                    "x-forwarded-for": "1.2.3.4, 1.1.1.1, 1.1.1.1",
                },
            )
            .headers["content-length"]
        )
        self.assertEqual(content_length, "90000000")

    def test_head_content_length_is_forwarded(self):
        self.addCleanup(create_appconfig_agent(2772))
        self.addCleanup(
            create_filter(
                8080,
                (
                    ("ORIGIN_HOSTNAME", "localhost:8081"),
                    ("ORIGIN_PROTO", "http"),
                    ("COPILOT_ENVIRONMENT", "staging"),
                    ("APPCONFIG_PROFILES", "testapp:testenv:testconfig"),
                ),
            )
        )
        self.addCleanup(create_origin(8081))
        wait_until_connectable(8080)
        wait_until_connectable(8081)
        wait_until_connectable(2772)

        content_length = (
            urllib3.PoolManager()
            .request(
                "HEAD",
                url="http://127.0.0.1:8080/",
                headers={
                    "x-forwarded-for": "1.2.3.4, 1.1.1.1, 1.1.1.1",
                    "x-echo-response-header-content-length": "12345678",
                },
            )
            .headers["content-length"]
        )
        # This should probably be 12345678
        self.assertEqual(content_length, "0")

    def test_request_cookie_is_forwarded(self):
        self.addCleanup(create_appconfig_agent(2772))
        self.addCleanup(
            create_filter(
                8080,
                (
                    ("ORIGIN_HOSTNAME", "localtest.me:8081"),
                    ("ORIGIN_PROTO", "http"),
                    ("COPILOT_ENVIRONMENT", "staging"),
                    ("APPCONFIG_PROFILES", "testapp:testenv:testconfig"),
                ),
            )
        )
        self.addCleanup(create_origin(8081))
        wait_until_connectable(8080)
        wait_until_connectable(8081)
        wait_until_connectable(2772)

        response_header = (
            urllib3.PoolManager()
            .request(
                "GET",
                url="http://127.0.0.1:8080/",
                headers={
                    "x-forwarded-for": "1.2.3.4, 1.1.1.1, 1.1.1.1",
                    "cookie": "my_name=my_value",
                },
            )
            .headers["x-echo-header-cookie"]
        )
        self.assertEqual(response_header, "my_name=my_value")

        response_header = (
            urllib3.PoolManager()
            .request(
                "GET",
                url="http://127.0.0.1:8080/",
                headers={
                    "x-forwarded-for": "1.2.3.4, 1.1.1.1, 1.1.1.1",
                    "cookie": "my_name=my_value; my_name_b=my_other_value",
                },
            )
            .headers["x-echo-header-cookie"]
        )
        self.assertEqual(response_header, "my_name=my_value; my_name_b=my_other_value")

    def test_response_cookie_is_forwarded(self):
        self.addCleanup(create_appconfig_agent(2772))
        self.addCleanup(
            create_filter(
                8080,
                (
                    ("ORIGIN_HOSTNAME", "localtest.me:8081"),
                    ("ORIGIN_PROTO", "http"),
                    ("COPILOT_ENVIRONMENT", "staging"),
                    ("APPCONFIG_PROFILES", "testapp:testenv:testconfig"),
                ),
            )
        )
        self.addCleanup(create_origin(8081))
        wait_until_connectable(8080)
        wait_until_connectable(8081)
        wait_until_connectable(2772)

        response_header = (
            urllib3.PoolManager()
            .request(
                "GET",
                url="http://127.0.0.1:8080/",
                headers={
                    "x-forwarded-for": "1.2.3.4, 1.1.1.1, 1.1.1.1",
                    "x-echo-response-header-set-cookie": "my_name=my_value",
                },
            )
            .headers["set-cookie"]
        )
        self.assertEqual(response_header, "my_name=my_value")

        # A full cookie with lots of components
        full_cookie_value = (
            "my_name=my_value; Domain=.localtest.me; "
            "Expires=Wed, 29-Apr-2020 15:06:49 GMT; Secure; "
            "HttpOnly; Path=/path"
        )
        response_header = (
            urllib3.PoolManager()
            .request(
                "GET",
                url="http://127.0.0.1:8080/path",
                headers={
                    "x-forwarded-for": "1.2.3.4, 1.1.1.1, 1.1.1.1",
                    "x-echo-response-header-set-cookie": full_cookie_value,
                },
            )
            .headers["set-cookie"]
        )
        self.assertEqual(response_header, full_cookie_value)

        # Checking the treatment of Max-Age (which Python requests can change
        # to Expires)
        response_header = (
            urllib3.PoolManager()
            .request(
                "GET",
                url="http://127.0.0.1:8080/path",
                headers={
                    "x-forwarded-for": "1.2.3.4, 1.1.1.1, 1.1.1.1",
                    "x-echo-response-header-set-cookie": "my_name=my_value; Max-Age=100",
                },
            )
            .headers["set-cookie"]
        )
        self.assertEqual(response_header, "my_name=my_value; Max-Age=100")

    def test_multiple_response_cookies_are_forwarded(self):
        self.addCleanup(create_appconfig_agent(2772))
        self.addCleanup(
            create_filter(
                8080,
                (
                    ("ORIGIN_HOSTNAME", "localtest.me:8081"),
                    ("ORIGIN_PROTO", "http"),
                    ("COPILOT_ENVIRONMENT", "staging"),
                    ("APPCONFIG_PROFILES", "testapp:testenv:testconfig"),
                ),
            )
        )
        self.addCleanup(create_origin(8081))
        wait_until_connectable(8080)
        wait_until_connectable(8081)
        wait_until_connectable(2772)

        # We make sure we don't depend or are thwarted by magic that an HTTP
        # client in the tests does regarding multiple HTTP headers of the same
        # name, and specifically any handing of multiple Set-Cookie headers
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(("127.0.0.1", 8080))
        sock.send(
            b"GET http://localtest.me:8081/multiple-cookies HTTP/1.1\r\n"
            b"host:127.0.0.1\r\n"
            b"x-forwarded-for:1.2.3.4, 1.1.1.1, 1.1.1.1\r\n"
            b"x-multiple-cookies:name_a=value_a,name_b=value_b\r\n"
            b"\r\n"
        )

        response = b""
        while b"\r\n\r\n" not in response:
            response += sock.recv(4096)
        sock.close()

        self.assertIn(b"set-cookie: name_a=value_a\r\n", response)
        self.assertIn(b"set-cookie: name_b=value_b\r\n", response)

    def test_cookie_not_stored(self):
        self.addCleanup(create_appconfig_agent(2772))
        self.addCleanup(
            create_filter(
                8080,
                (
                    ("ORIGIN_HOSTNAME", "localtest.me:8081"),
                    ("ORIGIN_PROTO", "http"),
                    ("COPILOT_ENVIRONMENT", "staging"),
                    ("APPCONFIG_PROFILES", "testapp:testenv:testconfig"),
                ),
            )
        )
        self.addCleanup(create_origin(8081))
        wait_until_connectable(8080)
        wait_until_connectable(8081)
        wait_until_connectable(2772)

        # Ensure that the filter itself don't store cookies set by the origin
        cookie_header = "x-echo-header-cookie"
        set_cookie = (
            urllib3.PoolManager()
            .request(
                "GET",
                url="http://127.0.0.1:8080/",
                headers={
                    "x-forwarded-for": "1.2.3.4, 1.1.1.1, 1.1.1.1",
                    "x-echo-response-header-set-cookie": "my_name=my_value_a; Domain=.localtest.me; Path=/path",
                },
            )
            .headers["set-cookie"]
        )
        self.assertEqual(
            set_cookie, "my_name=my_value_a; Domain=.localtest.me; Path=/path"
        )
        has_cookie = (
            cookie_header
            in urllib3.PoolManager()
            .request(
                "GET",
                url="http://127.0.0.1:8080/",
                headers={
                    "x-forwarded-for": "1.2.3.4, 1.1.1.1, 1.1.1.1",
                },
            )
            .headers
        )
        self.assertFalse(has_cookie)

        # Meta test, ensuring that cookie_header is the right header to
        # check for to see if the echo origin received the cookie
        cookie_header_value = (
            urllib3.PoolManager()
            .request(
                "GET",
                url="http://127.0.0.1:8080/",
                headers={
                    "x-forwarded-for": "1.2.3.4, 1.1.1.1, 1.1.1.1",
                    "cookie": "my_name=my_value_b",
                },
            )
            .headers[cookie_header]
        )
        self.assertEqual(cookie_header_value, "my_name=my_value_b")

    def test_gzipped(self):
        self.addCleanup(create_appconfig_agent(2772))
        self.addCleanup(
            create_filter(
                8080,
                (
                    ("ORIGIN_HOSTNAME", "localtest.me:8081"),
                    ("ORIGIN_PROTO", "http"),
                    ("COPILOT_ENVIRONMENT", "staging"),
                    ("APPCONFIG_PROFILES", "testapp:testenv:testconfig"),
                ),
            )
        )
        self.addCleanup(create_origin(8081))
        wait_until_connectable(8080)
        wait_until_connectable(8081)
        wait_until_connectable(2772)

        response = urllib3.PoolManager().request(
            "GET",
            url="http://127.0.0.1:8080/gzipped",
            headers={
                "host": "localtest.me:8081",
                "x-forwarded-for": "1.2.3.4, 1.1.1.1, 1.1.1.1",
            },
            body=b"something-to-zip",
        )
        self.assertEqual(response.data, b"something-to-zip")
        self.assertEqual(response.headers["content-encoding"], "gzip")
        self.assertIn("content-length", response.headers)

    @unittest.skip("TODO: fix broken test")
    def test_slow_upload(self):
        self.addCleanup(create_appconfig_agent(2772))
        self.addCleanup(
            create_filter(
                8080,
                (
                    ("ORIGIN_HOSTNAME", "localhost:8081"),
                    ("ORIGIN_PROTO", "http"),
                    ("COPILOT_ENVIRONMENT", "staging"),
                    ("APPCONFIG_PROFILES", "testapp:testenv:testconfig"),
                ),
            )
        )
        self.addCleanup(create_origin(8081))
        wait_until_connectable(8080)
        wait_until_connectable(8081)
        wait_until_connectable(2772)

        num_bytes = 35

        def body():
            for _ in range(0, num_bytes):
                yield b"-"
                time.sleep(1)

        # Testing non-chunked streaming requests
        data = (
            urllib3.PoolManager()
            .request(
                "POST",
                "http://127.0.0.1:8080/",
                headers={
                    "content-length": str(num_bytes),
                    "x-forwarded-for": "1.2.3.4, 1.1.1.1, 1.1.1.1",
                },
                body=body(),
            )
            .data
        )
        self.assertEqual(data, b"-" * num_bytes)

    def test_chunked_response(self):
        self.addCleanup(create_appconfig_agent(2772))
        self.addCleanup(
            create_filter(
                8080,
                (
                    ("ORIGIN_HOSTNAME", "localhost:8081"),
                    ("ORIGIN_PROTO", "http"),
                    ("COPILOT_ENVIRONMENT", "staging"),
                    ("APPCONFIG_PROFILES", "testapp:testenv:testconfig"),
                ),
            )
        )
        self.addCleanup(create_origin(8081))
        wait_until_connectable(8080)
        wait_until_connectable(8081)
        wait_until_connectable(2772)

        response = urllib3.PoolManager().request(
            "GET",
            url="http://127.0.0.1:8080/chunked",
            headers={
                "host": "127.0.0.1:8081",
                "x-forwarded-for": "1.2.3.4, 1.1.1.1, 1.1.1.1",
                "x-chunked-num-bytes": "10000",
            },
            preload_content=False,
            chunked=True,
        )

        self.assertEqual("chunked", response.headers["Transfer-Encoding"])
        self.assertNotIn("content-length", response.headers)
        self.assertEqual(response.data, b"-" * 10000)

    def test_https(self):
        self.addCleanup(create_appconfig_agent(2772))
        self.addCleanup(
            create_filter(
                8080,
                (
                    ("ORIGIN_HOSTNAME", "www.google.com"),
                    ("ORIGIN_PROTO", "https"),
                    ("COPILOT_ENVIRONMENT", "staging"),
                    ("APPCONFIG_PROFILES", "testapp:testenv:testconfig"),
                ),
            )
        )
        wait_until_connectable(8080)
        wait_until_connectable(2772)

        # On the one hand not great to depend on a 3rd party/external site,
        # but it does test that the filter can connect to a regular/real site
        # that we cannot have customised to make the tests pass. Plus,
        # www.google.com is extremely unlikely to go down
        data = (
            urllib3.PoolManager()
            .request(
                "GET",
                url="http://127.0.0.1:8080/",
                headers={
                    "host": "www.google.com",
                    "x-forwarded-for": "1.2.3.4, 1.1.1.1, 1.1.1.1",
                },
            )
            .data
        )
        self.assertIn(b"<title>https://www.google.com/</title>", data)

    def test_https_origin_not_exist_returns_500(self):
        self.addCleanup(create_appconfig_agent(2772))
        self.addCleanup(
            create_filter(
                8080,
                (
                    ("ORIGIN_HOSTNAME", "does.not.exist"),
                    ("ORIGIN_PROTO", "https"),
                    ("COPILOT_ENVIRONMENT", "staging"),
                    ("APPCONFIG_PROFILES", "testapp:testenv:testconfig"),
                ),
            )
        )
        wait_until_connectable(8080)
        wait_until_connectable(2772)

        response = urllib3.PoolManager().request(
            "GET",
            url="http://127.0.0.1:8080/",
            headers={
                "x-forwarded-for": "1.2.3.4, 1.1.1.1, 1.1.1.1",
            },
        )
        self.assertEqual(response.status, 500)

    def test_http_origin_not_exist_returns_500(self):
        self.addCleanup(create_appconfig_agent(2772))
        self.addCleanup(
            create_filter(
                8080,
                (
                    ("ORIGIN_HOSTNAME", "does.not.exist"),
                    ("ORIGIN_PROTO", "http"),
                    ("COPILOT_ENVIRONMENT", "staging"),
                    ("APPCONFIG_PROFILES", "testapp:testenv:testconfig"),
                ),
            )
        )
        wait_until_connectable(8080)
        wait_until_connectable(2772)

        response = urllib3.PoolManager().request(
            "GET",
            url="http://127.0.0.1:8080/",
            headers={
                "x-forwarded-for": "1.2.3.4, 1.1.1.1, 1.1.1.1",
            },
        )
        self.assertEqual(response.status, 500)

    def test_not_running_origin_returns_500(self):
        self.addCleanup(create_appconfig_agent(2772))
        self.addCleanup(
            create_filter(
                8080,
                (
                    ("ORIGIN_HOSTNAME", "localhost:8081"),
                    ("ORIGIN_PROTO", "http"),
                    ("COPILOT_ENVIRONMENT", "staging"),
                    ("APPCONFIG_PROFILES", "testapp:testenv:testconfig"),
                ),
            )
        )
        wait_until_connectable(8080)
        wait_until_connectable(2772)

        status = (
            urllib3.PoolManager()
            .request(
                "GET",
                url="http://127.0.0.1:8080/",
                headers={
                    "host": "127.0.0.1:8081",
                    "x-forwarded-for": "1.2.3.4, 1.1.1.1, 1.1.1.1",
                },
            )
            .status
        )
        self.assertEqual(status, 500)


class IpFilterLogicTestCase(unittest.TestCase):
    """Tests covering the IP filter logic"""

    def test_missing_x_forwarded_for_returns_403_and_origin_not_called(self):
        # Origin not running: if an attempt was made to connect to it, we
        # would get a 500
        self.addCleanup(create_appconfig_agent(2772))
        self.addCleanup(
            create_filter(
                8080,
                (
                    ("ORIGIN_HOSTNAME", "localhost:8081"),
                    ("ORIGIN_PROTO", "http"),
                    ("COPILOT_ENVIRONMENT", "staging"),
                    ("APPCONFIG_PROFILES", "testapp:testenv:testconfig"),
                ),
            )
        )
        wait_until_connectable(8080)
        wait_until_connectable(2772)
        response = urllib3.PoolManager().request(
            "GET",
            url="http://127.0.0.1:8080/",
        )
        self.assertEqual(response.status, 403)
        # TODO find way of capturing log output and check for missing x-forwarded message

    def test_incorrect_x_forwarded_for_returns_403_and_origin_not_called(self):
        # Origin not running: if an attempt was made to connect to it, we
        # would get a 500
        self.addCleanup(create_appconfig_agent(2772))
        self.addCleanup(
            create_filter(
                8080,
                (
                    ("ORIGIN_HOSTNAME", "localhost:8081"),
                    ("ORIGIN_PROTO", "http"),
                    ("COPILOT_ENVIRONMENT", "staging")
                ),
            )
        )
        wait_until_connectable(8080)

        x_forwarded_for_headers = [
            "1.2.3.4, 1.1.1.1, 1.1.1.1, 1.1.1.1",
            "3.3.3.3, 1.1.1.1, 1.1.1.1",
            "1.2.3.4, 1.1.1.1",
            "1.2.3.4",
            "",
        ]
        statuses = [
            urllib3.PoolManager()
            .request(
                "GET",
                url="http://127.0.0.1:8080/",
                headers={
                    "x-forwarded-for": x_forwarded_for_header,
                },
            )
            .status
            for x_forwarded_for_header in x_forwarded_for_headers
        ]
        self.assertEqual(statuses, [403] * len(x_forwarded_for_headers))

    def test_x_forwarded_for_index_respected(self):
        self.addCleanup(create_appconfig_agent(2772, {
            "mytest:env:iplist": """
IpRanges:
  - 1.2.3.4/32
"""
        }))
        self.addCleanup(
            create_filter(
                8080,
                (
                    ("ORIGIN_HOSTNAME", "localhost:8081"),
                    ("ORIGIN_PROTO", "http"),
                    ("IP_DETERMINED_BY_X_FORWARDED_FOR_INDEX", "-2"),
                    ("COPILOT_ENVIRONMENT", "staging"),
                    ("APPCONFIG_PROFILES", "mytest:env:iplist")
                ),
            )
        )
        self.addCleanup(create_origin(8081))
        wait_until_connectable(8080)
        wait_until_connectable(8081)
        wait_until_connectable(2772)

        response = urllib3.PoolManager().request(
            "GET",
            url="http://127.0.0.1:8080/",
            headers={
                "host": "somehost.com",
                "x-forwarded-for": "1.2.3.4, 1.1.1.1, 1.1.1.1",
            },
        )
        self.assertEqual(response.status, 403)
        self.assertIn(b">1.1.1.1<", response.data)
        self.assertIn(b">/<", response.data)

        status = (
            urllib3.PoolManager()
            .request(
                "GET",
                url="http://127.0.0.1:8080/",
                headers={
                    "host": "somehost.com",
                    "x-forwarded-for": "1.2.3.4, 1.1.1.1",
                },
            )
            .status
        )
        self.assertEqual(status, 200)

    def test_ip_matching_cidr_respected(self):
        self.addCleanup(create_appconfig_agent(2772, {
            "testapp:testenv:testconfig2": """
IpRanges:
    - 1.2.3.0/24
"""
        }))
        self.addCleanup(
            create_filter(
                8080,
                (
                    ("ORIGIN_HOSTNAME", "localhost:8081"),
                    ("ORIGIN_PROTO", "http"),
                    ("IP_DETERMINED_BY_X_FORWARDED_FOR_INDEX", "-3"),
                    ("COPILOT_ENVIRONMENT", "staging"),
                    ("APPCONFIG_PROFILES", "testapp:testenv:testconfig,testapp:testenv:testconfig2")
                ),
            )
        )
        self.addCleanup(create_origin(8081))
        wait_until_connectable(8080)
        wait_until_connectable(8081)
        wait_until_connectable(2772)

        status = (
            urllib3.PoolManager()
            .request(
                "GET",
                url="http://127.0.0.1:8080/",
                headers={
                    "host": "somehost.com",
                    "x-forwarded-for": "1.2.3.4, 1.1.1.1, 1.1.1.1",
                },
            )
            .status
        )
        self.assertEqual(status, 200)

        status = (
            urllib3.PoolManager()
            .request(
                "GET",
                url="http://127.0.0.1:8080/",
                headers={
                    "host": "somehost.com",
                    "x-forwarded-for": "1.2.3.5, 1.1.1.1, 1.1.1.1",
                },
            )
            .status
        )
        self.assertEqual(status, 200)

        status = (
            urllib3.PoolManager()
            .request(
                "GET",
                url="http://127.0.0.1:8080/",
                headers={
                    "host": "somehost.com",
                    "x-forwarded-for": "1.2.4.5, 1.1.1.1, 1.1.1.1",
                },
            )
            .status
        )
        self.assertEqual(status, 403)

    def test_trace_id_is_reported(self):
        self.addCleanup(create_appconfig_agent(2772,
        {
            "testapp:testenv:testconfig2": """
IpRanges:
    - 1.2.3.4/32
"""
        }))
        self.addCleanup(
            create_filter(
                8080,
                (
                    ("ORIGIN_HOSTNAME", "localhost:8081"),
                    ("ORIGIN_PROTO", "http"),
                    ("IP_DETERMINED_BY_X_FORWARDED_FOR_INDEX", "-2"),
                    ("COPILOT_ENVIRONMENT", "staging"),
                    ("APPCONFIG_PROFILES", "testapp:testenv:testconfig2"),
                ),
            )
        )
        self.addCleanup(create_origin(8081))
        wait_until_connectable(8080)
        wait_until_connectable(8081)
        wait_until_connectable(2772)

        response = urllib3.PoolManager().request(
            "GET",
            url="http://127.0.0.1:8080/__some_path",
            headers={
                "host": "somehost.com",
                "x-forwarded-for": "1.1.1.1, 1.1.1.1, 1.1.1.1",
                "x-cdn-secret": "my-mangos",
                "X-B3-Traceid": "1234magictraceid",
            },
        )
        self.assertEqual(response.status, 403)
        self.assertIn(b">1234magictraceid<", response.data)

    def test_client_ipv6_is_handled(self):
        self.addCleanup(create_appconfig_agent(2772))
        self.addCleanup(
            create_filter(
                8080,
                (
                    ("ORIGIN_HOSTNAME", "localhost:8081"),
                    ("ORIGIN_PROTO", "http"),
                    ("COPILOT_ENVIRONMENT", "staging"),
                ),
            )
        )
        self.addCleanup(create_origin(8081))
        wait_until_connectable(8080)
        wait_until_connectable(8081)
        wait_until_connectable(2772)

        status = (
            urllib3.PoolManager()
            .request(
                "GET",
                url="http://127.0.0.1:8080/",
                headers={
                    "host": "somehost.com",
                    "x-forwarded-for": "2a00:23c4:ce80:a01:4979:78c8:535c:bc16, 1.1.1.1",
                },
            )
            .status
        )
        self.assertEqual(status, 403)


def create_filter(port, env=()):
    def stop():
        process.terminate()
        process.wait()

    with open("Procfile", "r") as f:
        lines = f.readlines()
    for line in lines:
        name, _, command = line.partition(":")
        if name.strip() == "web":
            break

    default_env = {
        "PORT": str(port),
        "EMAIL_NAME": "the Department for International Trade WebOps team",
        "EMAIL": "test@test.test",
        "LOG_LEVEL": "DEBUG",
        "DEBUG": "True",
    }

    process = subprocess.Popen(
        ["bash", "-c", command.strip()],
        env={
            **os.environ,
            **default_env,
            **dict(env),
        },
    )

    return stop


def create_origin(port):
    def start():
        # Avoid warning about this not a prod server
        os.environ["FLASK_ENV"] = "development"
        origin_app = Flask("origin")

        origin_app.endpoint("chunked")(chunked)
        origin_app.url_map.add(Rule("/chunked", endpoint="chunked"))

        origin_app.endpoint("multiple-cookies")(multiple_cookies)
        origin_app.url_map.add(Rule("/multiple-cookies", endpoint="multiple-cookies"))

        origin_app.endpoint("gzipped")(gzipped)
        origin_app.url_map.add(Rule("/gzipped", endpoint="gzipped"))

        origin_app.endpoint("echo")(echo)
        origin_app.url_map.add(Rule("/", endpoint="echo"))
        origin_app.url_map.add(Rule("/<path:path>", endpoint="echo"))

        def _stop(_, __):
            sys.exit()

        signal.signal(signal.SIGTERM, _stop)
        signal.signal(signal.SIGINT, _stop)

        WSGIRequestHandler.protocol_version = "HTTP/1.1"

        try:
            origin_app.run(host="", port=port, debug=False)
        except SystemExit:
            # origin_app.run doesn't seem to have a good way of killing the
            # server, and need to exit cleanly for code coverage to be saved
            pass

    def chunked():
        num_bytes = int(request.headers["x-chunked-num-bytes"])

        def data():
            chunk = b'-'
            for _ in range(0, num_bytes):
                yield hex(len(chunk))[2:].encode() + b'\r\n' + chunk + b'\r\n'
            yield b'0\r\n\r\n'

        return Response(
            data(),
            headers=[
                ("transfer-encoding", "chunked"),
            ],
            status=200,
        )

    def multiple_cookies():
        cookies = request.headers["x-multiple-cookies"].split(",")
        return Response(
            b"", headers=[("set-cookie", cookie) for cookie in cookies], status=200
        )

    def gzipped():
        gzip_buffer = BytesIO()
        gzip_file = gzip.GzipFile(mode="wb", compresslevel=9, fileobj=gzip_buffer)
        gzip_file.write(request.stream.read())
        gzip_file.close()
        zipped = gzip_buffer.getvalue()

        return Response(
            zipped,
            headers=[
                ("content-encoding", "gzip"),
                ("content-length", str(len(zipped))),
            ],
            status=200,
        )

    def echo(path="/"):
        # Echo via headers to be able to assert more on HEAD requests that
        # have no response body

        def _extract_path(url):

            parts = urllib.parse.urlparse(url)
            return parts.path + "?" + parts.query

        response_header_prefix = "x-echo-response-header-"
        headers = (
            [
                ("x-echo-method", request.method),
                ("x-echo-raw-uri", _extract_path(request.environ["RAW_URI"])),
                ("x-echo-remote-port", request.environ["REMOTE_PORT"]),
            ]
            + [("x-echo-header-" + k, v) for k, v in request.headers.items()]
            + [
                (k[len(response_header_prefix) :], v)
                for k, v in request.headers.items()
                if k.lower().startswith(response_header_prefix)
            ]
        )
        return Response(
            request.stream.read(),
            headers=headers,
            status=int(request.headers.get("x-echo-response-status", "200")),
        )

    def stop():
        process.terminate()
        process.join()

    process = Process(target=start)
    process.start()

    return stop


def create_appconfig_agent(port, config_map=None):
    default_config_map = {
        "testapp:testenv:testconfig": """
IpRanges:
  - 1.1.1.1/32
"""
    }

    def start():
        # Avoid warning about this not a prod server
        os.environ["FLASK_ENV"] = "development"
        origin_app = Flask("appconfig")

        origin_app.endpoint("config")(config_view)
        origin_app.url_map.add(
            Rule(
                "/applications/<string:application>/environments/<string:environment>/configurations/<string:configuration>/",
                endpoint="config",
            )
        )

        def _stop(_, __):
            sys.exit()

        signal.signal(signal.SIGTERM, _stop)
        signal.signal(signal.SIGINT, _stop)

        WSGIRequestHandler.protocol_version = "HTTP/1.1"

        try:
            origin_app.run(host="", port=port, debug=False)
        except SystemExit:
            # origin_app.run doesn't seem to have a good way of killing the
            # server, and need to exit cleanly for code coverage to be saved
            pass

    def config_view(application, environment, configuration):
        key = f"{application}:{environment}:{configuration}"

        config = default_config_map | (config_map or {})

        if key not in config:
            abort(404)

        return Response(
            config[key],
            headers={},
            status=200,
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
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                break
        except (OSError, ConnectionRefusedError):
            if i == max_attempts - 1:
                raise
            time.sleep(0.01)
