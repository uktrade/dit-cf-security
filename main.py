import sys
import logging
from ipaddress import ip_address, ip_network
import string

from flask import request, Response, render_template
from random import choices
import urllib3

from config import get_ipfilter_config

from flask import Flask

from pathlib import Path

app = Flask(__name__, template_folder=Path(__file__).parent, static_folder=None)
app.config.from_object("settings")


PoolClass = (
    urllib3.HTTPConnectionPool
    if app.config["ORIGIN_PROTO"] == "http"
    else urllib3.HTTPSConnectionPool
)
http = PoolClass(app.config["ORIGIN_HOSTNAME"], maxsize=1000)

logging.basicConfig(stream=sys.stdout, level=app.config["LOG_LEVEL"])
logger = logging.getLogger(__name__)

request_id_alphabet = string.ascii_letters + string.digits


def render_access_denied(client_ip, forwarded_url, request_id):
    return (
        render_template(
            "access-denied.html",
            client_ip=client_ip,
            email_name=app.config["EMAIL_NAME"],
            email=app.config["EMAIL"],
            request_id=request_id,
            forwarded_url=forwarded_url,
        ),
        403,
    )


@app.route(
    "/",
    defaults={"u_path": ""},
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"],
)
@app.route(
    "/<path:u_path>",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"],
)
def handle_request(u_path):
    request_id = request.headers.get("X-B3-TraceId") or "".join(
        choices(request_id_alphabet, k=8)
    )

    logger.info("[%s] Start", request_id)

    forwarded_url = request.path
    logger.info("[%s] Forwarded URL: %s", request_id, forwarded_url)

    # Find x-forwarded-for
    try:
        x_forwarded_for = request.headers["X-Forwarded-For"]
    except KeyError:
        logger.error("[%s] X-Forwarded-For header is missing", request_id)
        return render_access_denied("Unknown", forwarded_url, request_id)

    try:
        client_ip = x_forwarded_for.split(",")[
            app.config["IP_DETERMINED_BY_X_FORWARDED_FOR_INDEX"]
        ].strip()
    except IndexError:
        logger.error(
            "[%s] Not enough addresses in x-forwarded-for %s",
            request_id,
            x_forwarded_for,
        )
        return render_access_denied("Unknown", forwarded_url, request_id)

    # TODO: add shared header if enabled
    headers_to_remove = ["connection"]

    ip_filter_enabled_and_required_for_path = (
        app.config["IPFILTER_ENABLED"]
        and (
            not app.config["PROTECTED_PATHS"]
            or any(path.startswith(request.path) for path in app.config["PROTECTED_PATHS"])
        )
        and (
            not app.config["PUBLIC_PATHS"]
            or not any(path.startswith(request.path) for path in app.config["PUBLIC_PATHS"])
        )
    )

    if ip_filter_enabled_and_required_for_path:
        ip_filter_rules = get_ipfilter_config(app.config["APPCONFIG_PROFILES"])

        ip_in_whitelist = any(
            ip_address(client_ip) in ip_network(ip_range)
            for ip_range in ip_filter_rules["ips"]
        )

        # TODO: reintroduce shared token and basic auth checks
        all_checks_passed = ip_in_whitelist

        if not all_checks_passed:
            logger.warning("[%s] Request blocked for %s", request_id, client_ip)
            return render_access_denied(client_ip, forwarded_url, request_id)

    # Proxy the request to the upstream service

    logger.info("[%s] Making request to origin", request_id)

    def downstream_data():
        while True:
            contents = request.stream.read(65536)
            if not contents:
                break
            yield contents

    origin_response = http.request(
        request.method,
        request.url,
        headers={
            k: v for k, v in request.headers if k.lower() not in headers_to_remove
        },
        preload_content=False,
        redirect=False,
        assert_same_host=False,
        body=downstream_data(),
    )
    logger.info("[%s] Origin response status: %s", request_id, origin_response.status)

    def release_conn():
        origin_response.release_conn()
        logger.info("[%s] End", request_id)

    downstream_response = Response(
        origin_response.stream(65536, decode_content=False),
        status=origin_response.status,
        headers=[
            (k, v)
            for k, v in origin_response.headers.items()
            if k.lower() != "connection"
        ],
    )
    downstream_response.autocorrect_location_header = False
    downstream_response.call_on_close(release_conn)

    logger.info("[%s] Starting response to client", request_id)

    return downstream_response
