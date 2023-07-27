import os
import sys
import logging
from ipaddress import ip_address, ip_network
import string

from flask import Flask, request, Response, render_template
from flask_caching import Cache
from random import choices
import urllib3

from config import EnvConfigManager, get_ipfilter_config

app = Flask(__name__, template_folder=os.path.dirname(__file__), static_folder=None)

env = EnvConfigManager(os.environ)

config = {
    "DEBUG": True,  # some Flask specific configs
    "CACHE_TYPE": "SimpleCache",  # Flask-Caching related configs
    "CACHE_DEFAULT_TIMEOUT": 300,
}
app.config.from_mapping(config)
cache = Cache(app)

PoolClass = (
    urllib3.HTTPConnectionPool
    if env.get("ORIGIN_PROTO", "http") == "http"
    else urllib3.HTTPSConnectionPool
)
http = PoolClass(env["ORIGIN_HOSTNAME"], maxsize=1000)

logging.basicConfig(stream=sys.stdout, level=env.get("LOG_LEVEL", "DEBUG"))
logger = logging.getLogger(__name__)

request_id_alphabet = string.ascii_letters + string.digits


def render_access_denied(client_ip, forwarded_url, request_id):
    return (
        render_template(
            "access-denied.html",
            client_ip=client_ip,
            email_name=env["EMAIL_NAME"],
            email=env["EMAIL"],
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

    forwarded_url = request.base_url
    logger.info("[%s] Forwarded URL: %s", request_id, forwarded_url)

    # Find x-forwarded-for
    try:
        x_forwarded_for = request.headers["X-Forwarded-For"]
    except KeyError:
        logger.error("[%s] X-Forwarded-For header is missing", request_id)
        return render_access_denied("Unknown", forwarded_url, request_id)

    try:
        client_ip = x_forwarded_for.split(",")[
            env.get("IP_DETERMINED_BY_X_FORWARDED_FOR_INDEX", -2)
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

    protected_paths = env.get("PROTECTED_PATHS")
    public_paths = env.get("PUBLIC_PATHS")

    ip_filter_enabled_and_required_for_path = (
        env.get("IPFILTER_ENABLED", True)
        and (
            not protected_paths
            or any(path.startswith(request.path) for path in protected_paths)
        )
        and (
            not public_paths
            or not any(path.startswith(request.path) for path in public_paths)
        )
    )

    if ip_filter_enabled_and_required_for_path:
        ip_filter_rules = get_ipfilter_config(env.get("APPCONFIG_PROFILES", []))

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
