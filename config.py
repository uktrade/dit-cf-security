from collections import UserDict
import os
from urllib.parse import urljoin

import urllib3
import yaml


class EnvConfigManager(UserDict):
    @staticmethod
    def to_bool(val):
        return val.strip().lower() == "true"

    @staticmethod
    def to_list(val):
        if not val.strip():
            return []
        return [v.strip() for v in val.split(",")]

    # Config can be specified at the environment level wiht a key that has the format,
    # {ENV-NAME}_{KEY-NAME}, e.g. PRODUCTION_IPFILTER_ENABLED
    allow_environment_config = (
        "IPFILTER_ENABLED",
        "APPCONFIG_PROFILES",
        "PUBLIC_PATHS",
        "PROTECTED_PATHS",
    )

    field_types = {
        "IPFILTER_ENABLED": to_bool,
        "APPCONFIG_PROFILES": to_list,
        "PUBLIC_PATHS": to_list,
        "PROTECTED_PATHS": to_list,
        "IP_DETERMINED_BY_X_FORWARDED_FOR_INDEX": int,
    }

    def __init__(self, environ=None, /, **kwargs):
        env_name = environ["COPILOT_ENVIRONMENT"].upper()

        env_config = {}
        for key in self.allow_environment_config:
            env_key = f"{env_name}_{key}"

            if env_key in environ:
                env_config[key] = environ[env_key]

        dict = environ | env_config

        for key, func in self.field_types.items():
            if key in dict:
                dict[key] = func(dict[key])

        super().__init__(dict, **kwargs)


def get_appconfig_configuration(appconfig_path):
    """
    Retrieve appconfig data from a local appconfig agent. `appconfig_path` should be in the format:

    {application}:{environment}:{configuration}

    Note, environment refers to the AppConfig environment, not the local application environment.
    """
    application, environment, configuration = appconfig_path.split(":")


    url = urljoin(
        os.environ.get("APPCONFIG_URL", "http://localhost:2772"),
        f"/applications/{application}/environments/{environment}/configurations/{configuration}",
    )

    response = urllib3.PoolManager().request(
        "GET",
        url=url,
    )

    return yaml.safe_load(response.data)


def get_ipfilter_config(appconfig_paths):
    ips = []
    for config_path in appconfig_paths:
        config = get_appconfig_configuration(config_path)

        ips.extend(config.get("IpRanges", []))

    return {
        "ips": ips,
        "auth": None,
        "shared_token": None,
    }
