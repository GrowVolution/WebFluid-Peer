from webfluid.core.config import register_config

try: from fluid._my_config import MyConfig
except ImportError:
    class MyConfig: pass

DEFAULT_MASTER = "https://peers.webfluid.dev"


class PeerConfig:
    IS_MASTER = False
    JOIN_MASTER = DEFAULT_MASTER
    NETWORK_NAME = "webfluid"

    PEERING_PUBLIC_URL = None
    PEERING_NETWORK_ANCHOR = None
    PEERING_OPERATORS = {}
    PEERING_INACTIVE_DAYS = 30
    PEERING_ATTEST_MAX_AGE = 26 * 3600
    PEERING_MIN_GROUPS = 2
    PEERING_METADATA_RETENTION_DAYS = 90
    PEERING_TRUSTED_REFERENCES = {}

    LEGAL = {}

    BABEL_CONFIGURE_SOCKET = False
    BABEL_DEFAULT_LOCALE = "en"
    BABEL_SUPPORTED_LOCALES = [BABEL_DEFAULT_LOCALE, "de"]


@register_config(10)
class Config(MyConfig, PeerConfig):
    APP_CONFIG = {
        "title": "peering",
        "version": "1.0.0",
        "redoc_url": None,
        "docs_url": None,
        "openapi_url": None
    }
    APP_FRONTEND = {
        "type": "none"
    }
