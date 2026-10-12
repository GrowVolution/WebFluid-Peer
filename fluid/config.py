from webfluid.core.config import register_config

try: from fluid._my_config import MyConfig
except ImportError:
    class MyConfig: pass


class PeerConfig:
    PEERING_HOST = "http://localhost:8000"
    PEERING_PUBLIC_URL = "http://localhost:8001"
    PEERING_TRUSTED_REFERENCES = {}
    PEERING_SYNC_TIME = (23, 59)
    PEERING_CHECKPOINT_TIME = (0, 0)

    BABEL_DEFAULT_LOCALE = "en"
    BABEL_SUPPORTED_LOCALES = [BABEL_DEFAULT_LOCALE, "de"]


@register_config(10)
class Config(MyConfig, PeerConfig):
    APP_CONFIG = {
        "title": "peering",
        "version": "1.0.0",
        "redoc_url": None
    }
    APP_FRONTEND = {
		'type': 'none'
	}
