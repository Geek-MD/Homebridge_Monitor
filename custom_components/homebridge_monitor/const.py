"""Constants for homebridge_momnitor integration."""
from __future__ import annotations

DOMAIN = "homebridge_momnitor"
DEFAULT_NAME = "Homebridge Monitor"
SCAN_INTERVAL = 300  # seconds

# Config keys
CONF_HOST = "host"  # expects "ip:port" or "http(s)://ip:port"
CONF_VERIFY_SSL = "verify_ssl"
CONF_SWAGGER_PATH = "swagger_path"
CONF_TOKEN = "token"
CONF_TOKEN_EXPIRES = "token_expires"

# Endpoints (relative to base_url)
ENDPOINT_SWAGGER = "/swagger"
ENDPOINT_HOMEBRIDGE_VERSION = "/api/status/homebridge-version"
ENDPOINT_NODE_VERSION = "/api/status/nodejs"
ENDPOINT_PLUGINS = "/api/plugins"
ENDPOINT_LOGIN = "/api/auth/login"
ENDPOINT_REFRESH = "/api/auth/refresh"

# Refresh margin: refresh token when remaining lifetime <= this (seconds)
# Set to 30 minutes as requested
REFRESH_MARGIN_SECONDS = 30 * 60  # 1800 seconds

# Known package identifiers for Homebridge UI plugin; adjust if necessary
HOMEBRIDGE_UI_PACKAGE_NAMES = ["homebridge-config-ui-x", "homebridge-ui"]
HOMEBRIDGE_UI_DISPLAY_KEYS = ["config-ui", "homebridge-ui"]
