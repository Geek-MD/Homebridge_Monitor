"""Constants for the Homebridge Monitor integration."""

from typing import Final

DOMAIN: Final = "homebridge_monitor"

# Configuration keys (static – stored in entry.data)
CONF_HOST: Final = "host"
CONF_PORT: Final = "port"
CONF_USERNAME: Final = "username"
CONF_PASSWORD: Final = "password"

# Configuration keys (dynamic – stored in entry.options)
CONF_SCAN_INTERVAL: Final = "scan_interval"

# Default values
DEFAULT_PORT: Final = 8581
DEFAULT_SCAN_INTERVAL: Final = 30  # seconds
DEFAULT_TIMEOUT: Final = 10  # seconds

# Homebridge REST API paths
API_PATH_AUTH: Final = "/api/auth/login"
API_PATH_HB_VERSION: Final = "/api/status/homebridge-version"
API_PATH_PLUGINS: Final = "/api/plugins"
API_PATH_UPDATE_HOMEBRIDGE: Final = "/api/update/homebridge"
API_PATH_UPDATE_PLUGIN: Final = "/api/plugins/update"

# Homebridge package names
HB_PACKAGE_NAME: Final = "homebridge"
HB_UI_PACKAGE_NAME: Final = "homebridge-config-ui-x"
