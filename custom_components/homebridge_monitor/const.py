"""Constants for the Homebridge Monitor integration."""

from typing import Final

DOMAIN: Final = "homebridge_monitor"

# Configuration keys (static – stored in entry.data)
CONF_HOST: Final = "host"
CONF_PORT: Final = "port"

# Configuration keys (dynamic – stored in entry.options)
CONF_SCAN_INTERVAL: Final = "scan_interval"

# Default values
DEFAULT_PORT: Final = 8581
DEFAULT_SCAN_INTERVAL: Final = 30  # seconds
DEFAULT_TIMEOUT: Final = 10  # seconds

# Sensor
SENSOR_NAME: Final = "Connectivity"
