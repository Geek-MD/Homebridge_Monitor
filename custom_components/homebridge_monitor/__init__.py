"""Integration entry point for homebridge_momnitor."""
from __future__ import annotations

from typing import Any
import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers import aiohttp_client

from .const import DOMAIN, CONF_HOST, CONF_SWAGGER_PATH, CONF_VERIFY_SSL, CONF_TOKEN
from .coordinator import HomebridgeCoordinator

_LOGGER = logging.getLogger(__name__)

PLATFORMS = ["binary_sensor"]


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up homebridge_momnitor from a config entry."""
    host = entry.data.get(CONF_HOST)
    if not host:
        _LOGGER.error("No host configured for %s entry %s", DOMAIN, entry.entry_id)
        return False

    # base_url expects scheme+host:port, but user may supply host:port. We accept full url or host:port.
    base_input = host
    if base_input.startswith("http://") or base_input.startswith("https://"):
        base_url = base_input.rstrip("/")
    else:
        base_url = f"http://{base_input}"

    swagger_path = entry.data.get(CONF_SWAGGER_PATH, None)
    if swagger_path and not swagger_path.startswith("/"):
        swagger_path = f"/{swagger_path}"

    verify_ssl = entry.data.get(CONF_VERIFY_SSL, True)
    token = entry.data.get(CONF_TOKEN)

    session = aiohttp_client.async_get_clientsession(hass)

    # Pass the config entry so coordinator can update token in it
    coordinator = HomebridgeCoordinator(
        hass=hass,
        entry=entry,
        base_url=base_url,
        session=session,
        swagger_path=swagger_path,
        verify_ssl=verify_ssl,
        token=token,
    )

    # Perform first refresh (will raise UpdateFailed on errors and HA will handle retries)
    await coordinator.async_config_entry_first_refresh()

    hass.data.setdefault(DOMAIN, {})
    hass.data[DOMAIN][entry.entry_id] = coordinator

    # forward platforms
    hass.config_entries.async_setup_platforms(entry, PLATFORMS)

    return True
