"""Config flow for Homebridge Monitor integration."""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Any

import aiohttp
import voluptuous as vol
from homeassistant import config_entries
from homeassistant.core import callback
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .const import (
    CONF_HOST,
    CONF_PORT,
    CONF_SCAN_INTERVAL,
    DEFAULT_PORT,
    DEFAULT_SCAN_INTERVAL,
    DEFAULT_TIMEOUT,
    DOMAIN,
)

if TYPE_CHECKING:
    from homeassistant.config_entries import ConfigFlowResult
    from homeassistant.core import HomeAssistant

_LOGGER = logging.getLogger(__name__)


async def _test_connectivity(hass: HomeAssistant, host: str, port: int) -> bool:
    """Return True if an HTTP connection to host:port succeeds."""
    url = f"http://{host}:{port}/"
    session = async_get_clientsession(hass)
    try:
        async with session.get(
            url,
            timeout=aiohttp.ClientTimeout(total=DEFAULT_TIMEOUT),
        ):
            return True
    except (aiohttp.ClientError, asyncio.TimeoutError):
        return False


def _config_schema(
    host: str = "",
    port: int = DEFAULT_PORT,
) -> vol.Schema:
    """Return the schema for the initial configuration step."""
    return vol.Schema(
        {
            vol.Required(CONF_HOST, default=host): str,
            vol.Required(CONF_PORT, default=port): vol.All(
                vol.Coerce(int), vol.Range(min=1, max=65535)
            ),
        }
    )


def _options_schema(
    scan_interval: int = DEFAULT_SCAN_INTERVAL,
) -> vol.Schema:
    """Return the schema for the options step."""
    return vol.Schema(
        {
            vol.Required(CONF_SCAN_INTERVAL, default=scan_interval): vol.All(
                vol.Coerce(int), vol.Range(min=5, max=3600)
            ),
        }
    )


class FlowHandler(
    config_entries.ConfigFlow,
    domain=DOMAIN,  # type: ignore[call-arg]
):
    """Handle a config flow for Homebridge Monitor."""

    VERSION = 1

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle the initial step – ask for host and port."""
        errors: dict[str, str] = {}

        if user_input is not None:
            host: str = user_input[CONF_HOST].strip()
            port: int = user_input[CONF_PORT]

            await self.async_set_unique_id(f"{host}:{port}")
            self._abort_if_unique_id_configured()

            if not await _test_connectivity(self.hass, host, port):
                errors["base"] = "cannot_connect"
            else:
                return self.async_create_entry(
                    title=f"Homebridge ({host}:{port})",
                    data={CONF_HOST: host, CONF_PORT: port},
                )

        return self.async_show_form(
            step_id="user",
            data_schema=_config_schema(
                host=user_input[CONF_HOST] if user_input else "",
                port=user_input[CONF_PORT] if user_input else DEFAULT_PORT,
            )
            if user_input
            else _config_schema(),
            errors=errors,
        )

    @staticmethod
    @callback
    def async_get_options_flow(
        config_entry: config_entries.ConfigEntry,
    ) -> OptionsFlowHandler:
        """Return the options flow handler."""
        return OptionsFlowHandler()


class OptionsFlowHandler(config_entries.OptionsFlow):
    """Handle options flow for Homebridge Monitor."""

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Manage integration options."""
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)

        current_interval: int = self.config_entry.options.get(
            CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL
        )

        return self.async_show_form(
            step_id="init",
            data_schema=_options_schema(current_interval),
        )
