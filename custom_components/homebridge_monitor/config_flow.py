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
    API_PATH_AUTH,
    CONF_HOST,
    CONF_PASSWORD,
    CONF_PORT,
    CONF_SCAN_INTERVAL,
    CONF_USERNAME,
    DEFAULT_PORT,
    DEFAULT_SCAN_INTERVAL,
    DEFAULT_TIMEOUT,
    DOMAIN,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

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


async def _test_authentication(
    hass: HomeAssistant, host: str, port: int, username: str, password: str
) -> bool:
    """Return True if the credentials are accepted by the Homebridge REST API."""
    url = f"http://{host}:{port}{API_PATH_AUTH}"
    session = async_get_clientsession(hass)
    try:
        async with session.post(
            url,
            json={"username": username, "password": password},
            timeout=aiohttp.ClientTimeout(total=DEFAULT_TIMEOUT),
        ) as response:
            return response.status == 201
    except (aiohttp.ClientError, asyncio.TimeoutError):
        return False


def _config_schema(
    host: str = "",
    port: int = DEFAULT_PORT,
    username: str = "",
) -> vol.Schema:
    """Return the schema for the initial configuration step."""
    return vol.Schema(
        {
            vol.Required(CONF_HOST, default=host): str,
            vol.Required(CONF_PORT, default=port): vol.All(
                vol.Coerce(int), vol.Range(min=1, max=65535)
            ),
            vol.Required(CONF_USERNAME, default=username): str,
            vol.Required(CONF_PASSWORD): str,
        }
    )


def _options_schema(
    host: str = "",
    port: int = DEFAULT_PORT,
    username: str = "",
    scan_interval: int = DEFAULT_SCAN_INTERVAL,
) -> vol.Schema:
    """Return the schema for the options step."""
    return vol.Schema(
        {
            vol.Required(CONF_HOST, default=host): str,
            vol.Required(CONF_PORT, default=port): vol.All(
                vol.Coerce(int), vol.Range(min=1, max=65535)
            ),
            vol.Required(CONF_USERNAME, default=username): str,
            vol.Required(CONF_PASSWORD): str,
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

    VERSION = 2

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle the initial step – ask for host, port and credentials."""
        errors: dict[str, str] = {}

        if user_input is not None:
            host: str = user_input[CONF_HOST].strip()
            port: int = user_input[CONF_PORT]
            username: str = user_input[CONF_USERNAME].strip()
            password: str = user_input[CONF_PASSWORD]

            await self.async_set_unique_id(f"{host}:{port}")
            self._abort_if_unique_id_configured()

            if not await _test_connectivity(self.hass, host, port):
                errors["base"] = "cannot_connect"
            elif not await _test_authentication(self.hass, host, port, username, password):
                errors["base"] = "invalid_auth"
            else:
                return self.async_create_entry(
                    title=f"Homebridge ({host}:{port})",
                    data={
                        CONF_HOST: host,
                        CONF_PORT: port,
                        CONF_USERNAME: username,
                        CONF_PASSWORD: password,
                    },
                )

        return self.async_show_form(
            step_id="user",
            data_schema=_config_schema(
                host=user_input[CONF_HOST] if user_input else "",
                port=user_input[CONF_PORT] if user_input else DEFAULT_PORT,
                username=user_input[CONF_USERNAME] if user_input else "",
            )
            if user_input
            else _config_schema(),
            errors=errors,
        )

    async def async_step_reauth(
        self, entry_data: Mapping[str, Any]
    ) -> ConfigFlowResult:
        """Initiate reauth flow when credentials are missing or invalid."""
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Ask for updated credentials during reauth."""
        errors: dict[str, str] = {}
        reauth_entry = self._get_reauth_entry()
        host: str = reauth_entry.data[CONF_HOST]
        port: int = reauth_entry.data[CONF_PORT]

        if user_input is not None:
            username: str = user_input[CONF_USERNAME].strip()
            password: str = user_input[CONF_PASSWORD]

            if not await _test_connectivity(self.hass, host, port):
                errors["base"] = "cannot_connect"
            elif not await _test_authentication(self.hass, host, port, username, password):
                errors["base"] = "invalid_auth"
            else:
                self.hass.config_entries.async_update_entry(
                    reauth_entry,
                    data={
                        **reauth_entry.data,
                        CONF_USERNAME: username,
                        CONF_PASSWORD: password,
                    },
                )
                await self.hass.config_entries.async_reload(reauth_entry.entry_id)
                return self.async_abort(reason="reauth_successful")

        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=vol.Schema(
                {
                    vol.Required(
                        CONF_USERNAME,
                        default=reauth_entry.data.get(CONF_USERNAME, ""),
                    ): str,
                    vol.Required(CONF_PASSWORD): str,
                }
            ),
            description_placeholders={"host": host, "port": str(port)},
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
        """Manage integration options (host, port, credentials and scan interval)."""
        errors: dict[str, str] = {}

        if user_input is not None:
            host: str = user_input[CONF_HOST].strip()
            port: int = user_input[CONF_PORT]
            username: str = user_input[CONF_USERNAME].strip()
            password: str = user_input[CONF_PASSWORD]
            scan_interval: int = user_input[CONF_SCAN_INTERVAL]

            new_unique_id = f"{host}:{port}"
            for entry in self.hass.config_entries.async_entries(DOMAIN):
                if (
                    entry.entry_id != self.config_entry.entry_id
                    and entry.unique_id == new_unique_id
                ):
                    errors["base"] = "already_configured"
                    break

            if not errors and not await _test_connectivity(self.hass, host, port):
                errors["base"] = "cannot_connect"

            if not errors and not await _test_authentication(
                self.hass, host, port, username, password
            ):
                errors["base"] = "invalid_auth"

            if not errors:
                self.hass.config_entries.async_update_entry(
                    self.config_entry,
                    data={
                        CONF_HOST: host,
                        CONF_PORT: port,
                        CONF_USERNAME: username,
                        CONF_PASSWORD: password,
                    },
                    title=f"Homebridge ({host}:{port})",
                    unique_id=new_unique_id,
                )
                return self.async_create_entry(
                    title="", data={CONF_SCAN_INTERVAL: scan_interval}
                )

        current_host: str = self.config_entry.data.get(CONF_HOST, "")
        current_port: int = self.config_entry.data.get(CONF_PORT, DEFAULT_PORT)
        current_username: str = self.config_entry.data.get(CONF_USERNAME, "")
        current_interval: int = self.config_entry.options.get(
            CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL
        )

        return self.async_show_form(
            step_id="init",
            data_schema=_options_schema(
                current_host, current_port, current_username, current_interval
            ),
            errors=errors,
        )
