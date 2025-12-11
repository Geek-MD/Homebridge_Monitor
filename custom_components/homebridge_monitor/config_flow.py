"""Config flow and reauth flow for Homebridge Monitor integration."""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

import aiohttp
import async_timeout
import voluptuous as vol
from homeassistant import config_entries
from homeassistant.const import CONF_VERIFY_SSL
from homeassistant.data_entry_flow import FlowResult
from homeassistant.helpers import aiohttp_client

from .const import (
    CONF_HOST,
    CONF_SWAGGER_PATH,
    CONF_TOKEN,
    CONF_TOKEN_EXPIRES,
    DOMAIN,
    ENDPOINT_LOGIN,
)

_LOGGER = logging.getLogger(__name__)

STEP_USER_DATA_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_HOST): str,
        vol.Optional(CONF_SWAGGER_PATH, default="/swagger"): str,
        vol.Optional(CONF_VERIFY_SSL, default=True): bool,
    }
)

STEP_AUTH_DATA_SCHEMA = vol.Schema(
    {
        vol.Required("username"): str,
        vol.Required("password"): str,
    }
)


class HomebridgeUpdateFlowHandler(config_entries.ConfigFlow):
    """Handle a config flow for homebridge_monitor, including reauth."""

    VERSION = 1
    DOMAIN = DOMAIN
    CONNECTION_CLASS = config_entries.CONN_CLASS_LOCAL_POLL

    def __init__(self) -> None:
        """Initialize flow state."""
        self._host_data: dict[str, Any] = {}
        self._base_url: Optional[str] = None
        self._reauth_entry_id: Optional[str] = None
        self._reconfigure_entry_id: Optional[str] = None

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        """Initial step to ask for host:port (or full URL)."""
        if user_input is None:
            return self.async_show_form(step_id="user", data_schema=STEP_USER_DATA_SCHEMA)

        host = user_input[CONF_HOST].strip()
        swagger_path = user_input.get(CONF_SWAGGER_PATH, "/swagger")
        verify_ssl = user_input.get(CONF_VERIFY_SSL, True)

        # Normalize base_url. Accept both 'ip:port' and full URLs.
        if host.startswith("http://") or host.startswith("https://"):
            base_url = host.rstrip("/")
        else:
            base_url = f"http://{host.rstrip('/')}"
        if not swagger_path.startswith("/"):
            swagger_path = f"/{swagger_path}"

        # Use host as unique_id to prevent duplicates
        await self.async_set_unique_id(host)
        self._abort_if_unique_id_configured()

        # store for next step
        self._host_data = {
            CONF_HOST: host,
            CONF_SWAGGER_PATH: swagger_path,
            CONF_VERIFY_SSL: verify_ssl,
        }
        self._base_url = base_url

        # Proceed to auth popup where username/password are requested
        return await self.async_step_auth()

    async def async_step_auth(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        """Ask for Homebridge credentials and call /api/auth/login to obtain token (initial setup)."""
        errors: Dict[str, str] = {}

        if user_input is None:
            return self.async_show_form(step_id="auth", data_schema=STEP_AUTH_DATA_SCHEMA)

        username = user_input["username"]
        password = user_input["password"]

        try:
            token, token_expires_ts = await self._async_do_login(username, password)
        except InvalidAuth:
            errors["base"] = "invalid_auth"
        except CannotConnect:
            errors["base"] = "cannot_connect"
        except Exception:  # pylint: disable=broad-except
            _LOGGER.exception("Unexpected exception while authenticating")
            errors["base"] = "unknown"

        if errors:
            return self.async_show_form(step_id="auth", data_schema=STEP_AUTH_DATA_SCHEMA, errors=errors)

        entry_data = {
            CONF_HOST: self._host_data[CONF_HOST],
            CONF_SWAGGER_PATH: self._host_data[CONF_SWAGGER_PATH],
            CONF_VERIFY_SSL: self._host_data[CONF_VERIFY_SSL],
            CONF_TOKEN: token,
            CONF_TOKEN_EXPIRES: int(token_expires_ts) if token_expires_ts is not None else None,
        }

        return self.async_create_entry(title=self._host_data[CONF_HOST], data=entry_data)

    async def async_step_reauth(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        """Handle re-authentication (reauth flow)."""
        entry_id = self.context.get("entry_id")
        if not entry_id:
            _LOGGER.error("Reauth step started without entry_id in context")
            return self.async_abort(reason="missing_entry")

        self._reauth_entry_id = entry_id
        entry = self.hass.config_entries.async_get_entry(entry_id)
        if not entry:
            _LOGGER.error("Reauth entry not found: %s", entry_id)
            return self.async_abort(reason="missing_entry")

        if user_input is None:
            return self.async_show_form(
                step_id="reauth",
                data_schema=STEP_AUTH_DATA_SCHEMA,
                description_placeholders={"host": entry.data.get(CONF_HOST, "")},
            )

        username = user_input["username"]
        password = user_input["password"]

        try:
            token, token_expires_ts = await self._async_do_login(username, password)
        except InvalidAuth:
            return self.async_show_form(step_id="reauth", data_schema=STEP_AUTH_DATA_SCHEMA, errors={"base": "invalid_auth"})
        except CannotConnect:
            return self.async_show_form(step_id="reauth", data_schema=STEP_AUTH_DATA_SCHEMA, errors={"base": "cannot_connect"})
        except Exception:
            _LOGGER.exception("Unexpected error during reauth")
            return self.async_show_form(step_id="reauth", data_schema=STEP_AUTH_DATA_SCHEMA, errors={"base": "unknown"})

        new_data = {**entry.data, CONF_TOKEN: token}
        if token_expires_ts is not None:
            new_data[CONF_TOKEN_EXPIRES] = int(token_expires_ts)

        self.hass.config_entries.async_update_entry(entry, data=new_data)

        return self.async_abort(reason="reauth_successful")

    async def async_step_reconfigure(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        """Handle reconfiguration of the integration."""
        entry_id = self.context.get("entry_id")
        if not entry_id:
            _LOGGER.error("Reconfigure step started without entry_id in context")
            return self.async_abort(reason="missing_entry")

        self._reconfigure_entry_id = entry_id
        entry = self.hass.config_entries.async_get_entry(entry_id)
        if not entry:
            _LOGGER.error("Reconfigure entry not found: %s", entry_id)
            return self.async_abort(reason="missing_entry")

        if user_input is None:
            # Show form with current settings as defaults
            reconfigure_schema = vol.Schema(
                {
                    vol.Required(CONF_HOST, default=entry.data.get(CONF_HOST, "")): str,
                    vol.Optional(CONF_SWAGGER_PATH, default=entry.data.get(CONF_SWAGGER_PATH, "/swagger")): str,
                    vol.Optional(CONF_VERIFY_SSL, default=entry.data.get(CONF_VERIFY_SSL, True)): bool,
                }
            )
            return self.async_show_form(
                step_id="reconfigure",
                data_schema=reconfigure_schema,
                description_placeholders={"host": entry.data.get(CONF_HOST, "")},
            )

        # Process the updated settings
        host = user_input[CONF_HOST].strip()
        swagger_path = user_input.get(CONF_SWAGGER_PATH, "/swagger")
        verify_ssl = user_input.get(CONF_VERIFY_SSL, True)

        # Normalize base_url
        if host.startswith("http://") or host.startswith("https://"):
            base_url = host.rstrip("/")
        else:
            base_url = f"http://{host.rstrip('/')}"
        if not swagger_path.startswith("/"):
            swagger_path = f"/{swagger_path}"

        # Store settings for auth step
        self._host_data = {
            CONF_HOST: host,
            CONF_SWAGGER_PATH: swagger_path,
            CONF_VERIFY_SSL: verify_ssl,
        }
        self._base_url = base_url

        # Proceed to auth step to get new token
        return await self.async_step_reconfigure_auth()

    async def async_step_reconfigure_auth(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        """Handle authentication during reconfiguration."""
        if user_input is None:
            return self.async_show_form(
                step_id="reconfigure_auth",
                data_schema=STEP_AUTH_DATA_SCHEMA,
                description_placeholders={"host": self._host_data.get(CONF_HOST, "")},
            )

        username = user_input["username"]
        password = user_input["password"]

        try:
            token, token_expires_ts = await self._async_do_login(username, password)
        except InvalidAuth:
            return self.async_show_form(
                step_id="reconfigure_auth",
                data_schema=STEP_AUTH_DATA_SCHEMA,
                errors={"base": "invalid_auth"},
                description_placeholders={"host": self._host_data.get(CONF_HOST, "")},
            )
        except CannotConnect:
            return self.async_show_form(
                step_id="reconfigure_auth",
                data_schema=STEP_AUTH_DATA_SCHEMA,
                errors={"base": "cannot_connect"},
                description_placeholders={"host": self._host_data.get(CONF_HOST, "")},
            )
        except Exception:
            _LOGGER.exception("Unexpected error during reconfigure auth")
            return self.async_show_form(
                step_id="reconfigure_auth",
                data_schema=STEP_AUTH_DATA_SCHEMA,
                errors={"base": "unknown"},
                description_placeholders={"host": self._host_data.get(CONF_HOST, "")},
            )

        # Update the config entry with new settings and token
        entry = self.hass.config_entries.async_get_entry(self._reconfigure_entry_id)
        if not entry:
            _LOGGER.error("Entry disappeared during reconfigure: %s", self._reconfigure_entry_id)
            return self.async_abort(reason="missing_entry")

        new_data = {
            CONF_HOST: self._host_data[CONF_HOST],
            CONF_SWAGGER_PATH: self._host_data[CONF_SWAGGER_PATH],
            CONF_VERIFY_SSL: self._host_data[CONF_VERIFY_SSL],
            CONF_TOKEN: token,
            CONF_TOKEN_EXPIRES: int(token_expires_ts) if token_expires_ts is not None else None,
        }

        self.hass.config_entries.async_update_entry(entry, data=new_data)

        # Reload the integration to apply new settings
        await self.hass.config_entries.async_reload(entry.entry_id)

        return self.async_abort(reason="reconfigure_successful")

    async def _async_do_login(self, username: str, password: str) -> tuple[str, Optional[int]]:
        """Perform the login request and return (token, expires_epoch_seconds|None)."""
        assert self._base_url is not None, "base_url must be set before login"
        login_url = f"{self._base_url}{ENDPOINT_LOGIN}"
        session = aiohttp_client.async_get_clientsession(self.hass)
        try:
            async with async_timeout.timeout(15):
                payload = {"username": username, "password": password}
                try:
                    resp = await session.post(login_url, json=payload)
                except aiohttp.ClientConnectorError as err:
                    _LOGGER.debug("Connection error when posting to %s: %s", login_url, err)
                    raise CannotConnect() from err
                except aiohttp.ClientError as err:
                    _LOGGER.debug("Client error when posting to %s: %s", login_url, err)
                    raise CannotConnect() from err

                if resp.status in (200, 201):
                    data = await resp.json()
                    token = data.get("access_token") or data.get("token") or data.get("accessToken") or data.get("jwt")
                    if not token:
                        _LOGGER.debug("Login response did not contain token keys: %s", data)
                        raise InvalidAuth()

                    expires_in = data.get("expires_in") or data.get("expiresIn") or data.get("ttl")
                    expires_at = data.get("expires_at") or data.get("expiresAt") or data.get("expiration")

                    token_expires_ts: Optional[int] = None
                    if expires_in is not None:
                        try:
                            seconds = int(expires_in)
                            token_expires_ts = int((datetime.now(timezone.utc) + timedelta(seconds=seconds)).timestamp())
                        except Exception:
                            _LOGGER.debug("Could not parse expires_in: %s", expires_in)
                            token_expires_ts = None
                    elif expires_at is not None:
                        try:
                            if isinstance(expires_at, (int, float)):
                                token_expires_ts = int(expires_at)
                            else:
                                dt = datetime.fromisoformat(str(expires_at))
                                if dt.tzinfo is None:
                                    dt = dt.replace(tzinfo=timezone.utc)
                                token_expires_ts = int(dt.timestamp())
                        except Exception:
                            _LOGGER.debug("Could not parse expires_at: %s", expires_at)

                    return token, token_expires_ts

                if resp.status in (401, 403):
                    _LOGGER.debug("Invalid credentials for Homebridge login (status %s)", resp.status)
                    raise InvalidAuth()

                _LOGGER.debug("Unexpected status from login endpoint: %s", resp.status)
                raise CannotConnect()
        except async_timeout.TimeoutError as err:
            _LOGGER.debug("Timeout connecting to %s: %s", login_url, err)
            raise CannotConnect() from err


class InvalidAuth(Exception):
    """Raised when credentials are invalid."""


class CannotConnect(Exception):
    """Raised when connection to Homebridge failed."""
