"""DataUpdateCoordinator for Homebridge Monitor."""

from __future__ import annotations

import asyncio
import logging
from datetime import timedelta
from typing import TYPE_CHECKING, TypedDict

import aiohttp
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .const import (
    API_PATH_AUTH,
    API_PATH_HB_VERSION,
    API_PATH_PLUGINS,
    DEFAULT_TIMEOUT,
    DOMAIN,
    HB_UI_PACKAGE_NAME,
)

if TYPE_CHECKING:
    from homeassistant.core import HomeAssistant

_LOGGER = logging.getLogger(__name__)


class PluginUpdateInfo(TypedDict):
    """Info about a plugin with a pending update."""

    name: str
    current_version: str
    latest_version: str


class HomebridgeData(TypedDict):
    """Data returned by the coordinator on each poll."""

    connected: bool
    homebridge_current_version: str | None
    homebridge_latest_version: str | None
    homebridge_update_available: bool
    ui_current_version: str | None
    ui_latest_version: str | None
    ui_update_available: bool
    plugins_with_updates: list[PluginUpdateInfo]


def _empty_data(*, connected: bool) -> HomebridgeData:
    """Return an empty HomebridgeData structure."""
    return HomebridgeData(
        connected=connected,
        homebridge_current_version=None,
        homebridge_latest_version=None,
        homebridge_update_available=False,
        ui_current_version=None,
        ui_latest_version=None,
        ui_update_available=False,
        plugins_with_updates=[],
    )


class HomebridgeCoordinator(DataUpdateCoordinator[HomebridgeData]):
    """Coordinator that polls Homebridge for connectivity and update information."""

    def __init__(
        self,
        hass: HomeAssistant,
        host: str,
        port: int,
        username: str,
        password: str,
        scan_interval: int,
    ) -> None:
        """Initialize the coordinator."""
        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            update_interval=timedelta(seconds=scan_interval),
        )
        self.host = host
        self.port = port
        self._username = username
        self._password = password
        self._token: str | None = None

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    async def _async_authenticate(self) -> str | None:
        """Obtain a JWT access token from Homebridge and cache it."""
        url = f"http://{self.host}:{self.port}{API_PATH_AUTH}"
        session = async_get_clientsession(self.hass)
        try:
            async with session.post(
                url,
                json={"username": self._username, "password": self._password},
                timeout=aiohttp.ClientTimeout(total=DEFAULT_TIMEOUT),
            ) as response:
                if response.status == 201:
                    payload = await response.json()
                    token: str | None = payload.get("access_token")
                    _LOGGER.debug("Authenticated with Homebridge at %s:%s", self.host, self.port)
                    return token
                _LOGGER.warning(
                    "Authentication failed for Homebridge at %s:%s (HTTP %s)",
                    self.host,
                    self.port,
                    response.status,
                )
        except (aiohttp.ClientError, asyncio.TimeoutError) as err:
            _LOGGER.debug("Authentication request failed: %s", err)
        return None

    async def _async_get_json(
        self,
        session: aiohttp.ClientSession,
        path: str,
        headers: dict[str, str],
    ) -> dict | list | None:
        """Perform an authenticated GET and return parsed JSON, or None on error."""
        url = f"http://{self.host}:{self.port}{path}"
        try:
            async with session.get(
                url,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=DEFAULT_TIMEOUT),
            ) as response:
                if response.status == 200:
                    return await response.json()
                if response.status == 401:
                    return None  # Caller handles re-auth
                _LOGGER.debug("GET %s returned HTTP %s", path, response.status)
        except (aiohttp.ClientError, asyncio.TimeoutError) as err:
            _LOGGER.debug("GET %s failed: %s", path, err)
        return None

    # ------------------------------------------------------------------
    # Main update loop
    # ------------------------------------------------------------------

    async def _async_update_data(self) -> HomebridgeData:
        """Poll Homebridge for connectivity and update information."""
        session = async_get_clientsession(self.hass)

        # 1. Check connectivity (plain HTTP – no auth required)
        url = f"http://{self.host}:{self.port}/"
        try:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=DEFAULT_TIMEOUT),
            ) as response:
                _LOGGER.debug(
                    "Homebridge at %s:%s responded with HTTP %s",
                    self.host,
                    self.port,
                    response.status,
                )
        except (aiohttp.ClientError, asyncio.TimeoutError) as err:
            _LOGGER.debug("Homebridge at %s:%s is not reachable: %s", self.host, self.port, err)
            raise UpdateFailed(f"Cannot reach Homebridge: {err}") from err

        # 2. Authenticate (refresh token when missing)
        if self._token is None:
            self._token = await self._async_authenticate()

        if self._token is None:
            _LOGGER.warning(
                "Could not authenticate with Homebridge at %s:%s – update sensors will be unavailable",
                self.host,
                self.port,
            )
            return _empty_data(connected=True)

        headers = {"Authorization": f"Bearer {self._token}"}

        # 3. Fetch Homebridge version / update info
        hb_payload = await self._async_get_json(session, API_PATH_HB_VERSION, headers)
        if hb_payload is None:
            # Likely a 401 – token expired, re-authenticate once
            _LOGGER.debug("Token may have expired, re-authenticating…")
            self._token = await self._async_authenticate()
            if self._token is None:
                return _empty_data(connected=True)
            headers = {"Authorization": f"Bearer {self._token}"}
            hb_payload = await self._async_get_json(session, API_PATH_HB_VERSION, headers)

        if not isinstance(hb_payload, dict):
            hb_payload = {}

        hb_current: str | None = hb_payload.get("installedVersion")
        hb_latest: str | None = hb_payload.get("latestVersion")
        hb_update: bool = bool(hb_payload.get("updateAvailable", False))

        # 4. Fetch installed plugins list (includes homebridge-config-ui-x)
        plugins_payload = await self._async_get_json(session, API_PATH_PLUGINS, headers)
        if not isinstance(plugins_payload, list):
            plugins_payload = []

        ui_current: str | None = None
        ui_latest: str | None = None
        ui_update: bool = False
        plugins_with_updates: list[PluginUpdateInfo] = []

        for plugin in plugins_payload:
            if not isinstance(plugin, dict):
                continue
            name: str = plugin.get("name", "")
            installed: str | None = plugin.get("installedVersion")
            latest: str | None = plugin.get("latestVersion")
            update_available: bool = bool(plugin.get("updateAvailable", False))

            if name == HB_UI_PACKAGE_NAME:
                ui_current = installed
                ui_latest = latest
                ui_update = update_available
            elif update_available and installed and latest:
                plugins_with_updates.append(
                    PluginUpdateInfo(
                        name=name,
                        current_version=installed,
                        latest_version=latest,
                    )
                )

        return HomebridgeData(
            connected=True,
            homebridge_current_version=hb_current,
            homebridge_latest_version=hb_latest,
            homebridge_update_available=hb_update,
            ui_current_version=ui_current,
            ui_latest_version=ui_latest,
            ui_update_available=ui_update,
            plugins_with_updates=plugins_with_updates,
        )
