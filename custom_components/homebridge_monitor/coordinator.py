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
    API_PATH_AUTH_CHECK,
    API_PATH_AUTH_REFRESH,
    API_PATH_HB_VERSION,
    API_PATH_PLUGINS,
    API_PATH_UPDATE_PLUGIN,
    DEFAULT_TIMEOUT,
    DOMAIN,
    HB_PACKAGE_NAME,
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
        _LOGGER.debug(
            "Homebridge Monitor: authenticating – POST %s",
            url,
        )
        session = async_get_clientsession(self.hass)
        try:
            async with session.post(
                url,
                json={"username": self._username, "password": self._password},
                timeout=aiohttp.ClientTimeout(total=DEFAULT_TIMEOUT),
            ) as response:
                _LOGGER.debug(
                    "Homebridge Monitor: authentication response HTTP %s from %s:%s",
                    response.status,
                    self.host,
                    self.port,
                )
                if response.status == 201:
                    payload = await response.json()
                    token: str | None = payload.get("access_token")
                    if token:
                        _LOGGER.debug(
                            "Homebridge Monitor: JWT token obtained successfully from %s:%s",
                            self.host,
                            self.port,
                        )
                    else:
                        _LOGGER.warning(
                            "Homebridge Monitor: authentication response from %s:%s"
                            " did not contain an access_token (payload keys: %s)",
                            self.host,
                            self.port,
                            list(payload.keys()),
                        )
                    return token
                _LOGGER.warning(
                    "Homebridge Monitor: authentication failed for %s:%s"
                    " – HTTP %s (check username/password)",
                    self.host,
                    self.port,
                    response.status,
                )
        except asyncio.TimeoutError:
            _LOGGER.debug(
                "Homebridge Monitor: authentication request to %s:%s timed out"
                " (timeout=%ss)",
                self.host,
                self.port,
                DEFAULT_TIMEOUT,
            )
        except aiohttp.ClientError as err:
            _LOGGER.debug(
                "Homebridge Monitor: authentication request to %s:%s failed: %s",
                self.host,
                self.port,
                err,
            )
        return None

    async def _async_refresh_token(self) -> str | None:
        """Attempt to refresh the cached JWT using POST /api/auth/refresh.

        Returns the new token on success, None on failure.
        The caller is responsible for updating ``self._token``.
        """
        if self._token is None:
            return None
        url = f"http://{self.host}:{self.port}{API_PATH_AUTH_REFRESH}"
        _LOGGER.debug("Homebridge Monitor: refreshing token – POST %s", url)
        session = async_get_clientsession(self.hass)
        try:
            async with session.post(
                url,
                headers={"Authorization": f"Bearer {self._token}"},
                timeout=aiohttp.ClientTimeout(total=DEFAULT_TIMEOUT),
            ) as response:
                _LOGGER.debug(
                    "Homebridge Monitor: token refresh response HTTP %s from %s:%s",
                    response.status,
                    self.host,
                    self.port,
                )
                if response.status == 200:
                    payload = await response.json()
                    token: str | None = payload.get("access_token")
                    if token:
                        _LOGGER.debug(
                            "Homebridge Monitor: token refreshed successfully from %s:%s",
                            self.host,
                            self.port,
                        )
                    else:
                        _LOGGER.warning(
                            "Homebridge Monitor: token refresh response from %s:%s"
                            " did not contain an access_token (payload keys: %s)",
                            self.host,
                            self.port,
                            list(payload.keys()),
                        )
                    return token
        except asyncio.TimeoutError:
            _LOGGER.debug(
                "Homebridge Monitor: token refresh request to %s:%s timed out"
                " (timeout=%ss)",
                self.host,
                self.port,
                DEFAULT_TIMEOUT,
            )
        except aiohttp.ClientError as err:
            _LOGGER.debug(
                "Homebridge Monitor: token refresh request to %s:%s failed: %s",
                self.host,
                self.port,
                err,
            )
        return None

    async def _async_ensure_fresh_token(self) -> bool:
        """Ensure a valid JWT is cached before making authenticated requests.

        Strategy (in order):
        1. No token cached → full login via POST /api/auth/login.
        2. Token cached → verify via GET /api/auth/check.
           - HTTP 200: token still valid, nothing to do.
           - HTTP 401: try POST /api/auth/refresh; fall back to full login on failure.
           - Network error: assume token is still valid to avoid unnecessary re-auth.

        Returns True if a usable token is available, False otherwise.
        """
        if self._token is None:
            _LOGGER.debug(
                "Homebridge Monitor: no cached token – authenticating for %s:%s",
                self.host,
                self.port,
            )
            self._token = await self._async_authenticate()
            return self._token is not None

        # Token exists – verify it is still accepted by Homebridge.
        url = f"http://{self.host}:{self.port}{API_PATH_AUTH_CHECK}"
        session = async_get_clientsession(self.hass)
        try:
            async with session.get(
                url,
                headers={"Authorization": f"Bearer {self._token}"},
                timeout=aiohttp.ClientTimeout(total=DEFAULT_TIMEOUT),
            ) as response:
                _LOGGER.debug(
                    "Homebridge Monitor: token check → HTTP %s from %s:%s",
                    response.status,
                    self.host,
                    self.port,
                )
                if response.status == 200:
                    _LOGGER.debug(
                        "Homebridge Monitor: token is still valid for %s:%s",
                        self.host,
                        self.port,
                    )
                    return True
                if response.status == 401:
                    _LOGGER.debug(
                        "Homebridge Monitor: token expired on %s:%s"
                        " – attempting refresh",
                        self.host,
                        self.port,
                    )
                    new_token = await self._async_refresh_token()
                    if new_token:
                        self._token = new_token
                        return True
                    _LOGGER.debug(
                        "Homebridge Monitor: refresh failed on %s:%s"
                        " – falling back to full login",
                        self.host,
                        self.port,
                    )
                    self._token = await self._async_authenticate()
                    return self._token is not None
        except asyncio.TimeoutError:
            _LOGGER.debug(
                "Homebridge Monitor: token check timed out for %s:%s"
                " (timeout=%ss) – assuming token still valid",
                self.host,
                self.port,
                DEFAULT_TIMEOUT,
            )
        except aiohttp.ClientError as err:
            _LOGGER.debug(
                "Homebridge Monitor: token check for %s:%s failed: %s"
                " – assuming token still valid",
                self.host,
                self.port,
                err,
            )
        # Network error during check – keep existing token and let the caller
        # handle any subsequent 401 via the normal retry path.
        return True

    async def _async_get_json(
        self,
        session: aiohttp.ClientSession,
        path: str,
        headers: dict[str, str],
    ) -> dict | list | None:
        """Perform an authenticated GET and return parsed JSON, or None on error."""
        url = f"http://{self.host}:{self.port}{path}"
        _LOGGER.debug("Homebridge Monitor: GET %s", url)
        try:
            async with session.get(
                url,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=DEFAULT_TIMEOUT),
            ) as response:
                _LOGGER.debug(
                    "Homebridge Monitor: GET %s → HTTP %s",
                    path,
                    response.status,
                )
                if response.status == 200:
                    return await response.json()
                if response.status == 401:
                    _LOGGER.debug(
                        "Homebridge Monitor: GET %s returned HTTP 401 – token may have expired",
                        path,
                    )
                    return None  # Caller handles re-auth
                _LOGGER.warning(
                    "Homebridge Monitor: GET %s returned unexpected HTTP %s",
                    path,
                    response.status,
                )
        except asyncio.TimeoutError:
            _LOGGER.debug(
                "Homebridge Monitor: GET %s timed out (timeout=%ss)",
                path,
                DEFAULT_TIMEOUT,
            )
        except aiohttp.ClientError as err:
            _LOGGER.debug("Homebridge Monitor: GET %s failed: %s", path, err)
        return None

    async def _async_request(
        self,
        path: str,
    ) -> bool:
        """Perform an authenticated POST request and return True on success (HTTP 2xx).

        Automatically refreshes the token once on HTTP 401.
        """
        if self._token is None:
            _LOGGER.debug(
                "Homebridge Monitor: no cached token – authenticating before POST %s",
                path,
            )
            self._token = await self._async_authenticate()
        if self._token is None:
            _LOGGER.warning(
                "Homebridge Monitor: cannot perform POST %s on %s:%s – not authenticated",
                path,
                self.host,
                self.port,
            )
            return False

        session = async_get_clientsession(self.hass)
        url = f"http://{self.host}:{self.port}{path}"
        headers = {"Authorization": f"Bearer {self._token}"}

        for attempt in range(2):
            _LOGGER.debug(
                "Homebridge Monitor: POST %s (attempt %d/2)",
                url,
                attempt + 1,
            )
            try:
                async with session.post(
                    url,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=DEFAULT_TIMEOUT),
                ) as response:
                    _LOGGER.debug(
                        "Homebridge Monitor: POST %s → HTTP %s",
                        path,
                        response.status,
                    )
                    if 200 <= response.status < 300:
                        return True
                    if response.status == 401 and attempt == 0:
                        _LOGGER.debug(
                            "Homebridge Monitor: token expired during POST %s"
                            " – attempting refresh before retry",
                            path,
                        )
                        new_token = await self._async_refresh_token()
                        if new_token:
                            self._token = new_token
                        else:
                            _LOGGER.debug(
                                "Homebridge Monitor: refresh failed"
                                " – falling back to full login for POST %s",
                                path,
                            )
                            self._token = await self._async_authenticate()
                        if self._token is None:
                            _LOGGER.warning(
                                "Homebridge Monitor: re-authentication failed"
                                " – cannot complete POST %s on %s:%s",
                                path,
                                self.host,
                                self.port,
                            )
                            return False
                        headers = {"Authorization": f"Bearer {self._token}"}
                        continue
                    _LOGGER.warning(
                        "Homebridge Monitor: POST %s on %s:%s returned HTTP %s"
                        " – request was not accepted",
                        path,
                        self.host,
                        self.port,
                        response.status,
                    )
                    return False
            except asyncio.TimeoutError:
                _LOGGER.warning(
                    "Homebridge Monitor: POST %s on %s:%s timed out (timeout=%ss)",
                    path,
                    self.host,
                    self.port,
                    DEFAULT_TIMEOUT,
                )
                return False
            except aiohttp.ClientError as err:
                _LOGGER.warning(
                    "Homebridge Monitor: POST %s on %s:%s failed: %s",
                    path,
                    self.host,
                    self.port,
                    err,
                )
                return False
        return False

    # ------------------------------------------------------------------
    # Update action helper (called by button entity)
    # ------------------------------------------------------------------

    async def async_update_homebridge_core(self) -> bool:
        """Trigger a Homebridge core update via POST /api/plugins/update/homebridge.

        Returns True if the request was accepted.
        """
        path = f"{API_PATH_UPDATE_PLUGIN}/{HB_PACKAGE_NAME}"
        _LOGGER.debug(
            "Homebridge Monitor: requesting Homebridge core update on %s:%s",
            self.host,
            self.port,
        )
        result = await self._async_request(path)
        if result:
            _LOGGER.info(
                "Homebridge Monitor: Homebridge core update successfully initiated on %s:%s",
                self.host,
                self.port,
            )
        else:
            _LOGGER.warning(
                "Homebridge Monitor: Homebridge core update request failed on %s:%s",
                self.host,
                self.port,
            )
        return result

    async def async_update_ui(self) -> bool:
        """Trigger a Homebridge UI update via POST /api/plugins/update/homebridge-config-ui-x.

        Returns True if the request was accepted.
        """
        path = f"{API_PATH_UPDATE_PLUGIN}/{HB_UI_PACKAGE_NAME}"
        _LOGGER.debug(
            "Homebridge Monitor: requesting Homebridge UI update on %s:%s",
            self.host,
            self.port,
        )
        result = await self._async_request(path)
        if result:
            _LOGGER.info(
                "Homebridge Monitor: Homebridge UI update successfully initiated on %s:%s",
                self.host,
                self.port,
            )
        else:
            _LOGGER.warning(
                "Homebridge Monitor: Homebridge UI update request failed on %s:%s",
                self.host,
                self.port,
            )
        return result

    async def async_update_all_plugins(self) -> list[str]:
        """Trigger updates for all plugins with pending updates.

        Returns the list of plugin names for which the update request was accepted.
        """
        plugins: list[PluginUpdateInfo] = list(
            (self.data or {}).get("plugins_with_updates", [])
        )
        if not plugins:
            _LOGGER.debug(
                "Homebridge Monitor: no plugins with pending updates found on %s:%s"
                " – nothing to update",
                self.host,
                self.port,
            )
            return []
        _LOGGER.debug(
            "Homebridge Monitor: %d plugin(s) with pending updates on %s:%s: %s",
            len(plugins),
            self.host,
            self.port,
            ", ".join(p["name"] for p in plugins),
        )
        updated: list[str] = []
        failed: list[str] = []
        for plugin in plugins:
            name: str = plugin["name"]
            path = f"{API_PATH_UPDATE_PLUGIN}/{name}"
            _LOGGER.debug(
                "Homebridge Monitor: requesting update for plugin %s"
                " (%s → %s) on %s:%s",
                name,
                plugin["current_version"],
                plugin["latest_version"],
                self.host,
                self.port,
            )
            if await self._async_request(path):
                updated.append(name)
            else:
                failed.append(name)
        if failed:
            _LOGGER.warning(
                "Homebridge Monitor: update request failed for %d plugin(s) on %s:%s: %s",
                len(failed),
                self.host,
                self.port,
                ", ".join(failed),
            )
        return updated

    # ------------------------------------------------------------------
    # Main update loop
    # ------------------------------------------------------------------

    async def _async_update_data(self) -> HomebridgeData:
        """Poll Homebridge for connectivity and update information."""
        session = async_get_clientsession(self.hass)

        # 1. Check connectivity (plain HTTP – no auth required)
        url = f"http://{self.host}:{self.port}/"
        _LOGGER.debug(
            "Homebridge Monitor: checking connectivity – GET %s",
            url,
        )
        try:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=DEFAULT_TIMEOUT),
            ) as response:
                _LOGGER.debug(
                    "Homebridge Monitor: connectivity check %s:%s → HTTP %s",
                    self.host,
                    self.port,
                    response.status,
                )
        except asyncio.TimeoutError as err:
            _LOGGER.debug(
                "Homebridge Monitor: connectivity check timed out for %s:%s"
                " (timeout=%ss)",
                self.host,
                self.port,
                DEFAULT_TIMEOUT,
            )
            raise UpdateFailed(f"Cannot reach Homebridge: {err}") from err
        except aiohttp.ClientError as err:
            _LOGGER.debug(
                "Homebridge Monitor: Homebridge at %s:%s is not reachable: %s",
                self.host,
                self.port,
                err,
            )
            raise UpdateFailed(f"Cannot reach Homebridge: {err}") from err

        # 2. Ensure a valid token is available (check → refresh → full login).
        if not await self._async_ensure_fresh_token():
            _LOGGER.warning(
                "Homebridge Monitor: could not authenticate with %s:%s"
                " – update sensors will be unavailable",
                self.host,
                self.port,
            )
            return _empty_data(connected=True)

        headers = {"Authorization": f"Bearer {self._token}"}

        # 3. Fetch Homebridge version / update info
        hb_payload = await self._async_get_json(session, API_PATH_HB_VERSION, headers)
        if hb_payload is None:
            # Unexpected failure after token was verified – skip this cycle.
            _LOGGER.debug(
                "Homebridge Monitor: version fetch returned no data from %s:%s"
                " – skipping this update cycle",
                self.host,
                self.port,
            )
            return _empty_data(connected=True)

        if not isinstance(hb_payload, dict):
            hb_payload = {}

        hb_current: str | None = hb_payload.get("installedVersion")
        hb_latest: str | None = hb_payload.get("latestVersion")
        hb_update: bool = bool(hb_payload.get("updateAvailable", False))
        _LOGGER.debug(
            "Homebridge Monitor: Homebridge core – installed=%s latest=%s update_available=%s",
            hb_current,
            hb_latest,
            hb_update,
        )

        # 4. Fetch installed plugins list (includes homebridge-config-ui-x)
        plugins_payload = await self._async_get_json(session, API_PATH_PLUGINS, headers)
        if not isinstance(plugins_payload, list):
            _LOGGER.debug(
                "Homebridge Monitor: plugins endpoint returned unexpected data"
                " type (%s) from %s:%s – skipping plugin info",
                type(plugins_payload).__name__,
                self.host,
                self.port,
            )
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
                _LOGGER.debug(
                    "Homebridge Monitor: Homebridge UI (%s) – installed=%s"
                    " latest=%s update_available=%s",
                    name,
                    ui_current,
                    ui_latest,
                    ui_update,
                )
            elif update_available and installed and latest:
                plugins_with_updates.append(
                    PluginUpdateInfo(
                        name=name,
                        current_version=installed,
                        latest_version=latest,
                    )
                )

        if plugins_with_updates:
            _LOGGER.debug(
                "Homebridge Monitor: %d plugin(s) with pending updates on %s:%s: %s",
                len(plugins_with_updates),
                self.host,
                self.port,
                ", ".join(
                    f"{p['name']} ({p['current_version']} → {p['latest_version']})"
                    for p in plugins_with_updates
                ),
            )
        else:
            _LOGGER.debug(
                "Homebridge Monitor: all plugins are up to date on %s:%s",
                self.host,
                self.port,
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
