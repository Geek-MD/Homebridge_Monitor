"""Coordinator to fetch Homebridge update info and manage token refresh/reauth."""
from __future__ import annotations

from typing import Any, Dict, List, Optional
import asyncio
import logging
import time

import aiohttp
import async_timeout

from homeassistant.components import persistent_notification
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .const import (
    SCAN_INTERVAL,
    ENDPOINT_SWAGGER,
    ENDPOINT_HOMEBRIDGE_VERSION,
    ENDPOINT_NODE_VERSION,
    ENDPOINT_PLUGINS,
    ENDPOINT_REFRESH,
    HOMEBRIDGE_UI_PACKAGE_NAMES,
    HOMEBRIDGE_UI_DISPLAY_KEYS,
    CONF_TOKEN,
    CONF_TOKEN_EXPIRES,
    REFRESH_MARGIN_SECONDS,
    DOMAIN,
)

_LOGGER = logging.getLogger(__name__)


class HomebridgeCoordinator(DataUpdateCoordinator[dict]):
    """Coordinator to fetch and normalize update info from Homebridge and manage token refresh/reauth."""

    def __init__(
        self,
        hass: HomeAssistant,
        entry: ConfigEntry,
        base_url: str,
        session: aiohttp.ClientSession,
        swagger_path: str | None = None,
        verify_ssl: bool = True,
        token: str | None = None,
    ) -> None:
        """Initialize coordinator."""
        super().__init__(hass, _LOGGER, name="homebridge_monitor", update_interval=SCAN_INTERVAL)
        self.hass = hass
        self.entry = entry
        self.base_url = base_url.rstrip("/")
        self.session = session
        self.verify_ssl = verify_ssl
        self.swagger_path = swagger_path or ENDPOINT_SWAGGER
        self.token = token
        self._endpoints: Dict[str, str] = {}
        self.plugin_keys: set[str] = set()
        self._refresh_lock = asyncio.Lock()

    async def _async_update_data(self) -> dict:
        """Fetch data and try to refresh token when close to expiry."""
        headers: dict[str, str] = {}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        results: dict[str, Any] = {"plugins": []}

        # Check token expiry in entry data and refresh if necessary
        try:
            token_expires = self.entry.data.get(CONF_TOKEN_EXPIRES)
            if token_expires is not None:
                now = int(time.time())
                remaining = int(token_expires) - now
                _LOGGER.debug("Token remaining seconds: %s", remaining)
                if remaining <= 0:
                    _LOGGER.warning("Stored token has expired for %s", self.entry.title)
                    # trigger reauth flow and notify user
                    await self._trigger_reauth(
                        message=(
                            "El token de Homebridge ha expirado. Por favor, reautentícate en la integración "
                            "Homebridge Monitor para restaurar el acceso."
                        ),
                    )
                    raise UpdateFailed("Authentication token expired")
                if remaining <= REFRESH_MARGIN_SECONDS:
                    _LOGGER.debug("Token close to expiry (<= %s s): attempting refresh", REFRESH_MARGIN_SECONDS)
                    try:
                        await self._async_refresh_token()
                        if self.token:
                            headers["Authorization"] = f"Bearer {self.token}"
                    except UpdateFailed:
                        # _async_refresh_token will create notification / start reauth if needed
                        raise
                    except Exception as err:
                        _LOGGER.warning("Token refresh failed: %s", err)
        except Exception:
            _LOGGER.exception("Error checking token expiry")

        try:
            async with async_timeout.timeout(20):
                # Optionally try to GET swagger to ensure API up (best-effort)
                try:
                    swagger_url = f"{self.base_url}{self.swagger_path}"
                    resp = await self.session.get(swagger_url, ssl=self.verify_ssl)
                    if resp.status == 200:
                        _LOGGER.debug("Swagger descriptor reachable at %s", swagger_url)
                    else:
                        _LOGGER.debug("Swagger returned status %s (url: %s)", resp.status, swagger_url)
                except aiohttp.ClientError as err:
                    _LOGGER.debug("Could not fetch swagger descriptor: %s", err)

                # 1) Homebridge core version
                try:
                    url = f"{self.base_url}{ENDPOINT_HOMEBRIDGE_VERSION}"
                    resp = await self.session.get(url, headers=headers, ssl=self.verify_ssl)
                    if resp.status == 200:
                        data = await resp.json()
                        current = data.get("currentVersion") or data.get("current_version") or data.get("version")
                        latest = data.get("latestVersion") or data.get("latest_version")
                        update_available = data.get("updateAvailable") or data.get("update_available") or (
                            latest and current and latest != current
                        )
                        results["homebridge"] = {
                            "current_version": current,
                            "latest_version": latest,
                            "update_available": bool(update_available),
                        }
                    else:
                        _LOGGER.debug("Homebridge version endpoint returned %s", resp.status)
                except aiohttp.ClientError as err:
                    _LOGGER.debug("Error requesting homebridge version: %s", err)

                # 2) Node.js
                try:
                    url = f"{self.base_url}{ENDPOINT_NODE_VERSION}"
                    resp = await self.session.get(url, headers=headers, ssl=self.verify_ssl)
                    if resp.status == 200:
                        data = await resp.json()
                        current = data.get("currentVersion") or data.get("current_version") or data.get("version")
                        latest = data.get("latestVersion") or data.get("latest_version")
                        update_available = data.get("updateAvailable") or data.get("update_available") or (
                            latest and current and latest != current
                        )
                        results["node"] = {
                            "current_version": current,
                            "latest_version": latest,
                            "update_available": bool(update_available),
                        }
                    else:
                        _LOGGER.debug("Node version endpoint returned %s", resp.status)
                except aiohttp.ClientError as err:
                    _LOGGER.debug("Error requesting node version: %s", err)

                # 3) Plugins list
                try:
                    url = f"{self.base_url}{ENDPOINT_PLUGINS}"
                    resp = await self.session.get(url, headers=headers, ssl=self.verify_ssl)
                    if resp.status == 200:
                        data = await resp.json()
                        # Expected: list of plugin objects. Normalize fields defensively.
                        for p in data:
                            name = p.get("name") or p.get("displayName") or p.get("title") or p.get("pluginName")
                            package = p.get("package") or p.get("plugin") or p.get("packageName") or p.get("npm")
                            current = p.get("version") or p.get("installedVersion") or p.get("currentVersion")
                            latest = p.get("latestVersion") or p.get("availableVersion")
                            update_available = p.get("updateAvailable", False) or (latest and current and latest != current)
                            plugin_obj = {
                                "name": name or package or "unknown",
                                "package": package,
                                "current_version": current,
                                "latest_version": latest,
                                "update_available": bool(update_available),
                            }
                            results["plugins"].append(plugin_obj)
                    else:
                        _LOGGER.debug("Plugins endpoint returned %s", resp.status)
                except aiohttp.ClientError as err:
                    _LOGGER.debug("Error requesting plugins: %s", err)

                # Identify Homebridge UI among plugins, remove it from plugins list and add as 'ui' entry
                ui_info = {"current_version": None, "latest_version": None, "update_available": False}
                remaining_plugins: List[dict] = []
                for p in results["plugins"]:
                    pkg = (p.get("package") or "").lower() if p.get("package") else ""
                    nm = (p.get("name") or "").lower()
                    is_ui = False
                    for pkg_name in HOMEBRIDGE_UI_PACKAGE_NAMES:
                        if pkg_name in pkg:
                            is_ui = True
                            break
                    if not is_ui:
                        for display_key in HOMEBRIDGE_UI_DISPLAY_KEYS:
                            if display_key in nm:
                                is_ui = True
                                break
                    if is_ui:
                        ui_info["current_version"] = p.get("current_version")
                        ui_info["latest_version"] = p.get("latest_version")
                        ui_info["update_available"] = bool(p.get("update_available", False))
                    else:
                        remaining_plugins.append(p)
                results["plugins"] = remaining_plugins
                results["ui"] = ui_info

                # Ensure keys exist for homebridge and node (in case endpoints failed)
                results.setdefault("homebridge", {"current_version": None, "latest_version": None, "update_available": False})
                results.setdefault("node", {"current_version": None, "latest_version": None, "update_available": False})
                results.setdefault("ui", {"current_version": None, "latest_version": None, "update_available": False})
                results.setdefault("plugins", [])

                # Update plugin_keys set for dynamic entity lifecycle management
                self.plugin_keys = {self._plugin_key(p) for p in results["plugins"]}

                return results

        except asyncio.TimeoutError as err:
            raise UpdateFailed(f"Timeout fetching Homebridge data: {err}") from err
        except aiohttp.ClientError as err:
            raise UpdateFailed(f"Error fetching Homebridge data: {err}") from err

    async def _async_refresh_token(self) -> None:
        """Attempt to refresh the authentication token using /api/auth/refresh.

        Updates the config entry on success. On auth failure, trigger reauth flow.
        """
        async with self._refresh_lock:
            token_expires = self.entry.data.get(CONF_TOKEN_EXPIRES)
            if token_expires is not None and int(token_expires) - int(time.time()) > REFRESH_MARGIN_SECONDS:
                _LOGGER.debug("Concurrent refresh already updated the token; skipping.")
                return

            if not self.token:
                _LOGGER.debug("No token present to refresh.")
                return

            refresh_url = f"{self.base_url}{ENDPOINT_REFRESH}"
            headers = {"Authorization": f"Bearer {self.token}"}
            session = self.session

            try:
                async with async_timeout.timeout(10):
                    resp = await session.post(refresh_url, headers=headers, ssl=self.verify_ssl)
                    if resp.status in (200, 201):
                        data = await resp.json()
                        new_token = data.get("access_token") or data.get("token") or data.get("accessToken") or data.get("jwt")
                        expires_in = data.get("expires_in") or data.get("expiresIn") or data.get("ttl")
                        expires_at = data.get("expires_at") or data.get("expiresAt") or data.get("expiration")

                        if not new_token:
                            _LOGGER.warning("Refresh response did not include token: %s", data)
                            await self._trigger_reauth(
                                message="No se pudo renovar el token automáticamente. Reautentícate en la integración."
                            )
                            raise UpdateFailed("Refresh did not return token")

                        token_expires_ts: Optional[int] = None
                        if expires_in is not None:
                            try:
                                seconds = int(expires_in)
                                token_expires_ts = int(time.time()) + seconds
                            except Exception:
                                _LOGGER.debug("Could not parse expires_in value from refresh response: %s", expires_in)
                        elif isinstance(expires_at, (int, float)):
                            token_expires_ts = int(expires_at)

                        new_data = {**self.entry.data, CONF_TOKEN: new_token}
                        if token_expires_ts is not None:
                            new_data[CONF_TOKEN_EXPIRES] = int(token_expires_ts)

                        # Persist updated token
                        self.hass.config_entries.async_update_entry(self.entry, data=new_data)
                        self.token = new_token
                        # refresh local entry reference
                        self.entry = self.hass.config_entries.async_get_entry(self.entry.entry_id) or self.entry
                        _LOGGER.info("Successfully refreshed Homebridge token for %s", self.entry.title)
                        return

                    if resp.status in (401, 403):
                        _LOGGER.warning("Token refresh unauthorized (status %s) for %s", resp.status, self.entry.title)
                        await self._trigger_reauth(
                            message="La renovación automática del token ha fallado (credenciales inválidas). Reautentícate."
                        )
                        raise UpdateFailed("Refresh unauthorized")

                    _LOGGER.warning("Unexpected status from refresh endpoint: %s", resp.status)
                    await self._trigger_reauth(
                        message="Error al intentar renovar el token. Reautentícate si el problema persiste."
                    )
                    raise UpdateFailed(f"Unexpected status from refresh endpoint: {resp.status}")
            except asyncio.TimeoutError as err:
                _LOGGER.warning("Timeout while refreshing token: %s", err)
                raise UpdateFailed("Timeout while refreshing token") from err
            except aiohttp.ClientError as err:
                _LOGGER.warning("Client error while refreshing token: %s", err)
                raise UpdateFailed("Client error while refreshing token") from err

    async def _trigger_reauth(self, message: str) -> None:
        """Create notification and start a reauth flow for the config entry."""
        notification_id = f"{DOMAIN}_reauth_{self.entry.entry_id}"
        persistent_notification.async_create(
            self.hass,
            message,
            f"{DOMAIN}: autenticación requerida",
            notification_id=notification_id,
        )

        # Start reauth flow in the UI so user sees the reauth dialog in Integrations
        self.hass.async_create_task(
            self.hass.config_entries.flow.async_init(
                DOMAIN,
                context={"source": "reauth", "entry_id": self.entry.entry_id},
                data={"host": self.entry.data.get("host")},
            )
        )

    @staticmethod
    def _plugin_key(plugin: dict) -> str:
        pkg = plugin.get("package") or ""
        name = plugin.get("name") or pkg or "unknown"
        return f"{name}::{pkg}"
