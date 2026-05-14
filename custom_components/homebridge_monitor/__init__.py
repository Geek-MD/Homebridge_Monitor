"""The Homebridge Monitor integration."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import voluptuous as vol
from homeassistant.components.persistent_notification import async_create, async_dismiss
from homeassistant.const import Platform
from homeassistant.core import callback
from homeassistant.helpers import config_validation as cv

from .const import (
    CONF_HOST,
    CONF_PASSWORD,
    CONF_PORT,
    CONF_SCAN_INTERVAL,
    CONF_USERNAME,
    DEFAULT_SCAN_INTERVAL,
    DOMAIN,
)
from .coordinator import HomebridgeCoordinator

if TYPE_CHECKING:
    from homeassistant.config_entries import ConfigEntry
    from homeassistant.core import HomeAssistant, ServiceCall

_LOGGER = logging.getLogger(__name__)

PLATFORMS: list[Platform] = [Platform.BINARY_SENSOR, Platform.BUTTON, Platform.UPDATE]

SERVICE_UPDATE_PLUGINS = "update_plugins"
SERVICE_UPDATE_HOMEBRIDGE_CORE = "update_homebridge_core"
SERVICE_UPDATE_HOMEBRIDGE_UI = "update_homebridge_ui"
SERVICE_REAUTHENTICATE = "reauthenticate"

SERVICE_UPDATE_PLUGINS_SCHEMA = vol.Schema(
    {
        vol.Optional("plugins"): vol.All(cv.ensure_list, [cv.string]),
    }
)


async def async_migrate_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Migrate old config entries to the current schema version."""
    _LOGGER.debug("Migrating config entry from version %d", entry.version)

    if entry.version == 1:
        # v0.1.x entries do not have username/password; add empty placeholders so
        # async_setup_entry can detect the missing credentials and trigger reauth.
        new_data = {
            **entry.data,
            CONF_USERNAME: entry.data.get(CONF_USERNAME, ""),
            CONF_PASSWORD: entry.data.get(CONF_PASSWORD, ""),
        }
        hass.config_entries.async_update_entry(entry, data=new_data, version=2)
        _LOGGER.info("Migrated config entry to version 2")

    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up Homebridge Monitor from a config entry."""
    host: str = entry.data[CONF_HOST]
    port: int = entry.data[CONF_PORT]
    username: str = entry.data.get(CONF_USERNAME, "")
    password: str = entry.data.get(CONF_PASSWORD, "")
    scan_interval: int = entry.options.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL)

    if not username or not password:
        _LOGGER.warning(
            "Homebridge credentials are missing for entry %s; reauth required",
            entry.title,
        )
        entry.async_start_reauth(hass)
        return False

    coordinator = HomebridgeCoordinator(hass, host, port, username, password, scan_interval)
    await coordinator.async_config_entry_first_refresh()

    hass.data.setdefault(DOMAIN, {})
    hass.data[DOMAIN][entry.entry_id] = coordinator

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    # Register domain-level services (only once – on the first loaded entry)
    if not hass.services.has_service(DOMAIN, SERVICE_UPDATE_PLUGINS):

        async def _handle_update_plugins(call: ServiceCall) -> None:
            raw: list[str] | None = call.data.get("plugins") or None
            for coord in hass.data[DOMAIN].values():
                await coord.async_update_all_plugins(names=raw)

        hass.services.async_register(
            DOMAIN,
            SERVICE_UPDATE_PLUGINS,
            _handle_update_plugins,
            schema=SERVICE_UPDATE_PLUGINS_SCHEMA,
        )
        _LOGGER.debug(
            "Homebridge Monitor: registered domain service (%s)",
            SERVICE_UPDATE_PLUGINS,
        )

    if not hass.services.has_service(DOMAIN, SERVICE_UPDATE_HOMEBRIDGE_CORE):

        async def _handle_update_homebridge_core(_call: ServiceCall) -> None:
            for coord in hass.data[DOMAIN].values():
                await coord.async_update_homebridge_core()

        hass.services.async_register(
            DOMAIN, SERVICE_UPDATE_HOMEBRIDGE_CORE, _handle_update_homebridge_core
        )
        _LOGGER.debug(
            "Homebridge Monitor: registered domain service (%s)",
            SERVICE_UPDATE_HOMEBRIDGE_CORE,
        )

    if not hass.services.has_service(DOMAIN, SERVICE_UPDATE_HOMEBRIDGE_UI):

        async def _handle_update_homebridge_ui(_call: ServiceCall) -> None:
            for coord in hass.data[DOMAIN].values():
                await coord.async_update_ui()

        hass.services.async_register(
            DOMAIN, SERVICE_UPDATE_HOMEBRIDGE_UI, _handle_update_homebridge_ui
        )
        _LOGGER.debug(
            "Homebridge Monitor: registered domain service (%s)",
            SERVICE_UPDATE_HOMEBRIDGE_UI,
        )

    if not hass.services.has_service(DOMAIN, SERVICE_REAUTHENTICATE):

        async def _handle_reauthenticate(_call: ServiceCall) -> None:
            for coord in hass.data[DOMAIN].values():
                await coord.async_force_reauthenticate()

        hass.services.async_register(DOMAIN, SERVICE_REAUTHENTICATE, _handle_reauthenticate)
        _LOGGER.debug(
            "Homebridge Monitor: registered domain service (%s)",
            SERVICE_REAUTHENTICATE,
        )

    entry.async_on_unload(entry.add_update_listener(async_reload_entry))

    # Register a coordinator listener that manages persistent notifications
    # for every update sensor that becomes active.
    @callback
    def _async_update_notifications() -> None:
        """Create or dismiss persistent notifications based on update sensor states."""
        data = coordinator.data
        if data is None:
            return

        integration_url = f"/config/integrations/integration/{DOMAIN}"
        title = entry.title

        # --- Homebridge core update ---
        hb_notif_id = f"{DOMAIN}_{entry.entry_id}_hb_update"
        if data["homebridge_update_available"]:
            hb_cur = data["homebridge_current_version"] or "?"
            hb_lat = data["homebridge_latest_version"] or "?"
            async_create(
                hass,
                message=(
                    f"A new version of **Homebridge** is available for *{title}*"
                    f" ({hb_cur} → {hb_lat}).\n\n"
                    f"[Open integration]({integration_url}) and press the"
                    f" **Update Homebridge Core** button to install."
                ),
                title="Homebridge Update Available",
                notification_id=hb_notif_id,
            )
        else:
            async_dismiss(hass, hb_notif_id)

        # --- Homebridge UI update ---
        ui_notif_id = f"{DOMAIN}_{entry.entry_id}_ui_update"
        if data["ui_update_available"]:
            ui_cur = data["ui_current_version"] or "?"
            ui_lat = data["ui_latest_version"] or "?"
            async_create(
                hass,
                message=(
                    f"A new version of **Homebridge UI** is available for *{title}*"
                    f" ({ui_cur} → {ui_lat}).\n\n"
                    f"[Open integration]({integration_url}) and press the"
                    f" **Update Homebridge UI** button to install."
                ),
                title="Homebridge UI Update Available",
                notification_id=ui_notif_id,
            )
        else:
            async_dismiss(hass, ui_notif_id)

        # --- Plugin updates ---
        plugins_notif_id = f"{DOMAIN}_{entry.entry_id}_plugins_update"
        plugins_with_updates = data["plugins_with_updates"]
        if plugins_with_updates:
            count = len(plugins_with_updates)
            plugin_list = "\n".join(
                f"- **{p['name']}**: {p['current_version']} → {p['latest_version']}"
                for p in plugins_with_updates
            )
            plural = "s" if count != 1 else ""
            async_create(
                hass,
                message=(
                    f"{count} Homebridge plugin update{plural} available"
                    f" for *{title}*:\n\n{plugin_list}\n\n"
                    f"[Open integration]({integration_url}) and press the"
                    f" **Update Plugins** button to install."
                ),
                title=f"Homebridge Plugin Update{plural} Available",
                notification_id=plugins_notif_id,
            )
        else:
            async_dismiss(hass, plugins_notif_id)

        # --- Node.js update ---
        nodejs_notif_id = f"{DOMAIN}_{entry.entry_id}_nodejs_update"
        if data["nodejs_update_available"]:
            nodejs_cur = data["nodejs_current_version"] or "?"
            nodejs_lat = data["nodejs_latest_version"] or "?"
            async_create(
                hass,
                message=(
                    f"A new version of **Node.js** is available for *{title}*"
                    f" ({nodejs_cur} → {nodejs_lat}).\n\n"
                    f"Update Node.js on your Homebridge host to apply."
                ),
                title="Node.js Update Available",
                notification_id=nodejs_notif_id,
            )
        else:
            async_dismiss(hass, nodejs_notif_id)

    entry.async_on_unload(coordinator.async_add_listener(_async_update_notifications))

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    # Dismiss any persistent notifications created for this entry.
    for suffix in ("_hb_update", "_ui_update", "_plugins_update", "_nodejs_update"):
        async_dismiss(hass, f"{DOMAIN}_{entry.entry_id}{suffix}")

    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        hass.data[DOMAIN].pop(entry.entry_id)
        # Remove domain services when the last entry is unloaded
        if not hass.data[DOMAIN]:
            hass.services.async_remove(DOMAIN, SERVICE_UPDATE_PLUGINS)
            hass.services.async_remove(DOMAIN, SERVICE_UPDATE_HOMEBRIDGE_CORE)
            hass.services.async_remove(DOMAIN, SERVICE_UPDATE_HOMEBRIDGE_UI)
            hass.services.async_remove(DOMAIN, SERVICE_REAUTHENTICATE)
            _LOGGER.debug(
                "Homebridge Monitor: removed domain services (%s, %s, %s, %s)",
                SERVICE_UPDATE_PLUGINS,
                SERVICE_UPDATE_HOMEBRIDGE_CORE,
                SERVICE_UPDATE_HOMEBRIDGE_UI,
                SERVICE_REAUTHENTICATE,
            )
    return unload_ok


async def async_reload_entry(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Reload config entry."""
    await hass.config_entries.async_reload(entry.entry_id)
