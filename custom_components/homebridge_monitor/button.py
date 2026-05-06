"""Button platform for Homebridge Monitor integration – Diagnostics section."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from homeassistant.components.button import ButtonEntity
from homeassistant.const import EntityCategory
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import HomebridgeCoordinator

if TYPE_CHECKING:
    from homeassistant.config_entries import ConfigEntry
    from homeassistant.core import HomeAssistant
    from homeassistant.helpers.entity_platform import AddEntitiesCallback

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Homebridge Monitor diagnostic button entities."""
    coordinator: HomebridgeCoordinator = hass.data[DOMAIN][config_entry.entry_id]
    async_add_entities(
        [
            HomebridgeUpdateCoreButton(coordinator, config_entry),
            HomebridgeUpdateUIButton(coordinator, config_entry),
            HomebridgeUpdatePluginsButton(coordinator, config_entry),
            HomebridgeReauthenticateButton(coordinator, config_entry),
        ]
    )


def _device_info(coordinator: HomebridgeCoordinator, config_entry: ConfigEntry) -> DeviceInfo:
    """Return the shared DeviceInfo for all button entities."""
    return DeviceInfo(
        identifiers={(DOMAIN, config_entry.entry_id)},
        name="Homebridge",
        manufacturer="homebridge.io",
        model="Homebridge",
        configuration_url=f"http://{coordinator.host}:{coordinator.port}/",
    )


class HomebridgeUpdateCoreButton(
    CoordinatorEntity[HomebridgeCoordinator], ButtonEntity
):
    """Button that triggers a Homebridge core update."""

    _attr_has_entity_name = True
    _attr_translation_key = "update_homebridge_core"
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(
        self,
        coordinator: HomebridgeCoordinator,
        config_entry: ConfigEntry,
    ) -> None:
        """Initialize the button."""
        super().__init__(coordinator)
        self._config_entry = config_entry
        self._attr_unique_id = f"{DOMAIN}_{config_entry.entry_id}_update_homebridge_core"
        self._attr_device_info = _device_info(coordinator, config_entry)

    async def async_press(self) -> None:
        """Trigger a Homebridge core update."""
        _LOGGER.info(
            "Homebridge Monitor: [%s] triggering Homebridge core update on %s:%s",
            self.entity_id,
            self.coordinator.host,
            self.coordinator.port,
        )
        await self.coordinator.async_update_homebridge_core()


class HomebridgeUpdateUIButton(
    CoordinatorEntity[HomebridgeCoordinator], ButtonEntity
):
    """Button that triggers a Homebridge UI (homebridge-config-ui-x) update."""

    _attr_has_entity_name = True
    _attr_translation_key = "update_homebridge_ui"
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(
        self,
        coordinator: HomebridgeCoordinator,
        config_entry: ConfigEntry,
    ) -> None:
        """Initialize the button."""
        super().__init__(coordinator)
        self._config_entry = config_entry
        self._attr_unique_id = f"{DOMAIN}_{config_entry.entry_id}_update_homebridge_ui"
        self._attr_device_info = _device_info(coordinator, config_entry)

    async def async_press(self) -> None:
        """Trigger a Homebridge UI update."""
        _LOGGER.info(
            "Homebridge Monitor: [%s] triggering Homebridge UI update on %s:%s",
            self.entity_id,
            self.coordinator.host,
            self.coordinator.port,
        )
        await self.coordinator.async_update_ui()


class HomebridgeUpdatePluginsButton(
    CoordinatorEntity[HomebridgeCoordinator], ButtonEntity
):
    """Button that triggers updates for all Homebridge plugins with pending updates."""

    _attr_has_entity_name = True
    _attr_translation_key = "update_homebridge_plugins"
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(
        self,
        coordinator: HomebridgeCoordinator,
        config_entry: ConfigEntry,
    ) -> None:
        """Initialize the button."""
        super().__init__(coordinator)
        self._config_entry = config_entry
        self._attr_unique_id = f"{DOMAIN}_{config_entry.entry_id}_update_homebridge_plugins"
        self._attr_device_info = _device_info(coordinator, config_entry)

    async def async_press(self) -> None:
        """Trigger updates for all plugins with pending updates and log the result."""
        pending = self.coordinator.data.get("plugins_with_updates", []) if self.coordinator.data else []
        _LOGGER.info(
            "Homebridge Monitor: [%s] triggering plugin updates on %s:%s"
            " (%d plugin(s) pending)",
            self.entity_id,
            self.coordinator.host,
            self.coordinator.port,
            len(pending),
        )
        updated = await self.coordinator.async_update_all_plugins()
        if updated:
            _LOGGER.info(
                "Homebridge Monitor: [%s] plugin updates successfully initiated"
                " on %s:%s – %d plugin(s): %s",
                self.entity_id,
                self.coordinator.host,
                self.coordinator.port,
                len(updated),
                ", ".join(updated),
            )
        else:
            _LOGGER.info(
                "Homebridge Monitor: [%s] no plugin updates initiated on %s:%s"
                " (no pending updates or all requests failed)",
                self.entity_id,
                self.coordinator.host,
                self.coordinator.port,
            )


class HomebridgeReauthenticateButton(
    CoordinatorEntity[HomebridgeCoordinator], ButtonEntity
):
    """Button that forces a token refresh or full re-authentication."""

    _attr_has_entity_name = True
    _attr_translation_key = "reauthenticate"
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(
        self,
        coordinator: HomebridgeCoordinator,
        config_entry: ConfigEntry,
    ) -> None:
        """Initialize the button."""
        super().__init__(coordinator)
        self._config_entry = config_entry
        self._attr_unique_id = f"{DOMAIN}_{config_entry.entry_id}_reauthenticate"
        self._attr_device_info = _device_info(coordinator, config_entry)

    async def async_press(self) -> None:
        """Force a token refresh (if token is valid) or full re-authentication."""
        _LOGGER.info(
            "Homebridge Monitor: [%s] forcing re-authentication on %s:%s",
            self.entity_id,
            self.coordinator.host,
            self.coordinator.port,
        )
        await self.coordinator.async_force_reauthenticate()
