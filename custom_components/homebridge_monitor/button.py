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
        """Trigger the Homebridge core update and log the result."""
        _LOGGER.info(
            "Homebridge Monitor: triggering Homebridge core update on %s:%s",
            self.coordinator.host,
            self.coordinator.port,
        )
        success = await self.coordinator.async_update_homebridge_core()
        if success:
            _LOGGER.info(
                "Homebridge Monitor: Homebridge core update successfully initiated on %s:%s",
                self.coordinator.host,
                self.coordinator.port,
            )
        else:
            _LOGGER.warning(
                "Homebridge Monitor: failed to initiate Homebridge core update on %s:%s",
                self.coordinator.host,
                self.coordinator.port,
            )


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
        """Trigger the Homebridge UI update and log the result."""
        _LOGGER.info(
            "Homebridge Monitor: triggering Homebridge UI update on %s:%s",
            self.coordinator.host,
            self.coordinator.port,
        )
        success = await self.coordinator.async_update_ui()
        if success:
            _LOGGER.info(
                "Homebridge Monitor: Homebridge UI update successfully initiated on %s:%s",
                self.coordinator.host,
                self.coordinator.port,
            )
        else:
            _LOGGER.warning(
                "Homebridge Monitor: failed to initiate Homebridge UI update on %s:%s",
                self.coordinator.host,
                self.coordinator.port,
            )


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
        _LOGGER.info(
            "Homebridge Monitor: triggering plugin updates on %s:%s",
            self.coordinator.host,
            self.coordinator.port,
        )
        updated = await self.coordinator.async_update_all_plugins()
        if updated:
            _LOGGER.info(
                "Homebridge Monitor: plugin updates successfully initiated on %s:%s – plugins: %s",
                self.coordinator.host,
                self.coordinator.port,
                ", ".join(updated),
            )
        else:
            _LOGGER.info(
                "Homebridge Monitor: no plugin updates initiated on %s:%s"
                " (no pending updates or request failed)",
                self.coordinator.host,
                self.coordinator.port,
            )
