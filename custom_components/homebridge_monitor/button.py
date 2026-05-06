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
