"""Update platform for Homebridge Monitor integration."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from homeassistant.components.update import UpdateDeviceClass, UpdateEntity
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import HomebridgeCoordinator, PluginUpdateInfo

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
    """Set up Homebridge Monitor update sensors."""
    coordinator: HomebridgeCoordinator = hass.data[DOMAIN][config_entry.entry_id]
    async_add_entities(
        [
            HomebridgeUpdateEntity(coordinator, config_entry),
            HomebridgeUIUpdateEntity(coordinator, config_entry),
            HomebridgePluginsUpdateEntity(coordinator, config_entry),
        ]
    )


def _device_info(coordinator: HomebridgeCoordinator, config_entry: ConfigEntry) -> DeviceInfo:
    """Return the shared DeviceInfo for all update entities."""
    return DeviceInfo(
        identifiers={(DOMAIN, config_entry.entry_id)},
        name="Homebridge",
        manufacturer="homebridge.io",
        model="Homebridge",
        configuration_url=f"http://{coordinator.host}:{coordinator.port}/",
    )


class HomebridgeUpdateEntity(
    CoordinatorEntity[HomebridgeCoordinator], UpdateEntity
):
    """Update entity that reports whether a Homebridge update is available."""

    _attr_has_entity_name = True
    _attr_translation_key = "homebridge_update"
    _attr_device_class = UpdateDeviceClass.FIRMWARE
    _attr_title = "Homebridge"

    def __init__(
        self,
        coordinator: HomebridgeCoordinator,
        config_entry: ConfigEntry,
    ) -> None:
        """Initialize the entity."""
        super().__init__(coordinator)
        self._config_entry = config_entry
        self._attr_unique_id = f"{DOMAIN}_{config_entry.entry_id}_homebridge_update"
        self._attr_device_info = _device_info(coordinator, config_entry)

    @property
    def installed_version(self) -> str | None:
        """Return the currently installed Homebridge version."""
        return self.coordinator.data.get("homebridge_current_version")

    @property
    def latest_version(self) -> str | None:
        """Return the latest available Homebridge version."""
        return self.coordinator.data.get("homebridge_latest_version")

    @property
    def release_url(self) -> str | None:
        """Return a link to the Homebridge changelog."""
        return "https://github.com/homebridge/homebridge/releases"

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return extra state attributes."""
        return {
            "current_version": self.installed_version,
            "latest_version": self.latest_version,
        }


class HomebridgeUIUpdateEntity(
    CoordinatorEntity[HomebridgeCoordinator], UpdateEntity
):
    """Update entity that reports whether a Homebridge UI update is available."""

    _attr_has_entity_name = True
    _attr_translation_key = "ui_update"
    _attr_device_class = UpdateDeviceClass.FIRMWARE
    _attr_title = "Homebridge UI"

    def __init__(
        self,
        coordinator: HomebridgeCoordinator,
        config_entry: ConfigEntry,
    ) -> None:
        """Initialize the entity."""
        super().__init__(coordinator)
        self._config_entry = config_entry
        self._attr_unique_id = f"{DOMAIN}_{config_entry.entry_id}_ui_update"
        self._attr_device_info = _device_info(coordinator, config_entry)

    @property
    def installed_version(self) -> str | None:
        """Return the currently installed Homebridge UI version."""
        return self.coordinator.data.get("ui_current_version")

    @property
    def latest_version(self) -> str | None:
        """Return the latest available Homebridge UI version."""
        return self.coordinator.data.get("ui_latest_version")

    @property
    def release_url(self) -> str | None:
        """Return a link to the Homebridge UI changelog."""
        return "https://github.com/homebridge/homebridge-config-ui-x/releases"

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return extra state attributes."""
        return {
            "current_version": self.installed_version,
            "latest_version": self.latest_version,
        }


class HomebridgePluginsUpdateEntity(
    CoordinatorEntity[HomebridgeCoordinator], UpdateEntity
):
    """Update entity that reports whether any Homebridge plugin has an update."""

    _attr_has_entity_name = True
    _attr_translation_key = "plugins_update"
    _attr_device_class = UpdateDeviceClass.FIRMWARE
    _attr_title = "Homebridge Plugins"

    def __init__(
        self,
        coordinator: HomebridgeCoordinator,
        config_entry: ConfigEntry,
    ) -> None:
        """Initialize the entity."""
        super().__init__(coordinator)
        self._config_entry = config_entry
        self._attr_unique_id = f"{DOMAIN}_{config_entry.entry_id}_plugins_update"
        self._attr_device_info = _device_info(coordinator, config_entry)

    def _plugins_with_updates(self) -> list[PluginUpdateInfo]:
        """Return the list of plugins that have updates available."""
        return list(self.coordinator.data.get("plugins_with_updates", []))

    @property
    def installed_version(self) -> str | None:
        """Return a virtual 'version' representing the number of pending plugin updates."""
        count = len(self._plugins_with_updates())
        if count == 0:
            return "up-to-date"
        return f"{count} update{'s' if count != 1 else ''} available"

    @property
    def latest_version(self) -> str | None:
        """Return the desired state – no pending updates."""
        return "up-to-date"

    @property
    def release_url(self) -> str | None:
        """Return a link to the Homebridge plugins page."""
        return f"http://{self.coordinator.host}:{self.coordinator.port}/#/plugins"

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return the list of plugins with available updates."""
        return {
            "plugins_with_updates": self._plugins_with_updates(),
        }
