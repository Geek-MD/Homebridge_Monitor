"""Binary sensor platform for Homebridge Monitor integration."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
)
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN, SENSOR_NAME
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
    """Set up the Homebridge Monitor binary sensor."""
    coordinator: HomebridgeCoordinator = hass.data[DOMAIN][config_entry.entry_id]
    async_add_entities([HomebridgeConnectivitySensor(coordinator, config_entry)])


class HomebridgeConnectivitySensor(
    CoordinatorEntity[HomebridgeCoordinator], BinarySensorEntity
):
    """Binary sensor that reports Homebridge connectivity."""

    _attr_has_entity_name = True
    _attr_name = SENSOR_NAME
    _attr_device_class = BinarySensorDeviceClass.CONNECTIVITY

    def __init__(
        self,
        coordinator: HomebridgeCoordinator,
        config_entry: ConfigEntry,
    ) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator)
        self._config_entry = config_entry
        self._attr_unique_id = f"{DOMAIN}_{config_entry.entry_id}_connectivity"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, config_entry.entry_id)},
            name="Homebridge",
            manufacturer="homebridge.io",
            model="Homebridge",
            configuration_url=(
                f"http://{coordinator.host}:{coordinator.port}/"
            ),
        )

    @property
    def is_on(self) -> bool | None:
        """Return True if Homebridge is reachable."""
        return self.coordinator.data["connected"]

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return extra state attributes."""
        return {
            "host": self.coordinator.host,
            "port": self.coordinator.port,
        }
