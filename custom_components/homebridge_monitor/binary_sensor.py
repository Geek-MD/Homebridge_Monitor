"""Binary sensors exposing update availability from Homebridge."""
from __future__ import annotations

from typing import Any, Callable, Dict
import logging

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DEFAULT_NAME, DOMAIN
from .coordinator import HomebridgeCoordinator

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback) -> None:
    """Set up binary sensors for a Homebridge config entry."""

    coordinator: HomebridgeCoordinator = hass.data[DOMAIN][entry.entry_id]

    platform = hass.data.setdefault(f"{DOMAIN}_platform_{entry.entry_id}", {})
    platform["async_add_entities"] = async_add_entities  # keep ref for dynamic adds

    entities: list[HomebridgeUpdateBinarySensor] = []

    # Core components (homebridge, ui, node) — identifiers are 'homebridge', 'ui', 'node'
    entities.append(HomebridgeUpdateBinarySensor(coordinator, "homebridge", "Homebridge"))
    entities.append(HomebridgeUpdateBinarySensor(coordinator, "ui", "Homebridge UI"))
    entities.append(HomebridgeUpdateBinarySensor(coordinator, "node", "Node.js"))

    # Plugin sensors: create initial set
    for plugin in coordinator.data.get("plugins", []):
        unique = coordinator._plugin_key(plugin)
        entities.append(
            HomebridgeUpdateBinarySensor(
                coordinator,
                unique,
                plugin.get("name") or "plugin",
                is_plugin=True,
                plugin_meta=plugin,
            )
        )

    async_add_entities(entities, update_before_add=True)

    # Register listener for future updates to add/remove plugin entities dynamically
    coordinator.async_add_listener(_make_update_listener(hass, entry.entry_id, coordinator))


def _make_update_listener(hass: HomeAssistant, entry_id: str, coordinator: HomebridgeCoordinator) -> Callable[[], None]:
    """Return a callback to handle coordinator updates and add/remove plugin entities dynamically."""
    added_entities: Dict[str, HomebridgeUpdateBinarySensor] = {}

    @callback
    def _listener() -> None:
        """Handle coordinator update: add new plugin entities, remove missing ones."""
        platform = hass.data.get(f"{DOMAIN}_platform_{entry_id}", {})
        async_add = platform.get("async_add_entities")
        if async_add is None:
            _LOGGER.debug("No async_add_entities available for dynamic adds")
            return

        # Current plugin keys from coordinator
        current_keys = coordinator.plugin_keys

        # Add new plugins
        for plugin in coordinator.data.get("plugins", []):
            key = coordinator._plugin_key(plugin)
            if key not in added_entities and key not in (e.unique_id for e in added_entities.values()):
                # create and add
                ent = HomebridgeUpdateBinarySensor(coordinator, key, plugin.get("name") or "plugin", is_plugin=True, plugin_meta=plugin)
                added_entities[key] = ent
                _LOGGER.debug("Adding new plugin entity %s", key)
                async_add([ent], update_before_add=False)

        # Remove plugins that disappear
        to_remove = [k for k in added_entities.keys() if k not in current_keys]
        for k in to_remove:
            ent = added_entities.pop(k)
            _LOGGER.debug("Removing plugin entity %s", k)
            hass.async_create_task(ent.async_remove())

    return _listener


class HomebridgeUpdateBinarySensor(BinarySensorEntity):
    """Binary sensor indicating whether an update is available."""

    # Set device_class on instance to satisfy mypy/ruff stubs
    def __init__(
        self,
        coordinator: HomebridgeCoordinator,
        unique_id: str,
        name: str,
        is_plugin: bool = False,
        plugin_meta: dict | None = None,
    ) -> None:
        """Initialize the sensor."""
        self.coordinator = coordinator
        self._unique_id = unique_id
        self._name = name
        self._is_plugin = is_plugin
        self._plugin_meta = plugin_meta or {}

        # instance attributes for HA Entity modern pattern
        self._attr_device_class = BinarySensorDeviceClass.UPDATE
        self._attr_name = f"{DEFAULT_NAME} {name}"
        self._attr_available = True
        self._attr_should_poll = False
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, unique_id)},
            name=self._attr_name,
            manufacturer="Homebridge",
        )

    @property
    def unique_id(self) -> str:
        return f"{DOMAIN}_{self._unique_id}"

    @property
    def is_on(self) -> bool:
        """True if update_available is true."""
        data = self.coordinator.data or {}
        if self._is_plugin:
            # Try to find plugin by plugin key
            for p in data.get("plugins", []):
                if self.coordinator._plugin_key(p) == self._unique_id:
                    return bool(p.get("update_available", False))
            return False
        # core items
        key_map = {
            "homebridge": "homebridge",
            "ui": "ui",
            "node": "node",
        }
        key = key_map.get(self._unique_id, self._unique_id)
        comp = data.get(key, {})
        return bool(comp.get("update_available", False))

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        """Return attributes with version info and source."""
        data = self.coordinator.data or {}
        attrs: dict[str, Any] = {}
        if self._is_plugin:
            for p in data.get("plugins", []):
                if self.coordinator._plugin_key(p) == self._unique_id:
                    attrs["plugin"] = p.get("name")
                    attrs["package"] = p.get("package")
                    attrs["current_version"] = p.get("current_version")
                    attrs["latest_version"] = p.get("latest_version")
                    attrs["source"] = "plugin"
                    break
        else:
            key_map = {"homebridge": "homebridge", "ui": "ui", "node": "node"}
            key = key_map.get(self._unique_id, self._unique_id)
            comp = data.get(key, {})
            attrs["current_version"] = comp.get("current_version")
            attrs["latest_version"] = comp.get("latest_version")
            attrs["source"] = key
        return attrs

    async def async_added_to_hass(self) -> None:
        """Register listener with coordinator updates."""
        self.async_on_remove(self.coordinator.async_add_listener(self._handle_coordinator_update))

    @callback
    def _handle_coordinator_update(self) -> None:
        self.async_write_ha_state()
