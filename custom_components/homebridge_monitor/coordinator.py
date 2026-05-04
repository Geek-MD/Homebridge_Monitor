"""DataUpdateCoordinator for Homebridge Monitor."""

from __future__ import annotations

import asyncio
import logging
from datetime import timedelta
from typing import TYPE_CHECKING

import aiohttp
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from .const import DEFAULT_TIMEOUT, DOMAIN

if TYPE_CHECKING:
    from homeassistant.core import HomeAssistant

_LOGGER = logging.getLogger(__name__)


class HomebridgeCoordinator(DataUpdateCoordinator[bool]):
    """Coordinator that polls Homebridge for connectivity."""

    def __init__(
        self,
        hass: HomeAssistant,
        host: str,
        port: int,
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

    async def _async_update_data(self) -> bool:
        """Check connectivity to Homebridge by issuing an HTTP GET request."""
        url = f"http://{self.host}:{self.port}/"
        session = async_get_clientsession(self.hass)
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
                return True
        except (aiohttp.ClientError, asyncio.TimeoutError) as err:
            _LOGGER.debug(
                "Homebridge at %s:%s is not reachable: %s",
                self.host,
                self.port,
                err,
            )
            return False
