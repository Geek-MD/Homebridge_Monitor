# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-05-04

### Added
- **Initial release** of the Homebridge Monitor integration for Home Assistant.
- **Connectivity binary sensor** (`binary_sensor.homebridge_connectivity`): reports `on` (connected) or `off` (disconnected) based on whether the Homebridge web UI is reachable at the configured host and port.
- **Config flow**: UI-driven setup that asks for the Homebridge host (IP address or hostname) and port, with live connectivity validation before saving.
- **Options flow**: allows adjusting the polling interval (scan interval, 5–3600 seconds) without removing and re-adding the integration.
- **DataUpdateCoordinator**: efficient, non-blocking HTTP polling using Home Assistant's shared `aiohttp` session.
- **Device entry**: groups the sensor under a "Homebridge" device in the Home Assistant device registry, including a direct link to the Homebridge web UI.
- **HACS-compatible** structure (`hacs.json`, `manifest.json`).
- **GitHub Actions**: CI workflow with Ruff, Mypy, and Hassfest checks; HACS validation workflow.
- **Translations**: English and Spanish UI strings.
