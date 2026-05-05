# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-05-05

### Added
- **Homebridge REST API authentication**: the config flow now asks for a username and password, which are stored in the config entry and used to obtain a JWT access token from the Homebridge API (`POST /api/auth/login`). Credentials are validated during setup.
- **Update sensor – Homebridge** (`update.homebridge_homebridge_update`): reports whether a Homebridge core update is available, showing the installed and latest versions. Data is sourced from `GET /api/status/homebridge-version`.
- **Update sensor – Homebridge UI** (`update.homebridge_homebridge_ui_update`): reports whether a Homebridge UI (homebridge-config-ui-x) update is available. Data is sourced from `GET /api/plugins`.
- **Update sensor – Plugins** (`update.homebridge_plugins_update`): reports whether any installed Homebridge plugin has an update available. The sensor state is *on* when one or more plugins are outdated; the `plugins_with_updates` attribute lists each plugin name together with its installed and latest version.
- **Token refresh**: the coordinator automatically re-authenticates when it receives an HTTP 401 response, so the integration keeps working when the JWT access token expires.

### Changed
- **Coordinator** now returns a structured `HomebridgeData` typed dictionary instead of a plain `bool`; the connectivity binary sensor reads `data["connected"]`.
- **Config flow** initial step extended with `username` and `password` fields. An `invalid_auth` error is shown when the supplied credentials are rejected by Homebridge.



### Changed
- **Options flow** now allows editing the Homebridge host (IP address or hostname) and port in addition to the scan interval. Connectivity is validated before saving, and the entry title, unique ID, and stored data are updated automatically.

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
