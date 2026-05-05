# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.1] - 2026-05-05

### Fixed
- **Homebridge core update failure**: `async_update_homebridge_core` was sending `POST /api/update/homebridge` instead of the correct `PUT /api/update/homebridge` required by the Homebridge Config UI X REST API. This caused the button to always log a `WARNING` and never trigger the update.

### Added
- **Domain-level services** (`homebridge_monitor.update_homebridge_core`, `homebridge_monitor.update_homebridge_ui`, `homebridge_monitor.update_plugins`): the three update actions are now registered as first-class Home Assistant services under the `homebridge_monitor` domain and appear in **Developer Tools → Actions** without needing to locate the `button.press` action manually.
  - Services are registered when the first config entry is loaded and removed when the last one is unloaded.
  - Service descriptions are defined in `services.yaml` and translated in all supported languages (en, es, de, fr, pt).
- **Richer logging throughout the integration**: every significant step now emits a structured `DEBUG` (or `WARNING` on failure) log entry with full context – URL, HTTP method, response status, token lifecycle events, version numbers, and plugin update details – making it much easier to diagnose connectivity or authentication issues from the Home Assistant log.

## [0.3.0] - 2026-05-05

### Added
- **Diagnostic button – Update Homebridge Core** (`button.homebridge_update_homebridge_core`): pressing this button (or calling the `button.press` service on it) sends `POST /api/update/homebridge` to Homebridge and writes an `INFO` log entry to the Home Assistant log confirming the update was initiated (or a `WARNING` on failure).
- **Diagnostic button – Update Homebridge UI** (`button.homebridge_update_homebridge_ui`): triggers `PUT /api/plugins/update/homebridge-config-ui-x` and logs the result.
- **Diagnostic button – Update Plugins** (`button.homebridge_update_homebridge_plugins`): triggers `PUT /api/plugins/update/<name>` for every plugin that currently has a pending update (as reported by the coordinator) and logs which plugins were updated.
- All three buttons belong to the **Diagnostic** entity category and are grouped under the Homebridge device in the *Diagnostics* section of the HA UI.
- Token auto-refresh: if the stored JWT has expired when a button is pressed, the coordinator re-authenticates automatically before retrying the request.
- Translations for the three new button entities in all supported languages (en, es, de, fr, pt).

## [0.2.2] - 2026-05-05

### Fixed
- **Untranslated `reauth_successful` message**: the abort message shown after a successful re-authentication was appearing as the raw key `reauth_successful` in the UI. The translation is now properly defined in `strings.json` and all language files (en, es, fr, de, pt).
- **Untranslated entity names**: the binary sensor and update entity names ("Connectivity", "Homebridge Update", "Homebridge UI Update", "Plugins Update") were hardcoded in English and not translatable. They now use Home Assistant's `translation_key` mechanism and are fully translated in all supported languages.

## [0.2.1] - 2026-05-05

### Fixed
- **KeyError on migration**: when upgrading from v0.1.x (which stored no `username`/`password` in the config entry) to v0.2.x, `async_setup_entry` raised `KeyError: 'username'` and the integration failed to load. This release adds `async_migrate_entry` (VERSION 1 → 2) which fills in empty credential placeholders so the entry can be loaded again.
- **Reauth notification**: if credentials are missing or empty after migration, `async_setup_entry` now calls `entry.async_start_reauth()` and returns `False`. Home Assistant automatically shows a persistent **"Action required"** notification in the integrations panel with a direct link to the credential re-entry form – no manual deletion and re-setup required.

### Changed
- **Config entry schema** bumped to VERSION 2 to track the addition of credentials.
- **Options flow** now includes `username` and `password` fields so credentials can be updated at any time from the integration's **Configure** menu, without going through a full reauth.
- **Reauth flow** (`async_step_reauth_confirm`) added to `FlowHandler`: validates connectivity and credentials before saving, and reloads the entry on success.

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

## [0.1.1] - 2026-05-04

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
