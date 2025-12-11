# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2025-12-11

### Added
- Reconfigure flow support - users can now reconfigure the integration from the UI without removing and re-adding it
  - Update host, swagger path, and SSL verification settings
  - Re-authenticate with new settings
  - Integration automatically reloads after reconfiguration

### Fixed
- Fixed domain name typo in const.py (changed from "homebridge_momnitor" to "homebridge_monitor")
- Fixed mypy type errors in config_flow.py (ConfigFlow domain parameter)
- Fixed mypy type errors in binary_sensor.py (callback return type annotation)
- Fixed mypy type errors in __init__.py (async_setup_platforms call)

### Changed
- Updated manifest.json version to 0.3.0
- Updated hacs.json version to 0.3.0

## [0.1.0] - Initial Release

### Added
- Initial release of Homebridge Monitor integration
- Binary sensors for Homebridge core, UI, Node.js, and plugins
- Automatic token refresh mechanism
- Re-authentication flow support
- Dynamic plugin entity management
- Config flow setup (UI-based configuration)
- Support for custom swagger paths and SSL verification options
