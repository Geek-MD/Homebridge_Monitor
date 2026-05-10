[![Geek-MD - Homebridge Monitor](https://img.shields.io/static/v1?label=Geek-MD&message=Homebridge%20Monitor&color=blue&logo=github)](https://github.com/Geek-MD/Homebridge_Monitor)
[![Stars](https://img.shields.io/github/stars/Geek-MD/Homebridge_Monitor?style=social)](https://github.com/Geek-MD/Homebridge_Monitor)
[![Forks](https://img.shields.io/github/forks/Geek-MD/Homebridge_Monitor?style=social)](https://github.com/Geek-MD/Homebridge_Monitor)

[![GitHub Release](https://img.shields.io/github/release/Geek-MD/Homebridge_Monitor?include_prereleases&sort=semver&color=blue)](https://github.com/Geek-MD/Homebridge_Monitor/releases)
[![License](https://img.shields.io/badge/License-MIT-blue)](https://github.com/Geek-MD/Homebridge_Monitor/blob/main/LICENSE)
[![HACS Custom Repository](https://img.shields.io/badge/HACS-Custom%20Repository-blue)](https://hacs.xyz/)

[![Ruff + Mypy + Hassfest](https://github.com/Geek-MD/Homebridge_Monitor/actions/workflows/ci.yaml/badge.svg)](https://github.com/Geek-MD/Homebridge_Monitor/actions/workflows/ci.yaml)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![Checked with mypy](https://www.mypy-lang.org/static/mypy_badge.svg)](https://mypy-lang.org/)

![](https://github.com/Geek-MD/Homebridge_Monitor/blob/main/custom_components/homebridge_monitor/brand/logo.png)

# Homebridge Monitor

A custom Home Assistant integration that monitors the connectivity of a local [Homebridge](https://homebridge.io) instance.  
It exposes a **connectivity binary sensor** that turns `on` when Homebridge is reachable and `off` when it is not – similar in spirit to the built-in [Ping (ICMP)](https://www.home-assistant.io/integrations/ping/) integration, but targeted specifically at the Homebridge web UI endpoint.

---

## Features

- **Connectivity binary sensor** – `on` = connected, `off` = disconnected.
- **Device class `connectivity`** – integrates naturally with the Home Assistant UI and mobile apps.
- **REST API authentication** – the setup wizard asks for a username and password, validates them against the Homebridge API, and stores the credentials securely.
- **Update sensors** – three `update` entities report whether a new version of Homebridge core, Homebridge UI, or any installed plugin is available.
- **Diagnostic buttons** – four `button` entities (in the *Diagnostics* section of the device) let you trigger Homebridge core, UI, and plugin updates, as well as a forced token refresh/re-authentication, directly from the HA UI or from **Developer Tools → Actions** (`button.press`).
- **Domain services** – the same four actions are also exposed as first-class Home Assistant services under the `homebridge_monitor` domain (`homebridge_monitor.update_homebridge_core`, `homebridge_monitor.update_homebridge_ui`, `homebridge_monitor.update_plugins`, `homebridge_monitor.reauthenticate`) and appear directly in **Developer Tools → Actions**.
- **Persistent update notifications** – whenever any update sensor becomes active, Home Assistant automatically shows a persistent notification in the notifications panel with the installed/latest version and a direct link to the integration page to press the corresponding update button.
- **Config-flow setup** – configure entirely through the UI; no YAML needed.
- **Live validation** – the setup wizard tests both connectivity and credentials before saving the entry.
- **Reconfigurable connection** – change the host, port, credentials and polling interval after setup via the integration's options, with live connectivity and authentication validation.
- **Device entry** – groups all sensors under a _Homebridge_ device with a direct link to the Homebridge web UI.
- **HACS-compatible**.

---

## Requirements

| Requirement | Minimum version |
|-------------|----------------|
| Home Assistant | 2024.1.0 |
| HACS | 1.6.0 |

---

## Installation

### Via HACS (recommended)

1. Open HACS → **Integrations**.
2. Click the three-dot menu → **Custom repositories**.
3. Add `https://github.com/Geek-MD/Homebridge_Monitor` with category **Integration**.
4. Search for **Homebridge Monitor** and click **Download**.
5. Restart Home Assistant.

### Manual

1. Copy the `custom_components/homebridge_monitor` directory into your `<config>/custom_components/` folder.
2. Restart Home Assistant.

---

## Configuration

1. Go to **Settings → Devices & Services → Add Integration**.
2. Search for **Homebridge Monitor**.
3. Enter the **host** (IP address or hostname) and **port** of your Homebridge instance.  
   The default Homebridge web UI port is **8581**.
4. Enter your Homebridge **username** and **password**.  
   These credentials are used to obtain a JWT access token from the Homebridge REST API.
5. Click **Submit**. Home Assistant will verify both connectivity and credentials before saving.

### Options

After setup, click **Configure** on the integration card to adjust:

| Option | Description | Default |
|--------|-------------|---------|
| Host | IP address or hostname of the Homebridge instance | — |
| Port | TCP port of the Homebridge web UI | 8581 |
| Username | Username for the Homebridge web UI | — |
| Password | Password for the Homebridge web UI | — |
| Scan interval | How often (in seconds) HA checks Homebridge connectivity | 30 |

Both connectivity and credentials are validated before saving.

> **Upgrading from v0.1.x?** After updating to v0.2.1, Home Assistant will show an **"Action required"** notification for the Homebridge Monitor integration. Click it to open the re-authentication form and enter your Homebridge username and password. The integration will reload automatically once credentials are saved.

---

## Entities

| Entity | Domain | Device class | Entity category | Description |
|--------|--------|--------------|-----------------|-------------|
| `binary_sensor.<name>_connectivity` | `binary_sensor` | `connectivity` | — | `on` when Homebridge is reachable |
| `update.<name>_homebridge_update` | `update` | `firmware` | — | `on` when a Homebridge core update is available |
| `update.<name>_homebridge_ui_update` | `update` | `firmware` | — | `on` when a Homebridge UI update is available |
| `update.<name>_plugins_update` | `update` | `firmware` | — | `on` when one or more plugin updates are available |
| `button.<name>_update_homebridge_core` | `button` | — | `diagnostic` | Triggers a Homebridge core update (`POST /api/plugins/update/homebridge`) |
| `button.<name>_update_homebridge_ui` | `button` | — | `diagnostic` | Triggers a Homebridge UI update (`POST /api/plugins/update/homebridge-config-ui-x`) |
| `button.<name>_update_homebridge_plugins` | `button` | — | `diagnostic` | Triggers updates for all plugins with pending updates |
| `button.<name>_reauthenticate` | `button` | — | `diagnostic` | Forces a token refresh (if valid) or full re-authentication (if expired/absent) |

### Attributes

#### `binary_sensor.<name>_connectivity`

| Attribute | Description |
|-----------|-------------|
| `host` | Configured host |
| `port` | Configured port |

#### `update.<name>_homebridge_update` and `update.<name>_homebridge_ui_update`

| Attribute | Description |
|-----------|-------------|
| `current_version` | Currently installed version |
| `latest_version` | Latest available version |

#### `update.<name>_plugins_update`

| Attribute | Description |
|-----------|-------------|
| `plugins_with_updates` | List of plugins with updates, each containing the plugin name and its installed and latest versions |

### Diagnostic buttons

The three `button` entities belong to the **Diagnostics** category and are visible in the device's *Diagnostics* card.  
You can also call them from **Developer Tools → Actions** using the standard `button.press` action:

```yaml
action: button.press
target:
  entity_id: button.homebridge_update_homebridge_core
```

Replace `button.homebridge_update_homebridge_core` with any of the three entity IDs listed in the table above.  
When a button is pressed the coordinator logs an `INFO` entry on success or a `WARNING` entry on failure to the Home Assistant log.

### Domain services

The same three update actions are also available as standalone Home Assistant services under the `homebridge_monitor` domain.  
They appear in **Developer Tools → Actions** without needing to know the button entity IDs:

| Service | Description |
|---------|-------------|
| `homebridge_monitor.update_homebridge_core` | Triggers a Homebridge core update (`POST /api/plugins/update/homebridge`) |
| `homebridge_monitor.update_homebridge_ui` | Triggers a Homebridge UI update (`POST /api/plugins/update/homebridge-config-ui-x`) |
| `homebridge_monitor.update_plugins` | Triggers updates for all plugins with pending updates |
| `homebridge_monitor.reauthenticate` | Forces a token refresh (if token still valid) or full re-authentication (if expired/absent) |

Example usage in an automation:

```yaml
action: homebridge_monitor.update_homebridge_core
```

> **Note:** if you have multiple Homebridge instances configured, each service call acts on **all** of them simultaneously.

---

## Automations example

```yaml
automation:
  - alias: "Notify when Homebridge goes offline"
    trigger:
      - platform: state
        entity_id: binary_sensor.homebridge_connectivity
        to: "off"
        for: "00:01:00"
    action:
      - service: notify.mobile_app
        data:
          message: "⚠️ Homebridge is unreachable!"
```

---

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

---

## License

This project is licensed under the [MIT License](LICENSE).

---

<div align="center">

💻 **Proudly developed with GitHub Copilot** 🚀

</div>
