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
- **Token refresh** – the coordinator automatically re-authenticates when the JWT access token expires (HTTP 401), keeping the integration running without manual intervention.
- **Config-flow setup** – configure entirely through the UI; no YAML needed.
- **Live validation** – the setup wizard tests both connectivity and credentials before saving the entry.
- **Reconfigurable connection** – change the host, port and polling interval after setup via the integration's options, with live connectivity validation.
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
| Scan interval | How often (in seconds) HA checks Homebridge connectivity | 30 |

Connectivity to the new address is validated before saving.

---

## Entities

| Entity | Domain | Device class | Description |
|--------|--------|--------------|-------------|
| `binary_sensor.<name>_connectivity` | `binary_sensor` | `connectivity` | `on` when Homebridge is reachable |
| `update.<name>_homebridge_update` | `update` | `firmware` | `on` when a Homebridge core update is available |
| `update.<name>_homebridge_ui_update` | `update` | `firmware` | `on` when a Homebridge UI update is available |
| `update.<name>_plugins_update` | `update` | `firmware` | `on` when one or more plugin updates are available |

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
