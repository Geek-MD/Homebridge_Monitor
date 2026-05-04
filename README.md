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
- **Config-flow setup** – configure entirely through the UI; no YAML needed.
- **Live validation** – the setup wizard tests connectivity before saving the entry.
- **Adjustable polling interval** – change how often HA checks Homebridge via the integration's options (5 – 3600 seconds, default 30 s).
- **Device entry** – groups the sensor under a _Homebridge_ device with a direct link to the Homebridge web UI.
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
4. Click **Submit**. Home Assistant will verify the connection before saving.

### Options

After setup, click **Configure** on the integration card to adjust:

| Option | Description | Default |
|--------|-------------|---------|
| Scan interval | How often (in seconds) HA checks Homebridge connectivity | 30 |

---

## Entities

| Entity | Domain | Device class | Description |
|--------|--------|--------------|-------------|
| `binary_sensor.<name>_connectivity` | `binary_sensor` | `connectivity` | `on` when Homebridge is reachable |

### Attributes

| Attribute | Description |
|-----------|-------------|
| `host` | Configured host |
| `port` | Configured port |

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
