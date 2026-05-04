# Homebridge Monitor

[![hacs_badge](https://img.shields.io/badge/HACS-Custom-41BDF5.svg)](https://github.com/hacs/integration)
[![GitHub release](https://img.shields.io/github/v/release/Geek-MD/Homebridge_Monitor)](https://github.com/Geek-MD/Homebridge_Monitor/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

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