[![Geek-MD - Homebridge Monitor](https://img.shields.io/static/v1?label=Geek-MD&message=Homebridge%20Monitor&color=blue&logo=github)](https://github.com/Geek-MD/Homebridge_Monitor)
[![Stars](https://img.shields.io/github/stars/Geek-MD/Homebridge_Monitor?style=social)](https://github.com/Geek-MD/Homebridge_Monitor)
[![Forks](https://img.shields.io/github/forks/Geek-MD/Homebridge_Monitor?style=social)](https://github.com/Geek-MD/Homebridge_Monitor)

[![GitHub Release](https://img.shields.io/github/release/Geek-MD/Homebridge_Monitor?include_prereleases&sort=semver&color=blue)](https://github.com/Geek-MD/Homebridge_Monitor/releases)
[![License](https://img.shields.io/badge/License-MIT-blue)](#license)
![HACS Custom Repository](https://img.shields.io/badge/HACS-Custom%20Repository-blue)
[![Ruff](https://github.com/Geek-MD/Homebridge_Monitor/actions/workflows/ci.yaml/badge.svg?branch=main&label=Ruff)](https://github.com/Geek-MD/Homebridge_Monitor/actions/workflows/ci.yaml)

# Homebridge Monitor

Homebridge Monitor is a Home Assistant custom integration that monitors a Homebridge instance and its installed plugins for available updates. It exposes binary sensors that indicate whether updates are available for Homebridge core, Homebridge UI, Node.js, and individual plugins.

- Domain: `homebridge_monitor`
- Platforms: `binary_sensor`
- Integration type: Config Flow (UI setup — no YAML required)

---

## ✨ Features

- Detects available updates for:
  - Homebridge core
  - Homebridge UI (detected among plugins)
  - Node.js
  - Installed Homebridge plugins (dynamic)
- One binary sensor per monitored component: `on` when an update is available.
- Plugin entities are created and removed dynamically when the plugin list on Homebridge changes.
- Handles token-based authentication and attempts automatic token refresh when supported.
- Exposes extra attributes with current/latest version and package information for each entity.
- Configurable verify-ssl and swagger path.

---

## 🛠 Installation

### Option 1: HACS (recommended)
1. In HACS go to **Integrations → Custom repositories**.  
2. Add repository URL:  
   ```
   https://github.com/Geek-MD/Homebridge_Monitor
   ```
   and choose category **Integration**.  
3. Install the integration from HACS.  
4. Restart Home Assistant.  
5. Configure the integration via Settings → Devices & Services → Add Integration → "Homebridge Monitor".

### Option 2: Manual
1. Copy the folder `custom_components/homebridge_monitor` into:
   ```
   /config/custom_components/homebridge_monitor/
   ```
2. Restart Home Assistant.  
3. Configure the integration via Settings → Devices & Services → Add Integration → "Homebridge Monitor".

---

## ⚙️ Configuration

Configured through the Home Assistant UI (Integrations).

Required:
- Host — IP or hostname of the Homebridge instance. You may provide:
  - full URL (including scheme) e.g. `https://homebridge.example.com`
  - or `host:port` (if scheme omitted, `http://` is assumed)

Optional:
- Swagger Path — path to swagger descriptor (default `/swagger`). Leading slash will be normalized automatically.
- Verify SSL — whether to verify TLS certificates when using HTTPS (default `true`).
- Token — if your Homebridge instance uses token-based auth, provide token here. The integration stores token expiry and attempts refresh when available.

Behavior:
- If a refresh endpoint is available, the integration will attempt to refresh tokens before expiry.
- On refresh/auth failure the integration will trigger a re-auth flow to prompt the user to reauthenticate.

---

## Entities

Sensors follow the naming pattern `binary_sensor.homebridge_monitor_<component_key>`.

Component keys:
- `homebridge` — Homebridge core
- `ui` — Homebridge UI (if detected)
- `node` — Node.js
- `<plugin_name>::<package>` — plugin entries built from plugin display name and package

Each entity exposes attributes:
- `current_version` — installed version (string or null)
- `latest_version` — latest available version (string or null)
- `source` — `homebridge`, `ui`, `node`, or `plugin`
- plugin-specific attributes:
  - `plugin` — display name
  - `package` — package/npm name

Example entity IDs:
- `binary_sensor.homebridge_monitor_homebridge`
- `binary_sensor.homebridge_monitor_ui`
- `binary_sensor.homebridge_monitor_node`
- `binary_sensor.homebridge_monitor_myplugin::my.package`

---

## 🔧 Development

Developer tooling used in CI — pin these locally for consistent results.

- Ruff (linter/formatter): ruff==0.14.3  
  Usage:
  ```
  python -m pip install "ruff==0.14.3"
  ruff check custom_components/homebridge_monitor --fix
  ```

- Mypy (type checking): mypy==1.10.0  
  Usage:
  ```
  python -m pip install "mypy==1.10.0"
  mypy --config-file mypy.ini custom_components/homebridge_monitor
  ```

- Home Assistant stubs (optional, recommended for typing):
  ```
  python -m pip install homeassistant-stubs
  ```

- Hassfest validation (CI uses the official action). You can run hassfest in CI; local usage requires the hassfest tool.

Development recommendations:
- Keep imports grouped and ordered (stdlib → third-party → homeassistant → local) to satisfy Ruff/isort.
- Avoid side-effects at module import time — use lazy imports for Home Assistant-dependent imports when appropriate.
- Use DataUpdateCoordinator for polling and centralizing API calls and error handling.
- Keep entity unique IDs stable.

---

## 🧪 Testing & CI

This repository includes a CI workflow that runs:
- Ruff linting (pinned version)
- Mypy type checks
- Hassfest validation

Run them locally before creating a PR to ensure parity with CI.

---

## 🐛 Troubleshooting

- No entities appear:
  - Verify `host`/URL is reachable from Home Assistant.
  - Check Homebridge API endpoints (version, node, plugins, swagger, auth).
- Authentication / token issues:
  - If token expired or refresh fails the integration triggers re-auth — follow the UI prompts.
- Ruff / CI differences:
  - Ensure you run the same ruff version locally as CI (see Development).
- If you see type warnings from mypy, run with the provided mypy.ini to reproduce CI results.

---

## 💡 Example Use Cases

- Alert when Homebridge core has an available update.
- Notify when Node.js on the Homebridge host has an update.
- Monitor specific plugins and show update availability per-plugin.
- Combine with automations to notify maintainers or schedule maintenance windows.

---

## 📜 License

MIT License — see [LICENSE](LICENSE) for details.

---

## 🤝 Contributing

Contributions welcome! Please:
1. Open an issue for bugs/feature requests.  
2. Fork the repository and create a feature branch.  
3. Run ruff and mypy locally and ensure hassfest validation passes.  
4. Create a pull request with tests / description of changes.

---

## Changelog

See GitHub Releases for a history of changes and release notes.
