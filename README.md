# dhcp — Kea DHCP spoke (LM module)

<!-- INSTALLERS:START -->
## Installation

This repo holds the Kea DHCP spoke **source only** — it ships no installer of its own.
Install it one of two ways.

### As an agent role (preferred)

Load the `dhcp` role onto a generic LM agent from the hub WebUI, or pre-load it at install time:

```bash
curl -sSL https://raw.githubusercontent.com/lbockenstedt/lm/main/agent/install_agent.sh \
  | sudo bash -s -- --hub lm-hub.lrbtechnologies.com --roles dhcp
```

### Standalone, via the lm repo

```bash
sudo bash /opt/lm/dhcp/install_dhcp.sh --hub lm-hub.lrbtechnologies.com
```

| Flag | Purpose |
| :--- | :--- |
| `--hub URL` | Hub WebSocket URL. |
| `--id` | Pin the spoke id. |
| `--secret` | Pre-shared spoke secret. |
| `--infra-only` | Host-level infrastructure only — no spoke runtime. |

> A second copy of this source also lives at `lm/dhcp/`. The two drift deliberately; don't delete either.
<!-- INSTALLERS:END -->
