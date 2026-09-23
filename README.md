# dhcp — Kea DHCP Spoke (Lab Manager Module)

The `dhcp` module is the authoritative ISC Kea DHCPv4/v6 management spoke for the Lab Manager (LM) ecosystem. It provides automated subnet and pool management, static host reservations, real-time lease inspection, live utilization statistics, and high-availability (HA) clustering across redundant Kea daemon instances.

---

## Architecture

The spoke couples the Lab Manager control plane with ISC Kea DHCP servers through a multi-tier, fail-closed management hierarchy:

```
                  ┌────────────────────────┐
                  │    Lab Manager Hub     │
                  │   (REST API / WebUI)   │
                  └───────────┬────────────┘
                              │ WebSocket (Port 443)
                              ▼
                  ┌────────────────────────┐
                  │  DHCP Spoke / Cluster  │
                  │   Coordinator Instance │
                  └──────┬──────────┬──────┘
                         │          │ Mutual TLS / RPC
                         ▼          ▼
            ┌────────────────┐  ┌────────────────┐
            │  DHCP Worker   │  │  DHCP Worker   │
            │  (Node Primary)│  │  (Node Standby)│
            └───────┬────────┘  └───────┬────────┘
                    │ REST              │ REST
                    ▼ (Port 8001)       ▼ (Port 8001)
            ┌────────────────┐  ┌────────────────┐
            │ Kea Ctrl Agent │  │ Kea Ctrl Agent │
            │ (kea-dhcp4)    │  │ (kea-dhcp4)    │
            └────────────────┘  └────────────────┘
```

1. **Kea DHCP Control Agent & Daemon:**
   - ISC Kea `kea-dhcp4` daemon provides line-rate DHCP lease assignment.
   - ISC Kea Control Agent (`kea-ctrl-agent`) provides a local REST API (defaulting to port `8001` to prevent collisions with the LM hub on `8000`).
2. **Worker Tier (`dhcp_worker.py`):**
   - Headless node agent daemon operating directly on each Kea host.
   - Handles localized config staging, hook verification, atomic JSON schema validation (`config-test`), and safe rollbacks.
3. **Cluster Coordinator (`kea_cluster.py` & `dhcp_spoke.py`):**
   - Coordinates multi-member Kea HA pairs (Hot-Standby mode).
   - Enforces two-phase atomic configuration deployment across both cluster nodes.
   - Manages mutual TLS certificates and private keys via embedded local PKI (`ha_pki.py`).
4. **Fail-Closed Desired State:**
   - Cluster configuration changes follow a strictly transactional prepare-and-commit protocol.
   - If either member fails validation or application, both nodes automatically roll back to the previously active configuration.
   - Prevents split-brain and maintains persistent configuration cached on disk to survive network or daemon restarts.

---

## Features

- **Subnet & CIDR Management:** Dynamic creation, modification, and pruning of IPv4 subnet scopes.
- **Dynamic Address Pools:** Configurable allocation ranges (e.g., `.10` to `.254`) per subnet with automatic sanity checking against reserved ranges.
- **Static Host Reservations:** IP-to-MAC host reservations with optional hostnames. Automatically purges active dynamic leases when converting a lease to a static reservation to prevent IP collisions.
- **Rich DHCP Options:** Configurable standard DHCP options including default gateways (`routers`), DNS servers (`domain-name-servers`), domain search lists, and MTU.
- **Live Lease Inspection & Diagnostics:** Inspect active leases per subnet or fleet-wide, remove orphaned leases, and view interface binding states.
- **Real-Time Statistics:** Live packet accounting (`pkt4_received`, `pkt4_discover`, `pkt4_request`, `pkt4_offer_sent`, `pkt4_ack_sent`, `pkt4_nak_sent`) and continuous per-pool utilization percentages.
- **High-Availability (HA) Clustering:** Built-in multi-member hot-standby clustering with heartbeat tracking, automated failover state monitoring, and automated mTLS certificate rotation.

---

## Spoke Commands Reference

The spoke communicates with the Lab Manager hub over an authenticated WebSocket connection. The following commands are handled by `dhcp_spoke.py`:

| Command | Arguments | Description |
| :--- | :--- | :--- |
| `GET_VERSION` | None | Returns the current running version and commit metadata of the spoke. |
| `DHCP_STATUS` | None | Returns operational status, active member count, serving state, and Kea health. |
| `DHCP_STATS` | None | Queries Kea `statistic-get-all` for packet metrics and pool utilization percentages. |
| `DHCP_LIST_SUBNETS`| None | Returns all configured IPv4 subnet scopes and option parameters. |
| `DHCP_LIST_LEASES` | `subnet` *(optional)* | Lists active dynamic leases, optionally filtered by subnet CIDR or ID. |
| `DHCP_DEL_LEASE` | `ip` | Evicts an active lease by IP address across cluster members. |
| `DHCP_LIST_RES` | None | Returns all static host reservations configured across subnets. |
| `DHCP_ADD_RES` | `subnet_id`, `ip`, `mac`, `hostname` | Creates a new static host reservation and flushes conflicting active leases. |
| `DHCP_UPDATE_RES` | `old_ip`, `subnet_id`, `ip`, `mac`, `hostname` | Updates an existing reservation across Kea configurations. |
| `DHCP_DEL_RES` | `ip` | Deletes a static reservation by assigned IP address. |
| `DHCP_SYNC` | `subnets`, `reservations` | Full desired-state synchronization pushing entire scopes and reservations atomically. |
| `DHCP_DIAGNOSTICS` | None | Returns systemd service status, daemon logs, hook statuses, and process sanity. |
| `DHCP_HA_CONFIG` | `enabled`, `mode`, `members`, `pki` | Configures or updates multi-member HA clustering topology. |
| `DHCP_HA_STATUS` | None | Returns detailed cluster HA heartbeat states, peer connectivity, and role status. |
| `DHCP_HA_APPLY` | None | Re-applies the last-known desired state across all cluster members. |
| `DHCP_HA_ENROLL_WORKERS` | `workers` | Pre-stages worker enrollment credentials and certificates for new HA nodes. |
| `DHCP_HA_COMMIT_ENROLLMENT`| None | Finalizes worker enrollment and activates the updated cluster topology. |

---

## Worker Operations Reference

The worker tier daemon (`dhcp_worker.py`) executes localized commands on behalf of the cluster coordinator:

| Operation | Arguments | Description |
| :--- | :--- | :--- |
| `KEAW_STATUS` | None | Returns worker daemon state, host info, and local Kea service reachability. |
| `KEAW_GET_CONFIG` | None | Retrieves current live `kea-dhcp4` configuration JSON from local Kea. |
| `KEAW_VALIDATE` | `config` | Validates proposed Kea configuration syntax using Kea's config verification RPC. |
| `KEAW_APPLY` | `config`, `backup` | Stages new configuration, updates disk persistence, and reloads daemon. |
| `KEAW_ROLLBACK` | `backup` | Reverts Kea daemon configuration to previous known-good backup. |
| `KEAW_STANDDOWN` | None | Puts node into standby mode, stopping active lease issuance. |
| `KEAW_HA_STATUS` | None | Inspects local Kea HA hook library status, peer heartbeats, and failover state. |
| `KEAW_INSTALL_HOOKS` | `hooks` | Verifies and configures required Kea C++ hook libraries (`libdhcp_ha.so`, etc.). |
| `KEAW_LIST_SUBNETS`| None | Fetches locally configured subnets directly from Kea config memory. |
| `KEAW_LIST_LEASES` | `subnet` *(optional)* | Queries local Kea lease database for current active lease allocations. |
| `KEAW_LIST_RES` | None | Lists static reservations configured on the local Kea instance. |
| `KEAW_DEL_LEASE` | `ip` | Evicts an active lease directly from the local Kea lease storage. |
| `KEAW_DIAGNOSTICS` | None | Captures local daemon unit status, journal entries, and system resource metrics. |
| `KEAW_STATS` | None | Gathers raw performance and packet statistics from local Kea daemon. |

---

<!-- INSTALLERS:START -->
## Installation

This repo holds the Kea DHCP spoke **source only** — it ships no standalone installer package of its own. Install it using one of the following methods:

### As an Agent Role (Recommended)

Load the `dhcp` role onto a generic Lab Manager agent from the hub WebUI, or pre-load it at install time:

```bash
curl -sSL https://raw.githubusercontent.com/lbockenstedt/lm/main/agent/install_agent.sh \
  | sudo bash -s -- --hub lm-hub.lrbtechnologies.com --roles dhcp
```

### Standalone via LM Repository

To install as a dedicated systemd service on a standalone host:

```bash
sudo bash /opt/lm/dhcp/install_dhcp.sh --hub lm-hub.lrbtechnologies.com
```

| Flag | Purpose |
| :--- | :--- |
| `--hub URL` | Hub WebSocket URL (e.g. `wss://lm-hub.example.com:443`). |
| `--id` | Pin the spoke unique identifier. |
| `--secret` | Pre-shared spoke authentication secret. |
| `--infra-only` | Install host-level Kea packages and configuration only — no spoke runtime. |

> A mirrored copy of this source also lives at `lm/dhcp/`. The two drift deliberately; do not delete either.
<!-- INSTALLERS:END -->
