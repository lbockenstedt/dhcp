---
summary: "Thin Kea DHCP4 management spoke. Repo: dhcp. moduletype = 'dhcp'. See architecture-topology.md."
keywords: [auto, backends, behaviors, custom_fields, dhcp, dhcp_stats, dhcp_status, dhcp_update_res, kea_url, lm]
---

# dhcp — DHCP (Kea)

Thin Kea DHCP4 management spoke. Repo: `dhcp`. `module_type = "dhcp"`. See [architecture-topology.md](architecture-topology.md).

## Role & module_type

Wraps the Kea Control Agent REST API for subnet/lease/reservation listing and CRUD, plus a NetBox→Kea reservation sync. Minimal/stub-style repo — no installer, no API_SPEC, no root README.

## What it does

The `dhcp` module manages **Kea DHCP4** subnets, active leases, and static reservations for this node, and shows pool utilization at a glance. It's what hands out (or reserves) IP addresses to devices on a site's DHCP-served subnets — configured by hand, or filled in automatically from NetBox prefixes/IPs.

In the WebUI, open a node's **DHCP** module from the sidebar to reach the **Overview**, **Subnets**, **Leases**, and **Reservations** tabs — see the [WebUI](#webui) section below. This Kea instance is the site's real production DHCP server — it is **not** the same Kea used by the `cs` (Simulations) role's client-simulation feature (see Troubleshooting below).

## Entrypoints

`python3 -m src.main` (`DHCPControlPlane`); spoke `DHCPSpoke(BaseSpoke)`. **No install script** in this repo; no systemd unit shipped here.

> **Primarily a role now.** DHCP runs mainly as the **`dhcp`** role hosted by the generic agent (`agent-<hostname>`, unit `lm-agent`): the agent opens a sub-spoke `{agent}-dhcp` (module type `dhcp`, parent-auto-approved) and loads it in-process via `agent/src/agent_spoke.py::_install_role` (this repo is bundled in-tree; the role loader also does the Kea host prep). There is no dedicated `lm-dhcp` unit — the agent role is the standard path; a hand-rolled unit is the only standalone alternative. Config (`KEA_URL`) comes from the hub push (WebUI), not a per-module `.env`. (This module's Kea is the ctrl-agent :8001 instance — distinct from the cs `simulation` role's cs-owned `kea-dhcp4-sim` at :8002.)

## Ports / backends

Talks to the **Kea Control Agent** REST (`KeaManager`, `src/kea_manager.py`) via `requests`. Default `KEA_URL=http://localhost:8001` (deliberately not 8000, to avoid colliding with the hub). Sends Kea JSON commands (`{"command","service":["dhcp4"],"arguments"}`) and returns `arguments` from the first result item. Commands: `subnet4-list`, `config-get`/`config-set`/`config-write` (all subnet/reservation writes go through a read-modify-write of the whole Dhcp4 config), `lease4-get-all`, `statistic-get-all`, `version-get` (health check). No port served.

## Environment variables

`SPOKE_ID`, `SPOKE_SECRET`, `HUB_SECRET`, `HUB_WS`, `KEA_URL` (default `http://localhost:8001`).

## Install flags

None (no installer present).

## Key commands / handlers (`dhcp_spoke.handle_command`)

`GET_VERSION`, `UPDATE_CONFIG` (rebuild manager), `DHCP_STATUS`, `DHCP_LIST_SUBNETS`, `DHCP_LIST_LEASES` (optional `subnet` CIDR filter), `DHCP_LIST_RES`, `DHCP_ADD_RES` (`ip`+`mac`+`subnet_id` required), `DHCP_UPDATE_RES` (delete-then-add), `DHCP_DEL_RES` (by `ip`), `DHCP_SYNC` (`sync(subnets, reservations)` — only-add-missing against existing IPs, best-effort with added/skipped counts), `DHCP_STATS` (`get_stats` via Kea `statistic-get-all` — global + per-subnet pool utilization `{total,assigned,declined,utilization_pct}` and headline packet counters discover/request/offer/ack/nak; relayed by `GET /api/dhcp/stats`).

## High availability (two-node Kea pair)

A DHCP module can drive **two Kea hosts as one real HA pair** rather than two independent servers pointed at the same subnets.

**Shape.** One `dhcp` spoke is the **coordinator**; each Kea host runs an `lm-dhcp-worker` unit that dials the coordinator's `/ws/agent` listener on **8770** (dns uses 8769, so both roles can be co-loaded on one agent). Workers authenticate with a shared PSK and every frame is HMAC-signed. Workers are **not** spokes — tenant routing stays "one tenant → one coordinator".

**The hop is always encrypted AND verified.** Same posture as the DNS cluster: `wss://` by default, remote `ws://` refused, **no unverified mode**, the coordinator certificate provisioned at `/etc/lm-dhcp/tls/` and pinned by each worker via a required `--ca-cert`, and a listener that refuses to bind plaintext on `0.0.0.0`.

**Two control agents, deliberately.** The node-local Kea Control Agent stays on **127.0.0.1:8001, unauthenticated** — only the co-located worker may drive Kea, and publishing it would hand unauthenticated `config-set` rights to anyone who can reach the box. HA peer traffic uses a **separate** `kea-ha-agent` on **:8002** speaking **HTTPS with mutual certificate verification** (`trust-anchor` + `cert-file` + `key-file` + `cert-required`, from `--ha-ca`/`--ha-cert`/`--ha-key` — all mandatory). Basic-auth credentials (`--ha-user`/`--ha-password`) ride **inside** that TLS session; they are never sent over plaintext HTTP. The port is firewalled to the declared partner (`--ha-peer`) with **persistent** rules (`/etc/nftables.d/lm-kea-ha.nft`, or `netfilter-persistent save`) so they survive a reboot. Peer URLs are `https://` and a plaintext `http://` peer URL is rejected. The HA password is written into Kea's config and into `/etc/lm-dhcp/cluster.json` (mode 0600), is carried forward when a re-save omits it, and is **never** returned by `/api/dhcp/ha` or the diagnostics payload.

**The worker is not a generic agent.** Fixed op table: `KEAW_INSTALL_HOOKS`, `KEAW_GET_CONFIG`, `KEAW_VALIDATE`, `KEAW_APPLY`, `KEAW_ROLLBACK`, `KEAW_STANDDOWN`, `KEAW_HA_STATUS`, `KEAW_STATUS`, `KEAW_LIST_SUBNETS`, `KEAW_LIST_LEASES`, `KEAW_LIST_RES`, `KEAW_DIAGNOSTICS`, `KEAW_STATS`. The only shell command it can run is a fixed, argument-free `apt-get install -y kea-common` (the hook libraries ship in **kea-common**; there is no `kea-hooks` package). The hook directory is resolved on the node — the multiarch triplet differs per architecture.

**What "a real pair" means here.**

- Both nodes load `libdhcp_lease_cmds.so` **and** `libdhcp_ha.so`, in that order — the HA hook synchronises leases *through* lease_cmds, so a pair without it fails over to an empty lease database.
- Both nodes carry the **identical** `subnet4` block (same pools, reservations and option data), generated once by the coordinator from one shared intent (`build_subnet4`). Two nodes computing their own scopes is how a "HA pair" ends up handing out overlapping addresses.
- Each node's config is rendered **on top of that node's own running configuration** (`KEAW_GET_CONFIG`). Only the coordinator-owned keys (`subnet4`) and the HA hook entries are replaced; interfaces, lease database, loggers, client classes and unrelated hooks survive verbatim. A node whose config cannot be read aborts the whole transaction — rendering from `{}` would wipe it.
- Each node gets its own `this-server-name` and a peer list where every peer has a distinct control-agent URL. A topology that is not exactly two distinctly-named, distinctly-addressed servers is **rejected before anything is written**.
- **hot-standby is the only supported mode.** `load-balancing` is **rejected**: it requires each subnet's pool to be split between the two servers by client class (`HA_server1`/`HA_server2`), and `build_subnet4` emits one undivided pool per subnet — both servers would allocate from the same range. The API answers `ERROR` with `supported_modes: ["hot-standby"]`, and the UI offers no other option. An old `cluster.json` naming load-balancing is coerced to hot-standby with a loud warning rather than bricking the spoke. Peer roles are `primary`/`standby`.

**Apply is a serialized transaction.** Install hooks on both → read both configs → `config-test` **both** candidates → apply the standby/secondary, then the primary. A hook, read or validation failure on any node means **nothing** is applied. Concurrent syncs are serialized under one lock, so one transaction's validate can never interleave with another's apply.

A worker distinguishes the two apply failures that matter: `config-set` rejected (node **untouched**) versus `config-set` accepted but `config-write` failed (the node is **already running** the new config, unpersisted). In the second case the worker restores its snapshot locally and immediately; if that restore also fails it answers `PARTIAL` with `mutated: true`. The coordinator rolls back every **possibly-mutated** node — including the one that just failed — and reports `ERROR` when everything was restored, `PARTIAL` when a node may still hold the new config. No path returns `SUCCESS` for a half-applied pair.

**Enabling is one transaction.** Validate → persist topology → bind the listener → stand down removed nodes all run under the same lock every config apply takes, and the listener is **awaited**: if it does not come up (no cert, port in use) the call returns `ERROR` with the reason and the topology is rolled back.

**The candidate is journalled before it is applied.** `/var/lib/lm-dhcp/desired.json` carries the committed intent plus a `pending` block written **before** the first node is touched. Nothing is applied if that journal write fails. On success the committed record is promoted and the journal cleared. If the promote write fails **both nodes are rolled back** (a pair running a version the coordinator cannot remember is worse than no change). The journal is cleared **only after every touched node confirmed its restore** — if any node could not be rolled back the `pending` block is retained and records which node may still be holding the candidate. A restart that finds one reports it by name, marks the HA report unhealthy, and recommends a re-apply. A failed transaction leaves the previous committed intent untouched, so it cannot poison a later mutation.

**Reservation edits are read-modify-write under the transaction lock.** Computing the new list before taking the lock let two concurrent edits start from the same base and silently drop one. On a single-host install `update_reservation` is likewise **one** `config-set`: removing the old entry in one write and adding the replacement in a second meant a failure between them dropped the reservation entirely and the host fell back to a dynamic lease.

**Status.** `status-get` from both nodes is normalised into per-node HA state, scopes, partner state/`in-touch`, communication-interrupted and unacked clients, plus a shared-config digest per node so scope/reservation drift between the two is detected. Convergence is a **positive** claim: it needs a fresh, non-empty digest from **every** member, so a node that stops reporting drops its remembered digest and the pair reads `UNKNOWN`, never "matched". Module telemetry is `HEALTHY` only when both nodes are in sync **and** their configs match.

**Configure it.** DHCP → **Diagnostics** → *Configure HA pair* (Global Admin), or `POST /api/dhcp/ha` with `{"members": [{"id","host","ha_user","ha_password"}, …], "worker_secret": "…"}`. The worker secret **and** the per-node HA control credentials are required to enable a pair — the HA control agent rejects an unauthenticated peer, so a pair configured without them would come up looking configured and never heartbeat. Both are write-only: omit them on a re-save and the stored values are carried forward; omit them on a FIRST enablement and the request is refused naming the nodes that lack them. A rolled-back change also restores the previous worker PSK, so already-provisioned Kea workers keep authenticating.

**Each cluster role serves its own certificate.** On a generic agent hosting both cluster roles, the dhcp listener uses `/etc/lm-dhcp/tls` (overridable via `LM_DHCP_TLS_CERT`/`LM_DHCP_TLS_KEY`) and never inherits the dns role's. Then install each Kea host with the same value:

```
sudo bash install_dhcp.sh --member-id kea-a --coordinator <coordinator-host> --worker-secret <secret>
```

Add `--ca-cert <coordinator cert>` (required), `--ha-user`/`--ha-password` (required), `--ha-ca`/`--ha-cert`/`--ha-key` (required — the HA channel is mutually-verified HTTPS) and `--ha-peer <partner-ip>`. `--stand-down` reverses it and runs **before** the `--hub` check, so a node being removed from a pair does not have to name a hub it no longer belongs to. That installs Kea + the hook libraries from `kea-common`, stands up the HTTPS HA control agent on :8002 with persistent firewall rules scoped to the partner (the node-local :8001 agent stays loopback-only), and lays down the `lm-dhcp-worker` unit. It implies `--infra-only`. `--stand-down` reverses it: the worker and HA agent are stopped and the firewall rules removed. The coordinator install creates `/etc/lm-dhcp`, `/var/lib/lm-dhcp` and `/etc/lm-dhcp/tls` owned by `svc_lm` and mints a coordinator certificate. Unloading the `dhcp-server` deploy role also stops `lm-dhcp-worker` and `kea-ha-agent`. Without an HA pair configured the module behaves exactly as a single-host install: no listener is bound and every operation goes to the local `KeaManager`.

**See it.** DHCP → **Diagnostics** grows a *Kea HA pair* panel (per-node role, health, HA state, partner state, scopes, config digest) plus each node's own diagnostics findings, and a *Re-apply configuration to both nodes* action. `GET /api/dhcp/ha` returns the same report; Settings → Diagnostics carries a one-line summary. A non-admin sees the verdict but not node addressing or error text.


## NetBox auto-sync (source of truth)

NetBox is the IPAM source of truth. The hub's `DnsDhcpSyncMixin` (`core/src/dns_dhcp_sync.py`) reconciles Kea to NetBox on a periodic loop (`run_dns_dhcp_sync_loop`, `global_config.dns_dhcp_sync` `{enabled` default true`, interval` default 300s`}`) — a prefix/reservation added in NetBox lands in Kea without pressing **Sync now**. The loop and the on-demand `POST /api/dhcp/sync` share the same extraction helper (`build_dhcp_payload`), so button and loop never diverge. Only-add-missing (idempotent); skips quietly when NetBox/DHCP spokes are offline. Per-run status at `GET /api/dns-dhcp/sync-status`.

## WebUI

Module view tabs: **Overview** (pool-utilization / assigned-leases / packet-counter stat tiles + per-scope utilization bars + last-auto-sync line), **Subnets**, **Leases**, **Reservations**.

## Key files

`src/main.py`, `src/dhcp_spoke.py`, `src/kea_manager.py`, `src/__init__.py` (empty), `.env.template`, `requirements.txt` (`websockets, requests, python-dotenv`), `VERSION`.

## Notable behaviors & gotchas

- **`KEA_URL` default is :8001** (chosen specifically so it doesn't collide with the hub) — but a co-located install (Kea sharing a box with NetBox, a legacy webui-spoke, or a custom Kea CA port such as the netbox `install_kea.sh` convention of :8760) may still need `KEA_URL` overridden via hub push to match wherever that box's Kea Control Agent actually listens. A mismatched `KEA_URL` shows up as `DHCP_STATUS`/`DHCP_STATS` failing to reach Kea and empty Subnets/Leases/Reservations tabs.
- **Only spoke of this group with no FastAPI dep** (`requirements.txt` lacks `fastapi`/`uvicorn`) — a pure spoke.
- **Kea error handling** — `result != 0` raises `RuntimeError(result.text)`; `_cmd` returns `arguments` only.

## How it works

- **Where it runs.** Standard path: the **`dhcp`** role on the generic agent (unit `lm-agent`) opens a sub-spoke `{agent}-dhcp` (parent-auto-approved) and loads this repo in-process via `agent_spoke.py::_install_role`. Rare alternative: a hand-rolled `lm-dhcp` unit running `python3 -m src.main` (`DHCPControlPlane`) standalone.
- **Config delivery.** The hub pushes config with `UPDATE_CONFIG` (rebuilds the `KeaManager` with the configured Kea Control Agent URL) — there's no per-module `.env` to hand-edit on the box; the `KEA_URL` env var is only the fallback default before a push arrives.
- **IMPORTANT — two separate Kea instances.** This module's Kea is the site's real production Kea DHCP4 server, reached via its Control Agent at `KEA_URL` (current code default `http://localhost:8001`). This is **completely distinct** from the `cs` (Simulations) role's own Kea instance, `kea-dhcp4-sim`, whose Control Agent listens on `127.0.0.1:8002` and which only serves the simulated-client network `169.253.1.0/24` for auto-provisioning test VMs. The `dhcp` module never talks to `:8002`, and the simulation Kea is never involved in real subnet/lease/reservation management. Don't point one at the other's port.
- **Command flow.** WebUI/hub issues one command at a time: `GET_VERSION`, `UPDATE_CONFIG`, `DHCP_STATUS`, `DHCP_LIST_SUBNETS`, `DHCP_LIST_LEASES` (optional `subnet` filter), `DHCP_LIST_RES`, `DHCP_ADD_RES`, `DHCP_UPDATE_RES`, `DHCP_DEL_RES`, `DHCP_SYNC`, `DHCP_STATS`.
- **How subnets/reservations are actually written.** `KeaManager` talks Kea's JSON command protocol over HTTP to the Control Agent, unwraps the (possibly list-wrapped) response, and raises if `result != 0`. Every subnet/reservation write does `config-get` → mutates the in-memory `Dhcp4` config dict → `config-set` + `config-write` (the latter persists to Kea's on-disk config so it survives a Kea restart, not just a live reload).
- **`DHCP_SYNC` in detail.** Builds one `subnet4` object per prefix (gateway/DNS servers become Kea `option-data`; if no explicit pool is supplied, defaults to `.10`–`.254`); attaches only the reservations whose `subnet` field matches or whose IP falls inside that subnet; silently skips (not fails) any reservation missing `ip`/`mac` or with an unparsable IP, so one bad record doesn't sink the whole sync; then does a single `config-set` + `config-write` for everything.
- **`DHCP_UPDATE_RES` is genuinely non-atomic** — it's two separate Kea round trips: first `config-get`/`config-set`/`config-write` to remove the old reservation from every subnet, then a second `config-get`/`config-set`/`config-write` (via `add_reservation`) to add the new one. If something fails between the two calls, the reservation can be briefly (or permanently, if the second call fails) missing from Kea.
- **NetBox auto-sync loop** (see the section above): `build_dhcp_payload` (`core/src/dns_dhcp_sync.py`) turns NetBox prefixes into subnet definitions (`gateway`/`dns_servers` from prefix custom fields) and mints one reservation per IP carrying `custom_fields.mac_address`; shared by the loop (default 300s) and `POST /api/dhcp/sync` so they can never diverge. Only-add-missing (compares against existing IPs already in Kea); skips quietly when NetBox or the DHCP spoke is offline. Status at `GET /api/dns-dhcp/sync-status`.
- **Stats source in detail.** `DHCP_STATS` calls Kea's `statistic-get-all`, takes the newest sample of each pool/assignment counter, computes per-subnet and global `utilization_pct` (`assigned / total`), and surfaces headline packet counters (`pkt4_received`, `pkt4_discover`, `pkt4_request`, `pkt4_offer_sent`, `pkt4_ack_sent`, `pkt4_nak_sent`) — this is exactly what feeds the Overview tab's tiles and per-scope utilization bars. When the Kea Control Agent is unreachable, `get_stats` returns a `SUCCESS`/idle shape (`kea_running: false` + a note) instead of an error, so the Overview tile renders empty stats rather than a red error.

## How to use it

- **Add a reservation:** DHCP module → **Reservations** tab → Add → `subnet_id`, `ip`, and `mac` are required; `hostname` optional. `DHCP_ADD_RES` writes it straight into Kea's live config.
- **Edit a reservation:** use the update action — `DHCP_UPDATE_RES` needs `old_ip`, `subnet_id`, `ip`, and `mac`. Remember this is two separate Kea config pushes (remove, then add); re-check the tab if something looked off mid-edit.
- **Delete a reservation:** Reservations tab → delete action → `DHCP_DEL_RES` (by IP).
- **View subnets/pools:** **Subnets** tab (`DHCP_LIST_SUBNETS`).
- **View active leases:** **Leases** tab, optionally filtered by subnet (`DHCP_LIST_LEASES`).
- **Let NetBox drive it instead:** add/edit a prefix (set `custom_fields.gateway`/`dns_servers` as needed) and set `custom_fields.mac_address` on an IP — the periodic auto-sync loop (default every 300s) mints the subnet and/or reservation in Kea with no manual step.
- **Force an immediate reconcile:** **Overview** tab → **Sync now** (`POST /api/dhcp/sync` → `DHCP_SYNC`). Only adds what NetBox has that Kea doesn't — never removes.
- **Read pool health:** **Overview** tab — utilization / assigned-leases / packet-counter tiles, per-scope utilization bars, and a last-auto-sync line.

## Troubleshooting / common questions

- **"Subnets/Leases/Reservations tabs are empty even though Kea is running."** Check `KEA_URL` — the Kea Control Agent address this `dhcp` role/spoke is configured with — is actually reachable from the node. Current code defaults to `http://localhost:8001` specifically so it won't collide with the hub, but a box also running NetBox, a legacy webui-spoke, or a custom Kea CA port (e.g. :8760 per the netbox `install_kea.sh` convention) needs `KEA_URL` pushed/set to match. A wrong or unreachable `KEA_URL` surfaces as Kea-unreachable errors in `DHCP_STATUS`/`DHCP_STATS`, and empty lists everywhere else (`list_subnets`/`list_reservations` both swallow errors and return `[]`).
- **"I added a reservation/prefix in NetBox but it's not showing up in Kea."** Same NetBox → Kea auto-sync loop as DNS (default every 300s). An IP needs `custom_fields.mac_address` set to mint a reservation, and a prefix must exist for a subnet to be created. Check `GET /api/dns-dhcp/sync-status` for the last run's `subnets_synced`/`reservations_synced` counts and whether it was `skipped` (NetBox or DHCP spoke offline) or `error`. Or just press **Sync now** instead of waiting.
- **"The DHCP module shows offline/red in the WebUI."** The `{agent}-dhcp` sub-spoke isn't connected — check the node's `lm-agent` unit first, since the `dhcp` role rides on it and is loaded in-process (an agent-wide outage takes DHCP down with it). A standalone `lm-dhcp` unit (rare) would be its own separate failure point.
- **"Is this the same Kea used by the client/USB simulation feature (`cs` module)?"** No. This `dhcp` module manages the site's real Kea DHCP4 server via its Control Agent (`KEA_URL`, code default `:8001`). The `cs` (Simulations) role runs its own separate Kea instance, `kea-dhcp4-sim`, with its Control Agent on `127.0.0.1:8002`, serving only the simulated-client network `169.253.1.0/24` for auto-provisioning test VMs. They're independent Kea processes/configs, even on the same host — never point one module's `KEA_URL` at the other's port.
- **"A reservation update seems to have briefly disappeared, or a device got a different IP right after I updated its reservation."** `DHCP_UPDATE_RES` is delete-then-add — two separate Kea config pushes (remove the old reservation from every subnet, then add the new one). If a lease was already active in that gap, or the second push failed, re-check the Reservations tab and re-apply if the new entry didn't take.
- **"Pool utilization shows 0%, or stats look wrong right after adding subnets."** `DHCP_STATS` reads Kea's `statistic-get-all`, which only reports counters for subnets that already exist in Kea's live config. Run (or wait for) a sync first — manual add, **Sync now**, or the NetBox auto-sync loop — so the subnet actually exists in Kea, then re-check.

## Related pages

[architecture-topology.md](architecture-topology.md), [netbox.md](netbox.md) (NetBox→Kea scope sync), [install-flags.md](install-flags.md).