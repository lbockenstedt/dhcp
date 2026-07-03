# dhcp — DHCP (Kea)

Thin Kea DHCP4 management spoke. Repo: `dhcp`. `module_type = "dhcp"`. See [architecture-topology.md](architecture-topology.md).

## Role & module_type

Wraps the Kea Control Agent REST API for subnet/lease/reservation listing and CRUD, plus a NetBox→Kea reservation sync. Minimal/stub-style repo — no installer, no API_SPEC, no README.

## Entrypoints

`python3 -m src.main` (`DHCPControlPlane`); spoke `DHCPSpoke(BaseSpoke)`. **No install script** in this repo; no systemd unit shipped here.

## Ports / backends

Talks to the **Kea Control Agent** REST (`DHCPManager`, `src/dhcp_manager.py`) via `httpx`. Default `KEA_URL=http://localhost:8000`. Sends Kea JSON commands (`{"command","service":["dhcp4"],"arguments"}`) and returns `arguments` from the first result item. Commands: `subnet4-list`, `lease4-get-all`, `reservation-get-all`, `reservation-add`, `reservation-del`, `status-get`. No port served.

## Environment variables

`SPOKE_ID`, `SPOKE_SECRET`, `HUB_SECRET`, `HUB_WS`, `KEA_URL` (default `http://localhost:8000`).

## Install flags

None (no installer present).

## Key commands / handlers (`dhcp_spoke.handle_command`)

`GET_VERSION`, `UPDATE_CONFIG` (rebuild manager), `DHCP_STATUS`, `DHCP_LIST_SUBNETS`, `DHCP_LIST_LEASES` (optional `subnet_id`), `DHCP_LIST_RES`, `DHCP_ADD_RES` (`ip`+`mac`+`subnet_id` required), `DHCP_UPDATE_RES` (delete-then-add), `DHCP_DEL_RES` (by `ip` or `mac`+`subnet_id`), `DHCP_SYNC` (`sync(subnets, reservations)` — only-add-missing against existing IPs, best-effort with added/skipped counts).

## Key files

`src/main.py`, `src/dhcp_spoke.py`, `src/dhcp_manager.py`, `src/__init__.py` (empty), `.env.template`, `requirements.txt` (`websockets, httpx, python-dotenv`), `VERSION`.

## Notable behaviors & gotchas

- **`KEA_URL` default :8000 conflicts** with the netbox/`install_kea.sh` convention of Kea CA on :8760 — override where Kea shares a box with NetBox/the legacy webui-spoke on :8000 (the unified hub owns :443, so Kea :8000 no longer collides with the hub).
- **Only spoke of this group with no FastAPI dep** (`requirements.txt` lacks `fastapi`/`uvicorn`) — a pure spoke.
- **Kea error handling** — `result != 0` raises `RuntimeError(result.text)`; `_cmd` returns `arguments` only.

## Related pages

[architecture-topology.md](architecture-topology.md), [netbox.md](netbox.md) (NetBox→Kea scope sync), [install-flags.md](install-flags.md).