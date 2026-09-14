import base64
import copy
import logging
import re
from typing import Any, Dict, List, Optional, Tuple, Union
import requests
import ipaddress
import os
import shutil
import subprocess
import zlib

logger = logging.getLogger("KeaManager")


def worker_code_version() -> dict:
    """Best-effort ``{commit, commit_time, dirty}`` for the running worker's
    own checkout — added because a recurring "same error keeps coming back"
    report turned out to be a stale checkout that never received a merged
    fix (this worker's only code-update path is re-running the installer;
    there is no self-update). Surfacing the actual running commit + when it
    landed in diagnostics lets an operator immediately tell "still on old
    code" apart from "the fix is deployed but the failure is real", instead
    of needing separate manual git access to the host.
    """
    repo_root = os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))))
    out = {"commit": "", "commit_time": "", "dirty": None}
    if not shutil.which("git") or not os.path.isdir(os.path.join(repo_root, ".git")):
        return out
    try:
        commit = subprocess.run(
            ["git", "-C", repo_root, "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, timeout=10)
        if commit.returncode == 0:
            out["commit"] = commit.stdout.strip()
        ctime = subprocess.run(
            ["git", "-C", repo_root, "log", "-1", "--format=%cI"],
            capture_output=True, text=True, timeout=10)
        if ctime.returncode == 0:
            out["commit_time"] = ctime.stdout.strip()
        dirty = subprocess.run(
            ["git", "-C", repo_root, "status", "--porcelain"],
            capture_output=True, text=True, timeout=10)
        if dirty.returncode == 0:
            out["dirty"] = bool(dirty.stdout.strip())
    except Exception:  # noqa: BLE001 — best-effort only
        pass
    return out


def _stable_subnet_id(subnet_str: str, taken: set) -> int:
    """Deterministic Kea ``subnet-id`` for a CIDR, stable across syncs.

    The old scheme assigned ``id = enumerate(subnets, start=1)`` — a bare
    list POSITION. Any NetBox-side change that shifts the list (a scope
    removed, reordered, or one inserted ahead of others) silently reassigns
    every downstream subnet to a DIFFERENT numeric id on the very next sync.
    Kea does not purge ``statistic-get-all`` history for an id that
    disappears from ``subnet4`` on a ``config-set`` — those samples linger
    in the running daemon's memory until it restarts — so each reshuffle
    left the OLD id's stats behind as a permanent "Unknown scope (not in
    NetBox — stale?)" 0/0 entry in the Overview, and every subsequent
    NetBox edit minted a fresh batch of them.

    Deriving the id from the CIDR itself instead means a given scope keeps
    the same id release over release regardless of how many OTHER scopes
    are added, removed, or reordered around it — nothing is orphaned, so
    nothing goes stale. ``taken`` guards the astronomically unlikely CRC32
    collision by linear-probing to the next free id.
    """
    base = zlib.crc32(subnet_str.encode()) & 0x7FFFFFFF or 1  # never 0
    sid = base
    while sid in taken:
        sid = (sid % 0x7FFFFFFF) + 1
    taken.add(sid)
    return sid


def _normalize_mac(mac: str) -> str:
    """Normalize MAC address to colon-separated lowercase format (aa:bb:cc:dd:ee:ff)."""
    if not mac:
        return ""
    clean = re.sub(r'[^0-9a-fA-F]', '', str(mac)).lower()
    if len(clean) == 12:
        return ":".join(clean[i:i+2] for i in range(0, 12, 2))
    return str(mac).strip().lower().replace("-", ":")


def _add_option(kea_subnet: dict, name: str, value) -> None:
    """Append one Kea ``option-data`` entry if ``value`` is non-empty.

    ``value`` may be a plain string or a list (comma-joined the way Kea
    expects a multi-value option, e.g. multiple NTP servers).
    """
    if isinstance(value, (list, tuple)):
        value = ", ".join(v for v in value if v)
    if not value:
        return
    kea_subnet["option-data"].append({"name": name, "data": value})


# Standard DHCPv4 options beyond gateway/DNS that a scope may carry, sourced
# from the same NetBox prefix custom_fields as gateway/dns_servers (see
# ``dns_dhcp_sync.build_dhcp_payload``). Table-driven so adding another
# standard option is a one-line addition here plus the matching
# custom_fields read on the sync side, instead of a new one-off `if` block
# per option. Each entry is (subnet-dict key, Kea option-data "name").
_ADVANCED_OPTION_MAP = [
    ("domain_name",          "domain-name"),
    ("ntp_servers",          "ntp-servers"),
    ("tftp_server_name",     "tftp-server-name"),
    ("boot_file_name",       "boot-file-name"),
    ("netbios_name_servers", "netbios-name-servers"),
    ("broadcast_address",    "broadcast-address"),
]


def _parse_exclusion_ranges(raw_exclusions) -> list:
    """Parse exclusion ranges string or list into a list of (start_int, end_int) tuples."""
    if not raw_exclusions:
        return []
    items = []
    if isinstance(raw_exclusions, str):
        items = [x.strip() for x in raw_exclusions.replace(";", ",").split(",") if x.strip()]
    elif isinstance(raw_exclusions, (list, tuple, set)):
        items = list(raw_exclusions)

    parsed = []
    for item in items:
        if isinstance(item, dict):
            s, e = item.get("start"), item.get("end")
            if s and e:
                try:
                    s_int = int(ipaddress.ip_address(str(s).strip()))
                    e_int = int(ipaddress.ip_address(str(e).strip()))
                    parsed.append((min(s_int, e_int), max(s_int, e_int)))
                except ValueError:
                    continue
        elif isinstance(item, str):
            item = item.strip()
            if not item:
                continue
            if "-" in item:
                parts = item.split("-", 1)
                try:
                    s_int = int(ipaddress.ip_address(parts[0].strip()))
                    e_int = int(ipaddress.ip_address(parts[1].strip()))
                    parsed.append((min(s_int, e_int), max(s_int, e_int)))
                except ValueError:
                    continue
            else:
                try:
                    ip_int = int(ipaddress.ip_address(item))
                    parsed.append((ip_int, ip_int))
                except ValueError:
                    continue
    return parsed


def _carve_pools(base_ranges: list, exclusions: list) -> list:
    """Carve exclusion ranges out of base IP ranges [(start_int, end_int)]."""
    if not exclusions:
        return [{"pool": f"{ipaddress.ip_address(s)} - {ipaddress.ip_address(e)}"}
                for s, e in base_ranges if s <= e]

    sorted_ex = sorted(exclusions, key=lambda x: x[0])
    merged_ex = []
    for ex_s, ex_e in sorted_ex:
        if not merged_ex:
            merged_ex.append((ex_s, ex_e))
        else:
            prev_s, prev_e = merged_ex[-1]
            if ex_s <= prev_e + 1:
                merged_ex[-1] = (prev_s, max(prev_e, ex_e))
            else:
                merged_ex.append((ex_s, ex_e))

    result_pools = []
    for base_s, base_e in base_ranges:
        curr = base_s
        for ex_s, ex_e in merged_ex:
            if ex_e < curr or ex_s > base_e:
                continue
            if ex_s > curr:
                result_pools.append({
                    "pool": f"{ipaddress.ip_address(curr)} - {ipaddress.ip_address(min(ex_s - 1, base_e))}"
                })
            curr = max(curr, ex_e + 1)
            if curr > base_e:
                break
        if curr <= base_e:
            result_pools.append({
                "pool": f"{ipaddress.ip_address(curr)} - {ipaddress.ip_address(base_e)}"
            })
    return result_pools


def build_subnet4(subnets: list, reservations: list) -> tuple:
    """Translate LM/NetBox intent into Kea's ``subnet4`` list.

    Returns ``(kea_subnets, applied_reservations, skipped_reservations)``.
    Extracted from :meth:`KeaManager.sync` so an HA pair can be handed the
    IDENTICAL scope + reservation block for both nodes — two nodes computing
    their own subnet list independently is how a "HA pair" ends up handing out
    overlapping addresses.
    """
    kea_subnets = []
    applied = [False] * len(reservations)
    used_ids: set = set()
    for s in subnets:
        subnet_str = s.get("subnet", "")
        try:
            net = ipaddress.ip_network(subnet_str, strict=False)
        except ValueError:
            logger.warning("Invalid subnet %s — skipping", subnet_str)
            continue
        idx = _stable_subnet_id(subnet_str, used_ids)

        pools = [
            {"pool": f"{p['start']} - {p['end']}"}
            for p in s.get("pools", [])
            if p.get("start") and p.get("end")
        ]
        excl_raw = s.get("exclusion_ranges") or s.get("exclusions")
        if excl_raw:
            exclusions = _parse_exclusion_ranges(excl_raw)
            if pools:
                base_ranges = []
                for p in s.get("pools", []):
                    if p.get("start") and p.get("end"):
                        try:
                            s_int = int(ipaddress.ip_address(p["start"]))
                            e_int = int(ipaddress.ip_address(p["end"]))
                            if s_int <= e_int:
                                base_ranges.append((s_int, e_int))
                        except ValueError:
                            pass
            else:
                first = int(net.network_address) + 1
                last = int(net.broadcast_address) - 1
                base_ranges = [(first, last)] if first <= last else []
            pools = _carve_pools(base_ranges, exclusions)
        elif not pools:
            # Default pool: .10 → .254
            first = int(net.network_address) + 10
            last  = int(net.broadcast_address) - 1
            if first <= last:
                pools = [{"pool": f"{ipaddress.ip_address(first)} - {ipaddress.ip_address(last)}"}]

        kea_subnet = {
            "id":     idx,
            "subnet": str(net),
            "pools":  pools,
            "option-data": [],
        }
        # Carry the NetBox prefix description through in Kea's user-context so
        # the UI can label a scope by its real name/purpose instead of a bare
        # "subnet <id>" — Kea persists arbitrary user-context data untouched
        # and returns it back on subnet4-list, so this round-trips for free.
        description = (s.get("description") or "").strip()
        if description:
            kea_subnet["user-context"] = {"description": description}
        if s.get("gateway"):
            kea_subnet["option-data"].append(
                {"name": "routers", "data": s["gateway"]}
            )
        dns = s.get("dns_servers", [])
        if dns:
            kea_subnet["option-data"].append(
                {"name": "domain-name-servers", "data": ", ".join(dns)}
            )
        _add_option(kea_subnet, "domain-search", s.get("search_domains"))
        for key, opt_name in _ADVANCED_OPTION_MAP:
            _add_option(kea_subnet, opt_name, s.get(key))
        # valid-lifetime is a Kea subnet-level property (the DHCP lease time
        # in seconds), not an option-data entry — only set it when the scope
        # opted out of Kea's built-in global default.
        lease_time = s.get("lease_time")
        try:
            if lease_time:
                kea_subnet["valid-lifetime"] = int(lease_time)
        except (TypeError, ValueError):
            logger.warning("Ignoring non-numeric lease_time %r for %s",
                           lease_time, subnet_str)

        # Attach reservations that belong to this subnet. Guard ip/mac with
        # .get and wrap ip_network in try — one malformed reservation (missing
        # or invalid ip) must be skipped, not KeyError/ValueError out of the
        # whole sync (which would then config-set the subnet with NO reservations).
        subnet_res = []
        for res_idx, r in enumerate(reservations):
            ip, mac = r.get("ip"), r.get("mac")
            if not ip or not mac:
                continue
            try:
                in_subnet = (str(r.get("subnet_id")) == str(idx)
                             or r.get("subnet") == subnet_str
                             or net.overlaps(ipaddress.ip_network(f"{ip}/32")))
            except ValueError:
                continue  # malformed reservation IP
            if in_subnet:
                subnet_res.append({
                    "ip-address": ip,
                    "hw-address": _normalize_mac(mac),
                    "hostname": r.get("hostname", ""),
                })
                applied[res_idx] = True
        if subnet_res:
            kea_subnet["reservations"] = subnet_res

        kea_subnets.append(kea_subnet)

    applied_count = sum(1 for flag in applied if flag)
    return kea_subnets, applied_count, len(reservations) - applied_count



class KeaManager:
    """
    Manages Kea DHCP4 via the Kea Control Agent REST API.
    Default CA port is 8001 (we use 8001 to avoid conflict with the LM hub on 8000).
    """

    def __init__(self, ca_url: str = "http://localhost:8001"):
        self.ca_url = ca_url.rstrip("/")
        # One keep-alive Session reused across every RPC (sync() alone can fire
        # a config-get + config-set + config-write + subnet4-list in quick
        # succession). A fresh connection per call paid a TCP+HTTP handshake
        # every time; the shared Session holds the keep-alive connection so
        # back-to-back RPCs reuse it.
        self._session = requests.Session()

    # ── Kea Control Agent RPC ─────────────────────────────────────────

    def _rpc(self, service: str, command: str, args: dict = None) -> dict:
        payload = {"command": command, "service": [service]}
        if args is not None:
            payload["arguments"] = args
        try:
            r = self._session.post(self.ca_url, json=payload, timeout=10)
            r.raise_for_status()
            result = r.json()
            if isinstance(result, list):
                result = result[0]
            code = result.get("result", 0)
            # Kea's control channel uses result=3 ("empty") for queries that
            # succeeded but found no matching data — e.g. lease4-get-all on a
            # subnet with no active leases yet (exactly the case right after
            # DHCP starts serving again). Treating it as an error made every
            # diagnostics/list_leases call on an otherwise-healthy, freshly
            # recovered node fail with a misleading "Kea error" / lease
            # retrieval failure, even though there was genuinely nothing
            # wrong — only 1 (error) and 2 (unsupported) are real failures.
            if code not in (0, 3):
                raise RuntimeError(result.get("text", "Kea error"))
            return result.get("arguments", {})
        except requests.RequestException as e:
            raise RuntimeError(f"Kea CA unreachable: {e}")

    # ── Subnet (scope) management ─────────────────────────────────────

    def list_subnets(self) -> list:
        """Configured subnet4 scopes, straight from the running config.

        Deliberately NOT the ``subnet4-list`` command — that RPC requires
        ``libdhcp_subnet_cmds.so`` to be loaded, which this install's
        hooks-libraries does NOT include (only ``lease_cmds`` + ``ha`` are
        loaded; see kea-dhcp4.conf). Without that hook Kea answers
        ``result: 2`` ("command not supported"); our own ``_rpc()`` raises
        on any code other than 0/3, so this used to be silently swallowed by
        the try/except below, returning an empty list — every caller
        (get_stats' pool utilization, the WebUI Subnets/Overview tabs,
        diagnostics' id_to_cidr map) then saw ZERO subnets even though the
        subnet was correctly synced and actively serving DHCP.
        ``config-get`` is a core Kea command needing no optional hook, and
        its ``Dhcp4.subnet4`` array carries the exact same id/subnet/pools/
        user-context shape build_subnet4() writes — so this sources the
        identical data the removed RPC would have returned, just from a
        command guaranteed to exist.
        """
        try:
            return self.get_config().get("subnet4", []) or []
        except Exception as e:
            logger.error("list_subnets failed: %s", e)
            return []

    def get_config(self) -> dict:
        return self._rpc("dhcp4", "config-get").get("Dhcp4", {})

    def _set_config(self, dhcp4_config: dict):
        self._rpc("dhcp4", "config-set", {"Dhcp4": dhcp4_config})
        self._rpc("dhcp4", "config-write", {})

    def apply_config(self, dhcp4_config: dict) -> dict:
        """``config-set`` then ``config-write`` as two OBSERVABLE steps.

        ``_set_config`` collapses both into one exception, which loses the one
        distinction that matters for rollback: a ``config-write`` failure means
        the new config is ALREADY RUNNING (config-set succeeded) but is not
        persisted — the node is mutated and must be restored, whereas a
        ``config-set`` failure left it untouched. Returns
        ``{"set": bool, "written": bool, "error": str}``.
        """
        try:
            self._rpc("dhcp4", "config-set", {"Dhcp4": dhcp4_config})
        except Exception as e:  # noqa: BLE001 — a rejected config is the answer
            return {"set": False, "written": False, "error": str(e)}
        try:
            self._rpc("dhcp4", "config-write", {})
        except Exception as e:  # noqa: BLE001
            return {"set": True, "written": False, "error": str(e)}
        return {"set": True, "written": True, "error": ""}

    def write_config(self) -> dict:
        """Retry ``config-write`` alone against the ALREADY-set running config
        — used by the worker's config-write-permission self-heal, which fixes
        ``/etc/kea/kea-dhcp4.conf`` on disk and then just needs Kea to persist
        what it's already running, with no need to re-send/re-validate the
        whole config via ``config-set``. Returns ``{"written": bool,
        "error": str}``."""
        try:
            self._rpc("dhcp4", "config-write", {})
        except Exception as e:  # noqa: BLE001
            return {"written": False, "error": str(e)}
        return {"written": True, "error": ""}


    def sync(self, subnets: list, reservations: list) -> dict:
        """
        Full sync: replace all subnets and reservations.

        subnets:      [{subnet, gateway, dns_servers, pools: [{start, end}], description}]
        reservations: [{ip, mac, hostname, subnet}]
        """
        try:
            cfg = self.get_config()
        except Exception as e:
            return {"status": "ERROR", "message": f"Cannot read Kea config: {e}"}

        kea_subnets, _applied, _skipped = build_subnet4(subnets, reservations)

        cfg["subnet4"] = kea_subnets
        try:
            self._set_config(cfg)
        except Exception as e:
            return {"status": "ERROR", "message": str(e)}

        logger.info("Synced %d subnets, %d reservations to Kea", len(kea_subnets), len(reservations))
        return {"status": "SUCCESS", "subnets": len(kea_subnets), "reservations": len(reservations)}

    # ── Lease queries ─────────────────────────────────────────────────

    def list_leases(self, subnet: str = None) -> list:
        try:
            # ``lease4-get-all`` has no "all leases" sentinel value, and per
            # ISC docs omitting "arguments" entirely is supposed to mean
            # "every subnet" — but this HA-hooked node rejects a bare/no-args
            # call with "'subnets' parameter not specified" regardless (the
            # HA hook likely intercepts lease4-get-all and requires an
            # explicit subnet list to know which node's view is authoritative
            # for each one). Always pass "subnets" explicitly: every
            # currently-configured subnet ID for "all", or the one matching
            # ``subnet`` when filtering.
            kea_subnets = self.list_subnets()
            ids = [s["id"] for s in kea_subnets if "id" in s]
            if subnet:
                ids = [s["id"] for s in kea_subnets if s.get("subnet") == subnet]
            data = self._rpc("dhcp4", "lease4-get-all", {"subnets": ids})
            return data.get("leases", [])
        except Exception as e:
            logger.error("list_leases failed: %s", e)
            return []

    def delete_lease(self, ip: str) -> dict:
        """Delete an active lease by IP from Kea via lease4-del RPC."""
        try:
            res = self._rpc("dhcp4", "lease4-del", {"ip-address": ip})
            return {"status": "SUCCESS", "result": res}
        except Exception as e:
            logger.debug("delete_lease %s: %s", ip, e)
            return {"status": "SUCCESS", "message": str(e), "not_found": True}

    def purge_leases_for_mac_or_ip(self, mac: str = None, ip: str = None) -> list:
        """Purge any active lease for a given MAC or IP address."""
        purged = []
        if ip:
            self.delete_lease(ip)
            purged.append(ip)
        if mac:
            norm_mac = _normalize_mac(mac)
            try:
                leases = self.list_leases()
                for l in leases:
                    l_ip = l.get("ip-address") or l.get("ip")
                    l_mac = _normalize_mac(l.get("hw-address") or l.get("mac"))
                    if l_mac and l_mac == norm_mac and l_ip and l_ip not in purged:
                        self.delete_lease(l_ip)
                        purged.append(l_ip)
            except Exception as e:
                # A surviving lease means the client keeps its current address
                # and never picks up the reservation, so this must not stay a
                # debug-level detail.
                logger.warning("Could not purge leases for %s: %s", norm_mac, e)
        return purged

    # ── Manual reservation CRUD ───────────────────────────────────────

    def add_reservation(self, subnet_id: Any, ip: str, mac: str, hostname: str = "") -> dict:
        cfg = self.get_config()
        norm_mac = _normalize_mac(mac)
        for sub in cfg.get("subnet4", []):
            if str(sub.get("id")) == str(subnet_id):
                sub.setdefault("reservations", [])
                sub["reservations"].append({
                    "ip-address": ip,
                    "hw-address": norm_mac,
                    "hostname":   hostname,
                })
                break
        else:
            return {"status": "ERROR", "message": f"Subnet {subnet_id} not found"}
        self._set_config(cfg)
        purged = self.purge_leases_for_mac_or_ip(mac=norm_mac, ip=ip)
        return {"status": "SUCCESS", "lease_purge": {"purged": purged}}

    def list_reservations(self) -> list:
        """Return all static reservations across subnets."""
        out = []
        try:
            cfg = self.get_config()
        except Exception as e:
            logger.error("list_reservations failed: %s", e)
            return out
        for sub in cfg.get("subnet4", []):
            for r in sub.get("reservations", []):
                out.append({
                    "ip":        r.get("ip-address", ""),
                    "mac":       r.get("hw-address", ""),
                    "hostname":  r.get("hostname", ""),
                    "subnet_id": sub.get("id"),
                    "subnet":    sub.get("subnet", ""),
                })
        return out

    def update_reservation(self, old_ip: str, subnet_id: Any, ip: str,
                           mac: str, hostname: str = "") -> dict:
        """Update a reservation by IP in ONE config write.

        Previously this deleted the old entry in one ``config-set`` and added
        the replacement in a second: a failure (or a crash) between the two left
        the reservation DELETED and never re-created, so the host silently
        dropped to a dynamic lease. The removal and the insertion are now a
        single atomic write — either the replacement lands or nothing changes.
        Reservations still move freely between subnets, because the whole
        ``subnet4`` block is rewritten in that one write."""
        if not all([subnet_id, ip, mac]):
            return {"status": "ERROR", "message": "subnet_id, ip, and mac are required"}
        cfg = self.get_config()
        target = None
        norm_mac = _normalize_mac(mac)
        for sub in cfg.get("subnet4", []):
            if str(sub.get("id")) == str(subnet_id):
                target = sub
            sub["reservations"] = [
                r for r in sub.get("reservations", [])
                if r.get("ip-address") != old_ip
            ]
        if target is None:
            return {"status": "ERROR", "message": f"Subnet {subnet_id} not found"}
        target.setdefault("reservations", [])
        target["reservations"].append({
            "ip-address": ip,
            "hw-address": norm_mac,
            "hostname":   hostname,
        })
        try:
            self._set_config(cfg)
            purged = self.purge_leases_for_mac_or_ip(mac=norm_mac, ip=ip)
            if old_ip and old_ip != ip:
                purged += self.purge_leases_for_mac_or_ip(ip=old_ip)
        except Exception as e:
            return {"status": "ERROR", "message": str(e)}
        return {"status": "SUCCESS", "lease_purge": {"purged": purged}}

    def delete_reservation(self, ip: str) -> dict:
        cfg = self.get_config()
        for sub in cfg.get("subnet4", []):
            sub["reservations"] = [
                r for r in sub.get("reservations", [])
                if r.get("ip-address") != ip
            ]
        self._set_config(cfg)
        return {"status": "SUCCESS"}

    # ── Statistics ────────────────────────────────────────────────────

    def get_stats(self) -> dict:
        """Kea DHCP4 statistics via ``statistic-get-all``, normalized for the UI.

        Kea returns each statistic as a list of ``[value, timestamp]`` samples
        (newest first), plus per-subnet keys of the form
        ``subnet[<id>].<name>``. We pull the latest sample of the pool-size /
        assignment counters and derive a utilization percentage per subnet and
        overall, and surface the headline packet counters.
        """
        try:
            raw = self._rpc("dhcp4", "statistic-get-all", {})
        except Exception as e:
            # Kea CA not reachable (e.g. kea-ctrl-agent not installed/running on
            # this spoke). The DHCP module is legitimately dormant on a box
            # without Kea — surface an IDLE state, not a red ERROR, so the
            # Overview tile renders empty stats + a note instead of "Error:
            # Kea CA unreachable …". The module-health tile still sees
            # running=False via get_status telemetry.
            logger.warning("get_stats: Kea CA unreachable at %s: %s", self.ca_url, e)
            return {"status": "SUCCESS", "global": {}, "subnets": [],
                    "kea_running": False,
                    "note": f"Kea Control Agent not reachable at {self.ca_url} — "
                            f"start kea-ctrl-agent to enable DHCP."}

        def latest(key):
            v = raw.get(key)
            if isinstance(v, list) and v and isinstance(v[0], list) and v[0]:
                return v[0][0]
            return None

        def num(key):
            val = latest(key)
            return val if isinstance(val, (int, float)) else 0

        id_to_cidr = {s.get("id"): s.get("subnet", "") for s in self.list_subnets()}
        # user-context.description round-trips the NetBox prefix description
        # (see build_subnet4) — used to label a scope by its real name instead
        # of the bare "subnet <id>" fallback the UI used previously.
        id_to_desc = {
            s.get("id"): ((s.get("user-context") or {}).get("description") or "")
            for s in self.list_subnets()
        }

        # Kea's "assigned-addresses" statistic is a counter that only moves on
        # allocation/explicit release/reclamation events — it is NOT
        # guaranteed to reflect what's actually in the lease table right now
        # (e.g. a lease that vanished from lease4-get-all without Kea running
        # its reclamation timer leaves the counter stuck showing it as still
        # "assigned"). That drift is exactly what surfaced as "1 assigned
        # lease" on the Overview tile while the Leases tab — which reads
        # lease4-get-all directly — showed nothing. Count live, non-expired
        # leases ourselves so the two tabs can never disagree.
        assigned_by_subnet = {}
        try:
            for lease in self.list_leases():
                sid = lease.get("subnet-id")
                if sid is None:
                    continue
                # state: 0 = default/active, 1 = declined, 2 = expired-reclaimed.
                if lease.get("state", 0) not in (0, None):
                    continue
                assigned_by_subnet[sid] = assigned_by_subnet.get(sid, 0) + 1
        except Exception as e:
            logger.warning("get_stats: live lease count failed, falling back "
                           "to Kea's assigned-addresses statistic: %s", e)
            assigned_by_subnet = {}

        subnet_ids = set()
        for k in raw:
            m = re.match(r"subnet\[(\d+)\]\.", k)
            if m:
                subnet_ids.add(int(m.group(1)))

        # Kea does NOT purge statistic-get-all history for a subnet-id that
        # disappears from subnet4 on a config-set — those samples linger in
        # the running daemon's memory until it restarts. Before build_subnet4
        # switched to stable CIDR-derived ids, every NetBox-side reorder/
        # add/remove reassigned ids and left the OLD id's stats behind
        # forever as a meaningless "Unknown scope (not in NetBox — stale?)"
        # 0/0 row. Those ids no longer belong to any currently-configured
        # subnet — drop them outright instead of rendering a placeholder;
        # they carry no scope to label and no address pool to report on.
        stale_ids = subnet_ids - set(id_to_cidr)
        if stale_ids:
            logger.info("get_stats: dropping %d orphaned subnet stat id(s) "
                        "no longer in the live Kea config: %s",
                        len(stale_ids), sorted(stale_ids))
        subnet_ids &= set(id_to_cidr)

        subnets = []
        for sid in sorted(subnet_ids):
            total    = num(f"subnet[{sid}].total-addresses")
            assigned = assigned_by_subnet.get(sid, 0)
            declined = num(f"subnet[{sid}].declined-addresses")
            util = round(assigned / total * 100, 1) if total else 0.0
            subnets.append({
                "subnet_id":          sid,
                "subnet":             id_to_cidr.get(sid, ""),
                "description":        id_to_desc.get(sid, ""),
                "total_addresses":    total,
                "assigned_addresses": assigned,
                "declined_addresses": declined,
                "utilization_pct":    util,
            })

        g_total    = sum(s["total_addresses"] for s in subnets)
        g_assigned = sum(s["assigned_addresses"] for s in subnets)
        global_stats = {
            "total_addresses":    g_total,
            "assigned_addresses": g_assigned,
            "declined_addresses": num("declined-addresses"),
            "utilization_pct":    round(g_assigned / g_total * 100, 1) if g_total else 0.0,
            "pkt4_received":      num("pkt4-received"),
            "pkt4_discover":      num("pkt4-discover-received"),
            "pkt4_request":       num("pkt4-request-received"),
            "pkt4_offer_sent":    num("pkt4-offer-sent"),
            "pkt4_ack_sent":      num("pkt4-ack-sent"),
            "pkt4_nak_sent":      num("pkt4-nak-sent"),
        }
        return {"status": "SUCCESS", "global": global_stats, "subnets": subnets}

    def status(self) -> dict:
        try:
            self._rpc("dhcp4", "version-get")
            running = True
        except Exception:
            running = False
        return {
            "running":      running,
            "subnet_count": len(self.list_subnets()) if running else 0,
            "ca_url":       self.ca_url,
        }

    #: File whose absence/emptiness silently blocks kea-ctrl-agent.service from
    #: ever starting via its own ConditionFileNotEmpty= gate (see
    #: install_dhcp.sh) — a fully mechanical, safe-to-recreate condition that
    #: previously required the operator to notice and manually recreate the
    #: file (or reinstall the whole role) before Kea's CA would come back.
    _API_PASSWORD_FILE = "/etc/kea/kea-api-password"

    def _self_heal(self) -> list:
        """Best-effort, fixed-argv repair of conditions diagnostics() can fully
        explain and safely fix without operator action — never anything that
        touches DHCP scope/reservation data. Returns the list of repair
        actions taken (each a short human-readable string) for the UI/log.
        """
        actions = []
        try:
            actions.extend(self._heal_api_password_file())
        except Exception as e:  # noqa: BLE001 — self-heal must never crash diagnostics
            logger.warning("self-heal (api password) failed: %s", e)
        try:
            actions.extend(self._heal_inactive_units())
        except Exception as e:  # noqa: BLE001
            logger.warning("self-heal (units) failed: %s", e)
        try:
            actions.extend(self._heal_missing_interfaces())
        except Exception as e:  # noqa: BLE001
            logger.warning("self-heal (interfaces) failed: %s", e)
        return actions

    def _heal_api_password_file(self) -> list:
        path = self._API_PASSWORD_FILE
        try:
            needs_create = not os.path.exists(path) or os.path.getsize(path) == 0
        except OSError:
            needs_create = True
        if not needs_create:
            return []
        try:
            with open(path, "wb") as fh:
                fh.write(base64.b64encode(os.urandom(32)))
            os.chmod(path, 0o640)
            try:
                shutil.chown(path, group="_kea")
            except (LookupError, PermissionError, OSError):
                pass  # best-effort, same as the installer
        except OSError as e:
            logger.warning("could not recreate %s: %s", path, e)
            return []
        logger.info("self-heal: recreated missing/empty %s", path)
        return [f"recreated missing {path}"]

    def _heal_inactive_units(self) -> list:
        """Restart kea-dhcp4-server/kea-ctrl-agent if systemd reports them
        failed/inactive-but-enabled. A crash-looped or one-off-killed unit is
        exactly the case an uninstall/reinstall used to be needed to clear —
        ``systemctl restart`` is the same fixed, argument-free recovery a
        reinstall ultimately performs, without touching any configuration.
        """
        actions = []
        for unit in ("kea-dhcp4-server", "kea-ctrl-agent"):
            state = self._unit_status(unit)
            active = state.get("ActiveState")
            load = state.get("LoadState")
            if load != "loaded" or active == "active":
                continue
            if active not in ("failed", "inactive"):
                continue
            result = self._run_diag(["systemctl", "restart", unit], timeout=20)
            if result["ok"]:
                actions.append(f"restarted {unit} (was {active})")
                logger.info("self-heal: restarted %s (was %s)", unit, active)
            else:
                logger.warning(
                    "self-heal: restart of %s failed: %s", unit, result["error"])
        return actions

    def _heal_missing_interfaces(self) -> list:
        """Set ``interfaces-config.interfaces`` when it is empty.

        ``interfaces-config`` is node-owned (see ``build_node_config`` /
        ``COORDINATOR_OWNED_KEYS`` in ``kea_ha.py``) — the LM sync path never
        touches it, and the stock Debian ``kea-dhcp4-server`` package ships it
        as ``[]`` ("listen on nothing") with a comment telling the operator to
        fill it in by hand. Nothing in ``install_dhcp.sh`` ever did, so a node
        can run for a long time looking completely healthy — service active,
        HA heartbeats fine, control agent answering, config-get fine — while
        Kea has never actually opened a DHCPv4 socket and every real client is
        silently getting no offer at all. This is exactly the case behind the
        "Nothing is listening on DHCP server port UDP/67" recommendation.

        Heals by setting ``interfaces`` to ``["*"]`` — listen on every
        interface, the same safe default an operator would type by hand — via
        ``config-set``/``config-write``, then restarting the daemon: Kea's
        DHCPv4 socket set is bound once at startup, so a ``config-set`` alone
        (no restart) updates the on-disk/running JSON but does not open the
        new listener until the process restarts.
        """
        try:
            config = self.get_config()
        except Exception as e:
            logger.warning("self-heal (interfaces): could not read config: %s", e)
            # Surface the failure instead of silently returning [] — a caller
            # reading "no self-heal actions" has no way to tell "nothing
            # needed fixing" apart from "the heal itself couldn't even check",
            # which is exactly the ambiguity that let this stay broken.
            return [f"could not check interfaces-config: {e}"]
        raw_interfaces = ((config.get("interfaces-config", {}) or {})
                          .get("interfaces", []) or [])
        # Filter out blank/whitespace-only entries — Kea's config-get has been
        # observed to echo an "empty" interfaces list back as ``[""]`` rather
        # than ``[]``, which is still falsy/non-listening but IS a non-empty
        # Python list, so a plain truthiness check would wrongly treat it as
        # "already configured" and silently skip healing (matches the same
        # stricter filtering diagnostics() already applies below).
        interfaces = [v for v in raw_interfaces if str(v).strip()]
        if interfaces:
            return []
        new_config = copy.deepcopy(config)
        new_config.setdefault("interfaces-config", {})["interfaces"] = ["*"]
        try:
            result = self.apply_config(new_config)
        except Exception as e:
            logger.warning("self-heal (interfaces): apply failed: %s", e)
            return [f"failed to set interfaces-config: {e}"]
        if not (result.get("set") and result.get("written")):
            logger.warning("self-heal (interfaces): apply did not succeed: %s", result)
            return [f"could not set interfaces-config: "
                    f"{result.get('error') or 'config-set/config-write did not report success'}"]
        restart = self._run_diag(["systemctl", "restart", "kea-dhcp4-server"], timeout=20)
        if not restart["ok"]:
            logger.warning(
                "self-heal (interfaces): config updated but restart failed: %s",
                restart["error"])
            return ["set interfaces-config to listen on all interfaces "
                    "(restart failed — apply manually with systemctl restart "
                    "kea-dhcp4-server)"]
        logger.info(
            "self-heal: interfaces-config was empty (Kea was listening on "
            "nothing); set to listen on all interfaces and restarted "
            "kea-dhcp4-server")
        return ["set interfaces-config to listen on all interfaces "
                "(was empty) and restarted kea-dhcp4-server"]

    def diagnostics(self) -> dict:
        """Return Kea service, config, interface, listener, CA, and lease checks."""
        repairs = self._self_heal()
        units = {
            name: self._unit_status(name)
            for name in ("kea-dhcp4-server", "kea-ctrl-agent")
        }
        config_test = self._run_diag(
            ["kea-dhcp4", "-t", "/etc/kea/kea-dhcp4.conf"], timeout=10)
        # The control agent has its OWN config file (kea-ctrl-agent.conf) and
        # its own syntax-check binary invocation. A "Control Agent is not
        # active" recommendation with no further detail forced a manual SSH
        # to find out WHY — this test + the dedicated journal tail below give
        # the actual failure reason (bad JSON, socket path, port already
        # bound, etc.) directly in the diagnostics panel.
        ca_config_test = self._run_diag(
            ["kea-ctrl-agent", "-t", "/etc/kea/kea-ctrl-agent.conf"], timeout=10)
        sockets = self._run_diag(["ss", "-H", "-lntup"])
        if not sockets["ok"]:
            sockets = self._run_diag(["ss", "-H", "-lntu"])
        listener_lines = [
            line.strip() for line in sockets["output"].splitlines()
            if re.search(r"(?:\]:|:)(?:67|8001)(?:\s|$)", line)
        ]
        dhcp_listeners = [line for line in listener_lines
                          if re.search(r"(?:\]:|:)67(?:\s|$)", line)]
        ca_listeners = [line for line in listener_lines
                        if re.search(r"(?:\]:|:)8001(?:\s|$)", line)]

        ca = {"reachable": False, "config_loaded": False,
              "url": self.ca_url, "version": "", "error": ""}
        config = {}
        leases = None
        try:
            version = self._rpc("dhcp4", "version-get")
            ca["reachable"] = True
            ca["version"] = str(
                version.get("extended") or version.get("version") or "")
        except Exception as e:
            ca["error"] = str(e)
        if ca["reachable"]:
            try:
                config = self.get_config()
                ca["config_loaded"] = True
            except Exception as e:
                ca["error"] = str(e)
            try:
                # Always pass "subnets" explicitly — per ISC docs, omitting
                # "arguments" entirely means "every subnet", but this
                # HA-hooked node rejects a bare/no-args call with
                # "'subnets' parameter not specified" regardless (the HA hook
                # likely intercepts lease4-get-all and requires an explicit
                # subnet list to know which node's view is authoritative for
                # each one). Reuse the subnet4 IDs from the config already
                # fetched above rather than a second config-get/subnet4-list
                # round trip.
                subnet_ids = [s["id"] for s in (config.get("subnet4", []) or [])
                              if "id" in s]
                lease_data = self._rpc(
                    "dhcp4", "lease4-get-all", {"subnets": subnet_ids})
                leases = lease_data.get("leases", [])
            except Exception as e:
                if not ca["error"]:
                    ca["error"] = str(e)

        interfaces = [
            str(value).split("/", 1)[0].strip()
            for value in ((config.get("interfaces-config", {}) or {})
                          .get("interfaces", []) or [])
            if str(value).strip()
        ]
        missing_interfaces = [
            iface for iface in interfaces
            if iface != "*" and not os.path.exists(f"/sys/class/net/{iface}")
        ]
        subnets = config.get("subnet4", []) or []
        lease_file = ((config.get("lease-database", {}) or {}).get("name") or "")
        lease_db = {
            "path": lease_file,
            "exists": bool(lease_file and os.path.exists(lease_file)),
            "leases": len(leases) if leases is not None else None,
        }
        recent = self._run_diag([
            "journalctl", "-u", "kea-dhcp4-server", "-u", "kea-ctrl-agent",
            "-p", "warning", "-n", "20", "--no-pager",
        ])
        recent_errors = [
            line for line in recent["output"].splitlines()
            if line.strip() and "-- No entries --" not in line
        ][-20:]
        # kea-ctrl-agent's OWN tail, unfiltered by priority. When the CA unit
        # itself never came up (crash-looped, port already bound, bad JSON in
        # kea-ctrl-agent.conf), the failure is usually logged at "info"/"err"
        # around process exit — the combined "-p warning" tail above can miss
        # it entirely if kea-dhcp4-server is chattier. This is what actually
        # answers "why is Control Agent FAIL / connection refused".
        ca_recent = self._run_diag([
            "journalctl", "-u", "kea-ctrl-agent", "-n", "20",
            "--no-pager", "-o", "cat",
        ])
        ca_recent_errors = [
            line for line in ca_recent["output"].splitlines()
            if line.strip() and "-- No entries --" not in line
        ][-20:]

        recommendations = []
        for action in repairs:
            recommendations.append(f"Self-healed: {action}. Re-checking findings above.")
        if units["kea-dhcp4-server"].get("ActiveState") != "active":
            recommendations.append(
                "Kea DHCP4 is not active; inspect its service status and recent log.")
        ca_unit = units["kea-ctrl-agent"]
        if ca_unit.get("ActiveState") != "active":
            detail = (
                f" (exit status {ca_unit['ExecMainStatus']})"
                if ca_unit.get("ExecMainStatus") not in (None, "", "0") else "")
            recommendations.append(
                "Kea Control Agent is not active; the LM DHCP module cannot "
                f"manage Kea{detail}.")
            if not ca_config_test["ok"]:
                recommendations.append(
                    "kea-ctrl-agent.conf failed its own syntax check: "
                    + (ca_config_test["error"] or ca_config_test["output"]
                       or "see config_test output").strip()[:300])
            elif ca_recent_errors:
                recommendations.append(
                    "kea-ctrl-agent recent log: " + ca_recent_errors[-1][:300])
        if not config_test["ok"]:
            recommendations.append(
                "Kea configuration validation failed; fix the reported config error.")
        if not ca["reachable"]:
            recommendations.append(
                f"Kea Control Agent did not answer at {self.ca_url}.")
        elif not ca["config_loaded"]:
            recommendations.append(
                "Kea Control Agent answered, but DHCP4 configuration retrieval failed.")
        if leases is None:
            recommendations.append(
                "Kea lease retrieval failed; the active lease count is unavailable.")
        if missing_interfaces:
            recommendations.append(
                "Configured DHCP interface(s) are missing: "
                + ", ".join(missing_interfaces) + ".")
        if not dhcp_listeners:
            recommendations.append(
                "Nothing is listening on DHCP server port UDP/67.")

        healthy = (
            units["kea-dhcp4-server"].get("ActiveState") == "active"
            and units["kea-ctrl-agent"].get("ActiveState") == "active"
            and config_test["ok"]
            and ca["reachable"]
            and ca["config_loaded"]
            and leases is not None
            and not missing_interfaces
            and bool(dhcp_listeners)
        )
        return {
            "status": "SUCCESS",
            "healthy": healthy,
            "worker_code_version": worker_code_version(),
            "self_healed": repairs,
            "units": units,
            "ca": ca,
            "config_test": config_test,
            "ca_config_test": ca_config_test,
            "ca_recent_errors": ca_recent_errors,
            "interfaces_configured": interfaces,
            "interface_missing": missing_interfaces,
            "subnets": [
                {"id": s.get("id"), "subnet": s.get("subnet", ""),
                 "pools": [p.get("pool", "") for p in (s.get("pools", []) or [])]}
                for s in subnets
            ],
            "lease_db": lease_db,
            "listeners": {
                "dhcp4": dhcp_listeners,
                "control_agent": ca_listeners,
                "error": sockets["error"],
            },
            "last_errors": recent_errors,
            "recommendations": recommendations,
        }

    @staticmethod
    def _run_diag(cmd, timeout=5):
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout)
            output = (result.stdout or result.stderr or "").strip()[:4000]
            return {
                "ok": result.returncode == 0,
                "exit_code": result.returncode,
                "output": output,
                "error": "" if result.returncode == 0 else (output or "command failed"),
            }
        except Exception as e:
            return {"ok": False, "exit_code": None, "output": "", "error": str(e)}

    def _unit_status(self, unit):
        result = self._run_diag([
            "systemctl", "show", unit,
            "--property=LoadState,ActiveState,SubState,NRestarts,ExecMainStatus",
        ])
        values = {}
        for line in result["output"].splitlines():
            key, sep, value = line.partition("=")
            if sep:
                values[key] = value
        values["error"] = result["error"]
        return values
