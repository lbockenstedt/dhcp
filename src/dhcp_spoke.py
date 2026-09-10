import asyncio
import json
import logging
import os
import secrets
import socket
from pathlib import Path
from typing import Any, Dict, List

try:
    from base_spoke import BaseSpoke
except ImportError:
    from core.src.base_spoke import BaseSpoke

try:
    from kea_manager import KeaManager
except ImportError:  # loaded as a package (src.X) by the sibling entrypoint
    from src.kea_manager import KeaManager

try:
    from kea_ha import (
        DEFAULT_CLUSTER_CONFIG, DEFAULT_DESIRED_STATE, DHCP_WORKER_OPS,
        KeaHAConfigError, UnsupportedHAMode, build_peers, load_cluster_config,
        normalize_mode, save_cluster_config,
    )
    from kea_cluster import KeaHACoordinator
    from ha_pki import issue_member_material
except ImportError:  # loaded as a package (src.X) by the sibling entrypoint
    from src.kea_ha import (  # type: ignore
        DEFAULT_CLUSTER_CONFIG, DEFAULT_DESIRED_STATE, DHCP_WORKER_OPS,
        KeaHAConfigError, UnsupportedHAMode, build_peers, load_cluster_config,
        normalize_mode, save_cluster_config,
    )
    from src.kea_cluster import KeaHACoordinator  # type: ignore
    from src.ha_pki import issue_member_material  # type: ignore

logger = logging.getLogger("DHCPSpoke")

#: Member fields that are credentials. Stored so the coordinator can render the
#: HA hook config, NEVER returned to the hub/WebUI.
_SECRET_MEMBER_FIELDS = ("ha_password", "worker_secret", "password")

#: Member fields the UI may omit on a re-submit because they are write-only.
#: Carried over from the persisted member of the same id instead of being
#: silently cleared — clearing the HA password would break the pair on the next
#: apply, with no way for the operator to see why.
_PRESERVED_MEMBER_FIELDS = ("ha_password", "ha_user", "ha_port", "ha_scheme",
                            "ha_url", "ha_trust_anchor", "ha_cert", "ha_key")


def _merge_preserved(new_members, old_members):
    """Carry write-only/omitted HA fields forward from the stored topology."""
    by_id = {m.get("id"): m for m in (old_members or []) if isinstance(m, dict)}
    out = []
    for member in new_members or []:
        if not isinstance(member, dict):
            out.append(member)
            continue
        previous = by_id.get(member.get("id")) or {}
        merged = dict(member)
        for field in _PRESERVED_MEMBER_FIELDS:
            if not merged.get(field) and previous.get(field):
                merged[field] = previous[field]
        out.append(merged)
    return out


def _redact_members(members):
    """Strip HA credentials from a member list before it leaves the spoke."""
    out = []
    for member in members or []:
        if not isinstance(member, dict):
            out.append(member)
            continue
        clean = {k: v for k, v in member.items() if k not in _SECRET_MEMBER_FIELDS}
        if any(k in member for k in _SECRET_MEMBER_FIELDS):
            clean["ha_password_set"] = bool(member.get("ha_password"))
        out.append(clean)
    return out


def _topology_fingerprint(members, mode):
    """Stable marker used to reject a stale staged enrollment."""
    payload = {"members": members or [], "mode": mode or "hot-standby"}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


class _DisabledTransport:
    """Null transport used when the core cluster module isn't available.

    ``dhcp`` and ``lm`` deploy independently, so a spoke can be newer than the
    core beside it. Degrading to single-host is correct; crashing is not.
    """

    enabled = False
    members: List[Dict[str, str]] = []

    def set_members(self, members):
        return []

    def member_ids(self):
        return []

    def member_links(self):
        return []

    async def fanout(self, command, data, timeout=20.0, member_ids=None):
        return {"status": "ERROR", "results": {}, "ok": [], "failed": [],
                "message": "cluster transport unavailable"}

    async def call(self, member_id, command, data, timeout=20.0):
        return {"status": "ERROR", "message": "cluster transport unavailable"}


class DHCPSpoke(BaseSpoke):
    """
    Kea DHCP4 spoke.

    Two deployment shapes, one command surface:

    * **Local (default, unchanged).** The spoke drives the Kea Control Agent on
      its own host.
    * **HA pair.** Two Kea hosts run ``lm-dhcp-worker`` and dial this spoke's
      ``/ws/agent`` listener. The spoke renders both node configs from one shared
      scope/reservation set, validates both, and applies standby-then-primary as
      a single transaction — see ``kea_cluster.py`` / ``kea_ha.py``. Enabled only
      when exactly two members are configured, so an existing single-host install
      behaves exactly as before.

    Commands:
      GET_VERSION        — spoke/version string
      DHCP_SYNC          — replace all subnets + reservations from NetBox data
      DHCP_LIST_SUBNETS  — list all managed subnets
      DHCP_LIST_LEASES   — list active leases (optional subnet CIDR filter)
      DHCP_LIST_RES      — list all static reservations across subnets
      DHCP_ADD_RES       — add a static reservation (ip+mac+subnet_id required)
      DHCP_UPDATE_RES    — replace a reservation (delete-then-add, non-atomic)
      DHCP_DEL_RES       — remove a static reservation by IP
      DHCP_STATUS        — Kea health + subnet count
      DHCP_STATS         — statistic-get-all pool utilization + packet counters
      DHCP_DIAGNOSTICS   — service/config/interface/listener/lease evidence
      DHCP_HA_STATUS     — HA member state, lease sync, drift, recommendations
      DHCP_HA_CONFIG     — set the HA member pair + mode (+ worker secret)
      DHCP_HA_APPLY      — re-apply the current desired config to both nodes
    """

    def __init__(self, spoke_id: str, config: Dict[str, Any]):
        super().__init__(spoke_id, config)
        ca_url = config.get("kea_ca_url", "http://localhost:8001")
        self.mgr = KeaManager(ca_url=ca_url)

        self._cluster_config_path = config.get(
            "cluster_config",
            os.getenv("LM_DHCP_CLUSTER_CONFIG", DEFAULT_CLUSTER_CONFIG))
        self._ha_pki_dir = config.get(
            "ha_pki_dir",
            os.getenv("LM_DHCP_HA_PKI_DIR", "/etc/lm-dhcp/ha-pki"))
        self._pending_enrollment_path = config.get(
            "pending_enrollment",
            os.getenv("LM_DHCP_PENDING_ENROLLMENT",
                      "/etc/lm-dhcp/pending-enrollment.json"))
        self._pending_enrollment = self._load_pending_enrollment()
        persisted = load_cluster_config(self._cluster_config_path)
        members = config.get("cluster_members")
        if members is None:
            members = persisted["members"]
        mode = config.get("ha_mode") or persisted["mode"]
        self._hook_dir = config.get("hook_dir") or persisted["hook_dir"] or ""
        self._transport = self._build_transport(members)
        self.cluster = KeaHACoordinator(
            self._transport, mode=mode, hook_dir=self._hook_dir,
            state_path=config.get(
                "desired_state",
                os.getenv("LM_DHCP_DESIRED_STATE", DEFAULT_DESIRED_STATE)))

    # ── Cluster plumbing ────────────────────────────────────────────────────

    def _build_transport(self, members):
        """Wrap the shared coordinator transport around this spoke's listener.

        Imported lazily: the transport lives in the LM ``core`` repo, which
        deploys independently of this one. A core without it leaves HA disabled
        instead of crashing a working single-host spoke.
        """
        try:
            try:
                from core.src.messaging.service_cluster import ClusterCoordinator
            except ImportError:
                from messaging.service_cluster import ClusterCoordinator  # type: ignore
        except ImportError:
            logger.info("Cluster transport unavailable in this core build — "
                        "DHCP stays single-host")
            return _DisabledTransport()
        return ClusterCoordinator("dhcp", DHCP_WORKER_OPS,
                                  lambda: getattr(self, "control_plane", None),
                                  members=members)

    def cluster_listener_required(self) -> bool:
        """Tells the control plane whether to bind the DHCP ``/ws/agent`` port.

        Only a real HA pair binds a port — a single-host DHCP role must never
        open a listener it has no use for.
        """
        return bool(self.cluster.enabled or self._pending_enrollment)

    def _load_pending_enrollment(self) -> Dict[str, Any]:
        try:
            with open(self._pending_enrollment_path, encoding="utf-8") as stream:
                data = json.load(stream)
            return data if isinstance(data, dict) else {}
        except FileNotFoundError:
            return {}
        except Exception as exc:  # noqa: BLE001
            logger.error("Could not load pending DHCP enrollment: %s", exc)
            return {}

    def _save_pending_enrollment(self, data: Dict[str, Any]) -> None:
        path = Path(self._pending_enrollment_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
        self._pending_enrollment = data

    def _clear_pending_enrollment(self) -> None:
        self._pending_enrollment = {}
        try:
            os.unlink(self._pending_enrollment_path)
        except FileNotFoundError:
            pass

    async def _enroll_workers(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Stage a discovered pair and return retry-stable node bootstraps."""
        raw = data.get("members")
        if not isinstance(raw, list) or len(raw) != 2:
            return {"status": "ERROR",
                    "message": "DHCP HA discovery requires exactly 2 members"}
        members = []
        seen = set()
        for index, item in enumerate(raw):
            if not isinstance(item, dict):
                return {"status": "ERROR", "message": "each member must be an object"}
            member_id = str(item.get("id") or item.get("member_id") or "").strip()
            host = str(item.get("host") or "").strip()
            if not member_id or not host or member_id in seen:
                return {"status": "ERROR",
                        "message": "each member needs a distinct id and host"}
            seen.add(member_id)
            members.append({
                "id": member_id,
                "host": host,
                "role": "primary" if index == 0 else "standby",
            })

        async with self.cluster.transaction():
            cp = getattr(self, "control_plane", None)
            worker_secret = (
                cp.snapshot_agent_secret()
                if cp is not None and hasattr(cp, "snapshot_agent_secret")
                else "")
            worker_secret = (
                str(worker_secret or "").strip() or secrets.token_urlsafe(32))
            pending = self._pending_enrollment
            same_pair = [
                (m.get("id"), m.get("host")) for m in pending.get("members", [])
            ] == [(m["id"], m["host"]) for m in members]
            old_members = list(getattr(self._transport, "members", []) or [])
            ha_user = (
                str(pending.get("ha_user") or "").strip() if same_pair else ""
            ) or next(
                (str(m.get("ha_user") or "").strip() for m in old_members
                 if str(m.get("ha_user") or "").strip()),
                "kea-ha")
            ha_password = (
                str(pending.get("ha_password") or "") if same_pair else ""
            ) or next(
                (str(m.get("ha_password") or "") for m in old_members
                 if str(m.get("ha_password") or "")),
                secrets.token_urlsafe(32))
            for member in members:
                member.update({
                    "ha_user": ha_user,
                    "ha_password": ha_password,
                    "ha_trust_anchor": "/etc/kea/ha-tls/ha-ca.pem",
                    "ha_cert": "/etc/kea/ha-tls/node.crt",
                    "ha_key": "/etc/kea/ha-tls/node.key",
                })
            try:
                build_peers(members, "hot-standby")
            except KeaHAConfigError as exc:
                return {"status": "ERROR", "message": str(exc)}
            self._save_pending_enrollment({
                "members": members,
                "ha_user": ha_user,
                "ha_password": ha_password,
                "base_topology": _topology_fingerprint(
                    old_members, self.cluster.mode),
            })
            if cp is None or not hasattr(cp, "set_agent_secret"):
                return {"status": "ERROR",
                        "message": "DHCP cluster control plane is unavailable"}
            if not cp.set_agent_secret(worker_secret):
                return {
                    "status": "ERROR",
                    "message": "DHCP worker secret could not be persisted",
                }
            listener = await cp.ensure_cluster_listener()
            if not listener.get("ok"):
                return {"status": "ERROR", "listener": listener,
                        "message": "the DHCP cluster listener did not start: "
                                   + (listener.get("error") or "unknown error")}

            cert_path = Path(str(
                getattr(cp, "_listener_cert", "") or
                "/etc/lm-dhcp/tls/coordinator.crt"))
            try:
                coordinator_ca_pem = cert_path.read_text(encoding="utf-8")
            except OSError as exc:
                return {"status": "ERROR",
                        "message": f"could not read DHCP coordinator certificate: {exc}"}
            if "-----BEGIN CERTIFICATE-----" not in coordinator_ca_pem:
                return {"status": "ERROR",
                        "message": "DHCP coordinator certificate is invalid"}

            bootstraps = {}
            try:
                for member in members:
                    material = await asyncio.to_thread(
                        issue_member_material, self._ha_pki_dir,
                        member["id"], member["host"])
                    bootstraps[member["id"]] = {
                        **material,
                        "ha_user": ha_user,
                        "ha_password": ha_password,
                        "member_id": member["id"],
                        "coordinator": socket.getfqdn() or socket.gethostname(),
                        "worker_secret": worker_secret,
                        "coordinator_ca_pem": coordinator_ca_pem,
                        "ha_peers": [
                            m["host"] for m in members
                            if m["id"] != member["id"]],
                    }
            except Exception as exc:  # noqa: BLE001
                logger.exception("Could not issue DHCP HA member certificates")
                return {"status": "ERROR",
                        "message": f"could not issue DHCP HA certificates: {exc}"}
            return {"status": "SUCCESS", "pending": True,
                    "members": _redact_members(members), "workers": bootstraps}

    async def _commit_worker_enrollment(self) -> Dict[str, Any]:
        async with self.cluster.transaction():
            pending = self._pending_enrollment
            members = pending.get("members") or []
            if len(members) != 2:
                return {"status": "ERROR",
                        "message": "No DHCP enrollment is pending"}
            current_topology = _topology_fingerprint(
                self._transport.members, self.cluster.mode)
            if pending.get("base_topology") != current_topology:
                return {
                    "status": "ERROR",
                    "message": "DHCP topology changed while enrollment was "
                               "pending; run discovery again",
                }
            cp = getattr(self, "control_plane", None)
            connected = set((getattr(cp, "connected_agents", None) or {}).keys())
            missing = [m["id"] for m in members if m["id"] not in connected]
            if missing:
                return {"status": "ERROR", "waiting": missing,
                        "message": "Waiting for DHCP workers: " + ", ".join(missing)}
            result = await self._apply_ha_config_locked(
                members, {"members": members, "mode": "hot-standby"})
            if result.get("status") in ("SUCCESS", "PARTIAL"):
                self._clear_pending_enrollment()
            return result

    async def _apply_ha_config(
            self, data: Dict[str, Any], *, cancel_pending: bool = False
    ) -> Dict[str, Any]:
        """``DHCP_HA_CONFIG`` — declare the Kea pair and the HA mode.

        Write-only fields (``worker_secret``, per-member ``ha_password``) are
        never echoed back, and an omitted one is CARRIED FORWARD from the stored
        topology rather than cleared — a UI that cannot read a secret must not
        be able to erase it by re-saving the form.

        Enabling a pair for the first time REQUIRES an explicit
        ``worker_secret``: the spoke will not mint one, because a generated
        value the operator can never read cannot be given to the workers.

        Everything is validated and journalled candidate-first: on any failure
        the previous members, mode and hook dir are restored in memory so the
        live coordinator never ends up on a half-applied topology.
        """
        raw = data.get("members")
        if raw is None:
            return {"status": "ERROR", "message": "members is required"}
        if not isinstance(raw, list):
            return {"status": "ERROR", "message": "members must be a list"}
        # ONE critical section for validate → persist → rebind → stand down,
        # sharing the lock every apply/reservation takes: a topology edit must
        # never interleave with a config apply (which would then push to, or
        # stand down, a node the other transaction is mid-way through).
        async with self.cluster.transaction():
            result = await self._apply_ha_config_locked(raw, data)
            if cancel_pending and result.get("status") in ("SUCCESS", "PARTIAL"):
                self._clear_pending_enrollment()
            return result

    async def _apply_ha_config_locked(self, raw, data) -> Dict[str, Any]:
        previous = {
            "members": [dict(m) for m in self._transport.members],
            "mode": self.cluster.mode,
            "hook_dir": self._hook_dir,
        }

        def _restore():
            self._transport.set_members(previous["members"])
            self.cluster.mode = previous["mode"]
            self._hook_dir = previous["hook_dir"]
            self.cluster.hook_dir = previous["hook_dir"]

        merged = _merge_preserved(raw, previous["members"])
        members = self._transport.set_members(merged)
        if raw and not members:
            _restore()
            return {"status": "ERROR",
                    "message": "no usable members — each needs a non-empty id"}
        if "mode" in data:
            try:
                self.cluster.mode = normalize_mode(data.get("mode"))
            except UnsupportedHAMode as e:
                _restore()
                return {"status": "ERROR", "message": str(e),
                        "supported_modes": ["hot-standby"]}
        if "hook_dir" in data:
            self._hook_dir = str(data.get("hook_dir") or "")
            self.cluster.hook_dir = self._hook_dir

        # Reject a topology Kea itself would refuse BEFORE persisting it, so the
        # spoke never comes back from a restart holding an unusable pair.
        if members:
            try:
                self.cluster.peers()
            except KeaHAConfigError as e:
                _restore()
                return {"status": "ERROR", "message": str(e)}

        # Enabling requires a usable worker PSK. Refuse rather than mint one.
        cp = getattr(self, "control_plane", None)
        secret = str(data.get("worker_secret") or "").strip()
        enabling = len(members) >= 2
        have_secret = bool(getattr(cp, "agent_secret", "") or "")
        if enabling and not secret and not have_secret:
            _restore()
            return {"status": "ERROR", "secret_required": True,
                    "message": ("A worker secret is required to enable the Kea HA "
                                "pair. Supply the same value here and to each "
                                "node's installer (--worker-secret); it is "
                                "stored write-only and never displayed again.")}

        # Enabling ALSO requires HA control credentials on every node. The HA
        # control agent rejects an unauthenticated peer, so a pair configured
        # without them can never heartbeat — it would come up looking
        # configured and silently never synchronise. ``_merge_preserved`` has
        # already carried forward anything the caller omitted, so reaching here
        # without them means they were never set.
        if enabling:
            missing = [m["id"] for m in members
                       if not (str(m.get("ha_user") or "").strip()
                               and str(m.get("ha_password") or ""))]
            if missing:
                _restore()
                return {"status": "ERROR", "ha_credentials_required": True,
                        "members_missing_credentials": missing,
                        "message": (
                            "HA control credentials are required for: "
                            + ", ".join(missing)
                            + ". The Kea HA control agent rejects an "
                              "unauthenticated peer, so the pair could never "
                              "heartbeat. Supply ha_user + ha_password (the same "
                              "values passed to each node's installer as "
                              "--ha-user/--ha-password); the password is stored "
                              "write-only and preserved when you re-save without "
                              "retyping it.")}

        removing = [m["id"] for m in previous["members"]
                    if m.get("id") not in {n["id"] for n in members}]
        try:
            save_cluster_config(self._cluster_config_path, members,
                                self.cluster.mode, self._hook_dir)
        except Exception as e:  # noqa: BLE001
            _restore()
            return {"status": "ERROR",
                    "message": f"could not persist HA config: {e}"}

        # Stage the PSK: capture the one in force so any later failure can put
        # it back. Overwriting it and then rolling the topology back (the old
        # behaviour) left every already-provisioned worker unable to
        # authenticate against a coordinator whose config had been reverted.
        previous_secret = None
        if secret and cp is not None and hasattr(cp, "set_agent_secret"):
            if hasattr(cp, "snapshot_agent_secret"):
                previous_secret = cp.snapshot_agent_secret()
            cp.set_agent_secret(secret)

        def _restore_secret():
            if previous_secret is not None and hasattr(cp, "restore_agent_secret"):
                cp.restore_agent_secret(previous_secret)

        listener = {"ok": True, "serving": False, "endpoint": "", "error": ""}
        if cp is not None and hasattr(cp, "ensure_cluster_listener"):
            listener = await cp.ensure_cluster_listener() or listener
            if isinstance(listener, bool):        # older core: no readiness
                listener = {"ok": listener, "serving": listener,
                            "endpoint": "", "error": ""}
        if enabling and not listener.get("ok"):
            # The Kea workers can never reach a listener that did not start, so
            # SUCCESS here would be a lie the operator only discovers when
            # nothing converges. Roll the credential back with the topology.
            _restore()
            _restore_secret()
            try:
                save_cluster_config(self._cluster_config_path,
                                    previous["members"], previous["mode"],
                                    previous["hook_dir"])
            except Exception:  # noqa: BLE001
                pass
            return {"status": "ERROR", "listener": listener,
                    "message": (f"the DHCP cluster listener did not start: "
                                f"{listener.get('error') or 'unknown error'}")}

        stood_down, unreachable = await self._standdown_removed(removing)
        result = {"status": "SUCCESS", "members": _redact_members(members),
                  "mode": self.cluster.mode,
                  "cluster_enabled": self.cluster.enabled,
                  "listener": {**self._listener_hint(), **listener}}
        if removing:
            result["removed"] = removing
            result["removed_stood_down"] = stood_down
            result["removed_unreachable"] = unreachable
            if unreachable:
                result["status"] = "PARTIAL"
                result["message"] = (
                    "Topology saved, but these removed node(s) could not be "
                    "deconfigured and may still be running the HA hooks: "
                    + ", ".join(unreachable)
                    + ". Run install_dhcp.sh --stand-down on them, or stop "
                      "lm-dhcp-worker + kea-ha-agent there.")
        return result

    async def _standdown_removed(self, removed):
        """Ask removed nodes to leave the pair; report the ones we could not."""
        stood_down, unreachable = [], []
        for member_id in removed or []:
            reply = await self._transport.call(member_id, "KEAW_STANDDOWN", {},
                                               timeout=20.0)
            if isinstance(reply, dict) and reply.get("status") == "SUCCESS":
                stood_down.append(member_id)
            else:
                unreachable.append(member_id)
        return stood_down, unreachable

    def _listener_hint(self) -> Dict[str, Any]:
        cp = getattr(self, "control_plane", None)
        return {"port": int(os.environ.get("LM_DHCP_AGENT_PORT", "8770")),
                "path": "/ws/agent",
                "serving": bool(getattr(cp, "_agent_server_task", None))}

    async def _ha_diagnostics(self) -> Dict[str, Any]:
        """Per-node diagnostics + the HA view.

        Top-level evidence comes from ONE named node (``diagnostics_source``) so
        the existing Diagnostics panels keep rendering real data; ``healthy``
        requires every node healthy AND the pair in sync.
        """
        report = (await self.cluster.status()).copy()
        report.pop("status", None)
        fan = await self._transport.fanout("KEAW_DIAGNOSTICS", {}, timeout=25.0)
        per_member: Dict[str, Any] = {}
        for member_id, reply in (fan.get("results") or {}).items():
            per_member[member_id] = reply if isinstance(reply, dict) else {
                "status": "ERROR", "message": "malformed reply"}

        source = next((m["id"] for m in report.get("members", [])
                       if (per_member.get(m["id"]) or {}).get("status") == "SUCCESS"), "")
        base: Dict[str, Any] = dict(per_member.get(source) or {})
        base.pop("member_id", None)
        recommendations: List[str] = []
        for member_id, diag in per_member.items():
            if diag.get("status") != "SUCCESS":
                recommendations.append(
                    f"[{member_id}] diagnostics unavailable: "
                    f"{diag.get('message') or 'no response'}")
                continue
            for rec in diag.get("recommendations") or []:
                recommendations.append(f"[{member_id}] {rec}")
        recommendations.extend(report.get("recommendations") or [])

        members_healthy = bool(per_member) and all(
            d.get("status") == "SUCCESS" and d.get("healthy")
            for d in per_member.values())
        return {
            **base,
            "status": "SUCCESS",
            "healthy": bool(members_healthy and report.get("healthy")),
            "diagnostics_source": source,
            "cluster": report,
            "members": per_member,
            "recommendations": recommendations,
        }

    async def _ha_stats(self) -> Dict[str, Any]:
        """Per-node Kea statistics plus summed pool/packet totals."""
        fan = await self._transport.fanout("KEAW_STATS", {}, timeout=20.0)
        per_member: Dict[str, Any] = {}
        totals = {"total_addresses": 0, "assigned_addresses": 0,
                  "declined_addresses": 0, "pkt4_received": 0,
                  "pkt4_discover": 0, "pkt4_request": 0, "pkt4_offer_sent": 0,
                  "pkt4_ack_sent": 0, "pkt4_nak_sent": 0}
        subnets: List[Dict[str, Any]] = []
        for member_id, reply in (fan.get("results") or {}).items():
            per_member[member_id] = reply
            if not isinstance(reply, dict) or reply.get("status") != "SUCCESS":
                continue
            g = reply.get("global") or {}
            for key in totals:
                totals[key] += int(g.get(key) or 0)
            for sub in reply.get("subnets") or []:
                subnets.append({**sub, "member_id": member_id})
        # Pool capacity is the SAME address space on both nodes — summing it
        # would double-count. Report one node's view of capacity/usage.
        node_count = max(1, sum(1 for r in per_member.values()
                                if isinstance(r, dict) and r.get("status") == "SUCCESS"))
        for key in ("total_addresses", "assigned_addresses", "declined_addresses"):
            totals[key] = totals[key] // node_count
        totals["utilization_pct"] = (
            round(totals["assigned_addresses"] / totals["total_addresses"] * 100, 1)
            if totals["total_addresses"] else 0.0)
        return {"status": "SUCCESS", "global": totals, "subnets": subnets,
                "cluster": True, "members": per_member}

    async def _ha_list(self, command: str, payload: Dict[str, Any],
                       list_key: str) -> Dict[str, Any]:
        """Read a list from the HA pair.

        Both nodes hold the same scopes and (in hot-standby) the same lease
        database, so results are merged on identity and duplicates dropped. A
        node that fails is surfaced in ``member_errors`` rather than silently
        shrinking the answer.
        """
        fan = await self._transport.fanout(command, payload, timeout=20.0)
        merged: List[Any] = []
        seen = set()
        errors: Dict[str, str] = {}
        for member_id, reply in (fan.get("results") or {}).items():
            if not isinstance(reply, dict) or reply.get("status") != "SUCCESS":
                errors[member_id] = (reply or {}).get("message") or "no response"
                continue
            for item in reply.get(list_key) or []:
                if isinstance(item, dict):
                    key = (item.get("ip") or item.get("ip-address")
                           or item.get("address") or item.get("subnet")
                           or repr(sorted(item.items(), key=str)))
                else:
                    key = repr(item)
                if key in seen:
                    continue
                seen.add(key)
                merged.append(item)
        return {"status": "SUCCESS", list_key: merged, "cluster": True,
                "member_errors": errors}

    async def _ha_reservation(self, cmd: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Reservation CRUD in HA mode = re-render + re-apply BOTH nodes.

        A reservation lives in Kea's config, so changing it on one node only
        would put the pair out of sync. The read-modify-write happens INSIDE the
        coordinator's transaction lock (``mutate_reservation``) — doing it here,
        before the lock, let two concurrent edits start from the same base and
        the second silently discard the first.
        """
        action = "delete" if cmd == "DHCP_DEL_RES" else "upsert"
        return await self.cluster.mutate_reservation(action, data)

    async def handle_command(self, command_type: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Dispatch a hub command to the Kea manager.

        Every ``KeaManager`` call is offloaded to a worker thread via
        ``asyncio.to_thread``: the Kea Control Agent speaks sync HTTP
        (``requests``) and ``DHCP_SYNC`` chains 3–4 RPCs, while this role
        shares one event loop with the dns + base role sub-spokes — a slow
        or hung Kea CA would otherwise block every in-flight request across
        all three sub-spokes.
        """
        cmd = command_type.upper()

        if cmd == "GET_VERSION":
            return {"status": "SUCCESS", "version": self.get_version()}

        if cmd == "DHCP_HA_CONFIG":
            return await self._apply_ha_config(data, cancel_pending=True)

        if cmd == "DHCP_HA_ENROLL_WORKERS":
            return await self._enroll_workers(data)

        if cmd == "DHCP_HA_COMMIT_ENROLLMENT":
            return await self._commit_worker_enrollment()

        if cmd == "DHCP_HA_STATUS":
            if not self.cluster.enabled:
                return {"status": "SUCCESS", "enabled": False, "members": [],
                        "member_count": 0, "mode": self.cluster.mode,
                        "supported_modes": ["hot-standby"],
                        "reason": "no Kea HA pair configured"}
            return await self.cluster.status()

        if cmd == "DHCP_HA_APPLY":
            if not self.cluster.enabled:
                return {"status": "ERROR", "message": "Kea HA is not enabled"}
            desired = self.cluster.desired
            # Refuse a re-apply with nothing to apply. The desired intent is
            # repopulated by DHCP_SYNC (the NetBox loop or the Sync button); a
            # coordinator restarted before its first sync would otherwise push
            # an EMPTY subnet4 to both nodes and take DHCP down fleet-wide.
            if not desired.get("subnets"):
                return {"status": "ERROR", "message":
                        "No synchronised DHCP configuration to re-apply — run a "
                        "DHCP sync first."}
            return await self.cluster.apply(desired.get("subnets") or [],
                                            desired.get("reservations") or [])

        # ── HA path: both nodes are configured as one transaction ───────────
        if self.cluster.enabled:
            if cmd == "DHCP_SYNC":
                return await self.cluster.apply(data.get("subnets", []),
                                                data.get("reservations", []))
            if cmd in ("DHCP_ADD_RES", "DHCP_UPDATE_RES", "DHCP_DEL_RES"):
                return await self._ha_reservation(cmd, data)
            if cmd == "DHCP_LIST_SUBNETS":
                return await self._ha_list("KEAW_LIST_SUBNETS", {}, "subnets")
            if cmd == "DHCP_LIST_LEASES":
                return await self._ha_list("KEAW_LIST_LEASES",
                                           {"subnet": data.get("subnet")}, "leases")
            if cmd == "DHCP_LIST_RES":
                return await self._ha_list("KEAW_LIST_RES", {}, "reservations")
            if cmd == "DHCP_DIAGNOSTICS":
                return await self._ha_diagnostics()
            if cmd == "DHCP_STATS":
                return await self._ha_stats()
            if cmd == "DHCP_STATUS":
                report = await self.cluster.status()
                return {"status": "SUCCESS",
                        "running": bool(report.get("healthy")),
                        "subnet_count": max(
                            [m.get("subnet_count") or 0
                             for m in report.get("members", [])] or [0]),
                        "ca_url": self.mgr.ca_url,
                        "cluster": {k: v for k, v in report.items()
                                    if k != "status"}}

        # KeaManager does sync requests.post to the Kea Control Agent (10s
        # timeout) under every method, and DHCP_SYNC chains config-get +
        # config-set + config-write + subnet4-list (3-4 RPCs). This role runs
        # on the lm-svcs agent's ONE shared event loop alongside the dns + base
        # role sub-spokes; a slow/hung Kea CA blocks the whole loop and the
        # hub's 5s request_response fires for every in-flight request across
        # all three sub-spokes at once. Offload each mgr call to a worker thread
        # so the loop keeps servicing the other roles + the hub link.
        if cmd == "DHCP_SYNC":
            subnets      = data.get("subnets", [])
            reservations = data.get("reservations", [])
            return await asyncio.to_thread(self.mgr.sync, subnets, reservations)

        if cmd == "DHCP_LIST_SUBNETS":
            subnets = await asyncio.to_thread(self.mgr.list_subnets)
            return {"status": "SUCCESS", "subnets": subnets}

        if cmd == "DHCP_LIST_LEASES":
            subnet = data.get("subnet")
            leases = await asyncio.to_thread(self.mgr.list_leases, subnet)
            return {"status": "SUCCESS", "leases": leases}

        if cmd == "DHCP_ADD_RES":
            subnet_id = data.get("subnet_id")
            ip        = data.get("ip")
            mac       = data.get("mac")
            hostname  = data.get("hostname", "")
            if not all([subnet_id, ip, mac]):
                return {"status": "ERROR", "message": "subnet_id, ip, and mac are required"}
            return await asyncio.to_thread(self.mgr.add_reservation, int(subnet_id), ip, mac, hostname)

        if cmd == "DHCP_LIST_RES":
            reservations = await asyncio.to_thread(self.mgr.list_reservations)
            return {"status": "SUCCESS", "reservations": reservations}

        if cmd == "DHCP_UPDATE_RES":
            old_ip    = data.get("old_ip") or data.get("ip")
            subnet_id = data.get("subnet_id")
            ip        = data.get("ip")
            mac       = data.get("mac")
            hostname  = data.get("hostname", "")
            if not old_ip:
                return {"status": "ERROR", "message": "old_ip is required"}
            if not all([subnet_id, ip, mac]):
                return {"status": "ERROR", "message": "subnet_id, ip, and mac are required"}
            return await asyncio.to_thread(self.mgr.update_reservation, old_ip, int(subnet_id), ip, mac, hostname)

        if cmd == "DHCP_DEL_RES":
            ip = data.get("ip")
            if not ip:
                return {"status": "ERROR", "message": "ip is required"}
            return await asyncio.to_thread(self.mgr.delete_reservation, ip)

        if cmd == "DHCP_STATUS":
            s = await asyncio.to_thread(self.mgr.status)
            return {"status": "SUCCESS", **s}

        if cmd == "DHCP_DIAGNOSTICS":
            return await asyncio.to_thread(self.mgr.diagnostics)

        if cmd == "DHCP_STATS":
            return await asyncio.to_thread(self.mgr.get_stats)

        return {"status": "ERROR", "error": f"Unknown command: {command_type}"}

    async def get_status(self) -> Dict[str, Any]:
        # Polled by the hub for telemetry — offload the sync Kea CA RPC off the
        # shared loop (same reason as handle_command).
        if self.cluster.enabled:
            report = self.cluster.report()
            reachable = report["member_count"] - len(report["unreachable"])
            return {
                "spoke_id":     self.spoke_id,
                "module":       "dhcp",
                "kea":          "ha-pair",
                "subnet_count": max([m.get("subnet_count") or 0
                                     for m in report["members"]] or [0]),
                "cluster": {
                    "mode":      report["mode"],
                    "members":   report["member_count"],
                    "connected": reachable,
                    "state":     report["state"],
                    "config_converged": report["config_converged"],
                },
                # Only a fully in-sync pair on matching config is healthy — a
                # half-configured pair must never render green.
                "status": "HEALTHY" if report["healthy"] else "DEGRADED",
            }
        s = await asyncio.to_thread(self.mgr.status)
        out = {
            "spoke_id":     self.spoke_id,
            "module":       "dhcp",
            "kea":          "running" if s["running"] else "stopped",
            "subnet_count": s["subnet_count"],
            "status":       "HEALTHY" if s["running"] else "DEGRADED",
        }
        # Carry the reason for a down CA into the telemetry frame so the hub
        # surfaces it (single, deduped) instead of just "stopped".
        if s.get("error"):
            out["error"] = s["error"]
        return out

    def get_version(self) -> str:
        from pathlib import Path
        try:
            return (Path(__file__).parent.parent / "VERSION").read_text().strip()
        except Exception:
            return "unknown"
