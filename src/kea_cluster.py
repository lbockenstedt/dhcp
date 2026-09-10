"""Kea HA orchestration — the coordinator half of a two-node DHCP pair.

Owns the *shared* DHCP intent (subnets + reservations), renders the two
node-specific configs **on top of each node's own running configuration**, and
drives the apply as a single serialized transaction:

1. **Install hooks** on both nodes (idempotent). A node missing
   ``libdhcp_ha.so``/``libdhcp_lease_cmds.so`` cannot be part of a pair, so this
   is checked before anything is generated.
2. **Read each node's full config** (``KEAW_GET_CONFIG``) and replace ONLY the
   coordinator-owned keys (``subnet4``) plus the HA hook entries. Interfaces,
   lease database, loggers, client classes and every other node-local setting
   survive verbatim — rendering from ``{}`` would wipe them.
3. **Validate both** candidate configs with Kea's own ``config-test``. If either
   node rejects its config, NOTHING is applied.
4. **Apply standby/secondary first, then primary.** A failure aborts and rolls
   back every node that could have been mutated — including the node that just
   failed, whose ``config-set`` may have landed before its ``config-write``.

The desired intent + version are a **candidate** until the whole transaction
succeeds: a failed apply cannot poison a later mutation, and the promoted state
is persisted durably before the verdict is returned.

Every mutation runs under one asyncio lock, so two concurrent syncs can never
interleave a validate from one with an apply from the other.
"""

import asyncio
import json
import logging
import os
import time
from typing import Any, Dict, Iterable, List, Optional

try:
    from kea_ha import (
        DEFAULT_DESIRED_STATE, KeaHAConfigError, apply_order, build_node_config,
        build_peers, coerce_mode, config_fingerprint, parse_ha_status,
        resolve_hook_dir, summarize_ha,
    )
    from kea_manager import build_subnet4
except ImportError:  # loaded as a package (src.X) by the sibling entrypoint
    from src.kea_ha import (  # type: ignore
        DEFAULT_DESIRED_STATE, KeaHAConfigError, apply_order, build_node_config,
        build_peers, coerce_mode, config_fingerprint, parse_ha_status,
        resolve_hook_dir, summarize_ha,
    )
    from src.kea_manager import build_subnet4  # type: ignore

logger = logging.getLogger("KeaCluster")


class KeaHACoordinator:
    """Renders + applies a two-node HA config over the cluster transport.

    ``transport`` is anything exposing the ``ClusterCoordinator`` surface
    (``enabled``, ``member_ids``, ``member_links``, ``fanout``, ``call``), so the
    orchestration is testable without a websocket.
    """

    def __init__(self, transport, mode: str = "", hook_dir: str = "",
                 state_path: str = ""):
        self.transport = transport
        self.mode = coerce_mode(mode)
        # Empty means "resolve on the node" — the multiarch triplet differs per
        # host, so the coordinator must not bake in its own.
        self.hook_dir = hook_dir or ""
        self.state_path = state_path or os.getenv("LM_DHCP_DESIRED_STATE",
                                                  DEFAULT_DESIRED_STATE)
        #: Last COMMITTED shared intent — only ever advanced by a fully
        #: successful apply, so a failed transaction cannot poison the next one.
        self.desired: Dict[str, Any] = {"subnets": [], "reservations": []}
        self.version = 0
        self.last_apply: Dict[str, Any] = {}
        #: A candidate journalled to disk but not yet promoted. Set on load when
        #: the process died mid-transaction; the pair may be running it, the
        #: committed record may be a version behind, and only a re-apply can
        #: resolve that. Surfaced in :meth:`report` until an apply clears it.
        self.pending_candidate: Optional[Dict[str, Any]] = None
        self.config_digests: Dict[str, str] = {}
        self.ha_status: Dict[str, Dict[str, Any]] = {}
        #: Serializes the whole install→read→validate→apply transaction. Two
        #: concurrent syncs would otherwise interleave one's validate with the
        #: other's apply and leave the pair on a config neither node validated.
        #: Created lazily: the coordinator is constructed at module-load time,
        #: which on 3.9-era loop semantics is outside any running loop.
        self._lock: Optional[asyncio.Lock] = None
        self._load_state()

    def _get_lock(self) -> asyncio.Lock:
        if self._lock is None:
            self._lock = asyncio.Lock()
        return self._lock

    def transaction(self):
        """The SAME lock every apply/reservation/status-apply takes.

        Exposed so the spoke can run a topology change (validate → persist →
        rebind → stand down removed nodes) as one critical section with the
        config applies. Without it a topology edit could land between an apply's
        validate and its commit, and the apply would then push to a member list
        that no longer exists — or stand down a node mid-apply."""
        return self._get_lock()

    # ── Durable desired state ───────────────────────────────────────────────

    def _load_state(self) -> None:
        """Reload the committed intent + any un-promoted candidate.

        A corrupt/unreadable file leaves the coordinator at version 0 with no
        intent, which the ``DHCP_HA_APPLY`` guard treats as "nothing to
        re-apply" — never as "apply an empty config".

        A ``pending`` block means the process died between journalling a
        candidate and promoting it: the nodes may already be running the
        candidate while the committed record is a version behind. That is
        surfaced (not silently discarded) so an operator re-applies rather than
        trusting a version nobody verified.
        """
        if not self.state_path or not os.path.exists(self.state_path):
            return
        try:
            with open(self.state_path) as fh:
                data = json.load(fh)
            if not isinstance(data, dict):
                raise ValueError("desired state is not an object")
            subnets = data.get("subnets")
            reservations = data.get("reservations")
            if not isinstance(subnets, list) or not isinstance(reservations, list):
                raise ValueError("desired state subnets/reservations must be lists")
            self.desired = {"subnets": subnets, "reservations": reservations}
            self.version = int(data.get("version") or 0)
            pending = data.get("pending")
            if isinstance(pending, dict) and pending.get("version"):
                self.pending_candidate = pending
                logger.error(
                    "DHCP HA desired state carries an un-promoted candidate "
                    "(v%s journalled at %s): the pair may be running it while "
                    "the committed record is v%s. Re-apply to converge.",
                    pending.get("version"), pending.get("started_at"),
                    self.version)
        except Exception as e:  # noqa: BLE001
            logger.warning("Could not load DHCP desired state from %s: %s — "
                           "starting with no committed intent",
                           self.state_path, e)
            self.desired = {"subnets": [], "reservations": []}
            self.version = 0
            self.pending_candidate = None

    def _write_state(self, payload: Dict[str, Any]) -> None:
        """Atomic + fsynced write of the whole state document. Raises."""
        if not self.state_path:
            return
        directory = os.path.dirname(self.state_path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        tmp = self.state_path + ".tmp"
        with open(tmp, "w") as fh:
            json.dump(payload, fh)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, self.state_path)

    def _journal_candidate(self, subnets: List[Any], reservations: List[Any],
                           version: int) -> None:
        """Durably record the candidate BEFORE any node is touched. Raises.

        Without this, a coordinator that crashed mid-apply came back believing
        the OLD version was live while one or both nodes were running the new
        one — and the next mutation would build on the wrong base. The journal
        makes that state detectable on restart.
        """
        self._write_state({
            "version": self.version, "mode": self.mode,
            "subnets": self.desired.get("subnets") or [],
            "reservations": self.desired.get("reservations") or [],
            "updated_at": time.time(),
            "pending": {"version": version, "subnets": subnets,
                        "reservations": reservations, "started_at": time.time()},
        })

    def _promote_candidate(self, subnets: List[Any], reservations: List[Any],
                           version: int) -> None:
        """Commit the candidate and clear the journal. Raises on failure."""
        self._write_state({
            "version": version, "mode": self.mode, "subnets": subnets,
            "reservations": reservations, "updated_at": time.time(),
            "pending": None,
        })

    def _retain_candidate(self, version: int, unrestored: List[str]) -> None:
        """Persist the un-promoted candidate + which nodes may still hold it."""
        try:
            self._write_state({
                "version": self.version, "mode": self.mode,
                "subnets": self.desired.get("subnets") or [],
                "reservations": self.desired.get("reservations") or [],
                "updated_at": time.time(),
                "pending": {"version": version, "started_at": time.time(),
                            "unrestored": list(unrestored),
                            "subnets": self.desired.get("subnets") or [],
                            "reservations": self.desired.get("reservations") or []},
            })
        except Exception as e:  # noqa: BLE001
            logger.error("Could not retain the DHCP HA candidate journal at %s: "
                         "%s — a restart will not know %s may be ahead",
                         self.state_path, e, ", ".join(unrestored))

    def _clear_candidate(self) -> None:
        """Best-effort journal clear after a CONFIRMED full restore."""
        try:
            self._write_state({
                "version": self.version, "mode": self.mode,
                "subnets": self.desired.get("subnets") or [],
                "reservations": self.desired.get("reservations") or [],
                "updated_at": time.time(), "pending": None,
            })
            self.pending_candidate = None
        except Exception as e:  # noqa: BLE001
            logger.error("Could not clear the DHCP HA candidate journal at %s: "
                         "%s — the next start will report a pending candidate",
                         self.state_path, e)

    @property
    def enabled(self) -> bool:
        return bool(getattr(self.transport, "enabled", False))

    def members(self) -> List[Dict[str, Any]]:
        return list(getattr(self.transport, "members", []) or [])

    def peers(self) -> List[Dict[str, Any]]:
        """The validated Kea peer list. Raises :class:`KeaHAConfigError`."""
        return build_peers(self.members(), self.mode)

    # ── Config rendering ────────────────────────────────────────────────────

    def owned_config(self, subnets: Iterable[Any],
                     reservations: Iterable[Any]) -> Dict[str, Any]:
        """The coordinator-owned slice both nodes must share, identically."""
        kea_subnets, applied, skipped = build_subnet4(list(subnets or []),
                                                      list(reservations or []))
        return {"subnet4": kea_subnets, "_applied": applied, "_skipped": skipped}

    def render(self, subnets: Iterable[Any], reservations: Iterable[Any],
               node_configs: Optional[Dict[str, Dict[str, Any]]] = None
               ) -> Dict[str, Any]:
        """Build the per-node configs from one shared scope/reservation set.

        ``node_configs`` maps member id → that node's CURRENT ``Dhcp4`` config;
        everything the coordinator does not own is carried through from it.
        :meth:`apply` always reads every node first and refuses to proceed if any
        read failed, so a real apply never renders from an empty base.
        """
        peers = build_peers(self.members(), self.mode)
        owned = self.owned_config(subnets, reservations)
        applied, skipped = owned.pop("_applied"), owned.pop("_skipped")
        node_configs = node_configs or {}
        configs = {
            p["name"]: build_node_config(node_configs.get(p["name"]) or {},
                                         p["name"], peers, self.mode,
                                         self.hook_dir, owned=owned)
            for p in peers
        }
        return {
            "peers": peers,
            "configs": configs,
            "order": apply_order(peers),
            "subnets": len(owned["subnet4"]),
            "reservations": applied,
            "reservations_skipped": skipped,
            "digest": config_fingerprint(owned),
        }

    # ── Apply ───────────────────────────────────────────────────────────────

    async def apply(self, subnets: Iterable[Any], reservations: Iterable[Any],
                    timeout: float = 40.0) -> Dict[str, Any]:
        """Serialized transaction: hooks → read → validate both → standby, primary."""
        async with self._get_lock():
            return await self._apply_locked(list(subnets or []),
                                            list(reservations or []), timeout)

    async def mutate_reservation(self, action: str, data: Dict[str, Any],
                                 timeout: float = 40.0) -> Dict[str, Any]:
        """Add/update/delete one reservation, read-modify-write UNDER the lock.

        The read (of ``self.desired``) and the write must be inside the same
        critical section as the apply: computing the new list before taking the
        lock let two concurrent reservation edits each start from the same base
        and the second silently drop the first.
        """
        async with self._get_lock():
            desired = self.desired
            if not desired.get("subnets"):
                return {"status": "ERROR", "cluster": True, "message":
                        "The HA pair has no synchronised subnets yet — run a DHCP "
                        "sync before managing reservations."}
            ip = data.get("ip")
            if not ip:
                return {"status": "ERROR", "cluster": True,
                        "message": "ip is required"}
            old_ip = data.get("old_ip") or ip
            reservations = [r for r in (desired.get("reservations") or [])
                            if r.get("ip") not in (old_ip, ip)]
            if action != "delete":
                mac = data.get("mac")
                if not mac:
                    return {"status": "ERROR", "cluster": True,
                            "message": "mac is required"}
                reservations.append({"ip": ip, "mac": mac,
                                     "hostname": data.get("hostname", ""),
                                     "subnet": data.get("subnet", "")})
            return await self._apply_locked(list(desired.get("subnets") or []),
                                            reservations, timeout)

    async def _apply_locked(self, subnets: List[Any], reservations: List[Any],
                            timeout: float) -> Dict[str, Any]:
        try:
            peers = self.peers()
        except KeaHAConfigError as e:
            return self._verdict("ERROR", self._empty_plan([]), applied=[],
                                 failed=[], errors={}, stage="topology",
                                 message=str(e))
        order: List[str] = apply_order(peers)

        hooks = await self.transport.fanout(
            "KEAW_INSTALL_HOOKS", {"hook_dir": self.hook_dir}, timeout=timeout)
        missing = [mid for mid in order
                   if ((hooks.get("results") or {}).get(mid) or {}).get("status") != "SUCCESS"]
        if missing:
            return self._verdict("ERROR", self._empty_plan(order), applied=[],
                                 failed=order, errors={
                mid: ((((hooks.get("results") or {}).get(mid) or {}).get("message"))
                      or "HA hook libraries unavailable") for mid in missing},
                stage="install-hooks")

        # Read each node's FULL running config so the render preserves
        # everything the coordinator does not own.
        node_configs: Dict[str, Dict[str, Any]] = {}
        read_errors: Dict[str, str] = {}
        for member_id in order:
            reply = await self.transport.call(member_id, "KEAW_GET_CONFIG", {},
                                              timeout=timeout)
            cfg = reply.get("config") if isinstance(reply, dict) else None
            if not isinstance(reply, dict) or reply.get("status") != "SUCCESS" \
                    or not isinstance(cfg, dict):
                read_errors[member_id] = (
                    (reply or {}).get("message")
                    or "could not read the running configuration")
                continue
            node_configs[member_id] = cfg
        if read_errors:
            return self._verdict("ERROR", self._empty_plan(order), applied=[],
                                 failed=order, errors=read_errors,
                                 stage="read-config")

        try:
            plan = self.render(subnets, reservations, node_configs)
        except KeaHAConfigError as e:
            return self._verdict("ERROR", self._empty_plan(order), applied=[],
                                 failed=order, errors={}, stage="render",
                                 message=str(e))
        configs: Dict[str, Any] = plan["configs"]

        # Validate EVERY node before touching ANY node.
        validation_errors: Dict[str, str] = {}
        for member_id in order:
            reply = await self.transport.call(
                member_id, "KEAW_VALIDATE", {"config": configs[member_id]},
                timeout=timeout)
            if reply.get("status") != "SUCCESS":
                validation_errors[member_id] = (
                    reply.get("message") or "config-test rejected the configuration")
        if validation_errors:
            return self._verdict("ERROR", plan, applied=[], failed=order,
                                 errors=validation_errors, stage="validate")

        candidate_version = self.version + 1
        # Journal the candidate BEFORE touching any node: a crash after this
        # point is recoverable (the pending block is detected on restart);
        # a crash before it means nothing was applied.
        try:
            self._journal_candidate(subnets, reservations, candidate_version)
        except Exception as e:  # noqa: BLE001
            return self._verdict(
                "ERROR", plan, applied=[], failed=order, stage="journal",
                errors={"coordinator": f"could not journal the candidate: {e}"})

        applied: List[str] = []
        errors: Dict[str, str] = {}
        for member_id in order:
            reply = await self.transport.call(
                member_id, "KEAW_APPLY",
                {"config": configs[member_id], "version": candidate_version},
                timeout=timeout)
            if reply.get("status") == "SUCCESS":
                applied.append(member_id)
                continue
            errors[member_id] = reply.get("message") or "apply failed"
            return await self._rollback(order, applied, member_id, reply,
                                        errors, plan, timeout)

        # Every node confirmed. Promote the candidate ONLY now, and only once it
        # is durably on disk. If the promote write fails the pair is running a
        # version the coordinator cannot remember, so BOTH nodes are rolled
        # back rather than left ahead of the record.
        try:
            self._promote_candidate(subnets, reservations, candidate_version)
        except Exception as e:  # noqa: BLE001
            errors = {"coordinator":
                      f"both nodes applied v{candidate_version} but the "
                      f"coordinator could not persist it ({e}); rolling both "
                      f"back to v{self.version}"}
            rolled_back = []
            for node in list(applied):
                undo = await self.transport.call(node, "KEAW_ROLLBACK", {},
                                                 timeout=timeout)
                if undo.get("status") == "SUCCESS":
                    rolled_back.append(node)
                    self.config_digests.pop(node, None)
                else:
                    errors[node] = (
                        f"may still hold v{candidate_version} — rollback failed: "
                        f"{undo.get('message') or 'unknown error'}")
            remaining = [m for m in applied if m not in rolled_back]
            if remaining:
                self._retain_candidate(candidate_version, remaining)
                self.pending_candidate = {
                    "version": candidate_version, "started_at": time.time(),
                    "unrestored": list(remaining),
                }
                logger.error("Kea HA promote failed and %s could not be rolled "
                             "back — retaining the candidate journal",
                             ", ".join(remaining))
            else:
                self._clear_candidate()
            return self._verdict(
                "ERROR" if not remaining else "PARTIAL", plan,
                applied=remaining,
                failed=[m for m in order if m not in remaining],
                errors=errors, stage="promote", rolled_back=rolled_back)
        self.version = candidate_version
        self.desired = {"subnets": list(subnets), "reservations": list(reservations)}
        self.pending_candidate = None
        for member_id in applied:
            self.config_digests[member_id] = plan["digest"]
        return self._verdict("SUCCESS", plan, applied=applied, failed=[],
                             errors={}, stage="apply")

    async def _rollback(self, order: List[str], applied: List[str],
                        failed_member: str, reply: Dict[str, Any],
                        errors: Dict[str, str], plan: Dict[str, Any],
                        timeout: float) -> Dict[str, Any]:
        """Undo a mid-chain failure across every POSSIBLY-mutated node.

        The failing node itself is a rollback candidate: its ``config-set`` can
        land and its ``config-write`` (or its own local restore) then fail, so it
        may be running the new configuration despite reporting ERROR. It is
        excluded only when the worker positively asserts it did not mutate
        (``mutated=False``) — an older worker that says nothing is treated as
        possibly mutated.
        """
        suspect = list(applied)
        if reply.get("mutated") is not False:
            suspect.append(failed_member)
        rolled_back: List[str] = []
        for node in suspect:
            undo = await self.transport.call(node, "KEAW_ROLLBACK", {},
                                             timeout=timeout)
            if undo.get("status") == "SUCCESS":
                rolled_back.append(node)
                self.config_digests.pop(node, None)
            else:
                errors[node] = (
                    (errors.get(node, "") + "; " if errors.get(node) else "")
                    + f"may still hold the new configuration — rollback failed: "
                      f"{undo.get('message') or 'unknown error'}")
        remaining = [m for m in suspect if m not in rolled_back]
        status = "ERROR" if not remaining else "PARTIAL"
        if remaining:
            # At least one node may STILL be running the candidate. Keeping the
            # journal is the whole point: a restart must know the pair can be
            # ahead of the committed record. Clearing it here (the previous
            # behaviour) threw away the only evidence of a half-applied pair.
            self._retain_candidate(self.version + 1, remaining)
            self.pending_candidate = {
                "version": self.version + 1,
                "started_at": time.time(),
                "unrestored": list(remaining),
            }
            logger.error("Kea HA rollback incomplete — %s may still hold the "
                         "candidate; the journal is retained for recovery",
                         ", ".join(remaining))
        else:
            # Every touched node was confirmed restored: the journal has served
            # its purpose and would otherwise raise a false alarm on restart.
            self._clear_candidate()
        return self._verdict(status, plan, applied=remaining,
                             failed=[m for m in order if m not in remaining],
                             errors=errors, stage="apply",
                             rolled_back=rolled_back)

    def _empty_plan(self, order: List[str]) -> Dict[str, Any]:
        """A plan placeholder for failures that abort before rendering."""
        return {"peers": [], "configs": {}, "order": list(order), "subnets": 0,
                "reservations": 0, "reservations_skipped": 0, "digest": ""}

    def _verdict(self, status: str, plan: Dict[str, Any], applied: List[str],
                 failed: List[str], errors: Dict[str, str], stage: str,
                 rolled_back: Optional[List[str]] = None,
                 message: str = "") -> Dict[str, Any]:
        verdict = {
            "status": status,
            "cluster": True,
            "mode": self.mode,
            "stage": stage,
            "version": self.version,
            "applied": applied,
            "failed": failed,
            "errors": errors,
            "rolled_back": rolled_back or [],
            "order": plan["order"],
            "subnets": plan["subnets"],
            "reservations": plan["reservations"],
            "reservations_skipped": plan["reservations_skipped"],
            "digest": plan["digest"],
            "at": time.time(),
        }
        if status != "SUCCESS":
            nodes = ", ".join(failed) or "unknown"
            verdict["message"] = message or (
                f"Kea HA {stage} failed on: {nodes}"
                + (f"; rolled back {', '.join(rolled_back)}" if rolled_back else "")
                + (f"; still applied on {', '.join(applied)}" if applied else ""))
            logger.error("Kea HA apply %s at stage %s — applied=%s failed=%s",
                         status, stage, applied, failed)
        self.last_apply = verdict
        return dict(verdict)

    # ── Status ──────────────────────────────────────────────────────────────

    async def refresh_status(self, timeout: float = 15.0) -> Dict[str, Any]:
        """Collect ``status-get``-derived HA state from every node.

        A node that does not answer (or answers without a digest) has its
        remembered digest DROPPED, so ``config_converged`` cannot be satisfied
        by a stale value from a node that is no longer reporting.
        """
        fan = await self.transport.fanout("KEAW_HA_STATUS", {}, timeout=timeout)
        results = fan.get("results") or {}
        self.ha_status = {}
        for member_id, reply in results.items():
            if not isinstance(reply, dict):
                self.ha_status[member_id] = {"status": "ERROR",
                                             "message": "malformed reply"}
                self.config_digests.pop(member_id, None)
                continue
            record = dict(reply)
            raw = reply.get("status_get")
            if reply.get("status") == "SUCCESS" and isinstance(raw, dict):
                record["ha"] = parse_ha_status(raw)
            elif isinstance(reply.get("ha"), dict):
                record["ha"] = reply["ha"]
            if reply.get("status") == "SUCCESS" and reply.get("digest"):
                self.config_digests[member_id] = reply["digest"]
            else:
                self.config_digests.pop(member_id, None)
            self.ha_status[member_id] = record
        # A member that did not answer at all must not keep a stale digest.
        for member_id in list(self.config_digests):
            if member_id not in self.ha_status:
                self.config_digests.pop(member_id, None)
        return fan

    def report(self) -> Dict[str, Any]:
        """The HA view the Diagnostics page renders. Pure."""
        try:
            peers = self.peers()
        except KeaHAConfigError as e:
            return {"enabled": True, "mode": self.mode, "state": "invalid",
                    "healthy": False, "config_converged": False,
                    "config_digests_missing": [m["id"] for m in self.members()],
                    "peers": [], "members": [], "member_count": len(self.members()),
                    "healthy_count": 0, "degraded": [], "unreachable": [],
                    "last_apply": dict(self.last_apply),
                    "recommendations": [f"Kea HA topology is invalid: {e}"]}
        report = summarize_ha(self.mode, peers,
                              list(self.transport.member_links()),
                              self.ha_status, self.config_digests,
                              self.last_apply)
        if self.pending_candidate:
            report["pending_candidate"] = {
                "version": self.pending_candidate.get("version"),
                "started_at": self.pending_candidate.get("started_at"),
            }
            report["healthy"] = False
            if report["state"] == "healthy":
                report["state"] = "degraded"
            unrestored = self.pending_candidate.get("unrestored") or []
            report["pending_candidate"]["unrestored"] = list(unrestored)
            detail = (" These node(s) may still be running it: "
                      + ", ".join(unrestored) + "." if unrestored else "")
            report["recommendations"] = list(report["recommendations"]) + [
                f"A DHCP configuration v{self.pending_candidate.get('version')} "
                f"was journalled but never confirmed — the coordinator restarted "
                f"mid-apply or a rollback did not complete.{detail} Re-apply the "
                f"configuration to converge the pair."]
        return report

    async def status(self) -> Dict[str, Any]:
        await self.refresh_status()
        return {"status": "SUCCESS", **self.report()}
