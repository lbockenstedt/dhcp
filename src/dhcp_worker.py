"""``lm-dhcp-worker`` — the Kea-host half of an HA pair.

Runs on each Kea server and dials its coordinator's ``/ws/agent`` listener (the
``dhcp`` module spoke). Like the DNS worker this is deliberately NOT a generic
agent: the op table below is everything it can be asked to do. The only shell
command it ever runs is a fixed, argument-free package install for the Kea hook
libraries — there is no caller-supplied command, path or URL anywhere.

The apply op snapshots the running config before writing so the coordinator can
roll a node back when its partner fails mid-transaction.
"""

import argparse
import asyncio
import copy
import logging
import os
import shutil
import subprocess
from typing import Any, Dict, Optional

try:
    from kea_manager import KeaManager
    from kea_ha import config_fingerprint, hook_paths, parse_ha_status, resolve_hook_dir
except ImportError:  # loaded as a package (src.X)
    from src.kea_manager import KeaManager  # type: ignore
    from src.kea_ha import (  # type: ignore
        config_fingerprint, hook_paths, parse_ha_status, resolve_hook_dir)

logger = logging.getLogger("DHCPWorker")

#: The ONLY package install this worker can perform. Fixed argv — no shell, no
#: caller-supplied package name. The hook libraries ship in **kea-common** on
#: Debian/Ubuntu; there is no "kea-hooks" package, so the old value could only
#: ever fail and leave the node reporting its HA libraries missing.
_HOOK_PACKAGES = ("kea-common",)

DEFAULT_COORDINATOR_PORT = 8770


class DhcpWorkerOps:
    """The fixed operation table exposed to the coordinator."""

    def __init__(self, mgr: KeaManager):
        self.mgr = mgr
        self._snapshot: Optional[Dict[str, Any]] = None

    # ── Hooks ───────────────────────────────────────────────────────────────

    def install_hooks(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """``KEAW_INSTALL_HOOKS`` — make sure the HA + lease_cmds libs exist.

        Idempotent: present → SUCCESS without touching apt. Absent → one fixed
        ``apt-get install -y kea-common``. Still absent afterwards → ERROR, so
        the coordinator refuses to generate an HA config this node cannot load.
        """
        # Resolve the hook dir ON THIS NODE: the multiarch triplet differs per
        # architecture, so a coordinator's x86_64 default made every arm64
        # worker report its HA libraries missing.
        hook_dir = resolve_hook_dir(str(data.get("hook_dir") or ""))
        paths = hook_paths(hook_dir)
        missing = [name for name, path in paths.items() if not os.path.exists(path)]
        if not missing:
            return {"status": "SUCCESS", "libraries": paths, "installed": False,
                    "hook_dir": hook_dir}
        if not shutil.which("apt-get"):
            return {"status": "ERROR", "libraries": paths,
                    "message": f"missing Kea hook libraries: {', '.join(missing)} "
                               f"(no apt-get on this host to install them)"}
        try:
            proc = subprocess.run(
                ["apt-get", "install", "-y", "-qq", *_HOOK_PACKAGES],
                capture_output=True, text=True, timeout=300)
        except Exception as e:  # noqa: BLE001
            return {"status": "ERROR", "libraries": paths, "message": str(e)}
        # apt may have created the arch-specific dir only now, so re-resolve.
        hook_dir = resolve_hook_dir(str(data.get("hook_dir") or ""))
        paths = hook_paths(hook_dir)
        still_missing = [name for name, path in paths.items()
                         if not os.path.exists(path)]
        if still_missing:
            detail = (proc.stderr or proc.stdout or "").strip()[-500:]
            return {"status": "ERROR", "libraries": paths, "hook_dir": hook_dir,
                    "message": f"Kea hook libraries still missing after install: "
                               f"{', '.join(still_missing)}. {detail}"}
        return {"status": "SUCCESS", "libraries": paths, "installed": True,
                "hook_dir": hook_dir}

    # ── Config lifecycle ────────────────────────────────────────────────────

    @staticmethod
    def _config_of(data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        cfg = data.get("config")
        if isinstance(cfg, dict) and "Dhcp4" in cfg:
            cfg = cfg["Dhcp4"]
        return cfg if isinstance(cfg, dict) else None

    def validate(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """``KEAW_VALIDATE`` — Kea's own ``config-test`` on a candidate config.

        Uses the running daemon's parser rather than a local heuristic: only Kea
        can say whether Kea will accept a config.
        """
        cfg = self._config_of(data)
        if cfg is None:
            return {"status": "ERROR", "message": "config (Dhcp4) is required"}
        try:
            self.mgr._rpc("dhcp4", "config-test", {"Dhcp4": cfg})
        except Exception as e:  # noqa: BLE001 — a rejected config is the answer
            return {"status": "ERROR", "message": str(e)}
        return {"status": "SUCCESS", "digest": config_fingerprint(cfg)}

    def get_config(self, _data: Dict[str, Any]) -> Dict[str, Any]:
        """``KEAW_GET_CONFIG`` — this node's FULL running ``Dhcp4`` config.

        The coordinator renders the node's next config on top of this, so
        interfaces, lease database, loggers and every other node-local setting
        survive a cluster apply instead of being replaced by a generated stub.
        """
        try:
            cfg = self.mgr.get_config()
        except Exception as e:  # noqa: BLE001
            return {"status": "ERROR", "message": str(e)}
        if not isinstance(cfg, dict):
            return {"status": "ERROR",
                    "message": f"Kea returned {type(cfg).__name__}, not a config"}
        return {"status": "SUCCESS", "config": cfg,
                "digest": config_fingerprint(cfg)}

    def apply(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """``KEAW_APPLY`` — snapshot, ``config-set``, ``config-write``.

        The two Kea calls are distinguished because they fail differently:

        * ``config-set`` failed → the node is UNTOUCHED (``mutated: False``);
          the coordinator can skip it when rolling back.
        * ``config-set`` succeeded but ``config-write`` failed → the new config
          is ALREADY RUNNING but unpersisted. The worker restores its snapshot
          LOCALLY and immediately, because a coordinator that crashed here would
          otherwise leave the node silently diverged. If that local restore also
          fails the node is genuinely mutated (``mutated: True``,
          ``restored: False``) and the verdict is ``PARTIAL``, never ERROR — the
          distinction the coordinator needs to decide what to roll back.
        """
        cfg = self._config_of(data)
        if cfg is None:
            return {"status": "ERROR", "message": "config (Dhcp4) is required",
                    "mutated": False}
        try:
            self._snapshot = copy.deepcopy(self.mgr.get_config())
        except Exception as e:  # noqa: BLE001
            # No snapshot means no rollback; refuse rather than apply a change
            # the coordinator believes it can undo.
            return {"status": "ERROR", "mutated": False,
                    "message": f"cannot snapshot current config for rollback: {e}"}
        outcome = self.mgr.apply_config(copy.deepcopy(cfg))
        if outcome.get("set") and outcome.get("written"):
            return {"status": "SUCCESS", "version": data.get("version"),
                    "mutated": True, "digest": config_fingerprint(cfg)}
        if not outcome.get("set"):
            return {"status": "ERROR", "mutated": False,
                    "message": outcome.get("error") or "config-set failed"}
        # config-set landed, config-write did not: restore locally right now.
        # A restore counts ONLY when BOTH config-set and config-write succeeded.
        # A restore whose write failed leaves the node running the old config
        # but with the NEW one still on disk, so the next kea restart silently
        # boots the configuration we just decided to abandon — that is a mutated
        # node, not a clean one.
        restore = self.mgr.apply_config(copy.deepcopy(self._snapshot))
        if restore.get("set") and restore.get("written"):
            return {"status": "ERROR", "mutated": False, "restored": True,
                    "message": (f"config-write failed ({outcome.get('error')}); "
                                f"the previous configuration was restored and "
                                f"persisted on this node")}
        if restore.get("set"):
            return {"status": "PARTIAL", "mutated": True, "restored": False,
                    "message": (f"config-write failed ({outcome.get('error')}); "
                                f"the previous configuration is running again "
                                f"but could NOT be persisted "
                                f"({restore.get('error')}) — a Kea restart would "
                                f"boot the abandoned configuration")}
        return {"status": "PARTIAL", "mutated": True, "restored": False,
                "message": (f"config-write failed ({outcome.get('error')}) AND "
                            f"the local restore failed "
                            f"({restore.get('error')}) — this node is running "
                            f"the new, unpersisted configuration")}

    def rollback(self, _data: Dict[str, Any]) -> Dict[str, Any]:
        """``KEAW_ROLLBACK`` — restore the config captured by the last apply."""
        if self._snapshot is None:
            return {"status": "ERROR", "message": "no snapshot to roll back to"}
        outcome = self.mgr.apply_config(copy.deepcopy(self._snapshot))
        if not outcome.get("set"):
            return {"status": "ERROR",
                    "message": outcome.get("error") or "rollback config-set failed"}
        if not outcome.get("written"):
            # Running the old config again, just not persisted — say so rather
            # than claiming a clean rollback.
            return {"status": "PARTIAL",
                    "digest": config_fingerprint(self._snapshot),
                    "message": (f"previous configuration restored but not "
                                f"persisted ({outcome.get('error')})")}
        return {"status": "SUCCESS",
                "digest": config_fingerprint(self._snapshot)}

    def standdown(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """``KEAW_STANDDOWN`` — leave the HA pair cleanly.

        Issued when the operator removes this node from the topology. Strips the
        HA + lease_cmds hook entries from the running config so the node stops
        heartbeating at a partner it is no longer paired with (it keeps serving
        its own scopes — silently blackholing DHCP would be worse). Everything
        else in the node's configuration is preserved."""
        try:
            cfg = copy.deepcopy(self.mgr.get_config())
        except Exception as e:  # noqa: BLE001
            return {"status": "ERROR", "message": str(e)}
        before = len(cfg.get("hooks-libraries") or [])
        cfg["hooks-libraries"] = [
            h for h in (cfg.get("hooks-libraries") or [])
            if isinstance(h, dict) and not str(h.get("library", "")).endswith(
                ("libdhcp_ha.so", "libdhcp_lease_cmds.so"))]
        removed = before - len(cfg["hooks-libraries"])
        if not removed:
            return {"status": "SUCCESS", "changed": False,
                    "message": "no HA hooks were loaded"}
        outcome = self.mgr.apply_config(cfg)
        if not (outcome.get("set") and outcome.get("written")):
            return {"status": "ERROR", "changed": bool(outcome.get("set")),
                    "message": outcome.get("error") or "could not remove the HA hooks"}
        return {"status": "SUCCESS", "changed": True, "hooks_removed": removed}

    # ── Status ──────────────────────────────────────────────────────────────

    def ha_status(self, _data: Dict[str, Any]) -> Dict[str, Any]:
        """``KEAW_HA_STATUS`` — ``status-get`` plus the running config digest."""
        try:
            raw = self.mgr._rpc("dhcp4", "status-get", {})
        except Exception as e:  # noqa: BLE001
            return {"status": "ERROR", "message": str(e), "running": False}
        digest = ""
        subnet_count = None
        try:
            cfg = self.mgr.get_config()
            digest = config_fingerprint(cfg)
            subnet_count = len(cfg.get("subnet4") or [])
        except Exception as e:  # noqa: BLE001 — HA state is still worth reporting
            logger.debug("could not read config for digest: %s", e)
        return {"status": "SUCCESS", "running": True, "status_get": raw,
                "ha": parse_ha_status(raw), "digest": digest,
                "subnet_count": subnet_count}

    def status(self, _data: Dict[str, Any]) -> Dict[str, Any]:
        return {"status": "SUCCESS", **self.mgr.status()}

    def list_subnets(self, _data: Dict[str, Any]) -> Dict[str, Any]:
        return {"status": "SUCCESS", "subnets": self.mgr.list_subnets()}

    def list_leases(self, data: Dict[str, Any]) -> Dict[str, Any]:
        return {"status": "SUCCESS",
                "leases": self.mgr.list_leases(data.get("subnet") or None)}

    def list_reservations(self, _data: Dict[str, Any]) -> Dict[str, Any]:
        return {"status": "SUCCESS", "reservations": self.mgr.list_reservations()}

    def diagnostics(self, _data: Dict[str, Any]) -> Dict[str, Any]:
        return self.mgr.diagnostics()

    def stats(self, _data: Dict[str, Any]) -> Dict[str, Any]:
        return self.mgr.get_stats()

    def op_table(self) -> Dict[str, Any]:
        return {
            "KEAW_INSTALL_HOOKS": self.install_hooks,
            "KEAW_GET_CONFIG": self.get_config,
            "KEAW_VALIDATE": self.validate,
            "KEAW_APPLY": self.apply,
            "KEAW_ROLLBACK": self.rollback,
            "KEAW_STANDDOWN": self.standdown,
            "KEAW_HA_STATUS": self.ha_status,
            "KEAW_STATUS": self.status,
            "KEAW_LIST_SUBNETS": self.list_subnets,
            "KEAW_LIST_LEASES": self.list_leases,
            "KEAW_LIST_RES": self.list_reservations,
            "KEAW_DIAGNOSTICS": self.diagnostics,
            "KEAW_STATS": self.stats,
        }


def build_worker(member_id: str, coordinator_url: str, secret: str,
                 ca_url: str = "http://localhost:8001"):
    """Wire the op table into the shared cluster worker transport."""
    try:
        from core.src.messaging.service_cluster import ServiceWorkerClient
    except ImportError:
        from messaging.service_cluster import ServiceWorkerClient  # type: ignore
    ops = DhcpWorkerOps(KeaManager(ca_url=ca_url))
    # default_port drives the URL normalization, which REJECTS a plaintext
    # ws:// to a remote coordinator (the PSK rides in the handshake).
    return ServiceWorkerClient(member_id, coordinator_url, secret,
                               ops.op_table(), hostname=os.uname().nodename,
                               default_port=DEFAULT_COORDINATOR_PORT)


def main() -> None:
    parser = argparse.ArgumentParser(description="Lab Manager Kea HA worker")
    parser.add_argument("--id", default=os.getenv("LM_DHCP_MEMBER_ID", ""),
                        help="HA member id (must match the module's member list "
                             "and Kea's this-server-name)")
    parser.add_argument("--coordinator", default=os.getenv("LM_DHCP_COORDINATOR", ""),
                        help="wss://<dhcp-module-host>:8770/ws/agent")
    parser.add_argument("--secret", default=os.getenv("LM_DHCP_WORKER_SECRET", ""),
                        help="shared worker secret (matches the module's agent_secret)")
    parser.add_argument("--ca-url", default=os.getenv("KEA_CA_URL",
                                                      "http://localhost:8001"))
    args = parser.parse_args()
    if not args.id:
        parser.error("--id is required (or LM_DHCP_MEMBER_ID in the environment)")
    if not args.coordinator or not args.secret:
        parser.error("--coordinator and --secret are required "
                     "(or LM_DHCP_COORDINATOR / LM_DHCP_WORKER_SECRET)")
    logging.basicConfig(
        level=logging.INFO, force=True,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    worker = build_worker(args.id, args.coordinator, args.secret, ca_url=args.ca_url)
    asyncio.run(worker.run())


if __name__ == "__main__":
    main()
