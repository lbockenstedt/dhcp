"""``lm-dhcp-worker`` — the Kea-host half of an HA pair.

Runs on each Kea server and dials its coordinator's ``/ws/agent`` listener (the
``dhcp`` module spoke). Like the DNS worker this is deliberately NOT a generic
agent: the op table below is everything it can be asked to do. The only shell
commands it ever runs are a small number of FIXED, argument-free apt-get/dpkg
invocations for the Kea hook-library packages — there is no caller-supplied
command, package name, path or URL anywhere.

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
    from kea_manager import KeaManager, worker_code_version
    from kea_ha import config_fingerprint, hook_paths, parse_ha_status, resolve_hook_dir
except ImportError:  # loaded as a package (src.X)
    from src.kea_manager import KeaManager, worker_code_version  # type: ignore
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
            err_msg = str(e)
            if any(term in err_msg.lower() for term in ("likely to be offline", "permission denied", "connection refused", "unable to forward")):
                logger.warning("Kea DHCP4 appears offline or inaccessible (%s); attempting service restart & permission repair", err_msg)
                if self._restart_kea_dhcp4_service():
                    import time
                    time.sleep(1.0)
                    try:
                        cfg = self.mgr.get_config()
                    except Exception as retry_e:  # noqa: BLE001
                        return {"status": "ERROR", "message": f"{err_msg} (restart retry failed: {retry_e})"}
                else:
                    return {"status": "ERROR", "message": err_msg}
            else:
                return {"status": "ERROR", "message": err_msg}
        if not isinstance(cfg, dict):
            return {"status": "ERROR",
                    "message": f"Kea returned {type(cfg).__name__}, not a config"}
        return {"status": "SUCCESS", "config": cfg,
                "digest": config_fingerprint(cfg)}

    @staticmethod
    def _hook_load_failure_detail(error: str, hook_dir: str) -> str:
        """Enrich a Kea "hook libraries failed to load" config-set rejection.

        Kea's own error string (e.g. "One or more hook libraries failed to
        load") never says WHICH library or why — the real reason is only in
        the kea-dhcp4-server journal at the instant it tried to dlopen() the
        .so. Without this, that error was a dead end in the UI: the operator
        had to SSH in and grep journalctl themselves. Appends the resolved
        hook dir's actual listing (wrong arch triplet / missing file is
        visible immediately), the kea-dhcp4-server/kea-common package
        versions (a mismatch here means the libraries are for a DIFFERENT
        Kea ABI than the running daemon — a same-version ``--reinstall``
        cannot fix that), an ``ldd`` of the HA hook .so (surfaces "not found"
        shared-library dependencies, the #1 real dlopen() failure cause
        distinct from a missing/corrupt file), plus the last few HOOKS_*
        log lines.
        """
        if "hook librar" not in (error or "").lower():
            return error
        detail = [error]
        code_ver = worker_code_version()
        if code_ver.get("commit"):
            detail.append(
                f"worker code: {code_ver['commit']}"
                + (f" ({code_ver['commit_time']})" if code_ver.get("commit_time") else "")
                + (" [locally modified]" if code_ver.get("dirty") else ""))
        try:
            hook_dir = resolve_hook_dir(hook_dir)
            entries = sorted(os.listdir(hook_dir)) if os.path.isdir(hook_dir) else []
            detail.append(f"hook dir {hook_dir}: "
                          f"{', '.join(entries) if entries else '(missing or empty)'}")
        except Exception as e:  # noqa: BLE001
            detail.append(f"could not list hook dir: {e}")
        pkg_versions = DhcpWorkerOps._installed_package_versions()
        if pkg_versions:
            detail.append("package versions: " + ", ".join(
                f"{name}={ver}" for name, ver in pkg_versions.items()))
        ldd_issue = DhcpWorkerOps._ldd_missing_deps(
            os.path.join(hook_dir, "libdhcp_ha.so"))
        if ldd_issue:
            detail.append(f"libdhcp_ha.so dependency check: {ldd_issue}")
        ha_tls_issue = DhcpWorkerOps._ha_tls_permission_issue()
        if ha_tls_issue:
            detail.append(f"HA-TLS material check: {ha_tls_issue}")
        try:
            proc = subprocess.run(
                ["journalctl", "-u", "kea-dhcp4-server", "-n", "30", "--no-pager"],
                capture_output=True, text=True, timeout=10)
            # Prefer the actual ERROR/FATAL line over a later benign
            # "successfully closed" cleanup message — a real dlopen()/config
            # failure (e.g. HA_CONFIGURATION_FAILED "... Permission denied")
            # is almost always followed by Kea unloading the libraries it did
            # manage to load, and picking the LAST hook-related line surfaced
            # that harmless unload instead of the actual cause.
            hook_lines = [ln for ln in (proc.stdout or "").splitlines()
                         if "hook" in ln.lower() or "HOOKS_" in ln]
            error_lines = [ln for ln in hook_lines
                          if " ERROR " in ln or " FATAL " in ln]
            chosen = (error_lines or hook_lines)
            if chosen:
                detail.append("recent log: " + chosen[-1][:300])
        except Exception:  # noqa: BLE001 — best-effort only
            pass
        return " | ".join(detail)

    @staticmethod
    def _ha_tls_permission_issue() -> str:
        """Return a human-readable problem description if the HA-TLS material
        the daemon (running as ``_kea``) needs to read isn't actually
        readable by it — the #1 real cause behind a generic "hook libraries
        failed to load" when the files themselves are present and intact
        (see ``_repair_ha_tls_permissions``). Returns "" when fine or when the
        directory/user don't apply (HA not configured on this node)."""
        d = DhcpWorkerOps._HA_TLS_DIR
        if not os.path.isdir(d):
            return ""
        try:
            st = os.stat(d)
            import grp
            try:
                kea_gid = grp.getgrnam("_kea").gr_gid
            except KeyError:
                return ""
            mode = st.st_mode
            group_can_enter = bool(mode & 0o010) and st.st_gid == kea_gid
            world_can_enter = bool(mode & 0o001)
            if not (group_can_enter or world_can_enter):
                return (f"{d} is not readable by the _kea user (owner gid="
                        f"{st.st_gid}, mode={oct(mode & 0o777)}) — the daemon "
                        f"cannot traverse into it to read its HA trust anchor")
        except Exception:  # noqa: BLE001 — best-effort only
            pass
        return ""

    #: Packages whose version alignment matters for hook-library ABI
    #: compatibility — kea-common ships the hooks, kea-dhcp4-server is the
    #: daemon that dlopen()s them; a mismatch between the two after a partial
    #: upgrade is the leading cause of an ALL-hooks load failure that a same-
    #: version ``apt-get --reinstall kea-common`` can never fix.
    _VERSION_CHECK_PACKAGES = ("kea-common", "kea-dhcp4-server", "kea-ctrl-agent")

    @staticmethod
    def _installed_package_versions() -> Dict[str, str]:
        """``dpkg-query`` versions of the Kea packages, for the diagnostic
        detail above — lets an operator (or this code, see
        ``_repair_hook_libraries``) see at a glance whether kea-common and
        kea-dhcp4-server drifted apart, which a plain existence check can't."""
        if not shutil.which("dpkg-query"):
            return {}
        versions: Dict[str, str] = {}
        for pkg in DhcpWorkerOps._VERSION_CHECK_PACKAGES:
            try:
                proc = subprocess.run(
                    ["dpkg-query", "-W", "-f=${Version}", pkg],
                    capture_output=True, text=True, timeout=10)
                if proc.returncode == 0 and proc.stdout.strip():
                    versions[pkg] = proc.stdout.strip()
            except Exception:  # noqa: BLE001 — best-effort only
                continue
        return versions

    @staticmethod
    def _ldd_missing_deps(so_path: str) -> str:
        """Run ``ldd`` against a hook .so and report any "not found" shared
        library dependency — this is what an ABI/version mismatch (or a
        half-upgraded libc/libssl) actually looks like at the dynamic-loader
        level, versus Kea's own error which only says "failed to load".
        Returns "" when the file is missing, ldd isn't available, or every
        dependency resolves.
        """
        if not os.path.isfile(so_path) or not shutil.which("ldd"):
            return ""
        try:
            proc = subprocess.run(
                ["ldd", so_path], capture_output=True, text=True, timeout=10)
        except Exception as e:  # noqa: BLE001
            return f"ldd failed: {e}"
        missing = [ln.strip() for ln in (proc.stdout or "").splitlines()
                   if "not found" in ln]
        return "; ".join(missing) if missing else ""

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
        if outcome.get("set") and not outcome.get("written"):
            write_err = str(outcome.get("error") or "")
            # config-set landed (running config is already the new one) but
            # config-write couldn't persist it — if that's the master conf
            # file's own permissions (root:root 0644 with no group-write for
            # _kea, the same class of bug as the HA-TLS directory), fix it
            # and retry the SAME config-write once before falling through to
            # the restore-and-report path below.
            if "unable to open file" in write_err.lower() and "for writing" in write_err.lower():
                healed = []
                if self._repair_kea_conf_permissions():
                    healed.append("fixed /etc/kea/kea-dhcp4.conf permissions")
                if self._repair_kea_apparmor_write_access():
                    healed.append("granted AppArmor write access to /etc/kea/kea-dhcp4.conf")
                if healed:
                    retry_write = self.mgr.write_config()
                    if retry_write.get("written"):
                        return {"status": "SUCCESS", "version": data.get("version"),
                                "mutated": True, "digest": config_fingerprint(cfg),
                                "self_healed": healed}
                    outcome = {**outcome, "error": retry_write.get("error") or write_err}
        if not outcome.get("set"):
            hook_dir = str(data.get("hook_dir") or "")
            error = outcome.get("error") or "config-set failed"
            # A hook-load rejection can mean the .so EXISTS (install_hooks()
            # already checked that) but fails to dlopen() — corrupt package,
            # ABI mismatch after an unrelated OS update, bad permissions. This
            # used to be a dead end requiring a manual uninstall/reinstall of
            # the whole DHCP role; try the fixed, safe repair actions first
            # (HA-TLS permission fix, then reinstall the package that owns
            # the libraries) and retry the SAME config-set once before
            # giving up.
            if "hook librar" in error.lower():
                healed = []
                if self._repair_ha_tls_permissions():
                    healed.append("fixed /etc/kea/ha-tls permissions")
                if self._repair_hook_libraries(hook_dir):
                    healed.append("reinstalled Kea hook libraries")
                if healed:
                    retry = self.mgr.apply_config(copy.deepcopy(cfg))
                    if retry.get("set") and retry.get("written"):
                        return {"status": "SUCCESS", "version": data.get("version"),
                                "mutated": True, "digest": config_fingerprint(cfg),
                                "self_healed": healed}
                    if not retry.get("set"):
                        error = retry.get("error") or error
                    else:
                        outcome = retry  # fall through to the write-failed path below
            return {"status": "ERROR", "mutated": False,
                    "message": self._hook_load_failure_detail(error, hook_dir)}
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

    #: The HA-TLS material the daemon (running as ``_kea``) must be able to
    #: read for libdhcp_ha.so to load: the shared trust anchor + this node's
    #: own cert/key. Installed root:root 0750 before kea-common (and thus the
    #: ``_kea`` user) exists on a fresh HA-member install, then never
    #: revisited — leaving the daemon permanently unable to even traverse
    #: into the directory. Kea then only ever reports the generic "One or
    #: more hook libraries failed to load", masking the real
    #: HA_CONFIGURATION_FAILED "... Permission denied" underneath.
    _HA_TLS_DIR = "/etc/kea/ha-tls"

    @staticmethod
    def _repair_ha_tls_permissions() -> bool:
        """Group-own ``/etc/kea/ha-tls`` (and its contents) to ``_kea`` so the
        daemon can read its HA trust anchor / cert / key. Fixed, argument-free
        ``chgrp``/``chmod`` calls only — no caller-supplied path. Returns
        ``True`` iff the directory exists and every fix-up call succeeded."""
        d = DhcpWorkerOps._HA_TLS_DIR
        if not os.path.isdir(d):
            return False
        try:
            subprocess.run(["chgrp", "-R", "_kea", d],
                            capture_output=True, text=True, timeout=10, check=True)
            subprocess.run(["chmod", "0750", d],
                            capture_output=True, text=True, timeout=10, check=True)
            subprocess.run(["chmod", "-R", "g+rX", d],
                            capture_output=True, text=True, timeout=10, check=True)
        except Exception as e:  # noqa: BLE001
            logger.warning("could not repair %s permissions: %s", d, e)
            return False
        return True

    #: The Debian package ships this root:root 0644 (world-readable, no
    #: group-write). The daemon runs as _kea and "config-write" opens this
    #: exact path for writing IN-PROCESS as _kea — without a group-write
    #: grant every config-write (including a rollback's local restore) fails
    #: with "Unable to open file ... for writing", identical in spirit to the
    #: HA-TLS directory bug above but on the master config file itself.
    _KEA_DHCP4_CONF = "/etc/kea/kea-dhcp4.conf"

    @staticmethod
    def _repair_kea_conf_permissions() -> bool:
        """Group-own ``/etc/kea/kea-dhcp4.conf`` to ``_kea`` and grant
        group-write so the daemon's own ``config-write`` RPC can persist it.
        Fixed, argument-free ``chgrp``/``chmod`` calls only. Returns ``True``
        iff the file exists and every fix-up call succeeded."""
        f = DhcpWorkerOps._KEA_DHCP4_CONF
        if not os.path.isfile(f):
            return False
        try:
            subprocess.run(["chgrp", "_kea", f],
                            capture_output=True, text=True, timeout=10, check=True)
            # 0660 (not 0640): the file must be GROUP-WRITABLE for the _kea
            # daemon's own config-write RPC to persist -- 0640 only grants the
            # _kea group read, which looked identical to ha-tls/kea-api-password
            # (both correctly 0640, but those are only ever read by the _kea
            # process, never written) and silently never actually fixed the bug.
            subprocess.run(["chmod", "0660", f],
                            capture_output=True, text=True, timeout=10, check=True)
        except Exception as e:  # noqa: BLE001
            logger.warning("could not repair %s permissions: %s", f, e)
            return False
        return True

    #: Ubuntu's shipped AppArmor profiles for kea-dhcp4 and kea-ctrl-agent
    #: grant only ``/etc/kea/ r`` + ``/etc/kea/** r`` — read-only. Unix file
    #: permissions on kea-dhcp4.conf can be perfectly correct (0660 root:_kea)
    #: and config-write STILL fails with the identical "Unable to open file
    #: ... for writing", because AppArmor denies the write() syscall before
    #: the kernel even checks the file mode bits. This masqueraded as a
    #: permissions bug (see ``_repair_kea_conf_permissions`` above) for a long
    #: time because the error text is indistinguishable between the two
    #: causes. Fix: drop a local override (the profile's own
    #: ``#include <local/usr.sbin.kea-...>`` hook exists for exactly this)
    #: granting write on the conf file, then reload the profile so it takes
    #: effect without restarting kea.
    _AA_LOCAL_DIR = "/etc/apparmor.d/local"
    _AA_SYSTEM_DIR = "/etc/apparmor.d"
    _AA_OVERRIDE_LINE = "  /etc/kea/kea-dhcp4.conf rw,\n"
    _AA_PROFILES = ("usr.sbin.kea-dhcp4", "usr.sbin.kea-ctrl-agent")

    @classmethod
    def _repair_kea_apparmor_write_access(cls) -> bool:
        """Append a local AppArmor override granting write on
        ``kea-dhcp4.conf`` to both the ``kea-dhcp4`` and ``kea-ctrl-agent``
        profiles (if not already present), then reload each profile with
        ``apparmor_parser -r`` so it takes effect immediately. No-ops (and
        returns ``False``) if AppArmor isn't in use on this host. Returns
        ``True`` iff every profile needing the override got it applied."""
        if not os.path.isdir(cls._AA_LOCAL_DIR):
            return False
        ok = True
        for profile in cls._AA_PROFILES:
            override_path = os.path.join(cls._AA_LOCAL_DIR, profile)
            system_path = os.path.join(cls._AA_SYSTEM_DIR, profile)
            if not os.path.isfile(system_path):
                continue
            try:
                existing = ""
                if os.path.isfile(override_path):
                    with open(override_path, "r") as fh:
                        existing = fh.read()
                if cls._AA_OVERRIDE_LINE.strip() not in existing:
                    with open(override_path, "a") as fh:
                        fh.write(cls._AA_OVERRIDE_LINE)
                subprocess.run(["apparmor_parser", "-r", system_path],
                                capture_output=True, text=True, timeout=15, check=True)
            except Exception as e:  # noqa: BLE001
                logger.warning("could not repair AppArmor write access for %s: %s",
                               profile, e)
                ok = False
        return ok


    @staticmethod
    def _repair_hook_libraries(hook_dir: str) -> bool:
        """Reinstall the package(s) owning the Kea hook libraries and confirm
        the files are present afterward.

        A plain ``apt-get install --reinstall kea-common`` (the original,
        fixed repair) only re-lays down the SAME package version already on
        disk — it cannot fix an ABI mismatch where ``kea-common`` (which ships
        the hooks) and ``kea-dhcp4-server`` (the daemon that dlopen()s them)
        have drifted to different versions, e.g. after a partial/interrupted
        apt upgrade. That case makes EVERY hook fail with "failed to load"
        (as opposed to one specific corrupt/missing file), which is exactly
        what a repeated production failure with all 9 libraries listed looks
        like. So: check whether kea-common and kea-dhcp4-server versions
        match first; if they don't, refresh the apt cache and install BOTH
        packages together so apt is free to bring them to the same version,
        rather than reinstalling kea-common alone at its current (mismatched)
        version. Falls back to the original same-version reinstall when the
        versions already match (a corrupt/truncated file is the more likely
        cause there) or when dpkg-query isn't available to tell.
        """
        if not shutil.which("apt-get"):
            return False
        versions = DhcpWorkerOps._installed_package_versions()
        common_ver = versions.get("kea-common")
        daemon_ver = versions.get("kea-dhcp4-server")
        mismatched = bool(common_ver and daemon_ver and common_ver != daemon_ver)
        if mismatched:
            logger.warning(
                "kea-common (%s) and kea-dhcp4-server (%s) versions differ — "
                "repairing by realigning both packages instead of a same-"
                "version reinstall", common_ver, daemon_ver)
        try:
            if mismatched:
                subprocess.run(["apt-get", "update", "-y", "-qq"],
                                capture_output=True, text=True, timeout=300)
                subprocess.run(
                    ["apt-get", "install", "-y", "-qq",
                     "kea-common", "kea-dhcp4-server"],
                    capture_output=True, text=True, timeout=300)
            else:
                subprocess.run(
                    ["apt-get", "install", "--reinstall", "-y", "-qq", *_HOOK_PACKAGES],
                    capture_output=True, text=True, timeout=300)
        except Exception as e:  # noqa: BLE001
            logger.warning("hook library reinstall failed: %s", e)
            return False
        resolved = resolve_hook_dir(hook_dir)
        paths = hook_paths(resolved)
        still_missing = [name for name, path in paths.items() if not os.path.exists(path)]
        if still_missing:
            logger.warning("hook libraries still missing after reinstall: %s",
                            ", ".join(still_missing))
            return False
        # File-existence was always insufficient to prove a real fix — the
        # library can exist and still fail dlopen() (that's the whole bug
        # this method exists to address). Cross-check with ldd so a repair
        # that changed nothing meaningful doesn't get reported as a success
        # right before the retried config-set fails again anyway.
        ldd_issue = DhcpWorkerOps._ldd_missing_deps(paths.get("ha", ""))
        if ldd_issue:
            logger.warning("hook libraries present but still have unresolved "
                            "dependencies after reinstall: %s", ldd_issue)
            return False
        after = DhcpWorkerOps._installed_package_versions()
        logger.info("self-heal: reinstalled Kea hook libraries (%s); "
                    "package versions now: %s", resolved,
                    ", ".join(f"{k}={v}" for k, v in after.items()) or "unknown")
        return True

    @classmethod
    def _restart_kea_dhcp4_service(cls) -> bool:
        """Attempt to repair permissions and start/restart kea-dhcp4-server if offline."""
        cls._repair_ha_tls_permissions()
        cls._repair_kea_conf_permissions()
        cls._repair_kea_apparmor_write_access()
        try:
            if shutil.which("systemctl"):
                proc = subprocess.run(
                    ["systemctl", "restart", "kea-dhcp4-server"],
                    capture_output=True, text=True, timeout=15)
                if proc.returncode == 0:
                    logger.info("Successfully restarted kea-dhcp4-server service")
                    return True
                logger.warning("systemctl restart kea-dhcp4-server returned %d: %s",
                               proc.returncode, (proc.stderr or proc.stdout).strip())
            elif shutil.which("service"):
                proc = subprocess.run(
                    ["service", "kea-dhcp4-server", "restart"],
                    capture_output=True, text=True, timeout=15)
                if proc.returncode == 0:
                    logger.info("Successfully restarted kea-dhcp4-server service")
                    return True
        except Exception as e:  # noqa: BLE001
            logger.warning("Failed to restart kea-dhcp4-server service: %s", e)
        return False

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

    def delete_lease(self, data: Dict[str, Any]) -> Dict[str, Any]:
        ip = data.get("ip") or data.get("ip-address")
        old_ip = data.get("old_ip")
        mac = data.get("mac") or data.get("hw-address")
        if not ip and not mac and not old_ip:
            return {"status": "ERROR", "message": "ip, old_ip, or mac is required"}
        purged = set()
        if hasattr(self.mgr, "purge_leases_for_mac_or_ip"):
            if ip:
                purged.update(self.mgr.purge_leases_for_mac_or_ip(mac=mac, ip=ip))
            if old_ip and old_ip != ip:
                purged.update(self.mgr.purge_leases_for_mac_or_ip(mac=mac, ip=old_ip))
            if mac and not ip and not old_ip:
                purged.update(self.mgr.purge_leases_for_mac_or_ip(mac=mac))
        else:
            if ip:
                self.mgr.delete_lease(ip)
                purged.add(ip)
            if old_ip and old_ip != ip:
                self.mgr.delete_lease(old_ip)
                purged.add(old_ip)
        return {"status": "SUCCESS", "purged": list(purged)}

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
            "KEAW_DEL_LEASE": self.delete_lease,
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
