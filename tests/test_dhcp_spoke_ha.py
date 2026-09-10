"""``DHCPSpoke`` HA wiring + ``DhcpWorkerOps`` operation table.

The first group is the regression gate for every existing single-host install:
with no HA pair configured the spoke must still drive its LOCAL ``KeaManager``
exactly as before. The second group locks the worker's closed op table and its
snapshot/rollback contract — the coordinator's mid-chain rollback is only sound
if a node that applied can actually be restored.
"""

import asyncio
import copy
import json

import pytest

from dhcp_spoke import DHCPSpoke
from dhcp_worker import DhcpWorkerOps
from kea_ha import config_fingerprint

# The full per-member HA material a real node carries: mutually-verified TLS
# PLUS the control credentials the HA agent demands (see
# test_the_passwordless_fresh_ui_payload_fails_clearly for the omission case).
HA_TLS = {"ha_trust_anchor": "/etc/kea/ha-tls/ha-ca.pem",
          "ha_cert": "/etc/kea/ha-tls/node.crt",
          "ha_key": "/etc/kea/ha-tls/node.key",
          "ha_user": "kea-ha", "ha_password": "ha-pass"}


class FakeMgr:
    def __init__(self):
        self.calls = []
        self.ca_url = "http://localhost:8001"
        self.config = {"subnet4": [{"id": 1, "subnet": "10.0.1.0/24"}]}
        self.rpc = []
        self.rpc_fail = set()

    # KeaManager surface used by the spoke
    def sync(self, subnets, reservations):
        self.calls.append(("sync", len(subnets), len(reservations)))
        return {"status": "SUCCESS", "subnets": len(subnets),
                "reservations": len(reservations)}

    def list_subnets(self):
        self.calls.append(("list_subnets",))
        return [{"id": 1, "subnet": "10.0.1.0/24"}]

    def list_leases(self, subnet=None):
        self.calls.append(("list_leases", subnet))
        return [{"ip-address": "10.0.1.100"}]

    def list_reservations(self):
        self.calls.append(("list_reservations",))
        return [{"ip": "10.0.1.50"}]

    def add_reservation(self, subnet_id, ip, mac, hostname=""):
        self.calls.append(("add_reservation", subnet_id, ip, mac, hostname))
        return {"status": "SUCCESS"}

    def update_reservation(self, old_ip, subnet_id, ip, mac, hostname=""):
        self.calls.append(("update_reservation", old_ip, ip))
        return {"status": "SUCCESS"}

    def delete_reservation(self, ip):
        self.calls.append(("delete_reservation", ip))
        return {"status": "SUCCESS"}

    def status(self):
        self.calls.append(("status",))
        return {"running": True, "subnet_count": 1, "ca_url": self.ca_url}

    def diagnostics(self):
        self.calls.append(("diagnostics",))
        return {"status": "SUCCESS", "healthy": True, "recommendations": []}

    def get_stats(self):
        self.calls.append(("get_stats",))
        return {"status": "SUCCESS", "global": {}, "subnets": []}

    # KeaManager internals used by the worker ops
    def get_config(self):
        if "config-get" in self.rpc_fail:
            raise RuntimeError("CA unreachable")
        return copy.deepcopy(self.config)

    def _set_config(self, cfg):
        if "config-set" in self.rpc_fail:
            raise RuntimeError("config-set refused")
        self.config = copy.deepcopy(cfg)

    def apply_config(self, cfg):
        """Mirrors KeaManager.apply_config: two OBSERVABLE steps."""
        if "config-set" in self.rpc_fail:
            return {"set": False, "written": False, "error": "config-set refused"}
        self.config = copy.deepcopy(cfg)
        if "config-write" in self.rpc_fail:
            return {"set": True, "written": False, "error": "config-write refused"}
        return {"set": True, "written": True, "error": ""}

    def _rpc(self, service, command, args=None):
        self.rpc.append((command, args))
        if command in self.rpc_fail:
            raise RuntimeError(f"{command} rejected")
        if command == "status-get":
            return {"high-availability": [{"ha-servers": {
                "local": {"role": "primary", "state": "hot-standby",
                          "scopes": ["server1"]},
                "remote": {"role": "standby", "last-state": "hot-standby",
                           "in-touch": True, "last-scopes": []}}}]}
        return {}


class FakeTransport:
    def __init__(self, members):
        self.members = list(members)
        self.sent = []
        self.stood_down = []
        self.standdown_fails = set()

    @property
    def enabled(self):
        return len(self.members) >= 2

    def set_members(self, members):
        self.members = [m if isinstance(m, dict) else {"id": m, "host": ""}
                        for m in members if (m.get("id") if isinstance(m, dict) else m)]
        return self.members

    def member_ids(self):
        return [m["id"] for m in self.members]

    def member_links(self):
        return [{"id": m["id"], "host": m.get("host", ""), "role": "",
                 "connected": True, "pending_approval": False, "last_seen": 1.0,
                 "seconds_since_seen": 1.0, "version": "1.0"}
                for m in self.members]

    async def call(self, member_id, command, data, timeout=20.0):
        self.sent.append((member_id, command))
        if command == "KEAW_GET_CONFIG":
            return {"status": "SUCCESS",
                    "config": {"interfaces-config": {"interfaces": ["eth0"]},
                               "subnet4": []}}
        if command == "KEAW_STANDDOWN":
            if member_id in self.standdown_fails:
                return {"status": "ERROR", "message": "unreachable"}
            self.stood_down.append(member_id)
            return {"status": "SUCCESS", "changed": True}
        if command == "KEAW_APPLY":
            return {"status": "SUCCESS", "version": data.get("version"),
                    "mutated": True,
                    "digest": config_fingerprint(data["config"])}
        return {"status": "SUCCESS"}

    async def fanout(self, command, data, timeout=20.0, member_ids=None):
        targets = list(member_ids) if member_ids is not None else self.member_ids()
        results = {}
        for m in targets:
            self.sent.append((m, command))
            if command == "KEAW_LIST_SUBNETS":
                results[m] = {"status": "SUCCESS",
                              "subnets": [{"id": 1, "subnet": "10.0.1.0/24"}]}
            elif command == "KEAW_LIST_LEASES":
                results[m] = {"status": "SUCCESS",
                              "leases": [{"ip-address": "10.0.1.100"}]}
            elif command == "KEAW_DIAGNOSTICS":
                results[m] = {"status": "SUCCESS", "healthy": True,
                              "recommendations": [], "units": {}}
            elif command == "KEAW_HA_STATUS":
                results[m] = {"status": "SUCCESS", "running": True,
                              "subnet_count": 1, "digest": "shared",
                              "status_get": {"high-availability": [{"ha-servers": {
                                  "local": {"role": "primary", "state": "hot-standby",
                                            "scopes": ["server1"]},
                                  "remote": {"role": "standby",
                                             "last-state": "hot-standby",
                                             "in-touch": True, "last-scopes": []}}}]}}
            else:
                results[m] = {"status": "SUCCESS"}
        return {"status": "SUCCESS", "results": results, "ok": targets, "failed": []}


def _spoke(tmp_path, members=None):
    spoke = DHCPSpoke("dhcp-1", {
        "cluster_members": members or [],
        "cluster_config": str(tmp_path / "cluster.json"),
        "desired_state": str(tmp_path / "desired.json"),
    })
    spoke.mgr = FakeMgr()
    spoke._transport = FakeTransport(
        [{"id": m, "host": f"10.0.1.{10 + i}", **HA_TLS} if isinstance(m, str)
         else {**HA_TLS, **m}
         for i, m in enumerate(members or [])])
    spoke.cluster.transport = spoke._transport
    return spoke


def _run(coro):
    return asyncio.run(coro)


# ── Single-host: unchanged ──────────────────────────────────────────────────

def test_single_host_operations_still_go_to_the_local_kea(tmp_path):
    spoke = _spoke(tmp_path)
    assert spoke.cluster.enabled is False
    assert spoke.cluster_listener_required() is False
    assert _run(spoke.handle_command("DHCP_SYNC", {
        "subnets": [{"subnet": "10.0.1.0/24"}], "reservations": []}))["status"] == "SUCCESS"
    assert _run(spoke.handle_command("DHCP_LIST_SUBNETS", {}))["subnets"][0]["id"] == 1
    assert _run(spoke.handle_command("DHCP_STATUS", {}))["running"] is True
    assert _run(spoke.handle_command("DHCP_DIAGNOSTICS", {}))["healthy"] is True
    assert [c[0] for c in spoke.mgr.calls] == [
        "sync", "list_subnets", "status", "diagnostics"]
    assert spoke._transport.sent == []


def test_single_host_telemetry_shape_is_unchanged(tmp_path):
    status = _run(_spoke(tmp_path).get_status())
    assert status["kea"] == "running" and status["status"] == "HEALTHY"
    assert "cluster" not in status


def test_ha_status_on_a_single_host_says_disabled(tmp_path):
    out = _run(_spoke(tmp_path).handle_command("DHCP_HA_STATUS", {}))
    assert out["enabled"] is False and out["mode"] == "hot-standby"


# ── HA pair ─────────────────────────────────────────────────────────────────

def test_ha_sync_configures_both_nodes_and_skips_the_local_manager(tmp_path):
    spoke = _spoke(tmp_path, ["kea-a", "kea-b"])
    out = _run(spoke.handle_command("DHCP_SYNC", {
        "subnets": [{"subnet": "10.0.1.0/24"}],
        "reservations": [{"ip": "10.0.1.50", "mac": "aa:bb:cc:dd:ee:ff"}]}))
    assert out["status"] == "SUCCESS"
    assert out["applied"] == ["kea-b", "kea-a"], "standby applies before primary"
    assert spoke.mgr.calls == []


def test_ha_reservation_change_reapplies_the_whole_pair(tmp_path):
    spoke = _spoke(tmp_path, ["kea-a", "kea-b"])
    _run(spoke.handle_command("DHCP_SYNC", {
        "subnets": [{"subnet": "10.0.1.0/24"}], "reservations": []}))
    spoke._transport.sent.clear()
    out = _run(spoke.handle_command("DHCP_ADD_RES", {
        "subnet_id": 1, "ip": "10.0.1.50", "mac": "aa:bb:cc:dd:ee:ff"}))
    assert out["status"] == "SUCCESS"
    assert [c for c in spoke._transport.sent if c[1] == "KEAW_APPLY"] == [
        ("kea-b", "KEAW_APPLY"), ("kea-a", "KEAW_APPLY")]
    assert spoke.cluster.desired["reservations"][0]["ip"] == "10.0.1.50"


def test_ha_reservation_change_without_a_prior_sync_is_refused(tmp_path):
    spoke = _spoke(tmp_path, ["kea-a", "kea-b"])
    out = _run(spoke.handle_command("DHCP_ADD_RES", {
        "subnet_id": 1, "ip": "10.0.1.50", "mac": "aa:bb:cc:dd:ee:ff"}))
    assert out["status"] == "ERROR" and "run a DHCP sync" in out["message"]
    assert spoke._transport.sent == []


def test_ha_lists_merge_across_nodes_without_duplicates(tmp_path):
    spoke = _spoke(tmp_path, ["kea-a", "kea-b"])
    leases = _run(spoke.handle_command("DHCP_LIST_LEASES", {}))
    assert leases["cluster"] is True and len(leases["leases"]) == 1


def test_ha_diagnostics_carry_the_pair_view(tmp_path):
    spoke = _spoke(tmp_path, ["kea-a", "kea-b"])
    out = _run(spoke.handle_command("DHCP_DIAGNOSTICS", {}))
    assert out["cluster"]["mode"] == "hot-standby"
    assert out["cluster"]["state"] == "healthy"
    assert set(out["members"]) == {"kea-a", "kea-b"}
    assert out["healthy"] is True


def test_ha_telemetry_reports_the_pair(tmp_path):
    spoke = _spoke(tmp_path, ["kea-a", "kea-b"])
    _run(spoke.cluster.refresh_status())
    status = _run(spoke.get_status())
    assert status["kea"] == "ha-pair"
    assert status["cluster"]["mode"] == "hot-standby"
    assert status["status"] == "HEALTHY"


# ── Configuration ───────────────────────────────────────────────────────────

class FakePlane:
    def __init__(self, secret=None):
        self.secret = secret
        self.agent_secret = secret or ""
        self.restored = []
        self.ensured = 0
        self._agent_server_task = None

    def set_agent_secret(self, secret):
        self.secret = secret
        self.agent_secret = secret
        return True

    def snapshot_agent_secret(self):
        return str(self.agent_secret or "")

    def restore_agent_secret(self, previous):
        self.restored.append(previous)
        self.secret = previous or None
        self.agent_secret = previous
        return True

    async def ensure_cluster_listener(self):
        self.ensured += 1
        return True


def test_ha_config_persists_pair_and_mode_and_hides_the_psk(tmp_path):
    spoke = _spoke(tmp_path)
    plane = FakePlane()
    spoke.control_plane = plane
    out = _run(spoke.handle_command("DHCP_HA_CONFIG", {
        "members": [{"id": "kea-a", "host": "10.0.1.10", **HA_TLS},
                    {"id": "kea-b", "host": "10.0.1.11", **HA_TLS}],
        "worker_secret": "psk"}))
    assert out["status"] == "SUCCESS" and out["mode"] == "hot-standby"
    assert "psk" not in json.dumps(out)
    assert plane.secret == "psk" and plane.ensured == 1
    saved = json.loads((tmp_path / "cluster.json").read_text())
    assert saved["mode"] == "hot-standby"
    assert [m["id"] for m in saved["members"]] == ["kea-a", "kea-b"]


def test_ha_config_defaults_to_hot_standby(tmp_path):
    spoke = _spoke(tmp_path)
    spoke.control_plane = FakePlane(secret="already-set")
    out = _run(spoke.handle_command("DHCP_HA_CONFIG", {
        "members": [{"id": "kea-a", "host": "10.0.1.10", **HA_TLS},
                    {"id": "kea-b", "host": "10.0.1.11", **HA_TLS}]}))
    assert out["mode"] == "hot-standby"


def test_an_invalid_pair_is_refused_and_not_persisted(tmp_path):
    spoke = _spoke(tmp_path)
    spoke.control_plane = FakePlane(secret="already-set")
    out = _run(spoke.handle_command("DHCP_HA_CONFIG", {
        "members": [{"id": "kea-a", "host": "10.0.1.10", **HA_TLS},
                    {"id": "kea-b", "host": "10.0.1.10", **HA_TLS}]}))
    assert out["status"] == "ERROR" and "same control-agent URL" in out["message"]
    assert not (tmp_path / "cluster.json").exists()


# ── Worker op table ─────────────────────────────────────────────────────────

def _ops():
    return DhcpWorkerOps(FakeMgr())


def test_worker_exposes_only_the_declared_operations():
    from kea_ha import DHCP_WORKER_OPS
    assert set(_ops().op_table()) == set(DHCP_WORKER_OPS)


def test_validate_uses_keas_own_config_test():
    ops = _ops()
    out = ops.validate({"config": {"Dhcp4": {"subnet4": []}}})
    assert out["status"] == "SUCCESS"
    assert ops.mgr.rpc[-1][0] == "config-test"


def test_validate_reports_a_rejected_config():
    ops = _ops()
    ops.mgr.rpc_fail.add("config-test")
    out = ops.validate({"config": {"subnet4": []}})
    assert out["status"] == "ERROR" and "config-test rejected" in out["message"]


def test_validate_requires_a_config():
    assert _ops().validate({})["status"] == "ERROR"


def test_apply_snapshots_then_writes_and_rollback_restores():
    ops = _ops()
    before = copy.deepcopy(ops.mgr.config)
    new_cfg = {"subnet4": [{"id": 2, "subnet": "10.0.2.0/24"}]}
    out = ops.apply({"config": new_cfg, "version": 3})
    assert out["status"] == "SUCCESS" and out["version"] == 3
    assert out["mutated"] is True
    assert out["digest"] == config_fingerprint(new_cfg)
    assert ops.mgr.config == new_cfg
    assert ops.rollback({})["status"] == "SUCCESS"
    assert ops.mgr.config == before


def test_get_config_returns_the_full_running_config():
    """REGRESSION (review #5): the coordinator renders each node's next config
    on top of this."""
    ops = _ops()
    out = ops.get_config({})
    assert out["status"] == "SUCCESS"
    assert out["config"] == ops.mgr.config
    assert out["digest"] == config_fingerprint(ops.mgr.config)


def test_get_config_surfaces_an_unreachable_control_agent():
    ops = _ops()
    ops.mgr.rpc_fail.add("config-get")
    assert ops.get_config({})["status"] == "ERROR"


def test_config_write_failure_restores_locally_and_reports_not_mutated():
    """REGRESSION (review #6): config-set landed, so the node IS running the new
    config. The worker must restore it itself rather than leave it diverged."""
    ops = _ops()
    before = copy.deepcopy(ops.mgr.config)
    calls = {"n": 0}

    def flaky(cfg):
        calls["n"] += 1
        ops.mgr.config = copy.deepcopy(cfg)
        if calls["n"] == 1:
            return {"set": True, "written": False, "error": "config-write refused"}
        return {"set": True, "written": True, "error": ""}

    ops.mgr.apply_config = flaky
    out = ops.apply({"config": {"subnet4": [{"id": 2}]}, "version": 4})
    assert out["status"] == "ERROR"
    assert out["mutated"] is False and out["restored"] is True
    assert "config-write failed" in out["message"]
    assert ops.mgr.config == before, "the previous config must be back in place"


def test_a_restore_that_cannot_persist_counts_as_mutated():
    """REGRESSION (review #8): a restore whose config-write failed leaves the
    ABANDONED config on disk — a Kea restart would boot it. That is a mutated
    node, so the coordinator must still roll it back."""
    ops = _ops()

    def always_unpersisted(cfg):
        ops.mgr.config = copy.deepcopy(cfg)
        return {"set": True, "written": False, "error": "config-write refused"}

    ops.mgr.apply_config = always_unpersisted
    out = ops.apply({"config": {"subnet4": [{"id": 2}]}, "version": 4})
    assert out["status"] == "PARTIAL"
    assert out["mutated"] is True and out["restored"] is False
    assert "could NOT be persisted" in out["message"]


def test_write_and_restore_both_failing_is_partial_and_mutated():
    """REGRESSION (review #6): if the local restore also fails the node really
    is running the new config — PARTIAL, never ERROR-and-forget."""
    ops = _ops()
    new_cfg = {"subnet4": [{"id": 2}]}

    calls = {"n": 0}
    real_apply = ops.mgr.apply_config

    def flaky(cfg):
        calls["n"] += 1
        if calls["n"] == 1:
            ops.mgr.config = copy.deepcopy(cfg)
            return {"set": True, "written": False, "error": "config-write refused"}
        return {"set": False, "written": False, "error": "CA gone"}

    ops.mgr.apply_config = flaky
    out = ops.apply({"config": new_cfg, "version": 5})
    assert out["status"] == "PARTIAL"
    assert out["mutated"] is True and out["restored"] is False
    assert ops.mgr.config == new_cfg
    ops.mgr.apply_config = real_apply


def test_config_set_failure_reports_not_mutated():
    ops = _ops()
    ops.mgr.rpc_fail.add("config-set")
    out = ops.apply({"config": {"subnet4": []}, "version": 6})
    assert out["status"] == "ERROR" and out["mutated"] is False


def test_rollback_that_cannot_persist_is_partial():
    ops = _ops()
    ops.apply({"config": {"subnet4": [{"id": 2}]}, "version": 7})
    ops.mgr.rpc_fail.add("config-write")
    out = ops.rollback({})
    assert out["status"] == "PARTIAL" and "not persisted" in out["message"]


def test_apply_refuses_when_it_cannot_snapshot_for_rollback():
    ops = _ops()
    ops.mgr.rpc_fail.add("config-get")
    out = ops.apply({"config": {"subnet4": []}})
    assert out["status"] == "ERROR" and "cannot snapshot" in out["message"]


def test_apply_failure_leaves_the_running_config_alone():
    ops = _ops()
    before = copy.deepcopy(ops.mgr.config)
    ops.mgr.rpc_fail.add("config-set")
    assert ops.apply({"config": {"subnet4": []}})["status"] == "ERROR"
    assert ops.mgr.config == before


def test_rollback_without_a_snapshot_is_an_error_not_a_silent_success():
    assert _ops().rollback({})["status"] == "ERROR"


def test_ha_status_op_parses_state_and_reports_the_running_digest():
    ops = _ops()
    out = ops.ha_status({})
    assert out["status"] == "SUCCESS"
    assert out["ha"]["ha_enabled"] and out["ha"]["in_sync"]
    assert out["digest"] == config_fingerprint(ops.mgr.config)
    assert out["subnet_count"] == 1


def test_ha_status_op_reports_an_unreachable_control_agent():
    ops = _ops()
    ops.mgr.rpc_fail.add("status-get")
    out = ops.ha_status({})
    assert out["status"] == "ERROR" and out["running"] is False


def test_ha_reapply_without_a_prior_sync_is_refused(tmp_path):
    """A coordinator restarted before its first sync has no desired intent.
    Re-applying an EMPTY subnet4 to both nodes would take DHCP down fleet-wide."""
    spoke = _spoke(tmp_path, ["kea-a", "kea-b"])
    out = _run(spoke.handle_command("DHCP_HA_APPLY", {}))
    assert out["status"] == "ERROR" and "run a" in out["message"].lower()
    assert spoke._transport.sent == []


def test_ha_reapply_after_a_sync_reconfigures_both_nodes(tmp_path):
    spoke = _spoke(tmp_path, ["kea-a", "kea-b"])
    _run(spoke.handle_command("DHCP_SYNC", {
        "subnets": [{"subnet": "10.0.1.0/24"}], "reservations": []}))
    spoke._transport.sent.clear()
    out = _run(spoke.handle_command("DHCP_HA_APPLY", {}))
    assert out["status"] == "SUCCESS"
    assert [c for c in spoke._transport.sent if c[1] == "KEAW_APPLY"] == [
        ("kea-b", "KEAW_APPLY"), ("kea-a", "KEAW_APPLY")]


def test_ha_config_never_echoes_the_ha_password(tmp_path):
    """REGRESSION (review #1): the HA basic-auth credential renders into Kea's
    config and must not come back out through the API."""
    spoke = _spoke(tmp_path)
    spoke.control_plane = plane = FakePlane(secret="already-set")
    out = _run(spoke.handle_command("DHCP_HA_CONFIG", {
        "members": [{"id": "kea-a", "host": "10.0.1.10", **HA_TLS,
                     "ha_user": "u", "ha_password": "sekrit"},
                    {"id": "kea-b", "host": "10.0.1.11", **HA_TLS,
                     "ha_user": "u", "ha_password": "sekrit"}]}))
    assert out["status"] == "SUCCESS"
    assert "sekrit" not in json.dumps(out)
    assert out["members"][0]["ha_password_set"] is True
    # ...but it IS persisted so the coordinator can render the hook config.
    saved = json.loads((tmp_path / "cluster.json").read_text())
    assert saved["members"][0]["ha_password"] == "sekrit"


def test_ha_status_never_echoes_the_ha_password(tmp_path):
    spoke = _spoke(tmp_path, [
        {"id": "kea-a", "host": "10.0.1.10", "ha_user": "u",
         "ha_password": "sekrit"},
        {"id": "kea-b", "host": "10.0.1.11", "ha_user": "u",
         "ha_password": "sekrit"}])
    out = _run(spoke.handle_command("DHCP_HA_STATUS", {}))
    assert "sekrit" not in json.dumps(out)


def test_ha_member_fields_survive_normalization(tmp_path):
    """REGRESSION (review #1): normalize_members used to drop every key it did
    not know, silently reverting the pair to the default HA port + no auth."""
    spoke = _spoke(tmp_path)
    spoke.control_plane = FakePlane(secret="already-set")
    _run(spoke.handle_command("DHCP_HA_CONFIG", {
        "members": [{"id": "kea-a", "host": "10.0.1.10", "ha_port": 9002,
                     **HA_TLS, "ha_user": "u", "ha_password": "p"},
                    {"id": "kea-b", "host": "10.0.1.11", "ha_port": 9002,
                     **HA_TLS, "ha_user": "u", "ha_password": "p"}]}))
    saved = json.loads((tmp_path / "cluster.json").read_text())
    assert saved["members"][0]["ha_port"] == 9002
    assert saved["members"][0]["ha_user"] == "u"


# ── Review #2: the worker secret is never generated ────────────────────────

def test_enabling_a_pair_without_a_secret_is_refused(tmp_path):
    """REGRESSION (review #2): a minted secret nobody can read could never be
    given to the workers, so the pair could never authenticate."""
    spoke = _spoke(tmp_path)
    spoke.control_plane = FakePlane()          # no stored secret
    out = _run(spoke.handle_command("DHCP_HA_CONFIG", {
        "members": [{"id": "kea-a", "host": "10.0.1.10", **HA_TLS},
                    {"id": "kea-b", "host": "10.0.1.11", **HA_TLS}]}))
    assert out["status"] == "ERROR" and out["secret_required"] is True
    assert not (tmp_path / "cluster.json").exists()
    assert spoke.control_plane.secret is None
    assert spoke.cluster.enabled is False, "the topology must be rolled back"


def test_a_resubmit_without_a_secret_keeps_the_stored_one(tmp_path):
    spoke = _spoke(tmp_path)
    plane = FakePlane()
    spoke.control_plane = plane
    first = _run(spoke.handle_command("DHCP_HA_CONFIG", {
        "members": [{"id": "kea-a", "host": "10.0.1.10", **HA_TLS},
                    {"id": "kea-b", "host": "10.0.1.11", **HA_TLS}],
        "worker_secret": "psk"}))
    assert first["status"] == "SUCCESS"
    again = _run(spoke.handle_command("DHCP_HA_CONFIG", {
        "members": [{"id": "kea-a", "host": "10.0.1.10", **HA_TLS},
                    {"id": "kea-b", "host": "10.0.1.11", **HA_TLS}]}))
    assert again["status"] == "SUCCESS"
    assert plane.secret == "psk"


# ── Review #3: write-only HA fields are preserved, not cleared ─────────────

def test_omitted_ha_password_is_carried_forward(tmp_path):
    spoke = _spoke(tmp_path)
    spoke.control_plane = FakePlane(secret="already-set")
    _run(spoke.handle_command("DHCP_HA_CONFIG", {
        "members": [{"id": "kea-a", "host": "10.0.1.10", **HA_TLS,
                     "ha_user": "u", "ha_password": "sekrit", "ha_port": 9002},
                    {"id": "kea-b", "host": "10.0.1.11", **HA_TLS,
                     "ha_user": "u", "ha_password": "sekrit", "ha_port": 9002}]}))
    # A re-save from a UI that cannot read the password must not erase it.
    _run(spoke.handle_command("DHCP_HA_CONFIG", {
        "members": [{"id": "kea-a", "host": "10.0.1.10"},
                    {"id": "kea-b", "host": "10.0.1.11"}]}))
    saved = json.loads((tmp_path / "cluster.json").read_text())
    assert saved["members"][0]["ha_password"] == "sekrit"
    assert saved["members"][0]["ha_user"] == "u"
    assert saved["members"][0]["ha_port"] == 9002
    assert saved["members"][0]["ha_trust_anchor"] == HA_TLS["ha_trust_anchor"]


# ── Review #4: load-balancing is refused at the module boundary ────────────

def test_load_balancing_is_refused_by_the_spoke(tmp_path):
    spoke = _spoke(tmp_path)
    spoke.control_plane = FakePlane(secret="already-set")
    out = _run(spoke.handle_command("DHCP_HA_CONFIG", {
        "members": [{"id": "kea-a", "host": "10.0.1.10", **HA_TLS},
                    {"id": "kea-b", "host": "10.0.1.11", **HA_TLS}],
        "mode": "load-balancing"}))
    assert out["status"] == "ERROR"
    assert out["supported_modes"] == ["hot-standby"]
    assert "class" in out["message"]
    assert not (tmp_path / "cluster.json").exists()


# ── Review #12: topology restore on failure ────────────────────────────────

def test_a_failed_save_restores_the_previous_topology_and_mode(tmp_path):
    spoke = _spoke(tmp_path, ["kea-a", "kea-b"])
    spoke.control_plane = FakePlane(secret="already-set")
    before_ids = [m["id"] for m in spoke._transport.members]
    before_mode = spoke.cluster.mode
    before_hooks = spoke._hook_dir
    spoke._cluster_config_path = str(tmp_path / "missing" / "\0bad" / "c.json")
    out = _run(spoke.handle_command("DHCP_HA_CONFIG", {
        "members": [{"id": "kea-x", "host": "10.0.9.1", **HA_TLS},
                    {"id": "kea-y", "host": "10.0.9.2", **HA_TLS}],
        "hook_dir": "/somewhere/else"}))
    assert out["status"] == "ERROR"
    assert [m["id"] for m in spoke._transport.members] == before_ids
    assert spoke.cluster.mode == before_mode
    assert spoke._hook_dir == before_hooks
    assert spoke.cluster.hook_dir == before_hooks


# ── Review #13: removed nodes are stood down or reported ───────────────────

def test_removing_a_member_stands_it_down(tmp_path):
    spoke = _spoke(tmp_path, ["kea-a", "kea-b"])
    spoke.control_plane = FakePlane(secret="already-set")
    out = _run(spoke.handle_command("DHCP_HA_CONFIG", {"members": []}))
    assert out["status"] == "SUCCESS"
    assert sorted(out["removed"]) == ["kea-a", "kea-b"]
    assert sorted(out["removed_stood_down"]) == ["kea-a", "kea-b"]
    assert sorted(spoke._transport.stood_down) == ["kea-a", "kea-b"]


def test_an_unreachable_removed_member_is_reported_as_partial(tmp_path):
    spoke = _spoke(tmp_path, ["kea-a", "kea-b"])
    spoke.control_plane = FakePlane(secret="already-set")
    spoke._transport.standdown_fails.add("kea-b")
    out = _run(spoke.handle_command("DHCP_HA_CONFIG", {"members": []}))
    assert out["status"] == "PARTIAL"
    assert out["removed_unreachable"] == ["kea-b"]
    assert "still be running the HA hooks" in out["message"]


def test_standdown_op_strips_the_ha_hooks_only():
    ops = _ops()
    ops.mgr.config = {"interfaces-config": {"interfaces": ["eth0"]},
                      "subnet4": [{"id": 1}],
                      "hooks-libraries": [
                          {"library": "/h/libdhcp_ha.so"},
                          {"library": "/h/libdhcp_lease_cmds.so"},
                          {"library": "/h/libdhcp_stat_cmds.so"}]}
    out = ops.standdown({})
    assert out["status"] == "SUCCESS" and out["hooks_removed"] == 2
    libs = [h["library"] for h in ops.mgr.config["hooks-libraries"]]
    assert libs == ["/h/libdhcp_stat_cmds.so"]
    assert ops.mgr.config["subnet4"] == [{"id": 1}], "scopes are left serving"


def test_standdown_is_idempotent():
    ops = _ops()
    ops.mgr.config = {"subnet4": [], "hooks-libraries": []}
    out = ops.standdown({})
    assert out["status"] == "SUCCESS" and out["changed"] is False


# ── Round 3, #7: the worker uses kea-common + arch-aware discovery ─────────

def test_the_worker_installs_kea_common_not_kea_hooks():
    """REGRESSION: 'kea-hooks' is not a package; the hook libraries ship in
    kea-common, so the old value could only ever fail."""
    import dhcp_worker
    assert dhcp_worker._HOOK_PACKAGES == ("kea-common",)


def test_install_hooks_resolves_the_arch_specific_dir(monkeypatch, tmp_path):
    """REGRESSION: the coordinator's x86_64 default made every arm64 node
    report its HA libraries missing."""
    import kea_ha
    hooks = tmp_path / "usr" / "lib" / "aarch64-linux-gnu" / "kea" / "hooks"
    hooks.mkdir(parents=True)
    (hooks / "libdhcp_ha.so").write_text("")
    (hooks / "libdhcp_lease_cmds.so").write_text("")
    monkeypatch.setattr(kea_ha, "HOOK_DIR_GLOBS",
                        (str(tmp_path / "usr/lib/*/kea/hooks"),))
    ops = _ops()
    out = ops.install_hooks({})          # no hook_dir supplied
    assert out["status"] == "SUCCESS" and out["installed"] is False
    assert out["hook_dir"] == str(hooks)
    assert out["libraries"]["ha"] == str(hooks / "libdhcp_ha.so")
    assert "x86_64" not in out["libraries"]["ha"]


def test_install_hooks_never_falls_back_to_the_x86_default(monkeypatch, tmp_path):
    import kea_ha
    monkeypatch.setattr(kea_ha, "HOOK_DIR_GLOBS",
                        (str(tmp_path / "nothing-here/*"),))
    monkeypatch.setattr("dhcp_worker.shutil.which", lambda _n: None)
    ops = _ops()
    out = ops.install_hooks({})
    assert out["status"] == "ERROR"
    assert "missing Kea hook libraries" in out["message"]


def test_an_explicit_hook_dir_is_honoured(tmp_path):
    hooks = tmp_path / "custom"
    hooks.mkdir()
    (hooks / "libdhcp_ha.so").write_text("")
    (hooks / "libdhcp_lease_cmds.so").write_text("")
    out = _ops().install_hooks({"hook_dir": str(hooks)})
    assert out["status"] == "SUCCESS" and out["hook_dir"] == str(hooks)


# ── Round 3, #2: listener readiness gates the SUCCESS ─────────────────────

class _ListenerPlane(FakePlane):
    def __init__(self, result, secret="already-set"):
        super().__init__(secret=secret)
        self.result = result

    async def ensure_cluster_listener(self, timeout=20.0):
        self.ensured += 1
        return self.result


def test_a_listener_that_fails_to_start_is_reported_as_an_error(tmp_path):
    spoke = _spoke(tmp_path)
    spoke.control_plane = _ListenerPlane(
        {"ok": False, "serving": False, "endpoint": "",
         "error": "could not bind 0.0.0.0:8770: address in use"})
    out = _run(spoke.handle_command("DHCP_HA_CONFIG", {
        "members": [{"id": "kea-a", "host": "10.0.1.10", **HA_TLS},
                    {"id": "kea-b", "host": "10.0.1.11", **HA_TLS}]}))
    assert out["status"] == "ERROR"
    assert "did not start" in out["message"]
    assert "address in use" in out["listener"]["error"]
    assert spoke.cluster.enabled is False
    assert json.loads((tmp_path / "cluster.json").read_text())["members"] == []


def test_a_ready_listener_reports_its_endpoint(tmp_path):
    spoke = _spoke(tmp_path)
    spoke.control_plane = _ListenerPlane(
        {"ok": True, "serving": True, "endpoint": "wss://0.0.0.0:8770",
         "error": ""})
    out = _run(spoke.handle_command("DHCP_HA_CONFIG", {
        "members": [{"id": "kea-a", "host": "10.0.1.10", **HA_TLS},
                    {"id": "kea-b", "host": "10.0.1.11", **HA_TLS}]}))
    assert out["status"] == "SUCCESS"
    assert out["listener"]["endpoint"] == "wss://0.0.0.0:8770"


# ── Round 3, #6: topology edits share the apply lock ──────────────────────

def test_topology_change_and_apply_do_not_interleave(tmp_path):
    """REGRESSION: a topology edit landing mid-apply made the apply push to (or
    stand down) a node the other transaction was working on."""
    spoke = _spoke(tmp_path, ["kea-a", "kea-b"])
    spoke.control_plane = FakePlane(secret="already-set")
    _run(spoke.handle_command("DHCP_SYNC", {
        "subnets": [{"subnet": "10.0.1.0/24"}], "reservations": []}))
    spoke._transport.sent.clear()

    async def _race():
        return await asyncio.gather(
            spoke.handle_command("DHCP_SYNC", {
                "subnets": [{"subnet": "10.0.2.0/24"}], "reservations": []}),
            spoke.handle_command("DHCP_HA_CONFIG", {
                "members": [{"id": "kea-a", "host": "10.0.1.10", **HA_TLS},
                            {"id": "kea-b", "host": "10.0.1.11", **HA_TLS}]}))

    sync_out, topo_out = asyncio.run(_race())
    assert sync_out["status"] == "SUCCESS"
    assert topo_out["status"] == "SUCCESS"
    # No stand-down was interleaved into the apply.
    ops = [c[1] for c in spoke._transport.sent]
    first_apply = ops.index("KEAW_APPLY")
    assert ops[first_apply:first_apply + 2] == ["KEAW_APPLY", "KEAW_APPLY"]
    assert spoke._transport.stood_down == []


def test_a_removal_cannot_land_between_an_applys_validate_and_commit(tmp_path):
    spoke = _spoke(tmp_path, ["kea-a", "kea-b"])
    spoke.control_plane = FakePlane(secret="already-set")
    _run(spoke.handle_command("DHCP_SYNC", {
        "subnets": [{"subnet": "10.0.1.0/24"}], "reservations": []}))
    spoke._transport.sent.clear()

    async def _race():
        return await asyncio.gather(
            spoke.handle_command("DHCP_SYNC", {
                "subnets": [{"subnet": "10.0.3.0/24"}], "reservations": []}),
            spoke.handle_command("DHCP_HA_CONFIG", {"members": []}))

    sync_out, _ = asyncio.run(_race())
    ops = [c[1] for c in spoke._transport.sent]
    if "KEAW_APPLY" in ops and "KEAW_STANDDOWN" in ops:
        last_apply = len(ops) - 1 - ops[::-1].index("KEAW_APPLY")
        first_standdown = ops.index("KEAW_STANDDOWN")
        assert first_standdown > last_apply, \
            "a stand-down interleaved with an in-flight apply"
    assert sync_out["status"] in ("SUCCESS", "ERROR")


# ── Round 4, #1: HA control credentials are mandatory on first enablement ──

#: Byte-for-byte what WebUI/main.js::saveServiceCluster sends when the operator
#: leaves the HA password blank on a FRESH pair (blank fields are omitted).
FRESH_UI_PAYLOAD_NO_PASSWORD = {
    "members": [
        {"id": "kea-a", "host": "10.0.1.10",
         "ha_trust_anchor": "/etc/kea/ha-tls/ha-ca.pem",
         "ha_cert": "/etc/kea/ha-tls/node.crt",
         "ha_key": "/etc/kea/ha-tls/node.key"},
        {"id": "kea-b", "host": "10.0.1.11",
         "ha_trust_anchor": "/etc/kea/ha-tls/ha-ca.pem",
         "ha_cert": "/etc/kea/ha-tls/node.crt",
         "ha_key": "/etc/kea/ha-tls/node.key"},
    ],
    "mode": "hot-standby",
    "worker_secret": "psk",
}


def test_the_passwordless_fresh_ui_payload_fails_clearly(tmp_path):
    """REGRESSION (round 4, #1): the pair came up looking configured and could
    never heartbeat — the HA control agent rejects an unauthenticated peer."""
    spoke = _spoke(tmp_path)
    spoke.control_plane = FakePlane()
    out = _run(spoke.handle_command("DHCP_HA_CONFIG",
                                    dict(FRESH_UI_PAYLOAD_NO_PASSWORD)))
    assert out["status"] == "ERROR"
    assert out["ha_credentials_required"] is True
    assert sorted(out["members_missing_credentials"]) == ["kea-a", "kea-b"]
    assert "ha_user" in out["message"] and "ha_password" in out["message"]
    assert "unauthenticated peer" in out["message"]
    # Nothing was enabled or persisted.
    assert spoke.cluster.enabled is False
    assert not (tmp_path / "cluster.json").exists()


def test_a_user_without_a_password_is_also_refused(tmp_path):
    spoke = _spoke(tmp_path)
    spoke.control_plane = FakePlane()
    payload = dict(FRESH_UI_PAYLOAD_NO_PASSWORD)
    payload["members"] = [{**m, "ha_user": "kea-ha"} for m in payload["members"]]
    out = _run(spoke.handle_command("DHCP_HA_CONFIG", payload))
    assert out["status"] == "ERROR" and out["ha_credentials_required"] is True


def test_one_node_missing_credentials_names_only_that_node(tmp_path):
    spoke = _spoke(tmp_path)
    spoke.control_plane = FakePlane()
    payload = dict(FRESH_UI_PAYLOAD_NO_PASSWORD)
    payload["members"] = [
        {**payload["members"][0], "ha_user": "u", "ha_password": "p"},
        payload["members"][1],
    ]
    out = _run(spoke.handle_command("DHCP_HA_CONFIG", payload))
    assert out["status"] == "ERROR"
    assert out["members_missing_credentials"] == ["kea-b"]


def test_the_complete_fresh_ui_payload_is_accepted(tmp_path):
    spoke = _spoke(tmp_path)
    spoke.control_plane = FakePlane()
    payload = dict(FRESH_UI_PAYLOAD_NO_PASSWORD)
    payload["members"] = [{**m, "ha_user": "kea-ha", "ha_password": "p"}
                          for m in payload["members"]]
    out = _run(spoke.handle_command("DHCP_HA_CONFIG", payload))
    assert out["status"] == "SUCCESS" and spoke.cluster.enabled is True


def test_omission_is_allowed_when_the_stored_credentials_are_preserved(tmp_path):
    """The write-only field is blank on a re-save; _merge_preserved carries the
    stored password forward, so this must NOT trip the requirement."""
    spoke = _spoke(tmp_path)
    spoke.control_plane = FakePlane()
    first = dict(FRESH_UI_PAYLOAD_NO_PASSWORD)
    first["members"] = [{**m, "ha_user": "kea-ha", "ha_password": "p"}
                        for m in first["members"]]
    assert _run(spoke.handle_command("DHCP_HA_CONFIG", first))["status"] == "SUCCESS"

    again = dict(FRESH_UI_PAYLOAD_NO_PASSWORD)   # password omitted again
    out = _run(spoke.handle_command("DHCP_HA_CONFIG", again))
    assert out["status"] == "SUCCESS"
    saved = json.loads((tmp_path / "cluster.json").read_text())
    assert saved["members"][0]["ha_password"] == "p"


# ── Round 4, #4: a rolled-back topology restores the previous PSK ──────────

def test_a_listener_failure_restores_the_previous_worker_secret(tmp_path):
    """REGRESSION: the new PSK was written before the listener could fail, so a
    rejected change left every already-provisioned worker unable to
    authenticate."""
    spoke = _spoke(tmp_path, ["kea-a", "kea-b"])
    plane = _ListenerPlane(
        {"ok": True, "serving": True, "endpoint": "wss://0.0.0.0:8770",
         "error": ""}, secret="original-psk")
    spoke.control_plane = plane
    plane.result = {"ok": False, "serving": False, "endpoint": "",
                    "error": "could not bind 0.0.0.0:8770"}
    out = _run(spoke.handle_command("DHCP_HA_CONFIG", {
        "members": [{"id": "kea-a", "host": "10.0.1.10", **HA_TLS,
                     "ha_user": "u", "ha_password": "p"},
                    {"id": "kea-b", "host": "10.0.1.11", **HA_TLS,
                     "ha_user": "u", "ha_password": "p"}],
        "worker_secret": "brand-new-psk"}))
    assert out["status"] == "ERROR"
    assert plane.agent_secret == "original-psk", \
        "already-provisioned workers must keep authenticating"
    assert plane.restored == ["original-psk"]


def test_a_successful_change_keeps_the_new_worker_secret(tmp_path):
    spoke = _spoke(tmp_path)
    plane = _ListenerPlane(
        {"ok": True, "serving": True, "endpoint": "wss://0.0.0.0:8770",
         "error": ""}, secret="original-psk")
    spoke.control_plane = plane
    out = _run(spoke.handle_command("DHCP_HA_CONFIG", {
        "members": [{"id": "kea-a", "host": "10.0.1.10", **HA_TLS,
                     "ha_user": "u", "ha_password": "p"},
                    {"id": "kea-b", "host": "10.0.1.11", **HA_TLS,
                     "ha_user": "u", "ha_password": "p"}],
        "worker_secret": "brand-new-psk"}))
    assert out["status"] == "SUCCESS"
    assert plane.agent_secret == "brand-new-psk"
    assert plane.restored == []


# ── Round 4, #5: the atomic reservation replacement ───────────────────────

def test_a_failed_reservation_replacement_leaves_the_original_intact():
    """REGRESSION (round 4, #5): the LM twin deleted the old entry in one write
    and added the replacement in a second, so a failure between them dropped the
    reservation entirely and the host silently fell back to a dynamic lease."""
    from kea_manager import KeaManager

    mgr = KeaManager.__new__(KeaManager)
    original = {"ip-address": "10.0.1.50", "hw-address": "aa:bb:cc:dd:ee:ff",
                "hostname": "printer"}
    state = {"subnet4": [{"id": 1, "subnet": "10.0.1.0/24",
                          "reservations": [dict(original)]}]}
    writes = []

    mgr.get_config = lambda: copy.deepcopy(state)

    def _set_config(cfg):
        writes.append(copy.deepcopy(cfg))
        raise RuntimeError("Kea rejected the configuration")

    mgr._set_config = _set_config
    out = mgr.update_reservation("10.0.1.50", 1, "10.0.1.51",
                                 "11:22:33:44:55:66", "printer2")
    assert out["status"] == "ERROR"
    # The live config is untouched...
    assert state["subnet4"][0]["reservations"] == [original]
    # ...and there was exactly ONE write attempt carrying BOTH the removal and
    # the insertion, so no intermediate "deleted" state can ever be persisted.
    assert len(writes) == 1
    ips = [r["ip-address"] for r in writes[0]["subnet4"][0]["reservations"]]
    assert ips == ["10.0.1.51"]


def test_a_successful_reservation_replacement_is_one_write():
    from kea_manager import KeaManager

    mgr = KeaManager.__new__(KeaManager)
    state = {"subnet4": [{"id": 1, "subnet": "10.0.1.0/24",
                          "reservations": [{"ip-address": "10.0.1.50",
                                            "hw-address": "aa:bb:cc:dd:ee:ff",
                                            "hostname": "printer"}]}]}
    writes = []
    mgr.get_config = lambda: copy.deepcopy(state)

    def _set_config(cfg):
        writes.append(copy.deepcopy(cfg))
        state["subnet4"] = cfg["subnet4"]

    mgr._set_config = _set_config
    out = mgr.update_reservation("10.0.1.50", 1, "10.0.1.51",
                                 "11:22:33:44:55:66", "printer2")
    assert out["status"] == "SUCCESS" and len(writes) == 1
    reservations = state["subnet4"][0]["reservations"]
    assert [r["ip-address"] for r in reservations] == ["10.0.1.51"]
    assert reservations[0]["hw-address"] == "11:22:33:44:55:66"


def test_an_unknown_subnet_is_refused_before_any_write():
    from kea_manager import KeaManager

    mgr = KeaManager.__new__(KeaManager)
    state = {"subnet4": [{"id": 1, "reservations": [{"ip-address": "10.0.1.50"}]}]}
    writes = []
    mgr.get_config = lambda: copy.deepcopy(state)
    mgr._set_config = lambda cfg: writes.append(cfg)
    out = mgr.update_reservation("10.0.1.50", 99, "10.0.1.51", "aa:bb:cc:dd:ee:ff")
    assert out["status"] == "ERROR" and "not found" in out["message"]
    assert writes == [], "the original must not be deleted by a doomed update"
