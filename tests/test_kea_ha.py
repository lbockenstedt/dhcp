"""Kea HA tests: config generation, apply transaction, status, drift.

The properties this locks in:

* **hot-standby is the default**; load-balancing only when explicitly asked for.
* **Both nodes get the identical scope/reservation block** and differ ONLY in
  their HA identity — that is what makes them a pair rather than two servers
  handing out overlapping addresses.
* **Each node's own configuration survives.** Only the coordinator-owned keys
  (``subnet4``) and the HA hooks are replaced; interfaces, lease database and
  loggers are carried through from the node's running config.
* **HA peer traffic never uses the loopback control agent.** Peer URLs point at
  the dedicated authenticated HA port, and the password never appears in a
  status/diagnostics reply.
* **A topology that is not a valid pair is rejected up front.**
* **Validation happens on BOTH nodes before EITHER is touched**, the apply order
  is standby/secondary → primary, and a mid-chain failure rolls back every
  possibly-mutated node — including the one that just failed — reporting
  PARTIAL/ERROR. Never SUCCESS.
* **The desired version is a candidate** until the whole transaction succeeds
  and is durably persisted.
* **Convergence requires a fresh, non-empty digest from every member.**
"""

import asyncio
import copy
import json
import os

import pytest

from kea_cluster import KeaHACoordinator
from kea_ha import (
    DEFAULT_HA_PORT, DEFAULT_HOOK_DIR, HOT_STANDBY, LOAD_BALANCING,
    SUPPORTED_HA_MODES, KeaHAConfigError, UnsupportedHAMode, apply_order,
    build_ha_hooks, build_node_config, build_peers, coerce_mode,
    config_fingerprint, hook_paths, load_cluster_config, normalize_mode,
    parse_ha_status, peer_roles, public_peers, resolve_hook_dir,
    save_cluster_config, summarize_ha,
)

# HA peer traffic is HTTPS with mutual verification, so every member carries its
# TLS material. build_peers REFUSES a pair without a trust anchor.
HA_TLS = {"ha_trust_anchor": "/etc/kea/ha-tls/ha-ca.pem",
          "ha_cert": "/etc/kea/ha-tls/node.crt",
          "ha_key": "/etc/kea/ha-tls/node.key"}
MEMBERS = [{"id": "kea-a", "host": "10.0.1.10", **HA_TLS},
           {"id": "kea-b", "host": "10.0.1.11", **HA_TLS}]

SUBNETS = [{"subnet": "10.0.1.0/24", "gateway": "10.0.1.1",
            "dns_servers": ["10.0.1.5"],
            "pools": [{"start": "10.0.1.100", "end": "10.0.1.200"}]}]
RESERVATIONS = [{"ip": "10.0.1.50", "mac": "AA-BB-CC-DD-EE-FF", "hostname": "printer"}]

#: A node's running config: things the coordinator does NOT own and must keep.
NODE_LOCAL = {
    "interfaces-config": {"interfaces": ["eth0"]},
    "lease-database": {"type": "memfile", "name": "/var/lib/kea/kea-leases4.csv"},
    "valid-lifetime": 4000,
    "loggers": [{"name": "kea-dhcp4", "severity": "INFO"}],
    "subnet4": [{"id": 99, "subnet": "192.0.2.0/24"}],
}


# ── Mode + roles ────────────────────────────────────────────────────────────

@pytest.mark.parametrize("given", [None, "", "hot-standby", "HOT-STANDBY",
                                   "hot_standby", "load balancing", "nonsense"])
def test_mode_defaults_to_hot_standby(given):
    assert normalize_mode(given) == HOT_STANDBY


@pytest.mark.parametrize("given", ["load-balancing", "LOAD-BALANCING",
                                   "load_balancing", "  load-balancing  "])
def test_load_balancing_is_rejected(given):
    """REGRESSION (review #4): build_subnet4 emits ONE undivided pool per
    subnet. Load-balancing without class-split pools has both servers allocating
    from the same range."""
    with pytest.raises(UnsupportedHAMode, match="class"):
        normalize_mode(given)


def test_only_hot_standby_is_advertised_as_supported():
    assert SUPPORTED_HA_MODES == (HOT_STANDBY,)


def test_a_persisted_load_balancing_mode_is_coerced_not_fatal():
    """An old cluster.json must not brick the spoke on startup."""
    assert coerce_mode("load-balancing") == HOT_STANDBY


def test_peer_roles_match_what_the_kea_ha_hook_expects():
    assert peer_roles(HOT_STANDBY) == ("primary", "standby")
    # load-balancing is refused before it can ever pick roles.
    with pytest.raises(UnsupportedHAMode):
        peer_roles(LOAD_BALANCING)


# ── Peer validation + the dedicated HA channel ──────────────────────────────

def test_peers_use_the_dedicated_ha_port_not_the_loopback_control_agent():
    """REGRESSION (review #1): the node-local control agent on 8001 is
    loopback-only and unauthenticated. HA peers must dial the separate,
    authenticated HA agent."""
    peers = build_peers(MEMBERS, HOT_STANDBY)
    assert [p["name"] for p in peers] == ["kea-a", "kea-b"]
    assert [p["role"] for p in peers] == ["primary", "standby"]
    assert [p["url"] for p in peers] == [
        f"https://10.0.1.10:{DEFAULT_HA_PORT}/",
        f"https://10.0.1.11:{DEFAULT_HA_PORT}/"]
    assert DEFAULT_HA_PORT != 8001
    assert all(":8001/" not in p["url"] for p in peers)
    assert all(p["auto-failover"] for p in peers)


def test_peers_carry_mutual_tls_and_basic_auth():
    """REGRESSION (review #5): peer traffic is HTTPS with cert verification;
    the basic-auth credentials ride INSIDE that session."""
    peers = build_peers(
        [{"id": "kea-a", "host": "10.0.1.10", "ha_user": "u", "ha_password": "p",
          **HA_TLS},
         {"id": "kea-b", "host": "10.0.1.11", "ha_user": "u", "ha_password": "p",
          **HA_TLS}], HOT_STANDBY)
    for peer in peers:
        assert peer["url"].startswith("https://")
        assert peer["trust-anchor"] == HA_TLS["ha_trust_anchor"]
        assert peer["cert-file"] == HA_TLS["ha_cert"]
        assert peer["key-file"] == HA_TLS["ha_key"]
    assert peers[0]["basic-auth-user"] == "u"
    assert peers[0]["basic-auth-password"] == "p"


def test_a_member_that_omits_tls_gets_the_canonical_installer_paths():
    """REGRESSION (round 3, #4): the UI collects id/host/credentials, so the
    per-member TLS material defaults to exactly what install_dhcp.sh writes.
    The pair is still mutually-verified TLS."""
    peers = build_peers([{"id": "kea-a", "host": "10.0.1.10"},
                         {"id": "kea-b", "host": "10.0.1.11"}], HOT_STANDBY)
    assert peers[0]["trust-anchor"] == "/etc/kea/ha-tls/ha-ca.pem"
    assert peers[0]["cert-file"] == "/etc/kea/ha-tls/node.crt"
    assert peers[0]["key-file"] == "/etc/kea/ha-tls/node.key"
    assert all(p["url"].startswith("https://") for p in peers)


def test_an_explicitly_blanked_trust_anchor_is_still_refused():
    """REGRESSION (review #5): defaulting must not become a way to opt out."""
    with pytest.raises(KeaHAConfigError, match="trust anchor"):
        build_peers([{"id": "kea-a", "host": "10.0.1.10", "ha_trust_anchor": ""},
                     {"id": "kea-b", "host": "10.0.1.11"}], HOT_STANDBY)


def test_a_plaintext_http_peer_url_is_refused():
    with pytest.raises(KeaHAConfigError, match="plaintext http"):
        build_peers([{"id": "kea-a", "ha_url": "http://a.lab:8002", **HA_TLS},
                     {"id": "kea-b", "host": "10.0.1.11", **HA_TLS}], HOT_STANDBY)


def test_a_non_https_scheme_is_refused():
    with pytest.raises(KeaHAConfigError, match="only\\s+https"):
        build_peers([{"id": "kea-a", "host": "10.0.1.10", "ha_scheme": "http",
                      **HA_TLS},
                     {"id": "kea-b", "host": "10.0.1.11", **HA_TLS}], HOT_STANDBY)


def test_ha_password_is_never_echoed_in_a_report():
    """REGRESSION (review #1): the credential renders into Kea's config and
    goes nowhere else."""
    peers = build_peers(
        [{"id": "kea-a", "host": "10.0.1.10", "ha_user": "u",
          "ha_password": "sekrit", **HA_TLS},
         {"id": "kea-b", "host": "10.0.1.11", "ha_user": "u",
          "ha_password": "sekrit", **HA_TLS}], HOT_STANDBY)
    published = public_peers(peers)
    assert all("basic-auth-password" not in p for p in published)
    assert published[0]["basic-auth"] is True
    assert "sekrit" not in json.dumps(published)
    summary = summarize_ha(HOT_STANDBY, peers, [], {}, {})
    assert "sekrit" not in json.dumps(summary["peers"])


def test_explicit_ha_url_and_port_are_honored():
    peers = build_peers([{"id": "kea-a", "ha_url": "https://a.lab:9000", **HA_TLS},
                         {"id": "kea-b", "host": "10.0.1.11", "ha_port": 8005,
                          **HA_TLS}], HOT_STANDBY)
    assert peers[0]["url"] == "https://a.lab:9000/"
    assert peers[1]["url"] == "https://10.0.1.11:8005/"


def test_explicit_roles_reorder_so_primary_is_first():
    peers = build_peers([{"id": "kea-b", "host": "10.0.1.11", "role": "standby",
                          **HA_TLS},
                         {"id": "kea-a", "host": "10.0.1.10", "role": "primary",
                          **HA_TLS}], HOT_STANDBY)
    assert [p["name"] for p in peers] == ["kea-a", "kea-b"]
    assert peers[0]["role"] == "primary"


@pytest.mark.parametrize("members,match", [
    ([MEMBERS[0]], "exactly 2 members"),
    (MEMBERS + [{"id": "kea-c", "host": "10.0.1.12", **HA_TLS}], "exactly 2 members"),
    ([{"id": "kea-a", "host": "10.0.1.10", **HA_TLS},
      {"id": "", "host": "10.0.1.11", **HA_TLS}], "non-empty id"),
    ([{"id": "kea-a", "host": "10.0.1.10", **HA_TLS},
      {"id": "kea-a", "host": "10.0.1.11", **HA_TLS}], "peers must be distinct"),
    ([{"id": "kea-a", "host": "10.0.1.10", **HA_TLS},
      {"id": "kea-b", "host": "10.0.1.10", **HA_TLS}], "same control-agent URL"),
    ([{"id": "kea-a", **HA_TLS}, {"id": "kea-b", "host": "10.0.1.11", **HA_TLS}],
     "needs a host or an explicit HA url"),
])
def test_an_invalid_pair_is_rejected(members, match):
    with pytest.raises(KeaHAConfigError, match=match):
        build_peers(members, HOT_STANDBY)


# ── Node config generation ──────────────────────────────────────────────────

def _node_configs(mode=HOT_STANDBY, node_local=None, owned=None):
    peers = build_peers(MEMBERS, mode)
    base = copy.deepcopy(node_local if node_local is not None else NODE_LOCAL)
    owned = owned if owned is not None else {
        "subnet4": [{"id": 1, "subnet": "10.0.1.0/24"}]}
    return peers, {p["name"]: build_node_config(base, p["name"], peers, mode,
                                                DEFAULT_HOOK_DIR, owned=owned)
                   for p in peers}


def test_both_nodes_load_the_ha_and_lease_cmds_hooks():
    _, configs = _node_configs()
    paths = hook_paths(DEFAULT_HOOK_DIR)
    for cfg in configs.values():
        libs = [h["library"] for h in cfg["hooks-libraries"]]
        assert libs == [paths["lease_cmds"], paths["ha"]], \
            "lease_cmds must load before the HA hook — HA synchronises leases through it"


def test_each_nodes_own_configuration_is_preserved():
    """REGRESSION (review #5): rendering from {} silently wiped interfaces, the
    lease database and loggers the first time HA was applied."""
    _, configs = _node_configs()
    for cfg in configs.values():
        assert cfg["interfaces-config"] == {"interfaces": ["eth0"]}
        assert cfg["lease-database"]["name"] == "/var/lib/kea/kea-leases4.csv"
        assert cfg["valid-lifetime"] == 4000
        assert cfg["loggers"][0]["name"] == "kea-dhcp4"
        # Only the coordinator-owned key was replaced.
        assert cfg["subnet4"] == [{"id": 1, "subnet": "10.0.1.0/24"}]


def test_owned_keys_are_left_alone_when_the_coordinator_supplies_none():
    _, configs = _node_configs(owned={})
    assert configs["kea-a"]["subnet4"] == [{"id": 99, "subnet": "192.0.2.0/24"}]


def test_both_nodes_share_identical_scopes_and_differ_only_in_ha_identity():
    _, configs = _node_configs()
    a, b = configs["kea-a"], configs["kea-b"]
    assert a["subnet4"] == b["subnet4"]
    assert config_fingerprint(a) == config_fingerprint(b)

    def ha(c):
        return c["hooks-libraries"][1]["parameters"]["high-availability"][0]

    assert ha(a)["this-server-name"] == "kea-a"
    assert ha(b)["this-server-name"] == "kea-b"
    assert ha(a)["peers"] == ha(b)["peers"], "both nodes must agree on the peer list"


def test_hot_standby_writes_primary_and_standby_roles():
    _, configs = _node_configs(HOT_STANDBY)
    ha = configs["kea-a"]["hooks-libraries"][1]["parameters"]["high-availability"][0]
    assert ha["mode"] == HOT_STANDBY
    assert [p["role"] for p in ha["peers"]] == ["primary", "standby"]


def test_a_stale_ha_hook_is_replaced_not_appended():
    base = {"subnet4": [], "hooks-libraries": [
        {"library": "/old/path/libdhcp_ha.so",
         "parameters": {"high-availability": [{"this-server-name": "gone",
                                               "peers": [{"name": "ghost"}]}]}},
        {"library": "/old/path/libdhcp_lease_cmds.so"},
        {"library": "/usr/lib/kea/hooks/libdhcp_stat_cmds.so"},
    ]}
    _, configs = _node_configs(node_local=base)
    libs = [h["library"] for h in configs["kea-a"]["hooks-libraries"]]
    assert "/old/path/libdhcp_ha.so" not in libs
    assert "/old/path/libdhcp_lease_cmds.so" not in libs
    assert "/usr/lib/kea/hooks/libdhcp_stat_cmds.so" in libs, \
        "unrelated hooks must be preserved"
    assert sum(1 for lib in libs if lib.endswith("libdhcp_ha.so")) == 1


def test_building_a_config_for_a_non_peer_is_rejected():
    peers = build_peers(MEMBERS, HOT_STANDBY)
    with pytest.raises(KeaHAConfigError, match="not one of the HA peers"):
        build_ha_hooks("kea-z", peers, HOT_STANDBY)


def test_the_shared_fingerprint_ignores_ha_identity_but_tracks_scopes():
    _, configs = _node_configs()
    assert config_fingerprint(configs["kea-a"]) == config_fingerprint(configs["kea-b"])
    drifted = copy.deepcopy(configs["kea-b"])
    drifted["subnet4"] = [{"id": 1, "subnet": "10.0.2.0/24"}]
    assert config_fingerprint(drifted) != config_fingerprint(configs["kea-a"])


def test_apply_order_puts_the_primary_last():
    assert apply_order(build_peers(MEMBERS, HOT_STANDBY)) == ["kea-b", "kea-a"]


# ── status-get parsing ──────────────────────────────────────────────────────

def _status_get(state="hot-standby", remote_state="hot-standby", in_touch=True,
                interrupted=False):
    return {"high-availability": [{"ha-servers": {
        "local": {"role": "primary", "scopes": ["server1"], "state": state},
        "remote": {"role": "standby", "last-scopes": [], "last-state": remote_state,
                   "age": 2, "in-touch": in_touch,
                   "communication-interrupted": interrupted, "unacked-clients": 0},
    }}]}


def test_parse_ha_status_reports_a_healthy_pair():
    ha = parse_ha_status(_status_get())
    assert ha["ha_enabled"] and ha["in_sync"] and ha["state"] == "hot-standby"
    assert ha["remote_in_touch"] is True


def test_parse_ha_status_flags_a_partner_never_seen():
    assert parse_ha_status(_status_get(in_touch=False))["in_sync"] is False


def test_parse_ha_status_flags_a_syncing_node():
    assert parse_ha_status(_status_get(state="syncing"))["in_sync"] is False


def test_missing_ha_block_means_the_hook_is_not_loaded():
    ha = parse_ha_status({"pid": 1})
    assert ha["ha_enabled"] is False and ha["state"] == "not-configured"


# ── summarize_ha ────────────────────────────────────────────────────────────

def _links(*ids, connected=True):
    return [{"id": i, "host": "", "role": "", "connected": connected,
             "pending_approval": False, "last_seen": 1.0,
             "seconds_since_seen": 1.0, "version": "1.0"} for i in ids]


def _healthy_members(*ids):
    return {m: {"status": "SUCCESS", "running": True, "subnet_count": 1,
                "ha": parse_ha_status(_status_get())} for m in ids}


def test_summary_is_healthy_only_when_both_nodes_sync_on_matching_config():
    peers = build_peers(MEMBERS, HOT_STANDBY)
    out = summarize_ha(HOT_STANDBY, peers, _links("kea-a", "kea-b"),
                       _healthy_members("kea-a", "kea-b"),
                       {"kea-a": "d1", "kea-b": "d1"})
    assert out["state"] == "healthy" and out["healthy"] is True
    assert out["config_converged"] is True and out["recommendations"] == []


def test_convergence_requires_a_digest_from_every_member():
    """REGRESSION (review #12): a missing digest used to collapse the comparison
    set to one value and report the pair 'matched'."""
    peers = build_peers(MEMBERS, HOT_STANDBY)
    out = summarize_ha(HOT_STANDBY, peers, _links("kea-a", "kea-b"),
                       _healthy_members("kea-a", "kea-b"), {"kea-a": "d1"})
    assert out["config_converged"] is False
    assert out["config_digests_missing"] == ["kea-b"]
    assert out["healthy"] is False
    assert any("Configuration state is unknown" in r for r in out["recommendations"])


def test_convergence_rejects_an_empty_digest():
    peers = build_peers(MEMBERS, HOT_STANDBY)
    out = summarize_ha(HOT_STANDBY, peers, _links("kea-a", "kea-b"),
                       _healthy_members("kea-a", "kea-b"),
                       {"kea-a": "d1", "kea-b": ""})
    assert out["config_converged"] is False
    assert out["config_digests_missing"] == ["kea-b"]


def test_convergence_with_no_digests_at_all_is_not_converged():
    peers = build_peers(MEMBERS, HOT_STANDBY)
    out = summarize_ha(HOT_STANDBY, peers, _links("kea-a", "kea-b"),
                       _healthy_members("kea-a", "kea-b"), {})
    assert out["config_converged"] is False
    assert sorted(out["config_digests_missing"]) == ["kea-a", "kea-b"]


def test_summary_flags_config_drift_between_the_nodes():
    peers = build_peers(MEMBERS, HOT_STANDBY)
    out = summarize_ha(HOT_STANDBY, peers, _links("kea-a", "kea-b"),
                       _healthy_members("kea-a", "kea-b"),
                       {"kea-a": "d1", "kea-b": "d2"})
    assert out["config_converged"] is False and out["healthy"] is False
    assert any("DIFFERENT subnet/reservation" in r for r in out["recommendations"])


def test_summary_names_the_specific_failure_mode_per_node():
    peers = build_peers(MEMBERS, HOT_STANDBY)
    per_member = {
        "kea-a": {"status": "SUCCESS", "running": True,
                  "ha": parse_ha_status({"pid": 1})},                    # no hook
        "kea-b": {"status": "SUCCESS", "running": True,
                  "ha": parse_ha_status(_status_get(interrupted=True,
                                                    in_touch=False))},   # split
    }
    out = summarize_ha(HOT_STANDBY, peers, _links("kea-a", "kea-b"), per_member,
                       {"kea-a": "d1", "kea-b": "d1"})
    text = " ".join(out["recommendations"])
    assert "no HA hook loaded" in text
    assert "communication with its partner interrupted" in text
    assert out["state"] == "down"


def test_summary_flags_an_unreachable_node():
    peers = build_peers(MEMBERS, HOT_STANDBY)
    links = _links("kea-a") + _links("kea-b", connected=False)
    out = summarize_ha(HOT_STANDBY, peers, links, _healthy_members("kea-a"),
                       {"kea-a": "d1"})
    assert out["unreachable"] == ["kea-b"] and out["state"] == "degraded"
    assert any("not reachable" in r for r in out["recommendations"])


def test_summary_surfaces_a_partial_apply():
    peers = build_peers(MEMBERS, HOT_STANDBY)
    out = summarize_ha(HOT_STANDBY, peers, _links("kea-a", "kea-b"),
                       _healthy_members("kea-a", "kea-b"),
                       {"kea-a": "d1", "kea-b": "d1"},
                       last_apply={"status": "PARTIAL", "applied": ["kea-b"]})
    assert any("only completed on kea-b" in r for r in out["recommendations"])


def test_cluster_config_round_trip_is_secret_moded(tmp_path):
    path = str(tmp_path / "cluster.json")
    assert load_cluster_config(path)["mode"] == HOT_STANDBY
    save_cluster_config(path, MEMBERS, "hot-standby")
    got = load_cluster_config(path)
    assert got["mode"] == HOT_STANDBY and len(got["members"]) == 2
    # The member list can carry the HA basic-auth password.
    assert oct(os.stat(path).st_mode)[-3:] == "600"


# ── Coordinator transaction ─────────────────────────────────────────────────

class FakeTransport:
    """Scriptable ClusterCoordinator surface; records the exact call order."""

    def __init__(self, members=None, fail=None, connected=None,
                 node_configs=None, apply_replies=None):
        self.members = list(members if members is not None else MEMBERS)
        self.fail = fail or {}            # (member, command) -> message
        self.apply_replies = apply_replies or {}   # member -> full reply dict
        self.connected = set(connected if connected is not None
                             else [m["id"] for m in self.members])
        self.node_configs = node_configs if node_configs is not None else {
            m["id"]: copy.deepcopy(NODE_LOCAL) for m in self.members}
        self.calls = []
        self.applied_configs = {}

    @property
    def enabled(self):
        return len(self.members) >= 2

    def member_ids(self):
        return [m["id"] for m in self.members]

    def member_links(self):
        return [{"id": m["id"], "host": m.get("host", ""), "role": "",
                 "connected": m["id"] in self.connected, "pending_approval": False,
                 "last_seen": 1.0, "seconds_since_seen": 1.0, "version": "1.0"}
                for m in self.members]

    async def call(self, member_id, command, data, timeout=20.0):
        self.calls.append((member_id, command))
        if member_id not in self.connected:
            return {"status": "ERROR", "message": "not connected"}
        if (member_id, command) in self.fail:
            return {"status": "ERROR", "message": self.fail[(member_id, command)],
                    "mutated": False}
        if command == "KEAW_GET_CONFIG":
            cfg = self.node_configs.get(member_id)
            if cfg is None:
                return {"status": "ERROR", "message": "no config"}
            return {"status": "SUCCESS", "config": copy.deepcopy(cfg),
                    "digest": config_fingerprint(cfg)}
        if command == "KEAW_APPLY":
            if member_id in self.apply_replies:
                return dict(self.apply_replies[member_id])
            self.applied_configs[member_id] = copy.deepcopy(data["config"])
            return {"status": "SUCCESS", "version": data.get("version"),
                    "mutated": True, "digest": config_fingerprint(data["config"])}
        if command == "KEAW_HA_STATUS":
            return {"status": "SUCCESS", "running": True, "subnet_count": 1,
                    "digest": "shared", "status_get": _status_get()}
        return {"status": "SUCCESS"}

    async def fanout(self, command, data, timeout=20.0, member_ids=None):
        targets = list(member_ids) if member_ids is not None else self.member_ids()
        results = {m: await self.call(m, command, data) for m in targets}
        ok = [m for m, r in results.items() if r.get("status") == "SUCCESS"]
        failed = [m for m in targets if m not in ok]
        return {"status": "SUCCESS" if not failed else ("PARTIAL" if ok else "ERROR"),
                "results": results, "ok": ok, "failed": failed}


def _run(coro):
    return asyncio.run(coro)


def _coord(transport, tmp_path=None, **kw):
    return KeaHACoordinator(
        transport, state_path=str(tmp_path / "desired.json") if tmp_path else "",
        **kw)


def test_apply_reads_validates_then_applies_standby_before_primary(tmp_path):
    t = FakeTransport()
    coord = _coord(t, tmp_path)
    out = _run(coord.apply(SUBNETS, RESERVATIONS))
    assert out["status"] == "SUCCESS", out
    assert out["order"] == ["kea-b", "kea-a"]
    assert out["subnets"] == 1 and out["reservations"] == 1
    assert t.calls == [
        # Hook check is a fan-out (order irrelevant); read, validate and apply
        # are ordered, standby before primary.
        ("kea-a", "KEAW_INSTALL_HOOKS"), ("kea-b", "KEAW_INSTALL_HOOKS"),
        ("kea-b", "KEAW_GET_CONFIG"), ("kea-a", "KEAW_GET_CONFIG"),
        ("kea-b", "KEAW_VALIDATE"), ("kea-a", "KEAW_VALIDATE"),
        ("kea-b", "KEAW_APPLY"), ("kea-a", "KEAW_APPLY"),
    ]


def test_applied_configs_keep_each_nodes_local_settings(tmp_path):
    """REGRESSION (review #5): the config pushed to each node is built on that
    node's OWN running config."""
    t = FakeTransport()
    _run(_coord(t, tmp_path).apply(SUBNETS, RESERVATIONS))
    for member_id, cfg in t.applied_configs.items():
        assert cfg["interfaces-config"] == {"interfaces": ["eth0"]}
        assert cfg["lease-database"]["name"] == "/var/lib/kea/kea-leases4.csv"
        assert cfg["subnet4"][0]["subnet"] == "10.0.1.0/24"
        ha = cfg["hooks-libraries"][-1]["parameters"]["high-availability"][0]
        assert ha["this-server-name"] == member_id


def test_a_node_whose_config_cannot_be_read_aborts_before_any_apply(tmp_path):
    """REGRESSION (review #5): without the read we would have rendered from {}
    and wiped that node."""
    t = FakeTransport(fail={("kea-a", "KEAW_GET_CONFIG"): "CA unreachable"})
    out = _run(_coord(t, tmp_path).apply(SUBNETS, RESERVATIONS))
    assert out["status"] == "ERROR" and out["stage"] == "read-config"
    assert out["errors"]["kea-a"] == "CA unreachable"
    assert not any(c[1] == "KEAW_APPLY" for c in t.calls)


def test_a_validation_failure_on_either_node_applies_nothing(tmp_path):
    for bad in ("kea-a", "kea-b"):
        t = FakeTransport(fail={(bad, "KEAW_VALIDATE"): "bad subnet"})
        out = _run(_coord(t, tmp_path).apply(SUBNETS, RESERVATIONS))
        assert out["status"] == "ERROR" and out["stage"] == "validate"
        assert out["errors"][bad] == "bad subnet"
        assert not any(c[1] == "KEAW_APPLY" for c in t.calls), \
            "no node may be reconfigured when either rejected the config"


def test_missing_ha_hooks_abort_before_any_config_is_generated(tmp_path):
    t = FakeTransport(fail={("kea-a", "KEAW_INSTALL_HOOKS"): "no kea-hooks package"})
    out = _run(_coord(t, tmp_path).apply(SUBNETS, RESERVATIONS))
    assert out["status"] == "ERROR" and out["stage"] == "install-hooks"
    assert not any(c[1] in ("KEAW_GET_CONFIG", "KEAW_VALIDATE", "KEAW_APPLY")
                   for c in t.calls)


def test_a_primary_apply_failure_rolls_the_standby_back(tmp_path):
    t = FakeTransport(fail={("kea-a", "KEAW_APPLY"): "config-set refused"})
    coord = _coord(t, tmp_path)
    out = _run(coord.apply(SUBNETS, RESERVATIONS))
    assert out["status"] == "ERROR", "a rolled-back pair is not partially applied"
    assert out["stage"] == "apply"
    assert out["rolled_back"] == ["kea-b"]
    assert out["applied"] == []
    assert ("kea-b", "KEAW_ROLLBACK") in t.calls
    assert coord.version == 0, "a failed transaction must not advance the version"


def test_rollback_includes_the_failing_node_when_it_may_be_mutated(tmp_path):
    """REGRESSION (review #6): a node whose config-set landed but whose
    config-write (and local restore) failed is running the new config despite
    reporting failure — it MUST be rolled back too."""
    t = FakeTransport(apply_replies={"kea-a": {
        "status": "PARTIAL", "mutated": True, "restored": False,
        "message": "config-write failed AND the local restore failed"}})
    out = _run(_coord(t, tmp_path).apply(SUBNETS, RESERVATIONS))
    assert ("kea-a", "KEAW_ROLLBACK") in t.calls
    assert sorted(out["rolled_back"]) == ["kea-a", "kea-b"]
    assert out["status"] == "ERROR"


def test_rollback_skips_a_node_that_positively_reports_it_did_not_mutate(tmp_path):
    t = FakeTransport(apply_replies={"kea-a": {
        "status": "ERROR", "mutated": False, "message": "config-set refused"}})
    out = _run(_coord(t, tmp_path).apply(SUBNETS, RESERVATIONS))
    assert ("kea-a", "KEAW_ROLLBACK") not in t.calls
    assert out["rolled_back"] == ["kea-b"]


def test_a_failed_rollback_is_reported_as_partial_not_success(tmp_path):
    t = FakeTransport(fail={("kea-a", "KEAW_APPLY"): "config-set refused",
                            ("kea-b", "KEAW_ROLLBACK"): "CA gone"})
    out = _run(_coord(t, tmp_path).apply(SUBNETS, RESERVATIONS))
    assert out["status"] == "PARTIAL"
    assert out["applied"] == ["kea-b"]
    assert "rollback failed" in out["errors"]["kea-b"]


def test_an_invalid_topology_is_refused_without_touching_any_node(tmp_path):
    t = FakeTransport(members=[{"id": "kea-a", "host": "10.0.1.10", **HA_TLS},
                               {"id": "kea-b", "host": "10.0.1.10", **HA_TLS}])
    out = _run(_coord(t, tmp_path).apply(SUBNETS, RESERVATIONS))
    assert out["status"] == "ERROR" and "same control-agent URL" in out["message"]
    assert t.calls == []


# ── Item 7: candidate promotion is transactional + durable ─────────────────

def test_a_failed_apply_does_not_poison_the_next_mutation(tmp_path):
    """REGRESSION (review #7): the desired intent/version used to advance before
    the nodes confirmed, so a later mutation built on a set nobody was running."""
    t = FakeTransport(fail={("kea-a", "KEAW_APPLY"): "boom"})
    coord = _coord(t, tmp_path)
    failed = _run(coord.apply(SUBNETS, RESERVATIONS))
    assert failed["status"] == "ERROR"
    assert coord.version == 0
    assert coord.desired == {"subnets": [], "reservations": []}
    # The candidate journal is written before the apply and CLEARED on abort, so
    # a restart does not report a pending candidate that was already undone.
    saved = json.loads((tmp_path / "desired.json").read_text())
    assert saved["version"] == 0 and saved["pending"] is None

    t.fail.clear()
    ok = _run(coord.apply(SUBNETS, RESERVATIONS))
    assert ok["status"] == "SUCCESS" and coord.version == 1
    assert coord.desired["subnets"] == SUBNETS


def test_a_successful_apply_persists_the_promoted_version(tmp_path):
    t = FakeTransport()
    coord = _coord(t, tmp_path)
    _run(coord.apply(SUBNETS, RESERVATIONS))
    saved = json.loads((tmp_path / "desired.json").read_text())
    assert saved["version"] == 1
    assert saved["subnets"] == SUBNETS
    reborn = _coord(FakeTransport(), tmp_path)
    assert reborn.version == 1 and reborn.desired["subnets"] == SUBNETS


def test_a_coordinator_that_cannot_journal_applies_nothing(tmp_path):
    """REGRESSION (review #7): the candidate must be durable BEFORE any node is
    touched, so an un-writable state path aborts before the first apply."""
    t = FakeTransport()
    coord = _coord(t, tmp_path)
    coord.state_path = str(tmp_path / "nope" / "\0bad" / "desired.json")
    out = _run(coord.apply(SUBNETS, RESERVATIONS))
    assert out["status"] == "ERROR" and out["stage"] == "journal"
    assert coord.version == 0
    assert not any(c[1] == "KEAW_APPLY" for c in t.calls)
    assert "could not journal" in out["errors"]["coordinator"]


def test_a_promote_failure_rolls_both_nodes_back(tmp_path):
    """REGRESSION (review #7): a pair running a version the coordinator cannot
    remember is worse than no change \u2014 both nodes are rolled back."""
    t = FakeTransport()
    coord = _coord(t, tmp_path)
    real_promote = coord._promote_candidate

    def boom(*_a, **_kw):
        raise OSError("disk full")

    coord._promote_candidate = boom
    out = _run(coord.apply(SUBNETS, RESERVATIONS))
    coord._promote_candidate = real_promote
    assert out["status"] == "ERROR" and out["stage"] == "promote"
    assert sorted(out["rolled_back"]) == ["kea-a", "kea-b"]
    assert coord.version == 0
    assert t.calls.count(("kea-a", "KEAW_ROLLBACK")) == 1
    assert t.calls.count(("kea-b", "KEAW_ROLLBACK")) == 1


def test_a_pending_candidate_survives_a_restart_and_is_surfaced(tmp_path):
    """REGRESSION (review #7): a coordinator that died mid-apply must come back
    KNOWING the pair may be ahead of its committed record."""
    path = tmp_path / "desired.json"
    path.write_text(json.dumps({
        "version": 3, "mode": "hot-standby", "subnets": SUBNETS,
        "reservations": [], "updated_at": 1.0,
        "pending": {"version": 4, "subnets": SUBNETS, "reservations": [],
                    "started_at": 2.0}}))
    coord = _coord(FakeTransport(), tmp_path)
    assert coord.version == 3
    assert coord.pending_candidate["version"] == 4
    report = _run(coord.status())
    assert report["pending_candidate"]["version"] == 4
    assert report["healthy"] is False
    assert any("journalled but never confirmed" in r
               for r in report["recommendations"])


def test_a_successful_apply_clears_the_pending_candidate(tmp_path):
    path = tmp_path / "desired.json"
    path.write_text(json.dumps({
        "version": 3, "mode": "hot-standby", "subnets": SUBNETS,
        "reservations": [], "updated_at": 1.0,
        "pending": {"version": 4, "subnets": SUBNETS, "reservations": [],
                    "started_at": 2.0}}))
    coord = _coord(FakeTransport(), tmp_path)
    out = _run(coord.apply(SUBNETS, RESERVATIONS))
    assert out["status"] == "SUCCESS"
    assert coord.pending_candidate is None
    assert json.loads(path.read_text())["pending"] is None


def test_reservation_read_modify_write_happens_under_the_lock(tmp_path):
    """REGRESSION (review #9): computing the new list before taking the lock let
    two concurrent edits start from the same base and lose one."""
    t = FakeTransport()
    coord = _coord(t, tmp_path)
    _run(coord.apply(SUBNETS, []))

    async def _both():
        return await asyncio.gather(
            coord.mutate_reservation("upsert", {"ip": "10.0.1.50",
                                                "mac": "aa:bb:cc:dd:ee:01"}),
            coord.mutate_reservation("upsert", {"ip": "10.0.1.51",
                                                "mac": "aa:bb:cc:dd:ee:02"}))

    first, second = _run(_both())
    assert first["status"] == "SUCCESS" and second["status"] == "SUCCESS"
    ips = sorted(r["ip"] for r in coord.desired["reservations"])
    assert ips == ["10.0.1.50", "10.0.1.51"], \
        "neither concurrent edit may be lost"


def test_reservation_mutation_without_subnets_is_refused(tmp_path):
    coord = _coord(FakeTransport(), tmp_path)
    out = _run(coord.mutate_reservation("upsert", {"ip": "10.0.1.50",
                                                   "mac": "aa:bb:cc:dd:ee:01"}))
    assert out["status"] == "ERROR" and "run a DHCP sync" in out["message"]


def test_hook_dir_is_resolved_on_the_node(monkeypatch, tmp_path):
    """REGRESSION (review #6): the multiarch triplet differs per node, so a
    hard-coded x86_64 path made every arm64 node report missing HA libraries."""
    hooks = tmp_path / "usr" / "lib" / "aarch64-linux-gnu" / "kea" / "hooks"
    hooks.mkdir(parents=True)
    (hooks / "libdhcp_ha.so").write_text("")
    monkeypatch.setattr("kea_ha.HOOK_DIR_GLOBS",
                        (str(tmp_path / "usr/lib/*/kea/hooks"),))
    assert resolve_hook_dir() == str(hooks)
    assert hook_paths()["ha"] == str(hooks / "libdhcp_ha.so")


def test_an_explicit_hook_dir_overrides_discovery():
    assert resolve_hook_dir("/opt/custom/hooks") == "/opt/custom/hooks"


def test_a_corrupt_desired_state_starts_with_no_intent(tmp_path):
    (tmp_path / "desired.json").write_text("{not json")
    coord = _coord(FakeTransport(), tmp_path)
    assert coord.version == 0 and coord.desired["subnets"] == []


# ── Item 10: concurrent applies are serialized ─────────────────────────────

def test_concurrent_applies_do_not_interleave(tmp_path):
    """REGRESSION (review #10): without the lock one apply's validate could
    interleave with the other's apply and leave the pair on a config neither
    node validated."""
    t = FakeTransport()
    coord = _coord(t, tmp_path)

    async def _both():
        return await asyncio.gather(coord.apply(SUBNETS, RESERVATIONS),
                                    coord.apply(SUBNETS, []))

    _run(_both())
    # Each transaction's calls must appear as one contiguous run.
    seq = [c[1] for c in t.calls]
    first = seq.index("KEAW_APPLY")
    # The two APPLYs of transaction 1 are adjacent, then transaction 2 starts.
    assert seq[first:first + 2] == ["KEAW_APPLY", "KEAW_APPLY"]
    assert seq[first + 2] in ("KEAW_INSTALL_HOOKS",)
    assert coord.version == 2


# ── Status ──────────────────────────────────────────────────────────────────

def test_status_report_reflects_live_node_state(tmp_path):
    coord = _coord(FakeTransport(), tmp_path)
    report = _run(coord.status())
    assert report["status"] == "SUCCESS"
    assert report["mode"] == HOT_STANDBY
    assert report["state"] == "healthy" and report["config_converged"] is True


def test_status_report_marks_an_unreachable_node(tmp_path):
    coord = _coord(FakeTransport(connected=["kea-a"]), tmp_path)
    report = _run(coord.status())
    assert report["unreachable"] == ["kea-b"] and report["healthy"] is False


def test_a_node_that_stops_reporting_drops_its_stale_digest(tmp_path):
    """REGRESSION (review #12): a remembered digest from a node that no longer
    answers must not satisfy convergence."""
    t = FakeTransport()
    coord = _coord(t, tmp_path)
    _run(coord.status())
    assert coord.config_digests == {"kea-a": "shared", "kea-b": "shared"}
    t.connected.discard("kea-b")
    report = _run(coord.status())
    assert "kea-b" not in coord.config_digests
    assert report["config_converged"] is False
    assert report["config_digests_missing"] == ["kea-b"]


def test_report_explains_an_invalid_topology_instead_of_raising(tmp_path):
    coord = _coord(FakeTransport(
        members=[{"id": "kea-a", "host": "10.0.1.10", **HA_TLS},
                 {"id": "kea-a", "host": "10.0.1.11", **HA_TLS}]), tmp_path)
    report = coord.report()
    assert report["state"] == "invalid" and report["healthy"] is False
    assert any("topology is invalid" in r for r in report["recommendations"])


# ── Round 3, #4: the EXACT UI payload must build a valid pair ──────────────

#: Byte-for-byte what WebUI/main.js::saveServiceCluster sends for a fresh pair.
UI_PAYLOAD_MEMBERS = [
    {"id": "kea-a", "host": "10.0.1.10", "ha_user": "kea-ha",
     "ha_password": "s3cret", "ha_trust_anchor": "/etc/kea/ha-tls/ha-ca.pem",
     "ha_cert": "/etc/kea/ha-tls/node.crt", "ha_key": "/etc/kea/ha-tls/node.key"},
    {"id": "kea-b", "host": "10.0.1.11", "ha_user": "kea-ha",
     "ha_password": "s3cret", "ha_trust_anchor": "/etc/kea/ha-tls/ha-ca.pem",
     "ha_cert": "/etc/kea/ha-tls/node.crt", "ha_key": "/etc/kea/ha-tls/node.key"},
]


def test_the_exact_ui_payload_builds_a_valid_pair():
    """REGRESSION (round 3, #4): the form's payload used to omit the TLS
    material entirely, so build_peers rejected every pair created from the UI."""
    peers = build_peers(UI_PAYLOAD_MEMBERS, "hot-standby")
    assert [p["name"] for p in peers] == ["kea-a", "kea-b"]
    assert [p["role"] for p in peers] == ["primary", "standby"]
    assert all(p["url"].startswith("https://") for p in peers)
    assert all(p["trust-anchor"] == "/etc/kea/ha-tls/ha-ca.pem" for p in peers)
    assert all(p["basic-auth-user"] == "kea-ha" for p in peers)


def test_the_ui_tls_paths_match_the_installer_output():
    """The form's canonical paths are exactly what install_dhcp.sh writes."""
    from kea_ha import DEFAULT_HA_CA, DEFAULT_HA_CERT, DEFAULT_HA_KEY
    assert UI_PAYLOAD_MEMBERS[0]["ha_trust_anchor"] == DEFAULT_HA_CA
    assert UI_PAYLOAD_MEMBERS[0]["ha_cert"] == DEFAULT_HA_CERT
    assert UI_PAYLOAD_MEMBERS[0]["ha_key"] == DEFAULT_HA_KEY


def test_the_exact_ui_payload_renders_both_node_configs():
    coord = KeaHACoordinator(FakeTransport(members=UI_PAYLOAD_MEMBERS))
    plan = coord.render(SUBNETS, RESERVATIONS,
                        {"kea-a": dict(NODE_LOCAL), "kea-b": dict(NODE_LOCAL)})
    assert set(plan["configs"]) == {"kea-a", "kea-b"}
    for name, cfg in plan["configs"].items():
        ha = cfg["hooks-libraries"][-1]["parameters"]["high-availability"][0]
        assert ha["this-server-name"] == name
        assert ha["mode"] == "hot-standby"


# ── Round 3, #5: the journal survives an incomplete rollback ───────────────

def test_an_incomplete_rollback_retains_the_pending_journal(tmp_path):
    """REGRESSION: clearing the journal after a FAILED rollback threw away the
    only evidence that a node might still be running the candidate."""
    t = FakeTransport(fail={("kea-a", "KEAW_APPLY"): "config-set refused",
                            ("kea-b", "KEAW_ROLLBACK"): "CA gone"})
    coord = _coord(t, tmp_path)
    out = _run(coord.apply(SUBNETS, RESERVATIONS))
    assert out["status"] == "PARTIAL" and out["applied"] == ["kea-b"]
    assert coord.pending_candidate is not None
    assert coord.pending_candidate["unrestored"] == ["kea-b"]
    saved = json.loads((tmp_path / "desired.json").read_text())
    assert saved["pending"]["unrestored"] == ["kea-b"]


def test_a_complete_rollback_clears_the_journal(tmp_path):
    t = FakeTransport(fail={("kea-a", "KEAW_APPLY"): "config-set refused"})
    coord = _coord(t, tmp_path)
    out = _run(coord.apply(SUBNETS, RESERVATIONS))
    assert out["status"] == "ERROR" and out["rolled_back"] == ["kea-b"]
    assert coord.pending_candidate is None
    assert json.loads((tmp_path / "desired.json").read_text())["pending"] is None


def test_a_promote_failure_with_a_stuck_node_retains_the_journal(tmp_path):
    t = FakeTransport(fail={("kea-b", "KEAW_ROLLBACK"): "CA gone"})
    coord = _coord(t, tmp_path)

    def boom(*_a, **_kw):
        raise OSError("disk full")

    coord._promote_candidate = boom
    out = _run(coord.apply(SUBNETS, RESERVATIONS))
    assert out["status"] == "PARTIAL"
    assert coord.pending_candidate["unrestored"] == ["kea-b"]
    assert json.loads((tmp_path / "desired.json").read_text())["pending"]


def test_restart_recovery_names_the_unrestored_node(tmp_path):
    """A coordinator restarted after a partial rollback must SAY which node may
    still be ahead."""
    t = FakeTransport(fail={("kea-a", "KEAW_APPLY"): "boom",
                            ("kea-b", "KEAW_ROLLBACK"): "CA gone"})
    _run(_coord(t, tmp_path).apply(SUBNETS, RESERVATIONS))
    reborn = _coord(FakeTransport(), tmp_path)
    assert reborn.pending_candidate["unrestored"] == ["kea-b"]
    report = _run(reborn.status())
    assert report["healthy"] is False
    assert report["pending_candidate"]["unrestored"] == ["kea-b"]
    assert any("may still be running it: kea-b" in r
               for r in report["recommendations"])


def test_a_later_successful_apply_clears_a_retained_journal(tmp_path):
    t = FakeTransport(fail={("kea-a", "KEAW_APPLY"): "boom",
                            ("kea-b", "KEAW_ROLLBACK"): "CA gone"})
    coord = _coord(t, tmp_path)
    _run(coord.apply(SUBNETS, RESERVATIONS))
    assert coord.pending_candidate is not None
    t.fail.clear()
    out = _run(coord.apply(SUBNETS, RESERVATIONS))
    assert out["status"] == "SUCCESS"
    assert coord.pending_candidate is None
    assert json.loads((tmp_path / "desired.json").read_text())["pending"] is None
