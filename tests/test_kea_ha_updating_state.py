"""A pair applying a synced configuration reports "updating", not "degraded".

Root cause this covers: a NetBox -> Kea sync pushes ``config-set``, which
re-initialises Kea's HA hook. Kea then DELIBERATELY takes the node out of
service (``HA_LOCAL_DHCP_DISABLE ... while in the WAITING state``) and walks
WAITING -> SYNCING -> READY -> HOT-STANDBY. Observed live on mipbe-svcs01:
~31 s, inside ONE kea-dhcp4 process (PID 670, up 15 h -- no restart).

For that whole window ``in_sync`` was False on both nodes, so every member was
classified ``degraded``, the cluster went ``degraded``/``healthy: False``, and
``DHCP_STATUS.running`` (which was ``bool(healthy)``) said the server was DOWN.
The operator clicked Sync and was told "Kea HA pair needs attention" -- implying
a simultaneous two-node failure -- for a completely routine push.
"""
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from kea_ha import (  # noqa: E402
    APPLY_SETTLE_S,
    HOT_STANDBY,
    SERVING_HA_STATES,
    TRANSITIONAL_HA_STATES,
    build_peers,
    parse_ha_status,
    summarize_ha,
)

MEMBERS = [
    {"id": "kea-a", "host": "10.0.1.10",
     "ha_trust_anchor": "/etc/kea/ha-tls/ha-ca.pem",
     "ha_cert": "/etc/kea/ha-tls/node.crt", "ha_key": "/etc/kea/ha-tls/node.key"},
    {"id": "kea-b", "host": "10.0.1.11",
     "ha_trust_anchor": "/etc/kea/ha-tls/ha-ca.pem",
     "ha_cert": "/etc/kea/ha-tls/node.crt", "ha_key": "/etc/kea/ha-tls/node.key"},
]
NOW = 1_000_000.0


def _status_get(state="hot-standby", remote_state="hot-standby", in_touch=True,
                interrupted=False):
    return {"high-availability": [{"ha-servers": {
        "local": {"role": "primary", "scopes": ["server1"], "state": state},
        "remote": {"role": "standby", "last-scopes": [], "last-state": remote_state,
                   "age": 2, "in-touch": in_touch,
                   "communication-interrupted": interrupted, "unacked-clients": 0},
    }}]}


def _links(*ids, connected=True):
    return [{"id": i, "host": "", "role": "", "connected": connected,
             "pending_approval": False, "last_seen": 1.0,
             "seconds_since_seen": 1.0, "version": "1.0"} for i in ids]


def _members(**by_id):
    """{member_id: local HA state} -> the per_member map summarize_ha wants."""
    return {mid: {"status": "SUCCESS", "running": True, "subnet_count": 1,
                  "ha": parse_ha_status(_status_get(state=st, remote_state=st))}
            for mid, st in by_id.items()}


def _summary(by_id, digests, applied_ago=1.0, **kw):
    last_apply = ({"status": "SUCCESS", "at": NOW - applied_ago}
                  if applied_ago is not None else None)
    return summarize_ha(HOT_STANDBY, build_peers(MEMBERS, HOT_STANDBY),
                        _links(*by_id), _members(**by_id), digests,
                        last_apply, now=NOW, **kw)


# ── parse_ha_status: the new transitional / serving dimensions ───────────────
def test_the_kea_states_that_take_a_node_out_of_service_are_transitional():
    # Exactly the sequence observed in the live journal.
    assert TRANSITIONAL_HA_STATES == ("waiting", "syncing", "ready")
    for state in TRANSITIONAL_HA_STATES:
        ha = parse_ha_status(_status_get(state=state))
        assert ha["transitional"] is True, state
        assert ha["serving"] is False, state


def test_a_serving_node_is_not_transitional():
    for state in SERVING_HA_STATES:
        ha = parse_ha_status(_status_get(state=state))
        assert ha["serving"] is True, state
        assert ha["transitional"] is False, state


def test_partner_down_still_counts_as_serving():
    # It took over the whole scope; it is very much answering clients.
    assert parse_ha_status(_status_get(state="partner-down"))["serving"] is True


def test_a_missing_ha_block_is_neither_transitional_nor_serving():
    ha = parse_ha_status({"pid": 1})
    assert ha["transitional"] is False and ha["serving"] is False


def test_transitional_does_not_change_the_meaning_of_in_sync():
    # in_sync is relied on elsewhere; the new field must be additive only.
    assert parse_ha_status(_status_get(state="syncing"))["in_sync"] is False
    assert parse_ha_status(_status_get())["in_sync"] is True


# ── summarize_ha: the sync window ───────────────────────────────────────────
def test_a_pair_applying_a_just_synced_config_is_updating_not_degraded():
    """THE production symptom: click Sync -> "needs attention"."""
    out = _summary({"kea-a": "syncing", "kea-b": "waiting"},
                   {"kea-a": "d2", "kea-b": "d1"})
    assert out["state"] == "updating"
    assert out["updating"] is True
    assert sorted(out["updating_members"]) == ["kea-a", "kea-b"]
    assert out["degraded"] == [] and out["unreachable"] == []
    assert [m["health"] for m in out["members"]] == ["updating", "updating"]


def test_a_rolling_apply_leaves_the_serving_node_healthy():
    # Standby reconfigures first (apply_order), primary still serving.
    out = _summary({"kea-a": "hot-standby", "kea-b": "ready"},
                   {"kea-a": "d2", "kea-b": "d2"})
    assert out["state"] == "updating"
    health = {m["id"]: m["health"] for m in out["members"]}
    assert health == {"kea-a": "healthy", "kea-b": "updating"}
    assert out["serving"] is True and out["serving_count"] == 1


def test_mid_apply_digest_drift_is_explained_not_alarming():
    out = _summary({"kea-a": "syncing", "kea-b": "waiting"},
                   {"kea-a": "d2", "kea-b": "d1"})
    assert out["config_converged"] is False
    joined = " ".join(out["recommendations"])
    assert "still converging" in joined
    # The scary wording must NOT appear during a normal rollout.
    assert "DIFFERENT subnet/reservation" not in joined


def test_the_per_node_advice_says_no_action_needed():
    out = _summary({"kea-a": "waiting", "kea-b": "waiting"},
                   {"kea-a": "d1", "kea-b": "d1"})
    joined = " ".join(out["recommendations"])
    assert "No action needed" in joined
    assert "within 30 seconds" in joined


# ── it must NOT paper over a real fault ─────────────────────────────────────
def test_a_node_stuck_transitional_with_no_apply_is_degraded():
    out = _summary({"kea-a": "hot-standby", "kea-b": "waiting"},
                   {"kea-a": "d1", "kea-b": "d1"}, applied_ago=None)
    assert out["state"] == "degraded"
    assert out["updating"] is False
    assert out["degraded"] == ["kea-b"]
    assert any("stuck in HA state" in r for r in out["recommendations"])
    assert any("NOT serving DHCP" in r for r in out["recommendations"])


def test_the_grace_window_expires():
    stale = _summary({"kea-a": "hot-standby", "kea-b": "waiting"},
                     {"kea-a": "d1", "kea-b": "d1"},
                     applied_ago=APPLY_SETTLE_S + 1)
    assert stale["state"] == "degraded" and stale["updating"] is False
    fresh = _summary({"kea-a": "hot-standby", "kea-b": "waiting"},
                     {"kea-a": "d1", "kea-b": "d1"},
                     applied_ago=APPLY_SETTLE_S - 1)
    assert fresh["state"] == "updating"


def test_an_apply_timestamp_in_the_future_does_not_grant_grace():
    out = _summary({"kea-a": "hot-standby", "kea-b": "waiting"},
                   {"kea-a": "d1", "kea-b": "d1"}, applied_ago=-5.0)
    assert out["state"] == "degraded"


def test_a_garbage_apply_timestamp_does_not_grant_grace():
    out = summarize_ha(HOT_STANDBY, build_peers(MEMBERS, HOT_STANDBY),
                       _links("kea-a", "kea-b"),
                       _members(**{"kea-a": "hot-standby", "kea-b": "waiting"}),
                       {"kea-a": "d1", "kea-b": "d1"},
                       {"status": "SUCCESS", "at": "not-a-number"}, now=NOW)
    assert out["state"] == "degraded"


def test_an_unreachable_node_is_never_excused_as_updating():
    out = summarize_ha(HOT_STANDBY, build_peers(MEMBERS, HOT_STANDBY),
                       _links("kea-a", "kea-b", connected=False),
                       _members(**{"kea-a": "waiting", "kea-b": "waiting"}),
                       {"kea-a": "d1", "kea-b": "d1"},
                       {"status": "SUCCESS", "at": NOW - 1}, now=NOW)
    assert out["state"] == "down"
    assert out["updating"] is False


def test_a_degraded_node_alongside_an_updating_one_keeps_the_pair_degraded():
    # kea-b has the HA hook missing entirely — a real fault that must win.
    per_member = _members(**{"kea-a": "waiting"})
    per_member["kea-b"] = {"status": "SUCCESS", "running": True,
                           "subnet_count": 1, "ha": parse_ha_status({"pid": 1})}
    out = summarize_ha(HOT_STANDBY, build_peers(MEMBERS, HOT_STANDBY),
                       _links("kea-a", "kea-b"), per_member,
                       {"kea-a": "d1", "kea-b": "d1"},
                       {"status": "SUCCESS", "at": NOW - 1}, now=NOW)
    assert out["state"] == "down"          # no healthy member at all
    assert out["updating"] is False
    assert out["degraded"] == ["kea-b"]


def test_a_fully_converged_pair_is_still_plain_healthy():
    out = _summary({"kea-a": "hot-standby", "kea-b": "hot-standby"},
                   {"kea-a": "d1", "kea-b": "d1"})
    assert out["state"] == "healthy" and out["healthy"] is True
    assert out["updating"] is False and out["updating_members"] == []
    assert out["serving"] is True and out["serving_count"] == 2
    assert out["recommendations"] == []
