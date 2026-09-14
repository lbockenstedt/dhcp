"""A reservation is only half-applied until the client's OLD lease is gone.

While the client still holds its previous lease it keeps using that address
and never moves to the reserved one, so the operator sees a reservation that
appears to "do nothing" (reserving 172.17.1.13 -> 172.17.1.199 left the client
on .13).

``_ha_reservation`` does purge the lease, but it used to fire-and-forget: the
fanout result was discarded and the exception swallowed at debug level, so a
disconnected node — which ``fanout`` counts as FAILED — left a live lease
behind with nothing logged. It now reports the purge and downgrades a clean
SUCCESS to PARTIAL when the lease survived.
"""

import asyncio

from dhcp_spoke import DHCPSpoke


class _Transport:
    def __init__(self, reply):
        self._reply = reply
        self.calls = []

    async def fanout(self, command, data, timeout=20.0, member_ids=None):
        self.calls.append((command, data))
        return self._reply


class _Cluster:
    def __init__(self, transport, mutate_result):
        self.transport = transport
        self._mutate = mutate_result
        self.mutated = []

    async def mutate_reservation(self, action, data, timeout=40.0):
        self.mutated.append((action, data))
        return dict(self._mutate)


def _spoke(fanout_reply, mutate_result=None):
    obj = object.__new__(DHCPSpoke)
    obj.cluster = _Cluster(_Transport(fanout_reply),
                           mutate_result or {"status": "SUCCESS"})
    return obj


_BOTH_OK = {"status": "SUCCESS",
            "results": {"node-a": {"status": "SUCCESS", "purged": ["172.17.1.13"]},
                        "node-b": {"status": "SUCCESS", "purged": ["172.17.1.13"]}},
            "ok": ["node-a", "node-b"], "failed": []}

_ONE_DOWN = {"status": "PARTIAL",
             "results": {"node-a": {"status": "SUCCESS", "purged": ["172.17.1.13"]},
                         "node-b": {"status": "ERROR", "message": "node offline"}},
             "ok": ["node-a"], "failed": ["node-b"]}


def _res(spoke, cmd="DHCP_ADD_RES", **data):
    payload = {"ip": "172.17.1.199", "mac": "bc:24:11:df:63:5e",
               "old_ip": "172.17.1.13"}
    payload.update(data)
    return asyncio.run(spoke._ha_reservation(cmd, payload))


def test_reservation_purges_the_old_lease_on_every_node():
    s = _spoke(_BOTH_OK)
    out = _res(s)
    assert out["status"] == "SUCCESS"
    assert out["lease_purge"]["purged"] == ["172.17.1.13"]
    assert not out["lease_purge"]["errors"]


def test_one_fanout_carries_new_ip_old_ip_and_mac():
    s = _spoke(_BOTH_OK)
    _res(s)
    # The worker purges all three from a single call; a second fanout for
    # old_ip was redundant.
    assert len(s.cluster.transport.calls) == 1
    cmd, data = s.cluster.transport.calls[0]
    assert cmd == "KEAW_DEL_LEASE"
    assert data == {"ip": "172.17.1.199", "old_ip": "172.17.1.13",
                    "mac": "bc:24:11:df:63:5e"}


def test_a_surviving_lease_downgrades_the_write_to_partial():
    s = _spoke(_ONE_DOWN)
    out = _res(s)
    # Previously this reported a clean SUCCESS while the client kept its
    # old address.
    assert out["status"] == "PARTIAL"
    assert "node-b" in out["lease_purge"]["errors"]
    assert "172.17.1.13" in out["message"]


def test_purge_failure_does_not_mask_the_reservation_itself():
    s = _spoke(_ONE_DOWN)
    out = _res(s)
    assert out["lease_purge"]["purged"] == ["172.17.1.13"]
    assert s.cluster.mutated[0][0] == "upsert"


def test_a_failed_reservation_skips_the_purge_entirely():
    s = _spoke(_BOTH_OK, mutate_result={"status": "ERROR", "message": "nope"})
    out = _res(s)
    assert out["status"] == "ERROR"
    assert not s.cluster.transport.calls
    assert "lease_purge" not in out


def test_delete_does_not_purge_leases():
    s = _spoke(_BOTH_OK)
    out = _res(s, cmd="DHCP_DEL_RES")
    assert out["status"] == "SUCCESS"
    assert not s.cluster.transport.calls


def test_no_node_answering_is_reported_not_silently_ignored():
    s = _spoke({"status": "ERROR", "results": {}, "ok": [], "failed": [],
                "message": "cluster transport unavailable"})
    out = _res(s)
    assert out["status"] == "PARTIAL"
    assert out["lease_purge"]["errors"]["cluster"] == "cluster transport unavailable"


def test_transport_exception_is_caught_and_reported():
    class _Boom(_Transport):
        async def fanout(self, command, data, timeout=20.0, member_ids=None):
            raise RuntimeError("websocket closed")

    s = object.__new__(DHCPSpoke)
    s.cluster = _Cluster(_Boom(None), {"status": "SUCCESS"})
    out = _res(s)
    assert out["status"] == "PARTIAL"
    assert "websocket closed" in out["lease_purge"]["errors"]["coordinator"]
