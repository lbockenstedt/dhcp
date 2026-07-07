"""Event-loop offload tests for ``DHCPSpoke.handle_command`` / ``get_status``.

The DHCP role runs on the lm-svcs agent's ONE shared event loop alongside the
dns + base role sub-spokes. ``KeaManager`` does sync ``requests.post`` to the
Kea Control Agent (10s timeout) under every method, and ``DHCP_SYNC`` chains
config-get + config-set + config-write + subnet4-list (3-4 RPCs). Calling those
directly from ``async def handle_command`` blocks the whole loop → the hub's 5s
``request_response`` fires for every in-flight request across all three
sub-spokes at once (the "lm-svcs-dhcp/dns/svcs time out in the same second"
incident). The fix wraps every mgr call in ``await asyncio.to_thread(...)`` so
the sync HTTP runs in a worker thread and the loop keeps servicing the other
roles + the hub WS link.

These tests lock that in: a fake mgr records the thread id it ran on, and each
command asserts the result contract is unchanged AND the mgr call ran in a
DIFFERENT thread than the event loop (i.e. it was offloaded, not called sync).
"""

import asyncio
import threading

import pytest

from dhcp_spoke import DHCPSpoke


class FakeMgr:
    """Records every call + the thread it ran in. Methods mirror KeaManager
    signatures + return shapes so the spoke's response wrapping is exercised."""

    def __init__(self):
        self.calls = []
        self.thread_ids = []

    def _tid(self):
        tid = threading.get_ident()
        self.thread_ids.append(tid)
        return tid

    def sync(self, subnets, reservations):
        self.calls.append(("sync", len(subnets), len(reservations)))
        self._tid()
        return {"status": "SUCCESS", "subnets": len(subnets), "reservations": len(reservations)}

    def list_subnets(self):
        self.calls.append(("list_subnets",))
        self._tid()
        return [{"id": 1, "subnet": "10.0.0.0/24"}]

    def list_leases(self, subnet=None):
        self.calls.append(("list_leases", subnet))
        self._tid()
        return [{"ip-address": "10.0.0.5"}]

    def add_reservation(self, subnet_id, ip, mac, hostname=""):
        self.calls.append(("add_reservation", subnet_id, ip, mac, hostname))
        self._tid()
        return {"status": "SUCCESS"}

    def list_reservations(self):
        self.calls.append(("list_reservations",))
        self._tid()
        return [{"ip": "10.0.0.5", "mac": "aa:bb:cc:dd:ee:ff", "subnet_id": 1}]

    def update_reservation(self, old_ip, subnet_id, ip, mac, hostname=""):
        self.calls.append(("update_reservation", old_ip, subnet_id, ip, mac, hostname))
        self._tid()
        return {"status": "SUCCESS"}

    def delete_reservation(self, ip):
        self.calls.append(("delete_reservation", ip))
        self._tid()
        return {"status": "SUCCESS"}

    def status(self):
        self.calls.append(("status",))
        self._tid()
        return {"running": True, "subnet_count": 2, "ca_url": "http://localhost:8001"}

    def get_stats(self):
        self.calls.append(("get_stats",))
        self._tid()
        return {"status": "SUCCESS", "global": {"total_addresses": 254}}


@pytest.fixture
def spoke():
    s = DHCPSpoke("test-dhcp", {"kea_ca_url": "http://localhost:8001"})
    s.mgr = FakeMgr()
    return s


@pytest.fixture
def loop():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        yield loop
    finally:
        loop.close()
        asyncio.set_event_loop(asyncio.new_event_loop())


def _run(loop, coro):
    return loop.run_until_complete(coro)


def _assert_offloaded(spoke, loop):
    """The mgr call ran in a worker thread, NOT the event-loop thread."""
    assert spoke.mgr.thread_ids, "mgr method was never called"
    loop_thread = threading.get_ident()
    for tid in spoke.mgr.thread_ids:
        assert tid != loop_thread, "mgr call ran on the event-loop thread (not offloaded)"


def test_get_version_does_not_touch_mgr(spoke, loop):
    resp = _run(loop, spoke.handle_command("GET_VERSION", {}))
    assert resp["status"] == "SUCCESS"
    assert "version" in resp
    assert spoke.mgr.calls == []


def test_dhcp_sync_offloaded(spoke, loop):
    resp = _run(loop, spoke.handle_command("DHCP_SYNC",
              {"subnets": [{"subnet": "10.0.0.0/24"}], "reservations": [{"ip": "10.0.0.5", "mac": "aa"}]}))
    assert resp["status"] == "SUCCESS"
    assert resp["subnets"] == 1
    assert resp["reservations"] == 1
    _assert_offloaded(spoke, loop)


def test_dhcp_list_subnets_offloaded(spoke, loop):
    resp = _run(loop, spoke.handle_command("DHCP_LIST_SUBNETS", {}))
    assert resp["status"] == "SUCCESS"
    assert resp["subnets"][0]["subnet"] == "10.0.0.0/24"
    _assert_offloaded(spoke, loop)


def test_dhcp_list_leases_offloaded(spoke, loop):
    resp = _run(loop, spoke.handle_command("DHCP_LIST_LEASES", {"subnet": "10.0.0.0/24"}))
    assert resp["status"] == "SUCCESS"
    assert resp["leases"][0]["ip-address"] == "10.0.0.5"
    _assert_offloaded(spoke, loop)
    assert spoke.mgr.calls[0] == ("list_leases", "10.0.0.0/24")


def test_dhcp_add_res_offloaded(spoke, loop):
    resp = _run(loop, spoke.handle_command("DHCP_ADD_RES",
              {"subnet_id": 1, "ip": "10.0.0.5", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "h"}))
    assert resp["status"] == "SUCCESS"
    _assert_offloaded(spoke, loop)


def test_dhcp_add_res_missing_fields_short_circuits_before_mgr(spoke, loop):
    resp = _run(loop, spoke.handle_command("DHCP_ADD_RES", {"subnet_id": 1}))
    assert resp["status"] == "ERROR"
    assert spoke.mgr.calls == []


def test_dhcp_list_res_offloaded(spoke, loop):
    resp = _run(loop, spoke.handle_command("DHCP_LIST_RES", {}))
    assert resp["status"] == "SUCCESS"
    assert resp["reservations"][0]["ip"] == "10.0.0.5"
    _assert_offloaded(spoke, loop)


def test_dhcp_update_res_offloaded(spoke, loop):
    resp = _run(loop, spoke.handle_command("DHCP_UPDATE_RES",
              {"old_ip": "10.0.0.5", "subnet_id": 1, "ip": "10.0.0.6", "mac": "aa:bb:cc:dd:ee:ff"}))
    assert resp["status"] == "SUCCESS"
    _assert_offloaded(spoke, loop)


def test_dhcp_update_res_missing_old_ip_short_circuits(spoke, loop):
    # old_ip falls back to data.get("ip"), so BOTH must be absent to trip the
    # guard. Validation runs on the loop and must NOT offload a doomed mgr call.
    resp = _run(loop, spoke.handle_command("DHCP_UPDATE_RES",
              {"subnet_id": 1, "mac": "aa:bb:cc:dd:ee:ff"}))
    assert resp["status"] == "ERROR"
    assert "old_ip" in resp["message"]
    assert spoke.mgr.calls == []


def test_dhcp_del_res_offloaded(spoke, loop):
    resp = _run(loop, spoke.handle_command("DHCP_DEL_RES", {"ip": "10.0.0.5"}))
    assert resp["status"] == "SUCCESS"
    _assert_offloaded(spoke, loop)


def test_dhcp_del_res_missing_ip_short_circuits(spoke, loop):
    resp = _run(loop, spoke.handle_command("DHCP_DEL_RES", {}))
    assert resp["status"] == "ERROR"
    assert spoke.mgr.calls == []


def test_dhcp_status_offloaded_and_spread(spoke, loop):
    resp = _run(loop, spoke.handle_command("DHCP_STATUS", {}))
    assert resp["status"] == "SUCCESS"
    assert resp["running"] is True
    assert resp["subnet_count"] == 2
    _assert_offloaded(spoke, loop)


def test_dhcp_stats_offloaded(spoke, loop):
    resp = _run(loop, spoke.handle_command("DHCP_STATS", {}))
    assert resp["status"] == "SUCCESS"
    _assert_offloaded(spoke, loop)


def test_unknown_command_no_mgr(spoke, loop):
    resp = _run(loop, spoke.handle_command("DHCP_NOPE", {}))
    assert resp["status"] == "ERROR"
    assert "Unknown command" in resp["error"]
    assert spoke.mgr.calls == []


def test_get_status_offloaded(spoke, loop):
    """get_status is polled by the hub for telemetry — the sync Kea CA RPC must
    be offloaded too, or a slow poll stalls the loop."""
    s = _run(loop, spoke.get_status())
    assert s["spoke_id"] == "test-dhcp"
    assert s["module"] == "dhcp"
    assert s["kea"] == "running"
    assert s["status"] == "HEALTHY"
    assert s["subnet_count"] == 2
    _assert_offloaded(spoke, loop)