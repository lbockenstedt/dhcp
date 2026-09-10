from pathlib import Path
import hashlib

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from dhcp_spoke import DHCPSpoke
from ha_pki import issue_member_material


def test_member_certificates_are_unique_and_share_a_persistent_ca(tmp_path):
    first = issue_member_material(str(tmp_path), "kea-a", "10.0.1.10")
    second = issue_member_material(str(tmp_path), "kea-b", "10.0.1.11")
    first_retry = issue_member_material(str(tmp_path), "kea-a", "10.0.1.10")

    assert first["ha_ca_pem"] == second["ha_ca_pem"]
    assert first["ha_cert_pem"] != second["ha_cert_pem"]
    assert first["ha_key_pem"] != second["ha_key_pem"]
    assert first_retry["ha_cert_pem"] == first["ha_cert_pem"]
    assert first_retry["ha_key_pem"] == first["ha_key_pem"]
    x509.load_pem_x509_certificate(first["ha_cert_pem"].encode())
    serialization.load_pem_private_key(first["ha_key_pem"].encode(), password=None)
    assert (tmp_path / "ha-ca.key").stat().st_mode & 0o777 == 0o600


def test_member_material_is_reissued_when_cached_key_does_not_match(tmp_path):
    first = issue_member_material(str(tmp_path), "kea-a", "10.0.1.10")
    second = issue_member_material(str(tmp_path), "kea-b", "10.0.1.11")
    safe_id = hashlib.sha256(b"kea-a").hexdigest()[:24]
    (tmp_path / f"{safe_id}.key").write_text(second["ha_key_pem"])

    repaired = issue_member_material(str(tmp_path), "kea-a", "10.0.1.10")

    assert repaired["ha_cert_pem"] != first["ha_cert_pem"]
    assert repaired["ha_key_pem"] != second["ha_key_pem"]


@pytest.mark.asyncio
async def test_discovery_enrollment_returns_complete_per_node_bootstrap(
        tmp_path, monkeypatch):
    listener = tmp_path / "coordinator.crt"
    listener.write_text(
        "-----BEGIN CERTIFICATE-----\npublic\n-----END CERTIFICATE-----\n")

    class _Plane:
        _listener_cert = str(listener)
        connected_agents = {}

        @staticmethod
        def snapshot_agent_secret():
            return "worker-secret"

        @staticmethod
        def set_agent_secret(_secret):
            return True

        @staticmethod
        async def ensure_cluster_listener():
            return {"ok": True, "serving": True}

    class _Transaction:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

    spoke = DHCPSpoke.__new__(DHCPSpoke)
    spoke.control_plane = _Plane()
    spoke._ha_pki_dir = str(tmp_path / "ha")
    spoke._pending_enrollment_path = str(tmp_path / "pending.json")
    spoke._pending_enrollment = {}
    spoke._transport = type("_Transport", (), {"members": []})()
    spoke.cluster = type(
        "_Cluster", (), {
            "mode": "hot-standby",
            "transaction": lambda self: _Transaction(),
        })()

    monkeypatch.setattr("dhcp_spoke.socket.getfqdn",
                        lambda: "dhcp-management.example")

    result = await spoke.handle_command("DHCP_HA_ENROLL_WORKERS", {
        "members": [
            {"id": "kea-a", "host": "10.0.1.10"},
            {"id": "kea-b", "host": "10.0.1.11"},
        ],
    })

    assert result["status"] == "SUCCESS"
    first = result["workers"]["kea-a"]
    second = result["workers"]["kea-b"]
    assert first["worker_secret"] == second["worker_secret"] == "worker-secret"
    assert first["ha_password"] == second["ha_password"]
    assert first["ha_cert_pem"] != second["ha_cert_pem"]
    assert first["ha_peers"] == ["10.0.1.11"]
    assert second["ha_peers"] == ["10.0.1.10"]
    assert spoke._pending_enrollment["members"][0]["ha_password"] == (
        spoke._pending_enrollment["members"][1]["ha_password"])

    spoke.control_plane.connected_agents = {"kea-a": {}, "kea-b": {}}

    async def _apply(raw, data):
        assert len(raw) == len(data["members"]) == 2
        return {"status": "SUCCESS"}

    spoke._apply_ha_config_locked = _apply
    committed = await spoke.handle_command("DHCP_HA_COMMIT_ENROLLMENT", {})
    assert committed["status"] == "SUCCESS"
    assert spoke._pending_enrollment == {}
    assert not Path(spoke._pending_enrollment_path).exists()


@pytest.mark.asyncio
async def test_enrollment_fails_when_worker_secret_is_not_persisted(
        tmp_path, monkeypatch):
    listener = tmp_path / "coordinator.crt"
    listener.write_text(
        "-----BEGIN CERTIFICATE-----\npublic\n-----END CERTIFICATE-----\n")

    class _Plane:
        _listener_cert = str(listener)

        @staticmethod
        def snapshot_agent_secret():
            return "worker-secret"

        @staticmethod
        def set_agent_secret(_secret):
            return False

    class _Transaction:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

    spoke = DHCPSpoke.__new__(DHCPSpoke)
    spoke.control_plane = _Plane()
    spoke._ha_pki_dir = str(tmp_path / "ha")
    spoke._pending_enrollment_path = str(tmp_path / "pending.json")
    spoke._pending_enrollment = {}
    spoke._transport = type("_Transport", (), {"members": []})()
    spoke.cluster = type(
        "_Cluster", (), {
            "mode": "hot-standby",
            "transaction": lambda self: _Transaction(),
        })()

    result = await spoke.handle_command("DHCP_HA_ENROLL_WORKERS", {
        "members": [
            {"id": "kea-a", "host": "10.0.1.10"},
            {"id": "kea-b", "host": "10.0.1.11"},
        ],
    })

    assert result["status"] == "ERROR"
    assert "could not be persisted" in result["message"]


@pytest.mark.asyncio
async def test_commit_rejects_enrollment_staged_against_old_topology(tmp_path):
    class _Transaction:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

    spoke = DHCPSpoke.__new__(DHCPSpoke)
    spoke._pending_enrollment_path = str(tmp_path / "pending.json")
    spoke._pending_enrollment = {
        "members": [
            {"id": "kea-a", "host": "10.0.1.10"},
            {"id": "kea-b", "host": "10.0.1.11"},
        ],
        "base_topology": '{"members":[],"mode":"hot-standby"}',
    }
    spoke._transport = type(
        "_Transport", (), {
            "members": [{"id": "manual", "host": "10.0.2.10"}],
        })()
    spoke.cluster = type(
        "_Cluster", (), {
            "mode": "hot-standby",
            "transaction": lambda self: _Transaction(),
        })()

    result = await spoke.handle_command("DHCP_HA_COMMIT_ENROLLMENT", {})

    assert result["status"] == "ERROR"
    assert "topology changed" in result["message"]
