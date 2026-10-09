"""Real-time Kea -> Unbound DNS registration hook (Option 1).

Covers: settings validation (incl. rejecting unsafe ``targets``/``domain``
values before they'd ever reach a shell command), the generated run_script
body (syntax + the actual per-hook-point logic against a fake
``unbound-control``), ``KeaManager.configure_dns_hook``/``dns_hook_status``
mutating only the one hooks-libraries entry this feature owns, and
``DHCPSpoke.handle_command`` dispatch in both the non-cluster and HA-fanout
paths.
"""

import os
import shutil
import subprocess
import tempfile

import pytest

import kea_dns_hook as h
from kea_manager import KeaManager


# ─────────────────────────── settings validation ───────────────────────────

def test_default_settings_disabled_with_localhost_target():
    d = h.default_settings()
    assert d["enabled"] is False
    assert d["targets"] == ["127.0.0.1@8953"]


def test_validate_settings_normalizes_domain_and_rejects_bad_ttl():
    clean = h.validate_settings({"enabled": True, "domain": "LAB.Local.", "ttl": 120})
    assert clean["domain"] == "lab.local"
    assert clean["ttl"] == 120

    with pytest.raises(h.DnsHookConfigError):
        h.validate_settings({"ttl": 0})
    with pytest.raises(h.DnsHookConfigError):
        h.validate_settings({"ttl": 10**9})


def test_validate_settings_rejects_bad_domain_and_injection_in_targets():
    with pytest.raises(h.DnsHookConfigError):
        h.validate_settings({"domain": "-not-valid"})
    with pytest.raises(h.DnsHookConfigError):
        h.validate_settings({"targets": ['127.0.0.1@8953"; rm -rf /']})
    with pytest.raises(h.DnsHookConfigError):
        h.validate_settings({"targets": []})
    with pytest.raises(h.DnsHookConfigError):
        h.validate_settings({"targets": "not-a-list"})


@pytest.mark.parametrize("target", [
    "$(touch /tmp/pwned)@8953",
    "127.0.0.1@8953`id`",
    "127.0.0.1@8953|id",
    "127.0.0.1@8953&id",
    "host(name)@8953",
    "127.0.0.1",        # missing @port entirely
    "127.0.0.1@",       # missing port
    "@8953",            # missing host
])
def test_validate_settings_strict_target_regex_rejects_shell_metacharacters(target):
    """The old blocklist only rejected quotes/semicolons/whitespace/newlines
    — ``$()``, backticks, ``|`` and ``&`` all passed it and would have run as
    shell code via the (now-removed) ``eval`` of this value in the generated
    script. The allowlist regex must reject all of these outright."""
    with pytest.raises(h.DnsHookConfigError):
        h.validate_settings({"targets": [target]})


def test_validate_settings_accepts_hostnames_and_ipv6_targets():
    clean = h.validate_settings({"targets": ["unbound-1.lab.local@8953", "::1@8953"]})
    assert clean["targets"] == ["unbound-1.lab.local@8953", "::1@8953"]


def test_validate_settings_boolean_coercion_rejects_falsy_strings():
    """``bool("false")`` is ``True`` in Python — a caller sending the JSON
    string "false" to disable the hook must not silently enable it."""
    clean = h.validate_settings({"enabled": "false", "register_ptr": "false"})
    assert clean["enabled"] is False
    assert clean["register_ptr"] is False

    clean = h.validate_settings({"enabled": "true"})
    assert clean["enabled"] is True

    with pytest.raises(h.DnsHookConfigError):
        h.validate_settings({"enabled": "maybe"})


def test_validate_settings_not_a_dict():
    with pytest.raises(h.DnsHookConfigError):
        h.validate_settings("nope")


# ─────────────────────────── hooks-libraries entry ─────────────────────────

def test_build_and_remove_dns_hook_entry_round_trips():
    entry = h.build_dns_hook_entry(hook_dir="/usr/lib/x86_64-linux-gnu/kea/hooks")
    assert entry["library"].endswith(h.RUN_SCRIPT_LIB)
    assert entry["parameters"]["name"] == h.DNS_HOOK_SCRIPT_PATH
    assert entry["parameters"]["sync"] is False

    others = [{"library": "/usr/lib/kea/hooks/libdhcp_lease_cmds.so"},
              {"library": "/usr/lib/kea/hooks/libdhcp_ha.so"}]
    hooks = others + [entry]
    stripped = h.remove_dns_hook_entry(hooks)
    assert stripped == others


def test_remove_dns_hook_entry_leaves_unrelated_run_script_untouched():
    """A different run_script hook (unrelated script path) must survive —
    this feature only owns ITS OWN script path, not the whole hook type."""
    foreign = {"library": "/usr/lib/kea/hooks/libdhcp_run_script.so",
               "parameters": {"name": "/opt/other/script.sh", "sync": False}}
    ours = h.build_dns_hook_entry()
    stripped = h.remove_dns_hook_entry([foreign, ours])
    assert stripped == [foreign]


# ─────────────────────────── generated script ──────────────────────────────

def _bash_available():
    return shutil.which("bash") is not None


@pytest.mark.skipif(not _bash_available(), reason="bash not available")
def test_rendered_script_is_syntactically_valid():
    body = h.render_script()
    with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as f:
        f.write(body)
        path = f.name
    try:
        r = subprocess.run(["bash", "-n", path], capture_output=True, text=True)
        assert r.returncode == 0, r.stderr
    finally:
        os.unlink(path)


@pytest.mark.skipif(not _bash_available(), reason="bash not available")
def test_script_registers_and_retracts_records_via_fake_unbound_control(tmp_path):
    """End-to-end exercise of the real hook body: a fake ``unbound-control`` on
    PATH records every invocation, and we assert on the exact arguments for a
    committed lease (+ a deleted one), a release, and that a client-supplied
    hostname containing shell metacharacters never reaches that command."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    calls_log = tmp_path / "calls.log"
    uc = bin_dir / "unbound-control"
    uc.write_text(f'#!/bin/bash\necho "$*" >> "{calls_log}"\nexit 0\n')
    uc.chmod(0o755)

    config = tmp_path / "hook.json"
    config.write_text(
        '{"enabled": true, "targets": ["127.0.0.1@8953"], '
        '"domain": "lab.local", "ttl": 300, "register_ptr": true}')
    log_path = tmp_path / "hook.log"

    body = h.render_script().replace(
        h.DNS_HOOK_CONFIG_PATH, str(config)).replace(
        h.DNS_HOOK_LOG_PATH, str(log_path))
    script = tmp_path / "lm-dns-sync.sh"
    script.write_text(body)
    script.chmod(0o755)

    env = dict(os.environ)
    env["PATH"] = f"{bin_dir}:{env['PATH']}"

    # New + renewed lease alongside one deactivated in the same transaction.
    env.update({
        "LEASES4_SIZE": "1", "LEASES4_AT0_ADDRESS": "192.168.1.50",
        "LEASES4_AT0_HOSTNAME": "MyHost",
        "DELETED_LEASES4_SIZE": "1", "DELETED_LEASES4_AT0_ADDRESS": "192.168.1.51",
        "DELETED_LEASES4_AT0_HOSTNAME": "oldhost",
    })
    r = subprocess.run([str(script), "leases4_committed"], env=env,
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    calls = calls_log.read_text().splitlines()
    assert "-s 127.0.0.1@8953 local_data myhost.lab.local. 300 IN A 192.168.1.50" in calls
    assert "-s 127.0.0.1@8953 local_data 50.1.168.192.in-addr.arpa. 300 IN PTR myhost.lab.local." in calls
    assert "-s 127.0.0.1@8953 local_data_remove oldhost.lab.local." in calls
    assert "-s 127.0.0.1@8953 local_data_remove 51.1.168.192.in-addr.arpa." in calls

    calls_log.write_text("")
    env2 = dict(env)
    env2.pop("LEASES4_SIZE", None)
    env2.update({"LEASE4_ADDRESS": "192.168.1.60", "LEASE4_HOSTNAME": "releasedhost"})
    r = subprocess.run([str(script), "lease4_release"], env=env2,
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    calls = calls_log.read_text().splitlines()
    assert "-s 127.0.0.1@8953 local_data_remove releasedhost.lab.local." in calls

    # Untrusted client-supplied hostname with shell metacharacters: must be
    # rejected (no unbound-control call at all), not escaped-and-passed.
    calls_log.write_text("")
    env3 = dict(env)
    for k in ("DELETED_LEASES4_SIZE", "DELETED_LEASES4_AT0_ADDRESS", "DELETED_LEASES4_AT0_HOSTNAME"):
        env3.pop(k, None)
    env3["LEASES4_SIZE"] = "1"
    env3["LEASES4_AT0_ADDRESS"] = "192.168.1.70"
    env3["LEASES4_AT0_HOSTNAME"] = 'evil"; touch ' + str(tmp_path / "PWNED") + '; echo "'
    r = subprocess.run([str(script), "leases4_committed"], env=env3,
                       capture_output=True, text=True)
    assert r.returncode == 0
    assert calls_log.read_text().strip() == ""
    assert not (tmp_path / "PWNED").exists()


@pytest.mark.skipif(not _bash_available(), reason="bash not available")
def test_script_processes_deletions_before_additions_same_batch(tmp_path):
    """A deleted lease and a newly-committed lease sharing the same hostname
    (e.g. a client moving IPs within one leases4_committed transaction) must
    leave the NEW lease's record in place — the delete must run first so the
    later add isn't the one that gets wiped."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    calls_log = tmp_path / "calls.log"
    uc = bin_dir / "unbound-control"
    uc.write_text(f'#!/bin/bash\necho "$*" >> "{calls_log}"\nexit 0\n')
    uc.chmod(0o755)

    config = tmp_path / "hook.json"
    config.write_text(
        '{"enabled": true, "targets": ["127.0.0.1@8953"], '
        '"domain": "lab.local", "ttl": 300, "register_ptr": false}')
    log_path = tmp_path / "hook.log"
    body = h.render_script().replace(
        h.DNS_HOOK_CONFIG_PATH, str(config)).replace(
        h.DNS_HOOK_LOG_PATH, str(log_path))
    script = tmp_path / "lm-dns-sync.sh"
    script.write_text(body)
    script.chmod(0o755)

    env = dict(os.environ)
    env["PATH"] = f"{bin_dir}:{env['PATH']}"
    env.update({
        "LEASES4_SIZE": "1", "LEASES4_AT0_ADDRESS": "192.168.1.99",
        "LEASES4_AT0_HOSTNAME": "samehost",
        "DELETED_LEASES4_SIZE": "1", "DELETED_LEASES4_AT0_ADDRESS": "192.168.1.98",
        "DELETED_LEASES4_AT0_HOSTNAME": "samehost",
    })
    r = subprocess.run([str(script), "leases4_committed"], env=env,
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    calls = calls_log.read_text().splitlines()
    remove_idx = next(i for i, c in enumerate(calls) if "local_data_remove samehost.lab.local." in c)
    add_idx = next(i for i, c in enumerate(calls)
                  if "local_data samehost.lab.local. 300 IN A 192.168.1.99" in c)
    assert remove_idx < add_idx, (
        "deletion of the stale 'samehost' lease must be applied BEFORE the "
        "new 'samehost' lease is registered, or the add would be wiped out")


@pytest.mark.skipif(not _bash_available(), reason="bash not available")
def test_script_removes_ptr_record_even_when_hostname_is_blank(tmp_path):
    """PTR removal only needs the IP (the reverse-zone name is derived from
    it), so a release/expire event with an unparseable/blank hostname must
    still clean up the PTR entry rather than silently skipping it."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    calls_log = tmp_path / "calls.log"
    uc = bin_dir / "unbound-control"
    uc.write_text(f'#!/bin/bash\necho "$*" >> "{calls_log}"\nexit 0\n')
    uc.chmod(0o755)

    config = tmp_path / "hook.json"
    config.write_text(
        '{"enabled": true, "targets": ["127.0.0.1@8953"], '
        '"domain": "lab.local", "ttl": 300, "register_ptr": true}')
    log_path = tmp_path / "hook.log"
    body = h.render_script().replace(
        h.DNS_HOOK_CONFIG_PATH, str(config)).replace(
        h.DNS_HOOK_LOG_PATH, str(log_path))
    script = tmp_path / "lm-dns-sync.sh"
    script.write_text(body)
    script.chmod(0o755)

    env = dict(os.environ)
    env["PATH"] = f"{bin_dir}:{env['PATH']}"
    env.update({"LEASE4_ADDRESS": "192.168.1.77", "LEASE4_HOSTNAME": ""})
    r = subprocess.run([str(script), "lease4_release"], env=env,
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    calls = calls_log.read_text().splitlines()
    assert "-s 127.0.0.1@8953 local_data_remove 77.1.168.192.in-addr.arpa." in calls


@pytest.mark.skipif(not _bash_available(), reason="bash not available")
def test_script_logs_partial_when_only_some_targets_accept(tmp_path):
    """Multi-resolver deployment: if only one of two targets accepts the
    update, that must be visibly logged as PARTIAL, not silently treated as
    a clean success (which would hide DNS drift between resolvers)."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    calls_log = tmp_path / "calls.log"
    uc = bin_dir / "unbound-control"
    uc.write_text(
        f'#!/bin/bash\necho "$*" >> "{calls_log}"\n'
        'if [[ "$*" == *9999* ]]; then exit 1; fi\nexit 0\n')
    uc.chmod(0o755)

    config = tmp_path / "hook.json"
    config.write_text(
        '{"enabled": true, "targets": ["127.0.0.1@8953", "127.0.0.1@9999"], '
        '"domain": "lab.local", "ttl": 300, "register_ptr": false}')
    log_path = tmp_path / "hook.log"
    body = h.render_script().replace(
        h.DNS_HOOK_CONFIG_PATH, str(config)).replace(
        h.DNS_HOOK_LOG_PATH, str(log_path))
    script = tmp_path / "lm-dns-sync.sh"
    script.write_text(body)
    script.chmod(0o755)

    env = dict(os.environ)
    env["PATH"] = f"{bin_dir}:{env['PATH']}"
    env.update({"LEASES4_SIZE": "1", "LEASES4_AT0_ADDRESS": "192.168.1.50",
                "LEASES4_AT0_HOSTNAME": "myhost"})
    r = subprocess.run([str(script), "leases4_committed"], env=env,
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    log_text = log_path.read_text()
    assert "PARTIAL A  myhost.lab.local. -> 192.168.1.50" in log_text


@pytest.mark.skipif(not _bash_available(), reason="bash not available")
def test_script_is_a_noop_when_disabled_or_unconfigured(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    calls_log = tmp_path / "calls.log"
    uc = bin_dir / "unbound-control"
    uc.write_text(f'#!/bin/bash\necho "$*" >> "{calls_log}"\nexit 0\n')
    uc.chmod(0o755)
    env = dict(os.environ)
    env["PATH"] = f"{bin_dir}:{env['PATH']}"

    log_path = tmp_path / "hook.log"
    missing_config = tmp_path / "missing.json"
    body = h.render_script().replace(
        h.DNS_HOOK_CONFIG_PATH, str(missing_config)).replace(
        h.DNS_HOOK_LOG_PATH, str(log_path))
    script = tmp_path / "lm-dns-sync.sh"
    script.write_text(body)
    script.chmod(0o755)

    env.update({"LEASES4_SIZE": "1", "LEASES4_AT0_ADDRESS": "192.168.1.50",
                "LEASES4_AT0_HOSTNAME": "myhost"})
    r = subprocess.run([str(script), "leases4_committed"], env=env,
                       capture_output=True, text=True)
    assert r.returncode == 0
    assert not calls_log.exists() or calls_log.read_text().strip() == ""


# ─────────────────────────── file writer ───────────────────────────────────

def test_write_hook_files_writes_config_and_executable_script(tmp_path, monkeypatch):
    monkeypatch.setattr(h, "DNS_HOOK_CONFIG_PATH", str(tmp_path / "hook.json"))
    monkeypatch.setattr(h, "DNS_HOOK_SCRIPT_PATH", str(tmp_path / "scripts" / "lm-dns-sync.sh"))
    monkeypatch.setattr(h, "DNS_HOOK_LOG_PATH", str(tmp_path / "log" / "hook.log"))

    settings = h.validate_settings({"enabled": True, "domain": "lab.local"})
    h.write_hook_files(settings)

    assert os.path.isfile(h.DNS_HOOK_CONFIG_PATH)
    assert os.path.isfile(h.DNS_HOOK_SCRIPT_PATH)
    assert os.access(h.DNS_HOOK_SCRIPT_PATH, os.X_OK)
    assert os.path.isdir(os.path.dirname(h.DNS_HOOK_LOG_PATH))

    status = h.read_status()
    assert status["settings"]["enabled"] is True
    assert status["settings"]["domain"] == "lab.local"
    assert status["script_installed"] is True


# ─────────────────────────── KeaManager wiring ─────────────────────────────

def test_configure_dns_hook_mutates_only_its_own_hooks_libraries_entry(tmp_path, monkeypatch):
    monkeypatch.setattr(h, "DNS_HOOK_CONFIG_PATH", str(tmp_path / "hook.json"))
    monkeypatch.setattr(h, "DNS_HOOK_SCRIPT_PATH", str(tmp_path / "scripts" / "lm-dns-sync.sh"))
    monkeypatch.setattr(h, "DNS_HOOK_LOG_PATH", str(tmp_path / "log" / "hook.log"))

    mgr = KeaManager()
    other_hook = {"library": "/usr/lib/kea/hooks/libdhcp_lease_cmds.so"}
    running_cfg = {"hooks-libraries": [other_hook]}
    applied = {}

    def fake_rpc(service, command, args=None):
        if command == "config-get":
            return {"Dhcp4": dict(running_cfg)}
        if command == "config-set":
            applied["hooks-libraries"] = args["Dhcp4"]["hooks-libraries"]
            running_cfg["hooks-libraries"] = args["Dhcp4"]["hooks-libraries"]
            return {}
        if command == "config-write":
            return {}
        raise AssertionError(f"unexpected command {command}")

    monkeypatch.setattr(mgr, "_rpc", fake_rpc)

    result = mgr.configure_dns_hook({"enabled": True, "targets": ["127.0.0.1@8953"]},
                                    hook_dir="/usr/lib/x86_64-linux-gnu/kea/hooks")
    assert result["status"] == "SUCCESS"
    assert other_hook in applied["hooks-libraries"]
    assert any(e.get("parameters", {}).get("name") == h.DNS_HOOK_SCRIPT_PATH
              for e in applied["hooks-libraries"] if isinstance(e, dict))
    assert os.path.isfile(h.DNS_HOOK_CONFIG_PATH)

    # Disabling removes OUR entry but must still leave the unrelated one.
    result2 = mgr.configure_dns_hook({"enabled": False})
    assert result2["status"] == "SUCCESS"
    assert applied["hooks-libraries"] == [other_hook]


def test_configure_dns_hook_rejects_invalid_settings_without_touching_kea(monkeypatch):
    mgr = KeaManager()

    def fail_rpc(*a, **k):
        raise AssertionError("must not call Kea for invalid settings")

    monkeypatch.setattr(mgr, "_rpc", fail_rpc)
    result = mgr.configure_dns_hook({"ttl": -1})
    assert result["status"] == "ERROR"


def test_configure_dns_hook_reports_error_on_config_get_failure(monkeypatch):
    mgr = KeaManager()
    monkeypatch.setattr(mgr, "_rpc", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("down")))
    result = mgr.configure_dns_hook({"enabled": True})
    assert result["status"] == "ERROR"
    assert "down" in result["message"]


def test_dns_hook_status_reports_loaded_in_running_config(tmp_path, monkeypatch):
    monkeypatch.setattr(h, "DNS_HOOK_CONFIG_PATH", str(tmp_path / "hook.json"))
    monkeypatch.setattr(h, "DNS_HOOK_SCRIPT_PATH", str(tmp_path / "scripts" / "lm-dns-sync.sh"))
    monkeypatch.setattr(h, "DNS_HOOK_LOG_PATH", str(tmp_path / "log" / "hook.log"))

    mgr = KeaManager()
    entry = h.build_dns_hook_entry()
    monkeypatch.setattr(mgr, "get_config", lambda: {"hooks-libraries": [entry]})
    status = mgr.dns_hook_status()
    assert status["loaded_in_running_config"] is True


# ─────────────────────────── DHCPSpoke dispatch ────────────────────────────

class _FakeMgr:
    def __init__(self, dns_hook_status_reply=None):
        self.configure_calls = []
        self._dns_hook_status_reply = dns_hook_status_reply or {
            "settings": h.default_settings(),
            "script_installed": True,
            "loaded_in_running_config": True,
        }

    def configure_dns_hook(self, settings, hook_dir=""):
        self.configure_calls.append((settings, hook_dir))
        return {"status": "SUCCESS", "enabled": settings.get("enabled")}

    def dns_hook_status(self):
        return dict(self._dns_hook_status_reply)


class _NoCluster:
    enabled = False


def _non_cluster_spoke(dns_hook_status_reply=None):
    from dhcp_spoke import DHCPSpoke
    obj = object.__new__(DHCPSpoke)
    obj.cluster = _NoCluster()
    obj.mgr = _FakeMgr(dns_hook_status_reply=dns_hook_status_reply)
    return obj


def test_handle_command_non_cluster_dns_hook_config_and_status():
    import asyncio
    obj = _non_cluster_spoke()

    res = asyncio.run(obj.handle_command(
        "DHCP_DNS_HOOK_CONFIG", {"settings": {"enabled": True}}))
    assert res["status"] == "SUCCESS"
    assert obj.mgr.configure_calls == [({"enabled": True}, "")]

    res = asyncio.run(obj.handle_command("DHCP_DNS_HOOK_STATUS", {}))
    assert res["status"] == "SUCCESS"
    assert res["script_installed"] is True


def test_handle_command_non_cluster_dns_hook_status_is_partial_when_running_config_read_fails():
    import asyncio
    obj = _non_cluster_spoke({
        "settings": h.default_settings(),
        "script_installed": True,
        "loaded_in_running_config": None,
        "running_config_error": "control agent down",
    })

    res = asyncio.run(obj.handle_command("DHCP_DNS_HOOK_STATUS", {}))
    assert res["status"] == "PARTIAL"
    assert res["running_config_error"] == "control agent down"


def test_handle_command_non_cluster_dns_hook_config_requires_settings():
    import asyncio
    obj = _non_cluster_spoke()
    res = asyncio.run(obj.handle_command("DHCP_DNS_HOOK_CONFIG", {}))
    assert res["status"] == "ERROR"


class _Transport:
    def __init__(self, reply, member_ids=None):
        self._reply = reply
        self.calls = []
        self._member_ids = member_ids

    async def fanout(self, command, data, timeout=20.0, member_ids=None):
        self.calls.append((command, data))
        return self._reply

    def member_ids(self):
        return self._member_ids or []


class _Cluster:
    enabled = True

    def __init__(self, transport):
        self.transport = transport


def _ha_spoke(fanout_reply, member_ids=None):
    from dhcp_spoke import DHCPSpoke
    obj = object.__new__(DHCPSpoke)
    obj.cluster = _Cluster(_Transport(fanout_reply, member_ids=member_ids))
    return obj


def test_handle_command_ha_dns_hook_config_fans_out_to_both_nodes():
    import asyncio
    reply = {"results": {"node-a": {"status": "SUCCESS"},
                         "node-b": {"status": "SUCCESS"}}}
    obj = _ha_spoke(reply)
    res = asyncio.run(obj.handle_command(
        "DHCP_DNS_HOOK_CONFIG", {"settings": {"enabled": True}}))
    assert res["status"] == "SUCCESS"
    assert obj.cluster.transport.calls[0][0] == "KEAW_DNS_HOOK_CONFIG"
    assert not res["member_errors"]


def test_handle_command_ha_dns_hook_config_reports_partial_node_failure():
    import asyncio
    reply = {"results": {"node-a": {"status": "SUCCESS"},
                         "node-b": {"status": "ERROR", "message": "kea unreachable"}}}
    obj = _ha_spoke(reply)
    res = asyncio.run(obj.handle_command(
        "DHCP_DNS_HOOK_CONFIG", {"settings": {"enabled": True}}))
    assert res["status"] == "ERROR"
    assert res["member_errors"]["node-b"] == "kea unreachable"


def test_handle_command_ha_dns_hook_status_returns_per_member_not_merged():
    import asyncio
    reply = {"results": {"node-a": {"status": "SUCCESS", "settings": {"enabled": True}},
                         "node-b": {"status": "SUCCESS", "settings": {"enabled": False}}}}
    obj = _ha_spoke(reply)
    res = asyncio.run(obj.handle_command("DHCP_DNS_HOOK_STATUS", {}))
    assert res["members"]["node-a"]["settings"]["enabled"] is True
    assert res["members"]["node-b"]["settings"]["enabled"] is False


def test_handle_command_ha_dns_hook_config_missing_member_is_not_success():
    # node-b never answers at all (e.g. disconnected) — dropped entirely
    # from `results`, not present with an explicit error. Without comparing
    # against the transport's own member_ids(), this used to read as a
    # clean SUCCESS because `errors` built only from `results` was empty.
    import asyncio
    reply = {"results": {"node-a": {"status": "SUCCESS"}}}
    obj = _ha_spoke(reply, member_ids=["node-a", "node-b"])
    res = asyncio.run(obj.handle_command(
        "DHCP_DNS_HOOK_CONFIG", {"settings": {"enabled": True}}))
    assert res["status"] == "ERROR"
    assert res["member_errors"]["node-b"] == "no response"


def test_handle_command_ha_dns_hook_status_missing_member_is_not_success():
    import asyncio
    reply = {"results": {"node-a": {"status": "SUCCESS", "settings": {"enabled": True}}}}
    obj = _ha_spoke(reply, member_ids=["node-a", "node-b"])
    res = asyncio.run(obj.handle_command("DHCP_DNS_HOOK_STATUS", {}))
    assert res["status"] == "ERROR"
    assert res["member_errors"]["node-b"] == "no response"


def test_handle_command_ha_dns_hook_status_preserves_member_error_messages():
    import asyncio
    reply = {"results": {
        "node-a": {"status": "SUCCESS", "settings": {"enabled": True}},
        "node-b": {"status": "PARTIAL",
                   "message": "cannot read running config",
                   "loaded_in_running_config": None,
                   "running_config_error": "config-get failed"},
        "node-c": {"status": "ERROR", "message": "hook files missing"},
    }}
    obj = _ha_spoke(reply, member_ids=["node-a", "node-b", "node-c", "node-d"])
    res = asyncio.run(obj.handle_command("DHCP_DNS_HOOK_STATUS", {}))
    assert res["status"] == "ERROR"
    assert res["member_errors"]["node-b"] == "cannot read running config"
    assert res["member_errors"]["node-c"] == "hook files missing"
    assert res["member_errors"]["node-d"] == "no response"


@pytest.mark.skipif(not _bash_available(), reason="bash not available")
def test_script_suffixes_lease_scope_domain_with_global_fallback(tmp_path):
    """A single-label lease hostname gets ITS Kea subnet's domain-name option
    (the DHCP scope's domain); a subnet without one falls back to the hook's
    global ``domain``; a dotted hostname is left alone."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    calls_log = tmp_path / "calls.log"
    uc = bin_dir / "unbound-control"
    uc.write_text(f'#!/bin/bash\necho "$*" >> "{calls_log}"\nexit 0\n')
    uc.chmod(0o755)
    kea_conf = tmp_path / "kea-dhcp4.conf"
    kea_conf.write_text(
        '// generated\n{"Dhcp4": {"subnet4": [\n'
        '  {"id": 1, "subnet": "10.0.1.0/24", "option-data": [{"name": "domain-name", "data": "Scope1.Example."}]},\n'
        '  {"id": 2, "subnet": "10.0.2.0/24", "option-data": [{"name": "routers", "data": "10.0.2.1"}]},\n'
        '  {"id": 4, "subnet": "10.0.4.0/24", "option-data": [{"name": "domain-name", "data": "bad domain"}]}],\n'
        ' "shared-networks": [{"subnet4": [\n'
        '  {"id": 3, "subnet": "10.0.3.0/24", "option-data": [{"name": "domain-name", "data": "shared.example"}]}]}]}}\n')
    config = tmp_path / "hook.json"
    config.write_text(
        '{"enabled": true, "targets": ["127.0.0.1@8953"], "domain": "lab.local", '
        f'"ttl": 300, "register_ptr": false, "kea_config": "{kea_conf}"}}')
    body = h.render_script().replace(
        h.DNS_HOOK_CONFIG_PATH, str(config)).replace(
        h.DNS_HOOK_LOG_PATH, str(tmp_path / "hook.log"))
    script = tmp_path / "lm-dns-sync.sh"
    script.write_text(body)
    script.chmod(0o755)
    env = dict(os.environ)
    env["PATH"] = f"{bin_dir}:{env['PATH']}"
    env.update({
        "LEASES4_SIZE": "5",
        "LEASES4_AT0_ADDRESS": "10.0.1.5", "LEASES4_AT0_HOSTNAME": "printer1", "LEASES4_AT0_SUBNET_ID": "1",
        "LEASES4_AT1_ADDRESS": "10.0.2.5", "LEASES4_AT1_HOSTNAME": "laptop2", "LEASES4_AT1_SUBNET_ID": "2",
        "LEASES4_AT2_ADDRESS": "10.0.3.5", "LEASES4_AT2_HOSTNAME": "cam3", "LEASES4_AT2_SUBNET_ID": "3",
        "LEASES4_AT3_ADDRESS": "10.0.1.6", "LEASES4_AT3_HOSTNAME": "fq.other.org", "LEASES4_AT3_SUBNET_ID": "1",
        "LEASES4_AT4_ADDRESS": "10.0.4.5", "LEASES4_AT4_HOSTNAME": "tv4", "LEASES4_AT4_SUBNET_ID": "4",
        "DELETED_LEASES4_SIZE": "1", "DELETED_LEASES4_AT0_ADDRESS": "10.0.1.9",
        "DELETED_LEASES4_AT0_HOSTNAME": "gone", "DELETED_LEASES4_AT0_SUBNET_ID": "1",
    })
    r = subprocess.run([str(script), "leases4_committed"], env=env, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    calls = calls_log.read_text().splitlines()
    assert "-s 127.0.0.1@8953 local_data printer1.scope1.example. 300 IN A 10.0.1.5" in calls
    assert "-s 127.0.0.1@8953 local_data laptop2.lab.local. 300 IN A 10.0.2.5" in calls
    assert "-s 127.0.0.1@8953 local_data cam3.shared.example. 300 IN A 10.0.3.5" in calls
    assert "-s 127.0.0.1@8953 local_data fq.other.org. 300 IN A 10.0.1.6" in calls
    assert "-s 127.0.0.1@8953 local_data tv4.lab.local. 300 IN A 10.0.4.5" in calls
    assert "-s 127.0.0.1@8953 local_data_remove gone.scope1.example." in calls

    calls_log.write_text("")
    env2 = {k: v for k, v in env.items() if not k.startswith(("LEASES4_", "DELETED_LEASES4_"))}
    env2.update({"LEASE4_ADDRESS": "10.0.3.7", "LEASE4_HOSTNAME": "bye", "LEASE4_SUBNET_ID": "3"})
    r = subprocess.run([str(script), "lease4_expire"], env=env2, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert calls_log.read_text().splitlines() == ["-s 127.0.0.1@8953 local_data_remove bye.shared.example."]
