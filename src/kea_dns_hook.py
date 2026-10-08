"""Real-time Kea lease -> Unbound DNS registration via the ``run_script`` hook.

Kea's open-source ``libdhcp_run_script.so`` hook library invokes an external
script at ``leases4_committed`` (fires on every new lease AND every renewal —
there is no ``lease4_select`` hook point), ``lease4_release``, ``lease4_expire``
and ``lease4_decline``, passing lease data as environment variables (the only
CLI argument is the hook point name). This module generates that script (a
static template — it reads its tunables from a JSON sidecar at runtime, so a
settings change never requires touching the script file itself) plus the
``hooks-libraries`` entry that loads it, and writes both straight to disk on
the Kea host — the same direct-file-write pattern ``KeaManager``'s self-heal
methods already use for ``/etc/kea/kea-api-password``.

The script talks to Unbound over ``unbound-control`` (``local_data`` /
``local_data_remove`` against the resolver's remote-control port), NOT through
the hub — this is the "no LM in the real-time path" requirement. The default
target (``127.0.0.1@8953``) assumes Kea and Unbound are co-located (the
documented single-agent-multi-role deployment); a multi-host resolver fleet
needs its ``control-interface`` opened to the Kea host's address and the
``unbound_control.pem``/``unbound_control.key``/``unbound_server.pem`` trio
copied there (``unbound-control -s`` verifies the server cert) — operational
steps, not something this hook can safely automate without inventing its own
cross-repo PKI distribution.

``unbound-control local_data`` writes are IN-MEMORY ONLY (they do not persist
across an ``unbound-control reload``/service restart) — this is what makes the
real-time path fast and hub-independent, but it also means an Unbound restart
silently drops every dynamically-registered name until the NEXT DHCP event for
that client. The NetBox->Unbound reconciliation loop (``lm/core/src/
dns_dhcp_sync.py``) is the durable backstop: once a Kea lease has a writeback
record in NetBox (see the ``fw_discovery_sync`` "kea" source), that loop
re-applies it to Unbound's on-disk ``conf.d`` every cycle regardless of
whether the in-memory entry survived a restart.
"""

import json
import logging
import os
import re
import stat
from typing import Any, Dict, List

logger = logging.getLogger("KeaDnsHook")

#: Fixed paths so every piece (KeaManager, the worker, KEAW_DNS_HOOK_STATUS,
#: install_dhcp.sh) agrees on where to look without passing paths around.
DNS_HOOK_SCRIPT_PATH = "/etc/kea/scripts/lm-dns-sync.sh"
DNS_HOOK_CONFIG_PATH = "/etc/kea/lm-dns-hook.json"
DNS_HOOK_LOG_PATH = "/var/log/kea/lm-dns-sync.log"

RUN_SCRIPT_LIB = "libdhcp_run_script.so"

#: Same multiarch search used by kea_ha.resolve_hook_dir for libdhcp_ha.so —
#: duplicated rather than imported to keep this module usable standalone (it
#: has nothing else to do with HA).
_HOOK_DIR_GLOBS = ("/usr/lib/*/kea/hooks", "/usr/lib/kea/hooks",
                   "/usr/local/lib/kea/hooks")
_DEFAULT_HOOK_DIR = "/usr/lib/x86_64-linux-gnu/kea/hooks"

#: Mirrors dns/src/dns_cluster.py's _NAME_RE (letters/digits/hyphen/underscore
#: per label, no leading/trailing hyphen, dots as separators) so a hostname
#: this hook is willing to register would also pass the dns spoke's own
#: validation. Client-supplied DHCP hostnames are untrusted input — this is
#: what keeps one from breaking out of the `unbound-control local_data`
#: argument.
NAME_RE = re.compile(r"^(?!-)[A-Za-z0-9_-]{1,63}(?<!-)"
                    r"(?:\.(?!-)[A-Za-z0-9_-]{1,63}(?<!-))*\.?$")

DEFAULT_TTL = 300
MIN_TTL = 1
MAX_TTL = 604800
DEFAULT_TARGETS = ["127.0.0.1@8953"]


class DnsHookConfigError(ValueError):
    """Invalid real-time DNS hook settings — refuse to write/apply anything."""


def default_settings() -> Dict[str, Any]:
    return {"enabled": False, "targets": list(DEFAULT_TARGETS),
            "domain": "", "ttl": DEFAULT_TTL, "register_ptr": False}


def validate_settings(settings: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize+validate a settings payload. Raises :class:`DnsHookConfigError`."""
    if not isinstance(settings, dict):
        raise DnsHookConfigError("settings must be an object")
    out = default_settings()
    out["enabled"] = bool(settings.get("enabled", False))
    domain = str(settings.get("domain", "") or "").strip().rstrip(".").lower()
    if domain and not NAME_RE.match(domain):
        raise DnsHookConfigError(f"domain '{domain}' is not a valid DNS suffix")
    out["domain"] = domain
    try:
        ttl = int(settings.get("ttl", DEFAULT_TTL))
    except (TypeError, ValueError):
        raise DnsHookConfigError("ttl must be an integer")
    if not (MIN_TTL <= ttl <= MAX_TTL):
        raise DnsHookConfigError(f"ttl must be between {MIN_TTL} and {MAX_TTL}")
    out["ttl"] = ttl
    out["register_ptr"] = bool(settings.get("register_ptr", False))
    targets = settings.get("targets")
    if targets is None:
        targets = list(DEFAULT_TARGETS)
    if not isinstance(targets, list) or not targets:
        raise DnsHookConfigError("targets must be a non-empty list of 'host@port' strings")
    clean_targets: List[str] = []
    for t in targets:
        t = str(t or "").strip()
        if not t or any(c in t for c in ('"', "'", "\n", "\r", ";", " ")):
            raise DnsHookConfigError(f"invalid unbound-control target: {t!r}")
        clean_targets.append(t)
    out["targets"] = clean_targets
    if out["enabled"] and not clean_targets:
        raise DnsHookConfigError("at least one DNS target is required when enabled")
    return out


def resolve_hook_dir(explicit: str = "") -> str:
    """Find the Kea hook directory on this node (same approach as kea_ha)."""
    explicit = (explicit or "").strip()
    if explicit:
        return explicit.rstrip("/")
    import glob as _glob
    for pattern in _HOOK_DIR_GLOBS:
        for candidate in sorted(_glob.glob(pattern)):
            if os.path.isfile(os.path.join(candidate, RUN_SCRIPT_LIB)):
                return candidate.rstrip("/")
    for pattern in _HOOK_DIR_GLOBS:
        for candidate in sorted(_glob.glob(pattern)):
            if os.path.isdir(candidate):
                return candidate.rstrip("/")
    return _DEFAULT_HOOK_DIR


def build_dns_hook_entry(hook_dir: str = "") -> Dict[str, Any]:
    """The ``hooks-libraries`` entry that loads the run_script hook.

    ``sync: false`` is the honest value, not a stylistic default — Kea's
    run_script library does not implement synchronous script execution at all
    (per its own docs), so claiming ``true`` would promise a guarantee Kea
    cannot keep.
    """
    base = resolve_hook_dir(hook_dir)
    return {"library": f"{base}/{RUN_SCRIPT_LIB}",
            "parameters": {"name": DNS_HOOK_SCRIPT_PATH, "sync": False}}


def remove_dns_hook_entry(hooks_libraries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Strip only OUR run_script entry (matched by library name AND the script
    path we own) — an operator's unrelated run_script hook for a different
    script survives untouched."""
    out = []
    for h in (hooks_libraries or []):
        if not isinstance(h, dict):
            out.append(h)
            continue
        if (str(h.get("library", "")).endswith(RUN_SCRIPT_LIB)
                and (h.get("parameters") or {}).get("name") == DNS_HOOK_SCRIPT_PATH):
            continue
        out.append(h)
    return out


#: Static script body. Reads /etc/kea/lm-dns-hook.json fresh on every
#: invocation (via a one-shot python3 call — the rest of the fleet already
#: requires Python 3.11, so this avoids a fragile hand-rolled JSON scrape and
#: avoids a jq dependency) so reconfiguring the hook never means redeploying
#: this file or restarting kea-dhcp4.
_SCRIPT_TEMPLATE = """#!/bin/bash
# lm-dns-sync.sh — generated by dhcp/src/kea_dns_hook.py. DO NOT EDIT BY HAND;
# re-running DHCP_DNS_HOOK_CONFIG will overwrite it.
#
# Kea (libdhcp_run_script.so) invokes this on leases4_committed (new leases AND
# renewals), lease4_release, lease4_expire and lease4_decline, with the hook
# point name as $1 and lease fields as environment variables. See
# kea_dns_hook.py's module docstring for the full design rationale.
set -u

CONFIG="{config_path}"
LOG="{log_path}"
HOOK="${{1:-}}"

mkdir -p "$(dirname "$LOG")" 2>/dev/null
log() {{ echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') [$HOOK] $*" >> "$LOG" 2>/dev/null; }}

[ -r "$CONFIG" ] || exit 0

CFG_LINES=$(python3 - "$CONFIG" 2>>"$LOG" <<'PY'
import json, sys
try:
    with open(sys.argv[1]) as fh:
        c = json.load(fh)
except Exception:
    print("ENABLED=false")
    sys.exit(0)
print(f"ENABLED={{'true' if c.get('enabled') else 'false'}}")
print(f"DOMAIN={{c.get('domain', '')}}")
print(f"TTL={{int(c.get('ttl', 300) or 300)}}")
print(f"REGISTER_PTR={{'true' if c.get('register_ptr') else 'false'}}")
targets = c.get('targets') or ['127.0.0.1@8953']
print("TARGETS=(" + " ".join('"%s"' % t for t in targets) + ")")
PY
)
eval "$CFG_LINES"
[ "${{ENABLED:-false}}" = "true" ] || exit 0
[ "${{#TARGETS[@]}}" -eq 0 ] && TARGETS=("127.0.0.1@8953")

NAME_RE='^[A-Za-z0-9_]([A-Za-z0-9_-]{{0,61}}[A-Za-z0-9_])?(\\.[A-Za-z0-9_]([A-Za-z0-9_-]{{0,61}}[A-Za-z0-9_])?)*\\.?$'

_fqdn() {{
    local h="${{1%.}}"
    [ -z "$h" ] && return 1
    if [[ "$h" != *.* && -n "${{DOMAIN:-}}" ]]; then h="${{h}}.${{DOMAIN}}"; fi
    h=$(printf '%s' "$h" | tr 'A-Z' 'a-z')  # portable lowercase (bash 3.2 lacks ${{var,,}})
    [[ "$h" =~ $NAME_RE ]] || return 1
    printf '%s' "$h"
}}

_ptr_name() {{
    local ip="$1" a b c d
    IFS='.' read -r a b c d <<< "$ip" 2>/dev/null || return 1
    [[ "$a" =~ ^[0-9]+$ && "$b" =~ ^[0-9]+$ && "$c" =~ ^[0-9]+$ && "$d" =~ ^[0-9]+$ ]] || return 1
    printf '%s.%s.%s.%s.in-addr.arpa.' "$d" "$c" "$b" "$a"
}}

_uc() {{
    local ok=1 t
    for t in "${{TARGETS[@]}}"; do
        if unbound-control -s "$t" "$@" >/dev/null 2>>"$LOG"; then ok=0; fi
    done
    return $ok
}}

add_record() {{
    local ip="$1" fqdn
    fqdn=$(_fqdn "$2") || {{ log "skip $ip — no usable hostname"; return; }}
    _uc local_data "${{fqdn}}. ${{TTL}} IN A ${{ip}}" && log "A  ${{fqdn}}. -> ${{ip}}"
    if [ "${{REGISTER_PTR:-false}}" = "true" ]; then
        local ptr; ptr=$(_ptr_name "$ip") || return
        _uc local_data "${{ptr}} ${{TTL}} IN PTR ${{fqdn}}." && log "PTR ${{ptr}} -> ${{fqdn}}."
    fi
}}

remove_record() {{
    local ip="$1" fqdn
    fqdn=$(_fqdn "$2") || return
    _uc local_data_remove "${{fqdn}}." && log "removed A ${{fqdn}}."
    if [ "${{REGISTER_PTR:-false}}" = "true" ]; then
        local ptr; ptr=$(_ptr_name "$ip") || return
        _uc local_data_remove "$ptr" && log "removed PTR ${{ptr}}"
    fi
}}

case "$HOOK" in
  leases4_committed)
    n="${{LEASES4_SIZE:-0}}"
    if [ "$n" -gt 0 ] 2>/dev/null; then
        for i in $(seq 0 $((n-1))); do
            eval "ip=\\${{LEASES4_AT${{i}}_ADDRESS:-}}"
            eval "host=\\${{LEASES4_AT${{i}}_HOSTNAME:-}}"
            [ -n "$ip" ] && add_record "$ip" "$host"
        done
    fi
    d="${{DELETED_LEASES4_SIZE:-0}}"
    if [ "$d" -gt 0 ] 2>/dev/null; then
        for i in $(seq 0 $((d-1))); do
            eval "ip=\\${{DELETED_LEASES4_AT${{i}}_ADDRESS:-}}"
            eval "host=\\${{DELETED_LEASES4_AT${{i}}_HOSTNAME:-}}"
            [ -n "$ip" ] && remove_record "$ip" "$host"
        done
    fi
    ;;
  lease4_release|lease4_expire|lease4_decline)
    [ -n "${{LEASE4_ADDRESS:-}}" ] && remove_record "$LEASE4_ADDRESS" "${{LEASE4_HOSTNAME:-}}"
    ;;
  *)
    ;;
esac
exit 0
"""


def render_script() -> str:
    return _SCRIPT_TEMPLATE.format(config_path=DNS_HOOK_CONFIG_PATH,
                                   log_path=DNS_HOOK_LOG_PATH)


def write_hook_files(settings: Dict[str, Any]) -> None:
    """Write the JSON sidecar + (if missing/stale) the script, on THIS node.

    Settings already validated by the caller (``validate_settings``). Atomic
    write for the JSON (tmp + rename) — the script reads it on every lease
    event, so a half-written file must never be observable.
    """
    os.makedirs(os.path.dirname(DNS_HOOK_CONFIG_PATH), exist_ok=True)
    tmp = DNS_HOOK_CONFIG_PATH + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(settings, fh, indent=2)
    os.replace(tmp, DNS_HOOK_CONFIG_PATH)
    os.chmod(DNS_HOOK_CONFIG_PATH, 0o644)

    os.makedirs(os.path.dirname(DNS_HOOK_SCRIPT_PATH), exist_ok=True)
    body = render_script()
    existing = ""
    if os.path.isfile(DNS_HOOK_SCRIPT_PATH):
        try:
            with open(DNS_HOOK_SCRIPT_PATH) as fh:
                existing = fh.read()
        except OSError:
            existing = ""
    if existing != body:
        tmp_script = DNS_HOOK_SCRIPT_PATH + ".tmp"
        with open(tmp_script, "w") as fh:
            fh.write(body)
        os.replace(tmp_script, DNS_HOOK_SCRIPT_PATH)
    os.chmod(DNS_HOOK_SCRIPT_PATH, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP
            | stat.S_IROTH | stat.S_IXOTH)  # 0755 — Kea execs it as itself

    os.makedirs(os.path.dirname(DNS_HOOK_LOG_PATH), exist_ok=True)


def read_status() -> Dict[str, Any]:
    """Current on-disk settings + a tail of the hook's own run log, for
    ``DHCP_DNS_HOOK_STATUS`` diagnosability."""
    settings = default_settings()
    settings["configured"] = False
    if os.path.isfile(DNS_HOOK_CONFIG_PATH):
        try:
            with open(DNS_HOOK_CONFIG_PATH) as fh:
                on_disk = json.load(fh)
            if isinstance(on_disk, dict):
                settings.update(on_disk)
                settings["configured"] = True
        except Exception as e:  # noqa: BLE001
            settings["read_error"] = str(e)
    log_tail: List[str] = []
    if os.path.isfile(DNS_HOOK_LOG_PATH):
        try:
            with open(DNS_HOOK_LOG_PATH) as fh:
                log_tail = fh.readlines()[-50:]
        except OSError:
            pass
    script_installed = os.path.isfile(DNS_HOOK_SCRIPT_PATH)
    return {"settings": settings, "script_installed": script_installed,
            "script_path": DNS_HOOK_SCRIPT_PATH, "log_tail": [l.rstrip("\n") for l in log_tail]}
