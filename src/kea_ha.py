"""Two-node Kea DHCP4 High Availability — config generation and orchestration.

A real HA pair, not two independent servers pointed at the same subnets:

* Both nodes load ``libdhcp_ha.so`` + ``libdhcp_lease_cmds.so`` (the HA hook
  cannot synchronise leases without the lease-commands hook) and carry the
  **identical** ``subnet4`` block — same pools, same reservations, same option
  data. Divergent scopes are the classic way a "HA pair" hands out overlapping
  addresses.
* Each node gets a **node-specific identity**: its own ``this-server-name`` and
  a peer list in which every peer has a distinct control-agent URL. A config
  where both nodes claim the same name (or point at the same URL) is rejected
  here rather than discovered as a split brain later.
* **hot-standby is the default.** Load-balancing is only used when the operator
  explicitly asks for it, because it requires both servers to be equally sized
  and reachable and silently degrades a small lab pair.
* Apply order is **standby/secondary first, then primary**. The secondary is the
  node that can absorb a bad config with the least blast radius, and the primary
  is what clients are talking to at that moment.
* Nothing here reports success it did not observe. A validation failure on
  either node aborts before ANY node is touched; a failure after the first node
  applied is reported as ``PARTIAL`` (with a rollback attempt), never SUCCESS.
"""

import copy
import json
import logging
import os
from typing import Any, Dict, Iterable, List, Optional, Tuple

logger = logging.getLogger("KeaHA")

#: Worker operations the DHCP coordinator may ever issue. Fixed at import.
DHCP_WORKER_OPS = (
    "KEAW_INSTALL_HOOKS",  # ensure the HA + lease_cmds hook libraries exist
    "KEAW_GET_CONFIG",     # read this node's FULL running Dhcp4 config
    "KEAW_VALIDATE",       # config-test a candidate node config
    "KEAW_APPLY",          # snapshot + config-set + config-write
    "KEAW_ROLLBACK",       # restore the pre-apply snapshot
    "KEAW_STANDDOWN",      # leave the pair: strip the HA hooks from this node
    "KEAW_HA_STATUS",      # status-get → HA state + lease sync
    "KEAW_STATUS",         # kea reachable + subnet count
    "KEAW_LIST_SUBNETS",   # subnet4-list
    "KEAW_LIST_LEASES",    # lease4-get-all
    "KEAW_LIST_RES",       # static reservations across subnets
    "KEAW_DIAGNOSTICS",    # full local diagnostics evidence
    "KEAW_STATS",          # statistic-get-all
)

HOT_STANDBY = "hot-standby"
LOAD_BALANCING = "load-balancing"
HA_MODES = (HOT_STANDBY, LOAD_BALANCING)
#: What this module will actually configure. ``load-balancing`` is NOT here: it
#: requires the pools to be split between the two servers by client class
#: (Kea's ``HA_server1``/``HA_server2`` classes), and ``build_subnet4`` emits a
#: single undivided pool per subnet. Configuring load-balancing against undivided
#: pools makes BOTH servers allocate from the same range — duplicate addresses,
#: which is worse than having no HA at all. Rejected until the pool splitting is
#: implemented.
SUPPORTED_HA_MODES = (HOT_STANDBY,)

#: Fallback multiarch hook dir. The real path carries the architecture triplet
#: (``/usr/lib/aarch64-linux-gnu/kea/hooks`` on arm64), so it is resolved at
#: runtime by :func:`resolve_hook_dir` on the node itself — hard-coding the
#: x86_64 triplet made every non-amd64 node report its HA libraries missing.
DEFAULT_HOOK_DIR = "/usr/lib/x86_64-linux-gnu/kea/hooks"

#: Where Debian/Ubuntu's ``kea-common`` package installs the hook libraries.
HOOK_DIR_GLOBS = ("/usr/lib/*/kea/hooks", "/usr/lib/kea/hooks",
                  "/usr/local/lib/kea/hooks")

DEFAULT_CLUSTER_CONFIG = "/etc/lm-dhcp/cluster.json"
DEFAULT_DESIRED_STATE = "/var/lib/lm-dhcp/desired.json"

#: The node-local Kea Control Agent stays LOOPBACK-ONLY (unauthenticated by
#: default), so nothing but the co-located worker can drive Kea. HA peer traffic
#: is a SEPARATE, authenticated control agent on its own port — see
#: ``install_dhcp.sh`` and ``_member_url``. Exposing 8001 to the network would
#: hand full, unauthenticated ``config-set`` rights to anyone who can reach it.
DEFAULT_CA_PORT = 8001          # loopback only, worker ↔ local Kea
DEFAULT_HA_PORT = 8002          # LAN, HTTPS + mutual cert + basic auth, peer ↔ peer
#: HA peer traffic is HTTPS, always. Basic-auth credentials ride inside the TLS
#: session (never over plaintext HTTP), and both ends verify the other's cert
#: against the HA trust anchor the installer provisions.
DEFAULT_HA_SCHEME = "https"
DEFAULT_HA_TLS_DIR = "/etc/kea/ha-tls"
#: Exactly what ``install_dhcp.sh`` writes on every HA node. Used as the default
#: per-member TLS material so a UI payload of {id, host, credentials} is a valid
#: pair; override per member to point elsewhere.
DEFAULT_HA_CA = f"{DEFAULT_HA_TLS_DIR}/ha-ca.pem"
DEFAULT_HA_CERT = f"{DEFAULT_HA_TLS_DIR}/node.crt"
DEFAULT_HA_KEY = f"{DEFAULT_HA_TLS_DIR}/node.key"

#: Kea HA timers. Conservative lab-friendly values; a heartbeat every 10s with a
#: 60s response ceiling avoids flapping over a slow link while still failing over
#: inside a lease renewal window.
HA_TIMERS = {
    "heartbeat-delay": 10000,
    "max-response-delay": 60000,
    "max-ack-delay": 5000,
    "max-unacked-clients": 5,
}


class KeaHAConfigError(ValueError):
    """The requested HA topology is not a valid pair."""


class UnsupportedHAMode(KeaHAConfigError):
    """A mode this module refuses to configure (currently: load-balancing)."""


def normalize_mode(mode: Any) -> str:
    """The HA mode to configure. Only hot-standby is supported.

    ``load-balancing`` RAISES :class:`UnsupportedHAMode` rather than being
    quietly accepted: it needs each subnet's pool split between the two servers
    by client class, and this module emits one undivided pool per subnet
    (``build_subnet4``). Accepting it would have both servers allocating from
    the same range. Anything unrecognised (``None``, typos) falls back to
    hot-standby — guessing a different allocation model from a misspelling is
    not acceptable either.
    """
    value = str(mode or "").strip().lower().replace("_", "-")
    if value == LOAD_BALANCING:
        raise UnsupportedHAMode(
            "load-balancing is not supported: it requires each subnet's pool to "
            "be split between the two servers by client class, which this "
            "module does not yet generate. Use hot-standby.")
    if value and value != HOT_STANDBY:
        logger.warning("Unknown Kea HA mode %r — defaulting to %s", mode, HOT_STANDBY)
    return HOT_STANDBY


def coerce_mode(mode: Any) -> str:
    """Loader-side mode read: never raises.

    A cluster.json written before load-balancing was rejected must not brick the
    spoke on startup — it is coerced to hot-standby with a loud warning, and the
    operator sees the unsupported mode called out in the HA report.
    """
    try:
        return normalize_mode(mode)
    except UnsupportedHAMode:
        logger.error("Persisted Kea HA mode %r is no longer supported — running "
                     "as %s. Re-apply the HA configuration to clear this.",
                     mode, HOT_STANDBY)
        return HOT_STANDBY


def peer_roles(mode: str) -> Tuple[str, str]:
    """``(primary_role, partner_role)`` for the given mode.

    Kea names the second server ``standby`` in hot-standby and ``secondary`` in
    load-balancing; using the wrong one makes the hook refuse the config.
    """
    return ("primary", "standby") if normalize_mode(mode) == HOT_STANDBY \
        else ("primary", "secondary")


def _member_url(member: Dict[str, Any]) -> str:
    """The peer URL the OTHER node dials for HA heartbeats/lease sync.

    This is deliberately NOT the node-local ``ca_port`` (8001): that agent is
    loopback-only and unauthenticated, and publishing it would expose
    unauthenticated ``config-set`` to the network. HA peers talk to the
    dedicated, basic-auth-protected HA agent on ``ha_port`` (8002 by default),
    which the installer firewalls to the partner address.
    """
    url = str(member.get("url") or member.get("ha_url") or "").strip()
    if url:
        if url.lower().startswith("http://"):
            raise KeaHAConfigError(
                f"member '{member.get('id')}' HA url {url} is plaintext http:// "
                f"— HA peer traffic carries the control credentials and must be "
                f"https://")
        return url if url.endswith("/") else url + "/"
    host = str(member.get("host") or "").strip()
    port = int(member.get("ha_port") or DEFAULT_HA_PORT)
    scheme = str(member.get("ha_scheme") or DEFAULT_HA_SCHEME).strip().lower()
    if scheme != "https":
        raise KeaHAConfigError(
            f"member '{member.get('id')}' requested HA scheme {scheme!r}; only "
            f"https is allowed for peer traffic")
    if not host:
        raise KeaHAConfigError(
            f"member '{member.get('id')}' needs a host or an explicit HA url")
    return f"https://{host}:{port}/"


def _member_auth(member: Dict[str, Any]) -> Dict[str, str]:
    """Per-peer TLS material + basic-auth credentials for the HA channel.

    Kea's HA hook dials the partner's control agent on every heartbeat. Both
    ends verify the other's certificate against the HA trust anchor, and the
    basic-auth credentials travel INSIDE that TLS session — they are never sent
    over plaintext HTTP. TLS material is required; basic auth is layered on top
    when configured.
    """
    out: Dict[str, str] = {}
    # Canonical installer paths. install_dhcp.sh writes exactly these on every
    # HA node, so a UI that only collects id/host/credentials still produces a
    # config build_peers accepts. An explicit empty string is NOT defaulted —
    # deliberately blanking the anchor still fails closed.
    trust = str(member.get("ha_trust_anchor", DEFAULT_HA_CA) or "").strip()
    cert = str(member.get("ha_cert", DEFAULT_HA_CERT) or "").strip()
    key = str(member.get("ha_key", DEFAULT_HA_KEY) or "").strip()
    if trust:
        out["trust-anchor"] = trust
    if cert:
        out["cert-file"] = cert
    if key:
        out["key-file"] = key
    user = str(member.get("ha_user") or "").strip()
    password = str(member.get("ha_password") or "")
    if user and password:
        out["basic-auth-user"] = user
        out["basic-auth-password"] = password
    return out


def build_peers(members: Iterable[Dict[str, Any]], mode: str) -> List[Dict[str, Any]]:
    """Validate the pair and produce Kea's ``peers`` list.

    Raises :class:`KeaHAConfigError` for anything that is not exactly two
    distinctly-identified, distinctly-addressed servers — the states that
    produce a split brain instead of an HA pair.
    """
    members = [m for m in (members or []) if isinstance(m, dict)]
    if len(members) != 2:
        raise KeaHAConfigError(
            f"Kea HA requires exactly 2 members, got {len(members)}")
    ids = [str(m.get("id") or "").strip() for m in members]
    if not all(ids):
        raise KeaHAConfigError("every Kea HA member needs a non-empty id")
    if ids[0] == ids[1]:
        raise KeaHAConfigError(
            f"both Kea HA members are named '{ids[0]}' — peers must be distinct")

    primary_role, partner_role = peer_roles(mode)
    explicit = [str(m.get("role") or "").strip().lower() for m in members]
    if explicit[0] in ("primary",) or explicit[1] in ("standby", "secondary"):
        ordered = members
    elif explicit[1] in ("primary",) or explicit[0] in ("standby", "secondary"):
        ordered = [members[1], members[0]]
    else:
        ordered = members  # no explicit roles → declaration order decides

    urls = [_member_url(m) for m in ordered]
    if urls[0] == urls[1]:
        raise KeaHAConfigError(
            f"both Kea HA members resolve to the same control-agent URL "
            f"{urls[0]} — each node needs its own address")
    peers = [
        {"name": str(ordered[0]["id"]).strip(), "url": urls[0],
         "role": primary_role, "auto-failover": True,
         **_member_auth(ordered[0])},
        {"name": str(ordered[1]["id"]).strip(), "url": urls[1],
         "role": partner_role, "auto-failover": True,
         **_member_auth(ordered[1])},
    ]
    missing_tls = [p["name"] for p in peers if not p.get("trust-anchor")]
    if missing_tls:
        raise KeaHAConfigError(
            "HA peer traffic must be verified TLS; no trust anchor configured "
            "for: " + ", ".join(missing_tls) + ". Re-run install_dhcp.sh with "
            "--ha-ca/--ha-cert/--ha-key on each node and supply ha_trust_anchor "
            "in the member configuration.")
    return peers


def apply_order(peers: List[Dict[str, Any]]) -> List[str]:
    """Member ids in apply order: the non-primary node first.

    Applying the primary last means the node currently answering clients is the
    last one disturbed, and a config the standby already rejected never reaches
    it.
    """
    partner = [p["name"] for p in peers if p["role"] != "primary"]
    primary = [p["name"] for p in peers if p["role"] == "primary"]
    return partner + primary


def resolve_hook_dir(explicit: str = "") -> str:
    """Find the Kea hook directory ON THIS NODE.

    An explicit path wins (operator override). Otherwise the multiarch globs are
    searched for a directory that actually contains ``libdhcp_ha.so`` — the
    architecture triplet differs per node, and a coordinator must never assume
    its own triplet applies to a worker. Falls back to
    :data:`DEFAULT_HOOK_DIR` so the caller still produces a usable (if wrong)
    path to report as missing.
    """
    explicit = (explicit or "").strip()
    if explicit:
        return explicit.rstrip("/")
    import glob as _glob
    for pattern in HOOK_DIR_GLOBS:
        for candidate in sorted(_glob.glob(pattern)):
            if os.path.isfile(os.path.join(candidate, "libdhcp_ha.so")):
                return candidate.rstrip("/")
    # No HA lib anywhere yet (hooks not installed): return the first existing
    # hook dir so the install step has somewhere to look, else the default.
    for pattern in HOOK_DIR_GLOBS:
        for candidate in sorted(_glob.glob(pattern)):
            if os.path.isdir(candidate):
                return candidate.rstrip("/")
    return DEFAULT_HOOK_DIR


def hook_paths(hook_dir: str = "") -> Dict[str, str]:
    base = resolve_hook_dir(hook_dir)
    return {"ha": f"{base}/libdhcp_ha.so",
            "lease_cmds": f"{base}/libdhcp_lease_cmds.so"}


def build_ha_hooks(this_name: str, peers: List[Dict[str, Any]], mode: str,
                   hook_dir: str = "") -> List[Dict[str, Any]]:
    """The two hook-library entries a Kea HA node needs, in load order.

    ``lease_cmds`` MUST be loaded — the HA hook uses it to pull leases from the
    partner during synchronisation, and without it a failover node serves an
    empty lease database.
    """
    names = [p["name"] for p in peers]
    if this_name not in names:
        raise KeaHAConfigError(
            f"'{this_name}' is not one of the HA peers ({', '.join(names)})")
    paths = hook_paths(hook_dir)
    return [
        {"library": paths["lease_cmds"]},
        {"library": paths["ha"],
         "parameters": {"high-availability": [{
             "this-server-name": this_name,
             "mode": normalize_mode(mode),
             **HA_TIMERS,
             "peers": copy.deepcopy(peers),
         }]}},
    ]


#: The ONLY keys the DHCP coordinator owns. Everything else in a node's running
#: ``Dhcp4`` config — interfaces-config, lease-database, option-def, loggers,
#: client-classes, expired-leases-processing, unrelated hooks — belongs to that
#: node and is carried through untouched.
COORDINATOR_OWNED_KEYS = ("subnet4",)


def build_node_config(node_dhcp4: Dict[str, Any], this_name: str,
                      peers: List[Dict[str, Any]], mode: str,
                      hook_dir: str = "",
                      owned: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Node-specific ``Dhcp4`` config built ON TOP OF that node's running config.

    ``node_dhcp4`` is the node's OWN current configuration (from
    ``KEAW_GET_CONFIG``). Only the coordinator-owned keys
    (:data:`COORDINATOR_OWNED_KEYS` — the shared scopes/reservations) and the HA
    hook entries are replaced; interfaces, lease database, loggers, client
    classes and every other node-local setting survive verbatim. Rendering from
    an empty ``{}`` would silently wipe a node's interface bindings and lease
    database the first time HA was applied.

    Non-HA hook libraries already present on the node are preserved; the HA and
    lease-commands entries are replaced wholesale so a stale peer list from an
    earlier topology cannot survive a reconfiguration.
    """
    cfg = copy.deepcopy(node_dhcp4 or {})
    for key in COORDINATOR_OWNED_KEYS:
        if owned is not None and key in owned:
            cfg[key] = copy.deepcopy(owned[key])
    keep = [h for h in (cfg.get("hooks-libraries") or [])
            if isinstance(h, dict)
            and not str(h.get("library", "")).endswith(
                ("libdhcp_ha.so", "libdhcp_lease_cmds.so"))]
    cfg["hooks-libraries"] = keep + build_ha_hooks(this_name, peers, mode, hook_dir)
    return cfg


def config_fingerprint(dhcp4: Dict[str, Any]) -> str:
    """Digest of the SHARED part of a node config (everything but HA identity).

    Two HA nodes are supposed to differ in exactly one place — the HA hook's
    ``this-server-name``. Comparing the rest is how drift in scopes,
    reservations or options is detected.
    """
    import hashlib

    shared = copy.deepcopy(dhcp4 or {})
    shared.pop("hooks-libraries", None)
    blob = json.dumps(shared, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def parse_ha_status(status_get: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize Kea ``status-get`` into the HA fields the UI needs.

    Returns ``ha_enabled=False`` when the payload carries no
    ``high-availability`` block — that means the HA hook is not loaded, which is
    a very different (and much worse) condition than "state unknown".
    """
    ha_list = (status_get or {}).get("high-availability") or []
    if not ha_list:
        return {"ha_enabled": False, "local": {}, "remote": {},
                "state": "not-configured", "scopes": [], "in_sync": False}
    servers = (ha_list[0] or {}).get("ha-servers") or {}
    local = servers.get("local") or {}
    remote = servers.get("remote") or {}
    state = str(local.get("state") or "unknown")
    remote_state = str(remote.get("last-state") or "unknown")
    # Kea reports the partner as in-touch once heartbeats are flowing; a pair
    # that has never exchanged one is NOT synchronised no matter what state the
    # local server claims for itself.
    in_touch = bool(remote.get("in-touch"))
    return {
        "ha_enabled": True,
        "state": state,
        "role": str(local.get("role") or ""),
        "scopes": list(local.get("scopes") or []),
        "remote_state": remote_state,
        "remote_role": str(remote.get("role") or ""),
        "remote_scopes": list(remote.get("last-scopes") or []),
        "remote_age": remote.get("age"),
        "remote_in_touch": in_touch,
        "communication_interrupted": bool(remote.get("communication-interrupted")),
        "unacked_clients": remote.get("unacked-clients"),
        "in_sync": bool(in_touch and state in ("hot-standby", "load-balancing")
                        and remote_state in ("hot-standby", "load-balancing")),
        "local": local,
        "remote": remote,
    }


def public_peers(peers: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Peer list with the HA basic-auth password removed.

    The password is needed to RENDER Kea's config and nowhere else; a status or
    diagnostics reply that carried it would leak the HA credential to every
    caller of ``/api/dhcp/ha``."""
    out = []
    for peer in peers or []:
        clean = {k: v for k, v in (peer or {}).items()
                 if k != "basic-auth-password"}
        if peer.get("basic-auth-password"):
            clean["basic-auth"] = True
        out.append(clean)
    return out


def summarize_ha(mode: str, peers: List[Dict[str, Any]],
                 links: List[Dict[str, Any]],
                 per_member: Dict[str, Dict[str, Any]],
                 config_digests: Optional[Dict[str, str]] = None,
                 last_apply: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Cluster/member stats, drift, partial failures and recommendations.

    Pure — the Diagnostics page renders exactly this, and every branch is
    directly testable.
    """
    config_digests = config_digests or {}
    roles = {p["name"]: p["role"] for p in peers}
    members: List[Dict[str, Any]] = []
    healthy_ids, degraded_ids, unreachable_ids = [], [], []
    for link in links:
        member_id = link["id"]
        status = per_member.get(member_id) or {}
        ha = status.get("ha") if isinstance(status.get("ha"), dict) else {}
        member = dict(link)
        member["ha_role"] = roles.get(member_id, link.get("role") or "")
        member["config_digest"] = config_digests.get(member_id)
        member.update({
            "ha_enabled": bool(ha.get("ha_enabled")),
            "ha_state": ha.get("state", "unknown"),
            "scopes": ha.get("scopes", []),
            "remote_state": ha.get("remote_state", "unknown"),
            "remote_in_touch": ha.get("remote_in_touch"),
            "communication_interrupted": ha.get("communication_interrupted"),
            "kea_running": status.get("running"),
            "subnet_count": status.get("subnet_count"),
            "error": status.get("message") or status.get("error") or "",
        })
        if not link["connected"] or status.get("status") != "SUCCESS":
            member["health"] = "unreachable"
            unreachable_ids.append(member_id)
        elif ha.get("ha_enabled") and ha.get("in_sync"):
            member["health"] = "healthy"
            healthy_ids.append(member_id)
        else:
            member["health"] = "degraded"
            degraded_ids.append(member_id)
        members.append(member)

    # Convergence is a POSITIVE claim: it requires a fresh, non-empty digest
    # from EVERY member. A missing/blank digest (node unreachable, config read
    # failed, never applied) previously collapsed the comparison set to <=1 and
    # reported "matched" — the exact false-green this guards against.
    member_ids = [m["id"] for m in members]
    reported = {mid: config_digests.get(mid) for mid in member_ids}
    have_all = bool(member_ids) and all(bool(reported[mid]) for mid in member_ids)
    config_converged = have_all and len(set(reported.values())) == 1
    missing_digests = [mid for mid in member_ids if not reported.get(mid)]
    total = len(members)
    if total and len(healthy_ids) == total and config_converged:
        state = "healthy"
    elif healthy_ids:
        state = "degraded"
    else:
        state = "down"

    recommendations: List[str] = []
    if total != 2:
        recommendations.append(
            f"Kea HA needs exactly two members; {total} configured.")
    for member_id in unreachable_ids:
        recommendations.append(
            f"Kea node '{member_id}' is not reachable through the DHCP module; "
            f"check lm-dhcp-worker and kea-ctrl-agent on that host.")
    for member in members:
        if member["health"] != "degraded":
            continue
        if not member["ha_enabled"]:
            recommendations.append(
                f"Kea node '{member['id']}' has no HA hook loaded — it is "
                f"serving DHCP independently, not as part of the pair.")
        elif member.get("communication_interrupted"):
            recommendations.append(
                f"Kea node '{member['id']}' reports communication with its "
                f"partner interrupted (state {member['ha_state']}); check "
                f"connectivity between the control agents.")
        else:
            recommendations.append(
                f"Kea node '{member['id']}' is in HA state "
                f"'{member['ha_state']}' and has not synchronised leases with "
                f"its partner.")
    if missing_digests:
        recommendations.append(
            "Configuration state is unknown for: " + ", ".join(missing_digests)
            + " — the pair cannot be confirmed converged until every node "
              "reports its running configuration.")
    elif not config_converged:
        recommendations.append(
            "The two Kea nodes are running DIFFERENT subnet/reservation "
            "configurations; re-apply the DHCP configuration to converge them.")
    if last_apply and last_apply.get("status") == "PARTIAL":
        recommendations.append(
            f"The last HA configuration apply only completed on "
            f"{', '.join(last_apply.get('applied') or []) or 'no node'}; the "
            f"pair is running mismatched configuration until it is re-applied.")

    return {
        "enabled": True,
        "mode": coerce_mode(mode),
        "state": state,
        "healthy": state == "healthy",
        "config_converged": config_converged,
        "config_digests_missing": missing_digests,
        "peers": public_peers(peers),
        "members": members,
        "member_count": total,
        "healthy_count": len(healthy_ids),
        "degraded": degraded_ids,
        "unreachable": unreachable_ids,
        "last_apply": dict(last_apply) if last_apply else {},
        "recommendations": recommendations,
    }


# ── Persisted cluster config ────────────────────────────────────────────────

def load_cluster_config(path: str) -> Dict[str, Any]:
    """Read the persisted HA topology. Missing/garbage → HA off."""
    empty = {"members": [], "mode": HOT_STANDBY, "hook_dir": ""}
    try:
        with open(path) as fh:
            data = json.load(fh)
    except FileNotFoundError:
        return empty
    except Exception as e:  # noqa: BLE001
        logger.warning("Could not read DHCP cluster config %s: %s", path, e)
        return empty
    if not isinstance(data, dict):
        return empty
    members = data.get("members")
    return {
        "members": members if isinstance(members, list) else [],
        "mode": coerce_mode(data.get("mode")),
        "hook_dir": str(data.get("hook_dir") or ""),
    }


def save_cluster_config(path: str, members: List[Dict[str, Any]], mode: str,
                        hook_dir: str = "") -> None:
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        json.dump({"members": members, "mode": coerce_mode(mode),
                   "hook_dir": hook_dir}, fh, indent=2)
    # Members may carry the HA basic-auth password, so this file is a secret.
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
