import logging
from typing import Any, Dict

try:
    from base_spoke import BaseSpoke
except ImportError:
    from core.src.base_spoke import BaseSpoke

try:
    from kea_manager import KeaManager
except ImportError:  # loaded as a package (src.X) by the sibling entrypoint
    from src.kea_manager import KeaManager

logger = logging.getLogger("DHCPSpoke")


class DHCPSpoke(BaseSpoke):
    """
    Kea DHCP4 spoke.

    Commands:
      DHCP_SYNC         — replace all subnets + reservations from NetBox data
      DHCP_LIST_SUBNETS — list all managed subnets
      DHCP_LIST_LEASES  — list active leases (optional subnet filter)
      DHCP_ADD_RES      — add a static reservation
      DHCP_DEL_RES      — remove a static reservation by IP
      DHCP_STATUS       — Kea health + subnet count
    """

    def __init__(self, spoke_id: str, config: Dict[str, Any]):
        super().__init__(spoke_id, config)
        ca_url = config.get("kea_ca_url", "http://localhost:8001")
        self.mgr = KeaManager(ca_url=ca_url)

    async def handle_command(self, command_type: str, data: Dict[str, Any]) -> Dict[str, Any]:
        cmd = command_type.upper()

        if cmd == "GET_VERSION":
            return {"status": "SUCCESS", "version": self.get_version()}

        if cmd == "DHCP_SYNC":
            subnets      = data.get("subnets", [])
            reservations = data.get("reservations", [])
            return self.mgr.sync(subnets, reservations)

        if cmd == "DHCP_LIST_SUBNETS":
            return {"status": "SUCCESS", "subnets": self.mgr.list_subnets()}

        if cmd == "DHCP_LIST_LEASES":
            subnet = data.get("subnet")
            return {"status": "SUCCESS", "leases": self.mgr.list_leases(subnet)}

        if cmd == "DHCP_ADD_RES":
            subnet_id = data.get("subnet_id")
            ip        = data.get("ip")
            mac       = data.get("mac")
            hostname  = data.get("hostname", "")
            if not all([subnet_id, ip, mac]):
                return {"status": "ERROR", "message": "subnet_id, ip, and mac are required"}
            return self.mgr.add_reservation(int(subnet_id), ip, mac, hostname)

        if cmd == "DHCP_LIST_RES":
            return {"status": "SUCCESS", "reservations": self.mgr.list_reservations()}

        if cmd == "DHCP_UPDATE_RES":
            old_ip    = data.get("old_ip") or data.get("ip")
            subnet_id = data.get("subnet_id")
            ip        = data.get("ip")
            mac       = data.get("mac")
            hostname  = data.get("hostname", "")
            if not old_ip:
                return {"status": "ERROR", "message": "old_ip is required"}
            if not all([subnet_id, ip, mac]):
                return {"status": "ERROR", "message": "subnet_id, ip, and mac are required"}
            return self.mgr.update_reservation(old_ip, int(subnet_id), ip, mac, hostname)

        if cmd == "DHCP_DEL_RES":
            ip = data.get("ip")
            if not ip:
                return {"status": "ERROR", "message": "ip is required"}
            return self.mgr.delete_reservation(ip)

        if cmd == "DHCP_STATUS":
            return {"status": "SUCCESS", **self.mgr.status()}

        if cmd == "DHCP_STATS":
            return self.mgr.get_stats()

        return {"status": "ERROR", "error": f"Unknown command: {command_type}"}

    async def get_status(self) -> Dict[str, Any]:
        s = self.mgr.status()
        out = {
            "spoke_id":     self.spoke_id,
            "module":       "dhcp",
            "kea":          "running" if s["running"] else "stopped",
            "subnet_count": s["subnet_count"],
            "status":       "HEALTHY" if s["running"] else "DEGRADED",
        }
        # Carry the reason for a down CA into the telemetry frame so the hub
        # surfaces it (single, deduped) instead of just "stopped".
        if s.get("error"):
            out["error"] = s["error"]
        return out

    def get_version(self) -> str:
        from pathlib import Path
        try:
            return (Path(__file__).parent.parent / "VERSION").read_text().strip()
        except Exception:
            return "unknown"
