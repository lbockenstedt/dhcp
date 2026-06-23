import logging
from typing import Any, Dict

try:
    from base_spoke import BaseSpoke
except ImportError:
    from core.src.base_spoke import BaseSpoke

from .dhcp_manager import DHCPManager

logger = logging.getLogger("DHCPSpoke")


class DHCPSpoke(BaseSpoke):
    """Kea DHCP4 integration spoke."""

    def __init__(self, spoke_id: str, config: Dict[str, Any]):
        super().__init__(spoke_id, config)
        url = config.get("KEA_URL", "http://localhost:8000")
        self.manager = DHCPManager(control_url=url)

    def _rebuild_manager(self):
        self.manager = DHCPManager(control_url=self.config.get("KEA_URL", "http://localhost:8000"))

    async def handle_command(self, command_type: str, data: Dict[str, Any]) -> Dict[str, Any]:
        cmd = command_type.upper()

        if cmd == "GET_VERSION":
            return {"status": "SUCCESS", "version": self.get_version()}

        if cmd == "UPDATE_CONFIG":
            self.config = data
            self._rebuild_manager()
            return {"status": "SUCCESS", "message": "DHCP config updated"}

        if cmd == "DHCP_STATUS":
            return await self.manager.status()

        if cmd == "DHCP_LIST_SUBNETS":
            try:
                subnets = await self.manager.list_subnets()
                return {"status": "SUCCESS", "subnets": subnets}
            except Exception as e:
                return {"status": "ERROR", "message": str(e)}

        if cmd == "DHCP_LIST_LEASES":
            subnet_id = data.get("subnet_id") or data.get("subnet")
            try:
                leases = await self.manager.list_leases(subnet_id=int(subnet_id) if subnet_id else None)
                return {"status": "SUCCESS", "leases": leases}
            except Exception as e:
                return {"status": "ERROR", "message": str(e)}

        if cmd == "DHCP_LIST_RES":
            try:
                reservations = await self.manager.list_reservations()
                return {"status": "SUCCESS", "reservations": reservations}
            except Exception as e:
                return {"status": "ERROR", "message": str(e)}

        if cmd == "DHCP_ADD_RES":
            ip        = data.get("ip")
            mac       = data.get("mac")
            hostname  = data.get("hostname", "")
            subnet_id = data.get("subnet_id")
            if not ip or not mac or not subnet_id:
                return {"status": "ERROR", "message": "ip, mac, and subnet_id are required"}
            try:
                return await self.manager.add_reservation(ip, mac, hostname, int(subnet_id))
            except Exception as e:
                return {"status": "ERROR", "message": str(e)}

        if cmd == "DHCP_UPDATE_RES":
            ip        = data.get("ip")
            mac       = data.get("mac")
            hostname  = data.get("hostname", "")
            subnet_id = data.get("subnet_id")
            if not ip or not subnet_id:
                return {"status": "ERROR", "message": "ip and subnet_id are required"}
            try:
                await self.manager.delete_reservation(ip=ip, subnet_id=int(subnet_id))
                return await self.manager.add_reservation(ip, mac, hostname, int(subnet_id))
            except Exception as e:
                return {"status": "ERROR", "message": str(e)}

        if cmd == "DHCP_DEL_RES":
            ip        = data.get("ip")
            mac       = data.get("mac")
            subnet_id = data.get("subnet_id")
            if not subnet_id:
                return {"status": "ERROR", "message": "subnet_id is required"}
            try:
                return await self.manager.delete_reservation(ip=ip, mac=mac, subnet_id=int(subnet_id))
            except Exception as e:
                return {"status": "ERROR", "message": str(e)}

        if cmd == "DHCP_SYNC":
            subnets      = data.get("subnets", [])
            reservations = data.get("reservations", [])
            try:
                return await self.manager.sync(subnets, reservations)
            except Exception as e:
                return {"status": "ERROR", "message": str(e)}

        logger.warning(f"Unknown command: {command_type}")
        return {"status": "ERROR", "message": f"Unknown command: {command_type}"}

    async def get_status(self) -> Dict[str, Any]:
        return await self.manager.status()

    def get_version(self) -> str:
        from pathlib import Path
        try:
            return (Path(__file__).parent.parent / "VERSION").read_text().strip()
        except Exception:
            return "unknown"
