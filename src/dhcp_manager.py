import asyncio
import logging
from typing import Any, Dict, List, Optional
import httpx

logger = logging.getLogger("DHCPManager")


class DHCPManager:
    """Kea DHCP4 control-agent client. Sends JSON commands to the Kea Control Agent REST API."""

    def __init__(self, control_url: str = "http://localhost:8000"):
        self.url = control_url.rstrip("/")

    async def _cmd(self, command: str, service: str = "dhcp4", arguments: Dict = None) -> Dict[str, Any]:
        """POST a single command to the Kea control agent and return the first result item."""
        body: Dict[str, Any] = {"command": command, "service": [service]}
        if arguments is not None:
            body["arguments"] = arguments
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.post(self.url, json=body)
            r.raise_for_status()
            data = r.json()
            # Kea returns a list of per-service results
            result = data[0] if isinstance(data, list) else data
            if result.get("result", 0) != 0:
                raise RuntimeError(result.get("text", "Kea error"))
            return result.get("arguments", {})

    async def list_subnets(self) -> List[Dict]:
        args = await self._cmd("subnet4-list")
        return args.get("subnets", [])

    async def list_leases(self, subnet_id: Optional[int] = None) -> List[Dict]:
        arguments = {"subnet-id": subnet_id} if subnet_id else {}
        args = await self._cmd("lease4-get-all", arguments=arguments if arguments else None)
        leases = args.get("leases", [])
        # Normalize to flat records
        out = []
        for lse in leases:
            out.append({
                "ip":         lse.get("ip-address", ""),
                "mac":        lse.get("hw-address", ""),
                "hostname":   lse.get("hostname", ""),
                "subnet_id":  lse.get("subnet-id"),
                "state":      lse.get("state", 0),
                "valid_lft":  lse.get("valid-lft", 0),
                "expire":     lse.get("expire", 0),
            })
        return out

    async def list_reservations(self) -> List[Dict]:
        subnets = await self.list_subnets()
        all_res = []
        for sn in subnets:
            sid = sn.get("id")
            try:
                args = await self._cmd("reservation-get-all", arguments={"subnet-id": sid})
                for res in args.get("hosts", []):
                    all_res.append({
                        "ip":        res.get("ip-address", ""),
                        "mac":       res.get("hw-address", ""),
                        "hostname":  res.get("hostname", ""),
                        "subnet_id": sid,
                        "subnet":    sn.get("subnet", ""),
                    })
            except Exception as e:
                logger.debug(f"reservation-get-all failed for subnet {sid}: {e}")
        return all_res

    async def add_reservation(self, ip: str, mac: str, hostname: str, subnet_id: int) -> Dict:
        await self._cmd("reservation-add", arguments={
            "reservation": {
                "subnet-id":   subnet_id,
                "hw-address":  mac,
                "ip-address":  ip,
                "hostname":    hostname,
            }
        })
        return {"status": "SUCCESS", "message": "Reservation added"}

    async def delete_reservation(self, ip: str = None, mac: str = None, subnet_id: int = None) -> Dict:
        args: Dict[str, Any] = {"subnet-id": subnet_id}
        if ip:
            args["ip-address"] = ip
        elif mac:
            args["identifier-type"] = "hw-address"
            args["identifier"] = mac
        await self._cmd("reservation-del", arguments=args)
        return {"status": "SUCCESS", "message": "Reservation deleted"}

    async def sync(self, subnets: List[Dict], reservations: List[Dict]) -> Dict:
        """Bulk apply subnets (best-effort) and reservations from NetBox."""
        added, skipped = 0, 0
        existing = {r["ip"]: r for r in await self.list_reservations()}
        for res in reservations:
            if res.get("ip") in existing:
                skipped += 1
                continue
            subnet_id = res.get("subnet_id")
            if not subnet_id:
                skipped += 1
                continue
            try:
                await self.add_reservation(res["ip"], res["mac"], res.get("hostname", ""), subnet_id)
                added += 1
            except Exception as e:
                logger.warning(f"Sync reservation failed for {res.get('ip')}: {e}")
                skipped += 1
        return {"status": "SUCCESS", "added": added, "skipped": skipped}

    async def status(self) -> Dict:
        try:
            await self._cmd("status-get")
            return {"status": "HEALTHY", "url": self.url}
        except Exception as e:
            return {"status": "UNHEALTHY", "error": str(e), "url": self.url}
