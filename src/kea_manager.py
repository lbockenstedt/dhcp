import json
import logging
import requests
import ipaddress

logger = logging.getLogger("KeaManager")


class KeaManager:
    """
    Manages Kea DHCP4 via the Kea Control Agent REST API.
    Default CA port is 8001 (we use 8001 to avoid conflict with the LM hub on 8000).
    """

    def __init__(self, ca_url: str = "http://localhost:8001"):
        self.ca_url = ca_url.rstrip("/")

    # ── Kea Control Agent RPC ─────────────────────────────────────────

    def _rpc(self, service: str, command: str, args: dict = None) -> dict:
        payload = {"command": command, "service": [service]}
        if args is not None:
            payload["arguments"] = args
        try:
            r = requests.post(self.ca_url, json=payload, timeout=10)
            r.raise_for_status()
            result = r.json()
            if isinstance(result, list):
                result = result[0]
            if result.get("result", 0) != 0:
                raise RuntimeError(result.get("text", "Kea error"))
            return result.get("arguments", {})
        except requests.RequestException as e:
            raise RuntimeError(f"Kea CA unreachable: {e}")

    # ── Subnet (scope) management ─────────────────────────────────────

    def list_subnets(self) -> list:
        try:
            data = self._rpc("dhcp4", "subnet4-list")
            return data.get("subnets", [])
        except Exception as e:
            logger.error("list_subnets failed: %s", e)
            return []

    def get_config(self) -> dict:
        return self._rpc("dhcp4", "config-get").get("Dhcp4", {})

    def _set_config(self, dhcp4_config: dict):
        self._rpc("dhcp4", "config-set", {"Dhcp4": dhcp4_config})
        self._rpc("dhcp4", "config-write", {})

    def sync(self, subnets: list, reservations: list) -> dict:
        """
        Full sync: replace all subnets and reservations.

        subnets:      [{subnet, gateway, dns_servers, pools: [{start, end}], description}]
        reservations: [{ip, mac, hostname, subnet}]
        """
        try:
            cfg = self.get_config()
        except Exception as e:
            return {"status": "ERROR", "message": f"Cannot read Kea config: {e}"}

        kea_subnets = []
        for idx, s in enumerate(subnets, start=1):
            subnet_str = s.get("subnet", "")
            try:
                net = ipaddress.ip_network(subnet_str, strict=False)
            except ValueError:
                logger.warning("Invalid subnet %s — skipping", subnet_str)
                continue

            pools = [
                {"pool": f"{p['start']} - {p['end']}"}
                for p in s.get("pools", [])
                if p.get("start") and p.get("end")
            ]
            if not pools:
                # Default pool: .10 → .254
                first = int(net.network_address) + 10
                last  = int(net.broadcast_address) - 1
                pools = [{"pool": f"{ipaddress.ip_address(first)} - {ipaddress.ip_address(last)}"}]

            kea_subnet = {
                "id":     idx,
                "subnet": str(net),
                "pools":  pools,
                "option-data": [],
            }
            if s.get("gateway"):
                kea_subnet["option-data"].append(
                    {"name": "routers", "data": s["gateway"]}
                )
            dns = s.get("dns_servers", [])
            if dns:
                kea_subnet["option-data"].append(
                    {"name": "domain-name-servers", "data": ", ".join(dns)}
                )

            # Attach reservations that belong to this subnet. Guard ip/mac with
            # .get and wrap ip_network in try — one malformed reservation (missing
            # or invalid ip) must be skipped, not KeyError/ValueError out of the
            # whole sync (which would then config-set the subnet with NO reservations).
            subnet_res = []
            for r in reservations:
                ip, mac = r.get("ip"), r.get("mac")
                if not ip or not mac:
                    continue
                try:
                    in_subnet = (r.get("subnet") == subnet_str
                                 or net.overlaps(ipaddress.ip_network(f"{ip}/32")))
                except ValueError:
                    continue  # malformed reservation IP
                if in_subnet:
                    subnet_res.append({
                        "ip-address": ip,
                        "hw-address": mac.lower().replace("-", ":"),
                        "hostname": r.get("hostname", ""),
                    })
            if subnet_res:
                kea_subnet["reservations"] = subnet_res

            kea_subnets.append(kea_subnet)

        cfg["subnet4"] = kea_subnets
        try:
            self._set_config(cfg)
        except Exception as e:
            return {"status": "ERROR", "message": str(e)}

        logger.info("Synced %d subnets, %d reservations to Kea", len(kea_subnets), len(reservations))
        return {"status": "SUCCESS", "subnets": len(kea_subnets), "reservations": len(reservations)}

    # ── Lease queries ─────────────────────────────────────────────────

    def list_leases(self, subnet: str = None) -> list:
        try:
            args = {"subnet-id": 0}  # 0 = all
            if subnet:
                for s in self.list_subnets():
                    if s.get("subnet") == subnet:
                        args["subnet-id"] = s["id"]
                        break
            data = self._rpc("dhcp4", "lease4-get-all", args)
            return data.get("leases", [])
        except Exception as e:
            logger.error("list_leases failed: %s", e)
            return []

    # ── Manual reservation CRUD ───────────────────────────────────────

    def add_reservation(self, subnet_id: int, ip: str, mac: str, hostname: str = "") -> dict:
        cfg = self.get_config()
        for sub in cfg.get("subnet4", []):
            if sub["id"] == subnet_id:
                sub.setdefault("reservations", [])
                sub["reservations"].append({
                    "ip-address": ip,
                    "hw-address": mac.lower().replace("-", ":"),
                    "hostname":   hostname,
                })
                break
        else:
            return {"status": "ERROR", "message": f"Subnet {subnet_id} not found"}
        self._set_config(cfg)
        return {"status": "SUCCESS"}

    def list_reservations(self) -> list:
        """Return all static reservations across subnets."""
        out = []
        try:
            cfg = self.get_config()
        except Exception as e:
            logger.error("list_reservations failed: %s", e)
            return out
        for sub in cfg.get("subnet4", []):
            for r in sub.get("reservations", []):
                out.append({
                    "ip":        r.get("ip-address", ""),
                    "mac":       r.get("hw-address", ""),
                    "hostname":  r.get("hostname", ""),
                    "subnet_id": sub.get("id"),
                    "subnet":    sub.get("subnet", ""),
                })
        return out

    def update_reservation(self, old_ip: str, subnet_id: int, ip: str,
                           mac: str, hostname: str = "") -> dict:
        """Update a reservation by IP. Implemented as delete-then-add since Kea
        reservations live in the subnet config block and may move between
        subnets when the IP changes."""
        if not all([subnet_id, ip, mac]):
            return {"status": "ERROR", "message": "subnet_id, ip, and mac are required"}
        # Remove the old reservation (by old IP) from any subnet.
        cfg = self.get_config()
        for sub in cfg.get("subnet4", []):
            sub["reservations"] = [
                r for r in sub.get("reservations", [])
                if r.get("ip-address") != old_ip
            ]
        try:
            self._set_config(cfg)
        except Exception as e:
            return {"status": "ERROR", "message": str(e)}
        return self.add_reservation(int(subnet_id), ip, mac, hostname)

    def delete_reservation(self, ip: str) -> dict:
        cfg = self.get_config()
        for sub in cfg.get("subnet4", []):
            sub["reservations"] = [
                r for r in sub.get("reservations", [])
                if r.get("ip-address") != ip
            ]
        self._set_config(cfg)
        return {"status": "SUCCESS"}

    def status(self) -> dict:
        try:
            self._rpc("dhcp4", "version-get")
            running = True
        except Exception:
            running = False
        return {
            "running":      running,
            "subnet_count": len(self.list_subnets()) if running else 0,
            "ca_url":       self.ca_url,
        }
