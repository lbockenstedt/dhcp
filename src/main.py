import asyncio
import logging
import argparse
import os

try:
    from core.src.messaging.control_plane import BaseControlPlane
except ImportError:
    from messaging.control_plane import BaseControlPlane

from src.dhcp_spoke import DHCPSpoke

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("DHCPControlPlane")


class DHCPControlPlane(BaseControlPlane):
    def get_service_name(self) -> str:
        return "lm-dhcp"

    def __init__(self, spoke_id: str, secret: str, hub_secret: str = None, hub_url: str = None):
        super().__init__(spoke_id, secret, hub_secret, hub_url)
        self.module_type = "dhcp"
        self.config = {
            "KEA_URL": os.getenv("KEA_URL", "http://localhost:8000"),
        }

    async def run(self):
        logger.info(f"Starting DHCP spoke → {self.hub_url}")
        dhcp_spoke = DHCPSpoke(self.spoke_id, self.config)
        self.register_module("dhcp", dhcp_spoke)
        await super().run()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--id",         required=True)
    parser.add_argument("--secret",     required=True)
    parser.add_argument("--hub-secret", nargs='?', default="", const="")
    parser.add_argument("--hub",        required=True)
    args = parser.parse_args()

    cp = DHCPControlPlane(args.id, args.secret, args.hub_secret, args.hub)
    asyncio.run(cp.run())
