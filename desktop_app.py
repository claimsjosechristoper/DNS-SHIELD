"""
DNS Security Gateway Desktop Launcher.
Launches the concurrent UDP/TCP DNS Security Gateway, FastAPI Administrative Web Server,
and opens the SOC Management Dashboard in default browser.
"""

import sys
import os
import uvicorn
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("DNSShield.DesktopApp")

from gateway.config import GatewayConfig
from gateway.server import DNSGatewayServer
from gateway.db import init_db
from api.main import app, policy_engine

def main():
    logger.info("Initializing DNS Security Gateway.")

    init_db(GatewayConfig.DB_PATH)

    # Start DNS Gateway Server
    dns_server = DNSGatewayServer(
        host=GatewayConfig.DNS_HOST,
        port=GatewayConfig.DNS_PORT,
        policy_engine=policy_engine,
        db_path=GatewayConfig.DB_PATH
    )
    dns_server.start()

    # Start FastAPI Application
    uvicorn.run(app, host=GatewayConfig.API_HOST, port=GatewayConfig.API_PORT, log_level="info")

if __name__ == "__main__":
    main()
