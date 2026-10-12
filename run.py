"""
DNS Security Gateway Master Launcher.
Launches the concurrent UDP/TCP DNS Gateway, FastAPI Administrative API,
and optional live demonstration traffic generator.
"""

import sys
import time
import argparse
import threading
import uvicorn
import logging
from dnslib import DNSRecord

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("DNSShield.Runner")

from gateway.config import GatewayConfig
from gateway.server import DNSGatewayServer
from gateway.db import init_db
from api.main import app, policy_engine

def run_demo_traffic_loop():
    """
    Simulates representative enterprise DNS traffic:
    Allowed corporate queries, known malware/phishing threats, admin policy blocks,
    and allowlist exceptions to showcase deterministic ALLOW/BLOCK decisions in real time.
    """
    logger.info("Demo Mode Active: Generating realistic DNS traffic stream (ALLOW vs BLOCK)...")
    time.sleep(2.0)

    test_scenarios = [
        # (domain, qtype, client_ip, expected_decision)
        ("google.com", "A", "192.168.1.102", "ALLOW"),
        ("github.com", "A", "192.168.1.105", "ALLOW"),
        ("malware-dropper.test", "A", "192.168.1.110", "BLOCK - MALWARE"),
        ("wikipedia.org", "A", "192.168.1.102", "ALLOW"),
        ("login-microsoft-secure.test", "A", "192.168.1.115", "BLOCK - PHISHING"),
        ("internal-prohibited.local", "A", "192.168.1.120", "BLOCK - ADMIN POLICY"),
        ("cloudflare.com", "A", "192.168.1.105", "ALLOW"),
        ("c2-beacon.test", "A", "192.168.1.130", "BLOCK - C2"),
        ("trusted-partner.example.com", "A", "192.168.1.105", "ALLOW - ALLOWLIST"),
        ("example.com", "ANY", "192.168.1.140", "BLOCK - RECORD TYPE ANY"),
        ("sub.internal-prohibited.local", "A", "192.168.1.120", "BLOCK - SUBDOMAIN POLICY"),
        ("aws.amazon.com", "A", "192.168.1.102", "ALLOW"),
    ]

    while True:
        for domain, qtype, client_ip, label in test_scenarios:
            try:
                # Generate real DNS query bytes
                req = DNSRecord.question(domain, qtype)
                raw_bytes = req.pack()
                # Process through policy engine
                policy_engine.process_query(raw_bytes, client_ip, 54321)
                logger.info(f"[DEMO TRAFFIC] {client_ip} -> {domain} ({qtype}) => {label}")
            except Exception as e:
                logger.debug(f"Demo query error: {e}")
            time.sleep(1.0)
        time.sleep(2.0)

def main():
    parser = argparse.ArgumentParser(description="DNS Security Gateway Runner")
    parser.add_argument("--demo", action="store_true", help="Launch live traffic simulation generating real ALLOW and BLOCK events")
    parser.add_argument("--server", action="store_true", help="Launch DNS Gateway server and FastAPI admin API")
    parser.add_argument("--dns-host", type=str, default=GatewayConfig.DNS_HOST, help="DNS listener host (default: 127.0.0.1)")
    parser.add_argument("--dns-port", type=int, default=GatewayConfig.DNS_PORT, help="DNS listener port (default: 5353)")
    parser.add_argument("--api-host", type=str, default=GatewayConfig.API_HOST, help="API server host (default: 127.0.0.1)")
    parser.add_argument("--api-port", type=int, default=GatewayConfig.API_PORT, help="API server port (default: 8000)")
    parser.add_argument("--pcap", type=str, help="Analyze offline PCAP file")

    args = parser.parse_args()

    # Initialize DB
    init_db(GatewayConfig.DB_PATH)

    if args.pcap:
        logger.info(f"Running PCAP analysis on: {args.pcap}")
        from forensics.pcap_analyzer import PCAPAnalyzer
        analyzer = PCAPAnalyzer()
        report = analyzer.analyze_pcap_file(args.pcap)
        import json
        print(json.dumps(report, indent=2))
        sys.exit(0)

    # Initialize and start DNS Gateway Server on UDP & TCP
    dns_server = DNSGatewayServer(
        host=args.dns_host,
        port=args.dns_port,
        policy_engine=policy_engine,
        db_path=GatewayConfig.DB_PATH
    )
    dns_server.start()

    logger.info("================================================================")
    logger.info("  DNS SECURITY GATEWAY INITIALIZED")
    logger.info(f"  DNS Gateway Listener: UDP & TCP {args.dns_host}:{args.dns_port}")
    logger.info(f"  Administrative Dashboard: http://{args.api_host}:{args.api_port}/")
    logger.info("================================================================")

    if args.demo:
        demo_thread = threading.Thread(target=run_demo_traffic_loop, daemon=True)
        demo_thread.start()

    # Run FastAPI web server
    uvicorn.run(app, host=args.api_host, port=args.api_port, log_level="info")

if __name__ == "__main__":
    main()
