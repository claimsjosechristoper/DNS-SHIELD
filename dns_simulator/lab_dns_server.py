"""
Safe Localhost Laboratory DNS Server.
Listens strictly on loopback (127.0.0.1) for educational DNS tunnel queries.
Reconstructs synthetic payloads and records active sessions in memory.
"""

import socket
import threading
import logging
from typing import Dict, Any, List, Optional
from dnslib import DNSRecord, QTYPE, RR, A, TXT
from dns_simulator.decoder import DNSDecoder

logger = logging.getLogger("DNSShield.LabDNSServer")

class LabDNSServer:
    def __init__(self, host: str = "127.0.0.1", port: int = 5353):
        # Restrict strictly to loopback or specified private test host
        if host not in ("127.0.0.1", "localhost"):
            logger.warning(f"Restricting server host '{host}' to localhost loopback interface '127.0.0.1' for safety.")
            host = "127.0.0.1"

        self.host = host
        self.port = port
        self.running = False
        self.sock: Optional[socket.socket] = None
        self.thread: Optional[threading.Thread] = None
        self.decoder = DNSDecoder()
        self.event_log: List[Dict[str, Any]] = []

    def start(self):
        """Starts UDP DNS server in a background thread."""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))
        self.running = True
        
        self.thread = threading.Thread(target=self._listen_loop, daemon=True)
        self.thread.start()
        logger.info(f"Lab DNS Server listening on UDP {self.host}:{self.port}")

    def _listen_loop(self):
        while self.running:
            try:
                data, addr = self.sock.recvfrom(4096)
                if not data:
                    continue
                reply_data = self.handle_dns_request(data, addr)
                if reply_data:
                    self.sock.sendto(reply_data, addr)
            except Exception as e:
                if self.running:
                    logger.debug(f"Error handling DNS request: {e}")

    def handle_dns_request(self, data: bytes, addr: tuple) -> bytes:
        try:
            request = DNSRecord.parse(data)
            qname = str(request.q.qname).rstrip('.')
            qtype = QTYPE[request.q.qtype]

            # Process query through decoder
            process_res = self.decoder.process_query(qname)

            event = {
                "source_ip": addr[0],
                "source_port": addr[1],
                "qname": qname,
                "qtype": qtype,
                "decoder_result": process_res
            }
            self.event_log.append(event)
            if len(self.event_log) > 1000:
                self.event_log.pop(0)

            # Build DNS Response
            reply = request.reply()
            if qtype == "A":
                reply.add_answer(RR(request.q.qname, QTYPE.A, rdata=A("127.0.0.1"), ttl=60))
            elif qtype == "TXT":
                txt_resp = f"ACK: session={process_res.get('session_id', 'none')}"
                reply.add_answer(RR(request.q.qname, QTYPE.TXT, rdata=TXT(txt_resp), ttl=60))
            else:
                reply.add_answer(RR(request.q.qname, QTYPE.A, rdata=A("127.0.0.1"), ttl=60))

            return reply.pack()
        except Exception as e:
            logger.error(f"Failed to parse DNS query from {addr}: {e}")
            return b""

    def stop(self):
        self.running = False
        if self.sock:
            self.sock.close()
        logger.info("Lab DNS Server stopped.")

    def get_sessions(self) -> Dict[str, Any]:
        """Returns all session states recorded by the decoder."""
        return self.decoder.sessions
