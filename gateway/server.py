"""
High-Performance Concurrent DNS Gateway Server.
Listens simultaneously on UDP and TCP sockets.
Default port 5353 for safe development; fully configurable for production deployment.
"""

import socket
import struct
import threading
import logging
from concurrent.futures import ThreadPoolExecutor
from typing import Optional
from gateway.policy import PolicyEngine
from gateway.config import GatewayConfig

logger = logging.getLogger("DNSShield.GatewayServer")

class DNSGatewayServer:
    def __init__(
        self,
        host: Optional[str] = None,
        port: Optional[int] = None,
        policy_engine: Optional[PolicyEngine] = None,
        db_path: Optional[str] = None
    ):
        self.host = host or GatewayConfig.DNS_HOST
        self.port = port if port is not None else GatewayConfig.DNS_PORT
        self.policy_engine = policy_engine or PolicyEngine(db_path=db_path)
        
        self.running = False
        self.udp_sock: Optional[socket.socket] = None
        self.tcp_sock: Optional[socket.socket] = None
        
        self.udp_thread: Optional[threading.Thread] = None
        self.tcp_thread: Optional[threading.Thread] = None
        self._max_workers = 64
        self._workers = ThreadPoolExecutor(max_workers=self._max_workers, thread_name_prefix="DNS-Request")

    def start(self):
        """Initializes and binds UDP and TCP listeners on configured host and port."""
        if self.running:
            return

        if getattr(self._workers, "_shutdown", False):
            self._workers = ThreadPoolExecutor(
                max_workers=self._max_workers, thread_name_prefix="DNS-Request"
            )
        try:
            # 1. Initialize UDP Socket
            self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.udp_sock.bind((self.host, self.port))

            # 2. Initialize TCP Socket (RFC 7766)
            self.tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.tcp_sock.bind((self.host, self.port))
            self.tcp_sock.listen(50)
            self.tcp_sock.settimeout(1.0)
            self.running = True

            self.udp_thread = threading.Thread(target=self._udp_listen_loop, daemon=True, name="DNS-UDP-Worker")
            self.udp_thread.start()
            self.tcp_thread = threading.Thread(target=self._tcp_listen_loop, daemon=True, name="DNS-TCP-Worker")
            self.tcp_thread.start()
        except Exception:
            self.stop()
            raise

        logger.info(f"DNS Security Gateway active on UDP & TCP {self.host}:{self.port}")

    def _udp_listen_loop(self):
        while self.running:
            try:
                data, addr = self.udp_sock.recvfrom(4096)
                if not data:
                    continue
                self._workers.submit(self._handle_udp_packet, data, addr)
            except Exception as e:
                if self.running:
                    logger.debug(f"UDP listener exception: {e}")

    def _handle_udp_packet(self, data: bytes, addr: tuple):
        client_ip, client_port = addr
        try:
            resp_bytes, _ = self.policy_engine.process_query(data, client_ip, client_port)
            if resp_bytes and self.udp_sock:
                self.udp_sock.sendto(resp_bytes, addr)
        except Exception as e:
            logger.error(f"Error handling UDP query from {addr}: {e}")

    def _tcp_listen_loop(self):
        while self.running:
            try:
                client_sock, addr = self.tcp_sock.accept()
                self._workers.submit(self._handle_tcp_client, client_sock, addr)
            except Exception as e:
                if self.running:
                    logger.debug(f"TCP listener exception: {e}")

    @staticmethod
    def _recv_exact(sock: socket.socket, size: int) -> Optional[bytes]:
        data = bytearray()
        while len(data) < size:
            chunk = sock.recv(size - len(data))
            if not chunk:
                return None
            data.extend(chunk)
        return bytes(data)

    def _handle_tcp_client(self, sock: socket.socket, addr: tuple):
        client_ip, client_port = addr
        sock.settimeout(5.0)
        try:
            while self.running:
                # Read 2-byte prefix length (RFC 7766)
                len_buf = self._recv_exact(sock, 2)
                if len_buf is None:
                    break
                msg_len = struct.unpack("!H", len_buf)[0]
                if msg_len == 0:
                    break
                
                # Read entire DNS message
                data = self._recv_exact(sock, msg_len)
                if data is None:
                    break

                resp_bytes, _ = self.policy_engine.process_query(data, client_ip, client_port)
                if resp_bytes:
                    prefix = struct.pack("!H", len(resp_bytes))
                    sock.sendall(prefix + resp_bytes)
        except Exception as e:
            logger.debug(f"TCP client {addr} connection terminated: {e}")
        finally:
            sock.close()

    def stop(self):
        """Gracefully shuts down listeners and releases bound ports."""
        self.running = False
        if self.udp_sock:
            try:
                self.udp_sock.close()
            except Exception:
                pass
        if self.tcp_sock:
            try:
                self.tcp_sock.close()
            except Exception:
                pass
        for thread in (self.udp_thread, self.tcp_thread):
            if thread and thread.is_alive():
                thread.join(timeout=2.0)
        self._workers.shutdown(wait=False, cancel_futures=True)
        logger.info("DNS Security Gateway stopped.")
