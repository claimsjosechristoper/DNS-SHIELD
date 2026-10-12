"""
High-Performance Concurrent DNS Gateway Server.
Listens simultaneously on UDP and TCP sockets with IPv4 and IPv6 support.
Default port 5353 for development; port 53 for production Windows service.
"""

import socket
import struct
import threading
import logging
from concurrent.futures import ThreadPoolExecutor
from typing import Optional, Tuple
from gateway.policy import PolicyEngine
from gateway.config import GatewayConfig

logger = logging.getLogger("DNSShield.GatewayServer")


class DNSGatewayServer:
    def __init__(
        self,
        host: Optional[str] = None,
        port: Optional[int] = None,
        policy_engine: Optional[PolicyEngine] = None,
        db_path: Optional[str] = None,
        ipv6_host: Optional[str] = "::1"
    ):
        self.host = host or GatewayConfig.DNS_HOST
        self.port = port if port is not None else GatewayConfig.DNS_PORT
        self.ipv6_host = ipv6_host
        self.policy_engine = policy_engine or PolicyEngine(db_path=db_path)

        self.running = False
        self.udp_sock: Optional[socket.socket] = None
        self.tcp_sock: Optional[socket.socket] = None
        self.udp6_sock: Optional[socket.socket] = None
        self.tcp6_sock: Optional[socket.socket] = None

        self.threads = []
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

        opened_sockets = []
        try:
            # 1. Initialize IPv4 UDP Socket
            self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            opened_sockets.append(self.udp_sock)
            self.udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.udp_sock.bind((self.host, self.port))

            # 2. Initialize IPv4 TCP Socket (RFC 7766)
            self.tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            opened_sockets.append(self.tcp_sock)
            self.tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.tcp_sock.bind((self.host, self.port))
            self.tcp_sock.listen(50)
            self.tcp_sock.settimeout(1.0)

            # 3. Optional IPv6 UDP and TCP Sockets (Dual-Stack Localhost)
            if self.ipv6_host and socket.has_ipv6:
                try:
                    self.udp6_sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
                    opened_sockets.append(self.udp6_sock)
                    self.udp6_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    self.udp6_sock.bind((self.ipv6_host, self.port))

                    self.tcp6_sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                    opened_sockets.append(self.tcp6_sock)
                    self.tcp6_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    self.tcp6_sock.bind((self.ipv6_host, self.port))
                    self.tcp6_sock.listen(50)
                    self.tcp6_sock.settimeout(1.0)
                except Exception as ipv6_err:
                    logger.debug(f"IPv6 listener initialization bypassed: {ipv6_err}")
                    if self.udp6_sock:
                        try:
                            self.udp6_sock.close()
                        except Exception:
                            pass
                        self.udp6_sock = None
                    if self.tcp6_sock:
                        try:
                            self.tcp6_sock.close()
                        except Exception:
                            pass
                        self.tcp6_sock = None

            self.running = True

            # Launch listener worker loops
            self.threads = []
            t_udp = threading.Thread(target=self._udp_listen_loop, args=(self.udp_sock,), daemon=True, name="DNS-UDP4-Worker")
            t_udp.start()
            self.threads.append(t_udp)

            t_tcp = threading.Thread(target=self._tcp_listen_loop, args=(self.tcp_sock,), daemon=True, name="DNS-TCP4-Worker")
            t_tcp.start()
            self.threads.append(t_tcp)

            if self.udp6_sock:
                t_udp6 = threading.Thread(target=self._udp_listen_loop, args=(self.udp6_sock,), daemon=True, name="DNS-UDP6-Worker")
                t_udp6.start()
                self.threads.append(t_udp6)

            if self.tcp6_sock:
                t_tcp6 = threading.Thread(target=self._tcp_listen_loop, args=(self.tcp6_sock,), daemon=True, name="DNS-TCP6-Worker")
                t_tcp6.start()
                self.threads.append(t_tcp6)

        except Exception:
            self.running = False
            for s in opened_sockets:
                try:
                    s.close()
                except Exception:
                    pass
            raise

        logger.info(f"DNS Security Gateway active on UDP & TCP {self.host}:{self.port}")

    def _udp_listen_loop(self, sock: socket.socket):
        while self.running:
            try:
                data, addr = sock.recvfrom(4096)
                if not data:
                    continue
                self._workers.submit(self._handle_udp_packet, sock, data, addr)
            except Exception as e:
                if self.running:
                    logger.debug(f"UDP listener loop exception: {e}")

    def _handle_udp_packet(self, sock: socket.socket, data: bytes, addr: tuple):
        client_ip = addr[0]
        client_port = addr[1]
        try:
            resp_bytes, _ = self.policy_engine.process_query(data, client_ip, client_port)
            if resp_bytes and sock and self.running:
                sock.sendto(resp_bytes, addr)
        except Exception as e:
            logger.error(f"Error handling UDP query from {addr}: {e}")

    def _tcp_listen_loop(self, sock: socket.socket):
        while self.running:
            try:
                client_sock, addr = sock.accept()
                self._workers.submit(self._handle_tcp_client, client_sock, addr)
            except Exception as e:
                if self.running:
                    logger.debug(f"TCP listener loop exception: {e}")

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
        client_ip = addr[0]
        client_port = addr[1]
        sock.settimeout(5.0)
        try:
            while self.running:
                # Read 2-byte prefix length (RFC 7766)
                len_buf = self._recv_exact(sock, 2)
                if len_buf is None:
                    break
                msg_len = struct.unpack("!H", len_buf)[0]
                if msg_len == 0 or msg_len > 65535:
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
        for s in (self.udp_sock, self.tcp_sock, self.udp6_sock, self.tcp6_sock):
            if s:
                try:
                    s.close()
                except Exception:
                    pass
        self.udp_sock = None
        self.tcp_sock = None
        self.udp6_sock = None
        self.tcp6_sock = None

        for thread in self.threads:
            if thread and thread.is_alive():
                thread.join(timeout=1.0)
        self.threads.clear()

        self._workers.shutdown(wait=False, cancel_futures=True)
        logger.info("DNS Security Gateway stopped.")
