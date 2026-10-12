"""
DNS Sniffer Module.
Provides live UDP DNS sniffing via Scapy and synthetic packet stream capabilities.
"""

import time
import threading
import logging
from typing import Callable, Optional, List, Dict, Any
from scapy.all import sniff, Packet
from packet_monitor.packet_parser import DNSPacketParser
from packet_monitor.feature_extractor import FeatureExtractor

logger = logging.getLogger("DNSShield.DNSSniffer")

class DNSSniffer:
    def __init__(self, interface: Optional[str] = None, filter_str: str = "udp port 53 or udp port 5353"):
        self.interface = interface
        self.filter_str = filter_str
        self.running = False
        self.thread: Optional[threading.Thread] = None
        self.callbacks: List[Callable[[Dict[str, Any], Dict[str, Any]], None]] = []

    def register_callback(self, callback: Callable[[Dict[str, Any], Dict[str, Any]], None]):
        """Registers a callback function taking (parsed_pkt, features)."""
        self.callbacks.append(callback)

    def _packet_handler(self, packet: Packet):
        parsed = DNSPacketParser.parse_scapy_packet(packet)
        if parsed:
            features = FeatureExtractor.extract_features(parsed)
            for cb in self.callbacks:
                try:
                    cb(parsed, features)
                except Exception as e:
                    logger.error(f"Error in sniffer callback: {e}")

    def start_live_sniff(self):
        """Starts live packet sniffing in background thread."""
        self.running = True
        self.thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self.thread.start()
        logger.info("Live DNS Sniffer started.")

    def _sniff_loop(self):
        try:
            sniff(
                iface=self.interface,
                filter=self.filter_str,
                prn=self._packet_handler,
                stop_filter=lambda p: not self.running,
                store=0
            )
        except Exception as e:
            logger.warning(f"Live sniffing encountered an issue (e.g. privileges/npcap): {e}. Falling back to active socket/API monitoring.")

    def process_raw_packet(self, packet: Packet) -> Optional[Dict[str, Any]]:
        """Directly processes a single Scapy packet (useful for testing and PCAP reading)."""
        parsed = DNSPacketParser.parse_scapy_packet(packet)
        if parsed:
            features = FeatureExtractor.extract_features(parsed)
            for cb in self.callbacks:
                cb(parsed, features)
            return features
        return None

    def stop(self):
        self.running = False
        logger.info("DNS Sniffer stopped.")
