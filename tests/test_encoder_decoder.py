"""
Tests for DNS Simulator Encoder, Decoder, and Localhost Server.
"""

import time
import pytest
from dns_simulator.encoder import DNSEncoder
from dns_simulator.decoder import DNSDecoder
from dns_simulator.lab_dns_server import LabDNSServer
from dns_simulator.client import LabDNSClient
from dns_simulator.synthetic_data import SyntheticDataGenerator

def test_encoding_decoding_base32():
    payload = "DNS-SHIELD-LAB-TEST-123"
    session_id, queries, meta = DNSEncoder.create_tunnel_queries(payload, encoding_method="base32")
    
    decoder = DNSDecoder()
    result = None
    for q in queries:
        result = decoder.process_query(q, encoding_method="base32")

    assert result["status"] == "complete"
    assert result["reconstructed_payload"] == payload

def test_encoding_decoding_base64():
    payload = "SECRET-LAB-DATA-999"
    session_id, queries, meta = DNSEncoder.create_tunnel_queries(payload, encoding_method="base64")
    
    decoder = DNSDecoder()
    result = None
    for q in queries:
        result = decoder.process_query(q, encoding_method="base64")

    assert result["status"] == "complete"
    assert result["reconstructed_payload"] == payload

def test_encoding_decoding_hex():
    payload = "HEX-SIMULATION-PAYLOAD"
    session_id, queries, meta = DNSEncoder.create_tunnel_queries(payload, encoding_method="hex")
    
    decoder = DNSDecoder()
    result = None
    for q in queries:
        result = decoder.process_query(q, encoding_method="hex")

    assert result["status"] == "complete"
    assert result["reconstructed_payload"] == payload

def test_lab_dns_server_and_client():
    server = LabDNSServer(host="127.0.0.1", port=5354)
    server.start()
    time.sleep(0.2)

    client = LabDNSClient(server_host="127.0.0.1", server_port=5354)
    test_payload = "LIVE-SERVER-CLIENT-TEST-PAYLOAD"
    res = client.simulate_tunnel_session(test_payload, encoding_method="base32")

    time.sleep(0.2)
    sessions = server.get_sessions()
    server.stop()

    assert res["session_id"] in sessions
    session_info = sessions[res["session_id"]]
    assert session_info["is_complete"] is True
    assert session_info["reconstructed_payload"] == test_payload
