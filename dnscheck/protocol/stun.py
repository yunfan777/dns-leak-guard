"""
Pure-Python RFC 5389 STUN (Session Traversal Utilities for NAT) Binding Request client.
Used to detect real UDP public IP (WebRTC srflx candidate equivalent) and local interface IP
even in CLI mode without a browser.
"""

from __future__ import annotations

import os
import socket
import struct
import time
from dataclasses import dataclass
from typing import List, Optional, Tuple

STUN_MAGIC_COOKIE = 0x2112A442
STUN_BINDING_REQUEST = 0x0001
STUN_BINDING_RESPONSE = 0x0101

ATTR_MAPPED_ADDRESS = 0x0001
ATTR_XOR_MAPPED_ADDRESS = 0x0020
ATTR_XOR_MAPPED_ADDRESS_LEGACY = 0x8020

DEFAULT_STUN_SERVERS: List[Tuple[str, str, int, str]] = [
    ("腾讯 STUN (国内)", "stun.qq.com", 3478, "CN"),
    ("小米 STUN (国内)", "stun.miwifi.com", 3478, "CN"),
    ("Cloudflare STUN (海外)", "stun.cloudflare.com", 3478, "GLOBAL"),
    ("Google STUN (海外)", "stun.l.google.com", 19302, "GLOBAL"),
]


@dataclass
class STUNProbeResult:
    """Result of a single STUN Binding Request probe."""
    provider_name: str
    server_host: str
    server_port: int
    region: str
    success: bool
    latency_ms: float
    mapped_ip: Optional[str] = None
    mapped_port: Optional[int] = None
    local_ip: Optional[str] = None
    ip_version: int = 4
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "provider_name": self.provider_name,
            "server": f"{self.server_host}:{self.server_port}",
            "region": self.region,
            "success": self.success,
            "latency_ms": round(self.latency_ms, 2),
            "mapped_ip": self.mapped_ip,
            "mapped_port": self.mapped_port,
            "local_ip": self.local_ip,
            "ip_version": self.ip_version,
            "error": self.error,
        }


def build_stun_binding_request(txid: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    """
    Build a 20-byte RFC 5389 STUN Binding Request header.
    Returns (txid_12_bytes, packet_20_bytes).
    """
    if txid is None:
        txid = os.urandom(12)
    if len(txid) != 12:
        raise ValueError("STUN transaction ID must be exactly 12 bytes")

    header = struct.pack("!HHI", STUN_BINDING_REQUEST, 0, STUN_MAGIC_COOKIE) + txid
    return txid, header


def parse_stun_binding_response(data: bytes, expected_txid: Optional[bytes] = None) -> Tuple[str, int]:
    """
    Parse an RFC 5389 STUN Binding Response packet and extract (public_ip, public_port).
    Supports both XOR-MAPPED-ADDRESS (0x0020 / 0x8020) and MAPPED-ADDRESS (0x0001).
    """
    if len(data) < 20:
        raise ValueError(f"STUN response too short ({len(data)} bytes)")

    msg_type, msg_len, cookie = struct.unpack("!HHI", data[:8])
    txid = data[8:20]

    if msg_type != STUN_BINDING_RESPONSE:
        raise ValueError(f"Unexpected STUN message type: 0x{msg_type:04x}")
    if expected_txid and txid != expected_txid:
        raise ValueError("STUN Transaction ID mismatch")

    offset = 20
    end = min(len(data), 20 + msg_len)
    mapped_fallback: Optional[Tuple[str, int]] = None

    while offset + 4 <= end:
        attr_type, attr_len = struct.unpack("!HH", data[offset : offset + 4])
        offset += 4
        attr_val = data[offset : offset + attr_len]
        # STUN attributes are padded to 4-byte boundaries
        padded_len = (attr_len + 3) & ~3
        offset += padded_len

        if attr_type in (ATTR_XOR_MAPPED_ADDRESS, ATTR_XOR_MAPPED_ADDRESS_LEGACY) and len(attr_val) >= 8:
            _, family, xport = struct.unpack("!BBH", attr_val[:4])
            port = xport ^ (STUN_MAGIC_COOKIE >> 16)
            if family == 0x01 and len(attr_val) >= 8:
                # IPv4: XOR 4 bytes with magic cookie
                (xaddr,) = struct.unpack("!I", attr_val[4:8])
                addr_int = xaddr ^ STUN_MAGIC_COOKIE
                ip_str = socket.inet_ntop(socket.AF_INET, struct.pack("!I", addr_int))
                return ip_str, port
            elif family == 0x02 and len(attr_val) >= 20:
                # IPv6: XOR 16 bytes with (magic_cookie_4B + txid_12B)
                xor_key = struct.pack("!I", STUN_MAGIC_COOKIE) + txid
                xaddr_bytes = attr_val[4:20]
                raw_ipv6 = bytes(a ^ b for a, b in zip(xaddr_bytes, xor_key))
                ip_str = socket.inet_ntop(socket.AF_INET6, raw_ipv6)
                return ip_str, port

        elif attr_type == ATTR_MAPPED_ADDRESS and len(attr_val) >= 8:
            _, family, port = struct.unpack("!BBH", attr_val[:4])
            if family == 0x01 and len(attr_val) >= 8:
                ip_str = socket.inet_ntop(socket.AF_INET, attr_val[4:8])
                mapped_fallback = (ip_str, port)
            elif family == 0x02 and len(attr_val) >= 20:
                ip_str = socket.inet_ntop(socket.AF_INET6, attr_val[4:20])
                mapped_fallback = (ip_str, port)

    if mapped_fallback:
        return mapped_fallback

    raise ValueError("No MAPPED-ADDRESS or XOR-MAPPED-ADDRESS found in STUN response")


def probe_stun_server(
    provider_name: str,
    host: str,
    port: int = 3478,
    region: str = "GLOBAL",
    timeout: float = 2.0,
    ipv6: bool = False,
) -> STUNProbeResult:
    """Perform a UDP STUN Binding Request against a STUN server."""
    family = socket.AF_INET6 if ipv6 else socket.AF_INET
    txid, req_pkt = build_stun_binding_request()
    start = time.perf_counter()
    try:
        infos = socket.getaddrinfo(host, port, family, socket.SOCK_DGRAM)
        if not infos:
            raise OSError(f"Cannot resolve STUN server {host}")
        target_addr = infos[0][4]
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.connect(target_addr)
            local_ip = sock.getsockname()[0]
            sock.send(req_pkt)
            resp_data = sock.recv(1024)
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        mapped_ip, mapped_port = parse_stun_binding_response(resp_data, expected_txid=txid)
        return STUNProbeResult(
            provider_name=provider_name,
            server_host=host,
            server_port=port,
            region=region,
            success=True,
            latency_ms=elapsed_ms,
            mapped_ip=mapped_ip,
            mapped_port=mapped_port,
            local_ip=local_ip,
            ip_version=6 if ipv6 else 4,
        )
    except Exception as exc:
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        return STUNProbeResult(
            provider_name=provider_name,
            server_host=host,
            server_port=port,
            region=region,
            success=False,
            latency_ms=elapsed_ms,
            ip_version=6 if ipv6 else 4,
            error=str(exc),
        )
