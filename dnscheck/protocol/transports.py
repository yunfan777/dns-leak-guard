"""
Multi-protocol DNS transport layer:
- UDP (Port 53, RFC 1035)
- TCP (Port 53, RFC 1035 / RFC 7766)
- DoT / DNS over TLS (Port 853, RFC 7858)
- DoH / DNS over HTTPS (Port 443, RFC 8484 wire format)
- System stub resolver (getaddrinfo)
"""

from __future__ import annotations

import base64
import socket
import ssl
import struct
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import List, Optional

from dnscheck.protocol.dns_packet import (
    CLASS_IN,
    DNSPacket,
    TYPE_A,
    TYPE_AAAA,
    TYPE_NAMES,
    build_dns_query,
    parse_dns_response,
)


@dataclass
class DNSQueryResult:
    """Unified result of a DNS query over any transport protocol."""
    server: str
    protocol: str  # "udp", "tcp", "dot", "doh", "system"
    domain: str
    qtype: str
    success: bool
    latency_ms: float
    rcode: str = "NOERROR"
    answers: List[str] = field(default_factory=list)
    ttl: Optional[int] = None
    packet: Optional[DNSPacket] = None
    error: Optional[str] = None
    edns_ecs: Optional[dict] = None
    dnssec_ad: bool = False
    server_name: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "server": self.server,
            "server_name": self.server_name or self.server,
            "protocol": self.protocol.upper(),
            "domain": self.domain,
            "qtype": self.qtype,
            "success": self.success,
            "latency_ms": round(self.latency_ms, 2),
            "rcode": self.rcode,
            "answers": self.answers,
            "ttl": self.ttl,
            "dnssec_ad": self.dnssec_ad,
            "edns_ecs": self.edns_ecs,
            "error": self.error,
        }


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    """Read exactly n bytes from a stream socket."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Socket closed before receiving full DNS frame")
        buf.extend(chunk)
    return bytes(buf)


def query_udp(
    server: str,
    domain: str,
    qtype: int = TYPE_A,
    qclass: int = CLASS_IN,
    port: int = 53,
    timeout: float = 2.5,
    use_edns: bool = True,
    edns_do: bool = False,
    ecs_ip: Optional[str] = None,
    ecs_prefix: Optional[int] = None,
    server_name: Optional[str] = None,
) -> DNSQueryResult:
    """Send a raw DNS query over UDP (port 53)."""
    qtype_str = TYPE_NAMES.get(qtype, str(qtype))
    txid, payload = build_dns_query(
        domain=domain,
        qtype=qtype,
        qclass=qclass,
        use_edns=use_edns,
        edns_do=edns_do,
        ecs_ip=ecs_ip,
        ecs_prefix=ecs_prefix,
    )
    family = socket.AF_INET6 if ":" in server else socket.AF_INET
    start = time.perf_counter()
    try:
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(payload, (server, port))
            # Wait for matching transaction ID (or first valid response)
            raw_resp, _ = sock.recvfrom(4096)
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        pkt = parse_dns_response(raw_resp)
        answers = [r.rdata for r in pkt.answers]
        ttl = pkt.answers[0].ttl if pkt.answers else None
        return DNSQueryResult(
            server=server,
            server_name=server_name,
            protocol="udp",
            domain=domain,
            qtype=qtype_str,
            success=(pkt.rcode == 0),
            latency_ms=elapsed_ms,
            rcode=pkt.rcode_name,
            answers=answers,
            ttl=ttl,
            packet=pkt,
            edns_ecs=pkt.ecs_response.to_dict() if pkt.ecs_response else None,
            dnssec_ad=pkt.ad,
            error=None if pkt.rcode == 0 else f"DNS RCODE: {pkt.rcode_name}",
        )
    except Exception as exc:
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        return DNSQueryResult(
            server=server,
            server_name=server_name,
            protocol="udp",
            domain=domain,
            qtype=qtype_str,
            success=False,
            latency_ms=elapsed_ms,
            rcode="ERROR",
            error=str(exc),
        )


def query_tcp(
    server: str,
    domain: str,
    qtype: int = TYPE_A,
    qclass: int = CLASS_IN,
    port: int = 53,
    timeout: float = 3.0,
    use_edns: bool = True,
    edns_do: bool = False,
    ecs_ip: Optional[str] = None,
    ecs_prefix: Optional[int] = None,
    server_name: Optional[str] = None,
) -> DNSQueryResult:
    """Send a raw DNS query over TCP (port 53) with RFC 1035 2-byte length framing."""
    qtype_str = TYPE_NAMES.get(qtype, str(qtype))
    _, payload = build_dns_query(
        domain=domain,
        qtype=qtype,
        qclass=qclass,
        use_edns=use_edns,
        edns_do=edns_do,
        ecs_ip=ecs_ip,
        ecs_prefix=ecs_prefix,
    )
    framed = struct.pack("!H", len(payload)) + payload
    start = time.perf_counter()
    try:
        with socket.create_connection((server, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(framed)
            len_bytes = _recv_exact(sock, 2)
            (resp_len,) = struct.unpack("!H", len_bytes)
            raw_resp = _recv_exact(sock, resp_len)
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        pkt = parse_dns_response(raw_resp)
        answers = [r.rdata for r in pkt.answers]
        ttl = pkt.answers[0].ttl if pkt.answers else None
        return DNSQueryResult(
            server=server,
            server_name=server_name,
            protocol="tcp",
            domain=domain,
            qtype=qtype_str,
            success=(pkt.rcode == 0),
            latency_ms=elapsed_ms,
            rcode=pkt.rcode_name,
            answers=answers,
            ttl=ttl,
            packet=pkt,
            edns_ecs=pkt.ecs_response.to_dict() if pkt.ecs_response else None,
            dnssec_ad=pkt.ad,
            error=None if pkt.rcode == 0 else f"DNS RCODE: {pkt.rcode_name}",
        )
    except Exception as exc:
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        return DNSQueryResult(
            server=server,
            server_name=server_name,
            protocol="tcp",
            domain=domain,
            qtype=qtype_str,
            success=False,
            latency_ms=elapsed_ms,
            rcode="ERROR",
            error=str(exc),
        )


def query_dot(
    server: str,
    domain: str,
    qtype: int = TYPE_A,
    qclass: int = CLASS_IN,
    port: int = 853,
    tls_hostname: Optional[str] = None,
    timeout: float = 3.5,
    use_edns: bool = True,
    edns_do: bool = False,
    ecs_ip: Optional[str] = None,
    ecs_prefix: Optional[int] = None,
    server_name: Optional[str] = None,
) -> DNSQueryResult:
    """Send a DNS over TLS (DoT, RFC 7858, port 853) query."""
    qtype_str = TYPE_NAMES.get(qtype, str(qtype))
    _, payload = build_dns_query(
        domain=domain,
        qtype=qtype,
        qclass=qclass,
        use_edns=use_edns,
        edns_do=edns_do,
        ecs_ip=ecs_ip,
        ecs_prefix=ecs_prefix,
    )
    framed = struct.pack("!H", len(payload)) + payload
    sni_host = tls_hostname or server

    ctx = ssl.create_default_context()
    start = time.perf_counter()
    try:
        with socket.create_connection((server, port), timeout=timeout) as raw_sock:
            raw_sock.settimeout(timeout)
            with ctx.wrap_socket(raw_sock, server_hostname=sni_host) as tls_sock:
                tls_sock.settimeout(timeout)
                tls_sock.sendall(framed)
                len_bytes = _recv_exact(tls_sock, 2)
                (resp_len,) = struct.unpack("!H", len_bytes)
                raw_resp = _recv_exact(tls_sock, resp_len)
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        pkt = parse_dns_response(raw_resp)
        answers = [r.rdata for r in pkt.answers]
        ttl = pkt.answers[0].ttl if pkt.answers else None
        return DNSQueryResult(
            server=f"tls://{sni_host}:{port}",
            server_name=server_name or f"{sni_host} (DoT)",
            protocol="dot",
            domain=domain,
            qtype=qtype_str,
            success=(pkt.rcode == 0),
            latency_ms=elapsed_ms,
            rcode=pkt.rcode_name,
            answers=answers,
            ttl=ttl,
            packet=pkt,
            edns_ecs=pkt.ecs_response.to_dict() if pkt.ecs_response else None,
            dnssec_ad=pkt.ad,
            error=None if pkt.rcode == 0 else f"DNS RCODE: {pkt.rcode_name}",
        )
    except Exception as exc:
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        return DNSQueryResult(
            server=f"tls://{sni_host}:{port}",
            server_name=server_name or f"{sni_host} (DoT)",
            protocol="dot",
            domain=domain,
            qtype=qtype_str,
            success=False,
            latency_ms=elapsed_ms,
            rcode="ERROR",
            error=str(exc),
        )


def query_doh(
    endpoint_url: str,
    domain: str,
    qtype: int = TYPE_A,
    qclass: int = CLASS_IN,
    timeout: float = 3.5,
    use_get: bool = False,
    use_edns: bool = True,
    edns_do: bool = False,
    ecs_ip: Optional[str] = None,
    ecs_prefix: Optional[int] = None,
    server_name: Optional[str] = None,
) -> DNSQueryResult:
    """
    Send a DNS over HTTPS (DoH, RFC 8484) query using application/dns-message wire format.
    """
    qtype_str = TYPE_NAMES.get(qtype, str(qtype))
    # RFC 8484 Section 4.1 recommends txid=0 for HTTP caching compatibility
    _, payload = build_dns_query(
        domain=domain,
        qtype=qtype,
        qclass=qclass,
        txid=0,
        use_edns=use_edns,
        edns_do=edns_do,
        ecs_ip=ecs_ip,
        ecs_prefix=ecs_prefix,
    )

    headers = {
        "Accept": "application/dns-message",
        "User-Agent": "DNSGuard-Checker/1.0",
    }

    if use_get:
        b64_dns = base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii")
        sep = "&" if "?" in endpoint_url else "?"
        req = urllib.request.Request(
            f"{endpoint_url}{sep}dns={b64_dns}",
            headers=headers,
            method="GET",
        )
    else:
        headers["Content-Type"] = "application/dns-message"
        req = urllib.request.Request(
            endpoint_url,
            data=payload,
            headers=headers,
            method="POST",
        )

    start = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw_resp = resp.read()
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        pkt = parse_dns_response(raw_resp)
        answers = [r.rdata for r in pkt.answers]
        ttl = pkt.answers[0].ttl if pkt.answers else None
        return DNSQueryResult(
            server=endpoint_url,
            server_name=server_name or endpoint_url,
            protocol="doh",
            domain=domain,
            qtype=qtype_str,
            success=(pkt.rcode == 0),
            latency_ms=elapsed_ms,
            rcode=pkt.rcode_name,
            answers=answers,
            ttl=ttl,
            packet=pkt,
            edns_ecs=pkt.ecs_response.to_dict() if pkt.ecs_response else None,
            dnssec_ad=pkt.ad,
            error=None if pkt.rcode == 0 else f"DNS RCODE: {pkt.rcode_name}",
        )
    except Exception as exc:
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        return DNSQueryResult(
            server=endpoint_url,
            server_name=server_name or endpoint_url,
            protocol="doh",
            domain=domain,
            qtype=qtype_str,
            success=False,
            latency_ms=elapsed_ms,
            rcode="ERROR",
            error=str(exc),
        )


def query_system_resolver(domain: str, qtype: int = TYPE_A) -> DNSQueryResult:
    """Resolve domain via OS system stub resolver (socket.getaddrinfo)."""
    qtype_str = TYPE_NAMES.get(qtype, str(qtype))
    family = socket.AF_INET6 if qtype == TYPE_AAAA else socket.AF_INET
    start = time.perf_counter()
    try:
        infos = socket.getaddrinfo(domain, None, family, socket.SOCK_STREAM)
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        ips: List[str] = []
        for info in infos:
            ip = info[4][0]
            if ip not in ips:
                ips.append(ip)
        return DNSQueryResult(
            server="System Stub Resolver",
            server_name="系统默认解析器 (OS Stub)",
            protocol="system",
            domain=domain,
            qtype=qtype_str,
            success=len(ips) > 0,
            latency_ms=elapsed_ms,
            rcode="NOERROR" if ips else "EMPTY",
            answers=ips,
        )
    except Exception as exc:
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        return DNSQueryResult(
            server="System Stub Resolver",
            server_name="系统默认解析器 (OS Stub)",
            protocol="system",
            domain=domain,
            qtype=qtype_str,
            success=False,
            latency_ms=elapsed_ms,
            rcode="NXDOMAIN",
            error=str(exc),
        )
