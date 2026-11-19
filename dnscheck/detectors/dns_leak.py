"""
Module 2: Deep DNS Leak Detection, OAST Out-of-Band Vector Attribution & UDP-53 Hijack Audit.

Architecture (Scheme B — Interactsh OAST Primary Engine + Multi-Source Authoritative Verification):
1. Low-latency ProjectDiscovery Interactsh (OAST) session racing across global authoritative NS cluster:
   - Fires 6 tagged probe vectors concurrently (sys-v4, sys-v6, qtype65, udp-sys, direct-sni, proxy-sni)
   - Captures every raw DNS packet arriving at the authoritative NS (even discarded fallback races!)
   - Pinpoints exact leak root causes: Clash/Mihomo Type-65 HTTPS bypass, concurrent nameserver+fallback
     race leaks, IPv6 stub leaks, and HTTP-proxy-only (non-TUN) OS stub leaks.
2. Authoritative DNS Echo probes (whoami.ds.akahelp.net TXT, o-o.myaddr.l.google.com TXT,
   resolver-identity.cloudfront.net A, whoami.akamai.net A) + ECS subnet extraction.
3. Auxiliary HTTP reflection / automatic bash.ws session fallback when OAST is unreachable.
4. Direct UDP-53 probes to 8.8.8.8 and 1.1.1.1 to audit transparent ISP port-53 hijacking.
"""

from __future__ import annotations

import ipaddress
import json
import re
import socket
import ssl
import time
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from dnscheck.detectors.split_route import SplitRouteReport, run_split_route_diagnostics
from dnscheck.detectors.system_env import parse_macos_scutil_dns, parse_resolv_conf
from dnscheck.enricher.ip_intel import IPIntel, enrich_ip, enrich_ips_batch, is_fake_ip
from dnscheck.protocol.dns_packet import CLASS_CH, TYPE_A, TYPE_AAAA, TYPE_HTTPS, TYPE_TXT
from dnscheck.protocol.interactsh import (
    InteractshInteraction,
    InteractshSession,
    register_fastest_oast_session,
)
from dnscheck.protocol.transports import query_system_resolver, query_udp

IP_EXTRACT_RE = re.compile(
    r"(?:\b(?:\d{1,3}\.){3}\d{1,3}\b|(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4})"
)

OAST_VECTOR_SPECS: Tuple[Tuple[str, str, str], ...] = (
    ("sys-v4", "系统解析器 (IPv4 Stub)", "A"),
    ("sys-v6", "系统解析器 (IPv6 Stub)", "AAAA"),
    ("qtype65", "HTTPS 记录穿透 (Type 65)", "HTTPS"),
    ("udp-sys", "系统主 DNS 并发竞速 (TXT)", "TXT"),
    ("direct-sni", "绕过系统代理直连 (Direct)", "A/HTTPS"),
    ("proxy-sni", "代理 / Fake-IP 嗅探出站", "A/HTTPS"),
)


@dataclass
class DiscoveredResolver:
    """An upstream recursive DNS resolver discovered during leak probing."""
    ip: str
    sources: List[str] = field(default_factory=list)
    vectors: List[str] = field(default_factory=list)
    qtypes: List[str] = field(default_factory=list)
    hits: int = 1
    ecs_seen: Optional[str] = None
    intel: Optional[IPIntel] = None
    latency_ms: float = 0.0

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "sources": self.sources,
            "vectors": self.vectors,
            "qtypes": self.qtypes,
            "hits": self.hits,
            "ecs_seen": self.ecs_seen,
            "latency_ms": round(self.latency_ms, 2),
            "intel": self.intel.to_dict() if self.intel else None,
        }


@dataclass
class OASTVectorProbe:
    """Per-channel attribution result from the Interactsh OAST authoritative server."""
    vector_id: str
    vector_name: str
    qtype: str
    subdomain: str
    local_answers: List[str] = field(default_factory=list)
    is_fake_ip: bool = False
    resolver_ips: List[str] = field(default_factory=list)
    cn_ips: List[str] = field(default_factory=list)
    overseas_ips: List[str] = field(default_factory=list)
    qtypes_seen: List[str] = field(default_factory=list)
    ecs_subnets: List[str] = field(default_factory=list)
    latency_ms: float = 0.0
    status: str = "INFO"  # "SAFE", "WARNING", "LEAK", "INTERCEPTED", "INACTIVE", "INFO"
    status_label: str = ""
    note: str = ""

    def to_dict(self) -> dict:
        return {
            "vector_id": self.vector_id,
            "vector_name": self.vector_name,
            "qtype": self.qtype,
            "subdomain": self.subdomain,
            "local_answers": self.local_answers,
            "is_fake_ip": self.is_fake_ip,
            "resolver_ips": self.resolver_ips,
            "cn_ips": self.cn_ips,
            "overseas_ips": self.overseas_ips,
            "qtypes_seen": self.qtypes_seen,
            "ecs_subnets": self.ecs_subnets,
            "latency_ms": round(self.latency_ms, 2),
            "status": self.status,
            "status_label": self.status_label,
            "note": self.note,
        }


@dataclass
class TransparentHijackProbe:
    """Result of testing a well-known public DNS over plain UDP-53 for ISP interception."""
    target_server: str
    target_name: str
    probe_domain: str
    success: bool
    returned_resolver_ip: Optional[str] = None
    chaos_id: Optional[str] = None
    hijacked: bool = False
    proxy_hijacked: bool = False
    reason: str = ""
    latency_ms: float = 0.0
    intel: Optional[IPIntel] = None

    def to_dict(self) -> dict:
        return {
            "target_server": self.target_server,
            "target_name": self.target_name,
            "probe_domain": self.probe_domain,
            "success": self.success,
            "returned_resolver_ip": self.returned_resolver_ip,
            "chaos_id": self.chaos_id,
            "hijacked": self.hijacked,
            "proxy_hijacked": self.proxy_hijacked,
            "reason": self.reason,
            "latency_ms": round(self.latency_ms, 2),
            "intel": self.intel.to_dict() if self.intel else None,
        }


@dataclass
class DNSLeakReport:
    """Comprehensive DNS leak detection & OAST vector attribution report."""
    resolvers: List[DiscoveredResolver]
    hijack_probes: List[TransparentHijackProbe]
    transparent_hijack_detected: bool
    leak_status: str  # "SAFE", "WARNING", "LEAK"
    leak_status_label: str
    risk_score: int  # 0..100 (100 = safest / healthiest)
    proxy_detected: bool
    cn_resolver_count: int
    overseas_resolver_count: int
    ecs_leaked_subnets: List[str]
    rounds_attempted: int
    rounds_succeeded: int
    findings: List[dict]
    # New Scheme B (Interactsh OAST) fields
    oast_enabled: bool = False
    oast_server: Optional[str] = None
    oast_register_ms: float = 0.0
    oast_events_count: int = 0
    vector_probes: List[OASTVectorProbe] = field(default_factory=list)
    concurrent_race_leak: bool = False
    qtype65_leak: bool = False
    direct_bypass_leak: bool = False

    def to_dict(self) -> dict:
        return {
            "resolvers": [r.to_dict() for r in self.resolvers],
            "hijack_probes": [h.to_dict() for h in self.hijack_probes],
            "transparent_hijack_detected": self.transparent_hijack_detected,
            "leak_status": self.leak_status,
            "leak_status_label": self.leak_status_label,
            "risk_score": self.risk_score,
            "proxy_detected": self.proxy_detected,
            "cn_resolver_count": self.cn_resolver_count,
            "overseas_resolver_count": self.overseas_resolver_count,
            "ecs_leaked_subnets": self.ecs_leaked_subnets,
            "rounds_attempted": self.rounds_attempted,
            "rounds_succeeded": self.rounds_succeeded,
            "findings": self.findings,
            "oast_enabled": self.oast_enabled,
            "oast_server": self.oast_server,
            "oast_register_ms": round(self.oast_register_ms, 2),
            "oast_events_count": self.oast_events_count,
            "vector_probes": [v.to_dict() for v in self.vector_probes],
            "concurrent_race_leak": self.concurrent_race_leak,
            "qtype65_leak": self.qtype65_leak,
            "direct_bypass_leak": self.direct_bypass_leak,
        }


def _extract_valid_ip(text: str) -> Optional[str]:
    """Extract first valid IPv4/IPv6 address from text."""
    for match in IP_EXTRACT_RE.findall(text):
        try:
            ipaddress.ip_address(match)
            return match
        except ValueError:
            continue
    return None


def parse_akahelp_txt_answers(answers: List[str]) -> Tuple[Optional[str], Optional[str]]:
    """
    Parse Akamai `whoami.ds.akahelp.net` TXT answers.
    Each TXT RR contains two character-strings joined by dns_packet.py (e.g., 'ns23.45.67.89'
    or 'ns 23.45.67.89', and 'ecs114.114.114.0/24/24' or 'ecs 114.114.114.0/24/24').
    Returns (resolver_ns_ip, ecs_cidr).
    """
    ns_ip: Optional[str] = None
    ecs_cidr: Optional[str] = None
    for raw in answers:
        clean = raw.strip().strip('"')
        low = clean.lower()
        if low.startswith("ns"):
            rem = clean[2:].strip(" \t:=\",")
            cand = _extract_valid_ip(rem) or rem
            try:
                ipaddress.ip_address(cand)
                ns_ip = cand
            except ValueError:
                pass
        elif low.startswith("ecs"):
            rem = clean[3:].strip(" \t:=\",")
            parts = rem.split("/")
            if len(parts) >= 2:
                try:
                    ip_obj = ipaddress.ip_address(parts[0].strip("[]"))
                    if not ip_obj.is_unspecified:
                        ecs_cidr = f"{ip_obj}/{parts[1]}"
                except ValueError:
                    pass
    return ns_ip, ecs_cidr


def _trigger_oast_vectors(
    session: InteractshSession,
    primary_sys_dns: str,
) -> Dict[str, Tuple[str, List[str], bool, float]]:
    """
    Concurrently fire all 6 tagged OAST DNS/HTTP probe vectors.
    Returns mapping: vector_id -> (subdomain, local_answers, saw_fake_ip, latency_ms).
    """
    subdomains = {vid: session.subdomain(tag=vid) for vid, _, _ in OAST_VECTOR_SPECS}
    meta: Dict[str, Tuple[str, List[str], bool, float]] = {}

    def _run_sys_v4() -> Tuple[str, Tuple[str, List[str], bool, float]]:
        sub = subdomains["sys-v4"]
        res = query_system_resolver(sub, qtype=TYPE_A)
        faked = any(is_fake_ip(ip) for ip in res.answers)
        return "sys-v4", (sub, res.answers, faked, res.latency_ms)

    def _run_sys_v6() -> Tuple[str, Tuple[str, List[str], bool, float]]:
        sub = subdomains["sys-v6"]
        res = query_system_resolver(sub, qtype=TYPE_AAAA)
        faked = any(is_fake_ip(ip) for ip in res.answers)
        return "sys-v6", (sub, res.answers, faked, res.latency_ms)

    def _run_qtype65() -> Tuple[str, Tuple[str, List[str], bool, float]]:
        sub = subdomains["qtype65"]
        res = query_udp(primary_sys_dns, sub, qtype=TYPE_HTTPS, timeout=2.4)
        return "qtype65", (sub, res.answers, False, res.latency_ms)

    def _run_udp_sys() -> Tuple[str, Tuple[str, List[str], bool, float]]:
        sub = subdomains["udp-sys"]
        # TXT bypasses Fake-IP A/AAAA spoofing, forcing the proxy/DNS core to reveal real upstream race behavior
        res = query_udp(primary_sys_dns, sub, qtype=TYPE_TXT, timeout=2.4)
        return "udp-sys", (sub, res.answers, False, res.latency_ms)

    def _run_direct_sni() -> Tuple[str, Tuple[str, List[str], bool, float]]:
        sub = subdomains["direct-sni"]
        t0 = time.perf_counter()
        answers: List[str] = []
        faked = False
        try:
            infos = socket.getaddrinfo(sub, 80, socket.AF_INET, socket.SOCK_STREAM)
            for info in infos:
                ip = info[4][0]
                if ip not in answers:
                    answers.append(ip)
            faked = any(is_fake_ip(ip) for ip in answers)
            # Bypass HTTP_PROXY / scutil --proxy to test non-proxy-aware CLI/native apps.
            # Try port-80 HTTP first (zero TLS handshake RTT, triggers HTTP Host sniffing immediately).
            ctx = ssl._create_unverified_context()
            https_handler = urllib.request.HTTPSHandler(context=ctx)
            no_proxy_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), https_handler)
            try:
                req = urllib.request.Request(f"http://{sub}/", headers={"User-Agent": "Interactsh-Client/1.2"})
                with no_proxy_opener.open(req, timeout=2.2) as resp:
                    resp.read(64)
            except Exception:
                req_tls = urllib.request.Request(f"https://{sub}/", headers={"User-Agent": "Interactsh-Client/1.2"})
                with no_proxy_opener.open(req_tls, timeout=2.0) as resp:
                    resp.read(64)
        except Exception:
            pass
        elapsed = (time.perf_counter() - t0) * 1000.0
        return "direct-sni", (sub, answers, faked, elapsed)

    def _run_proxy_sni() -> Tuple[str, Tuple[str, List[str], bool, float]]:
        sub = subdomains["proxy-sni"]
        t0 = time.perf_counter()
        # Try fast HTTP port-80 first to avoid slow TLS handshake overhead on high-latency proxies,
        # falling back to HTTPS TLS SNI if port 80 is blocked or fails.
        try:
            req = urllib.request.Request(f"http://{sub}/", headers={"User-Agent": "Interactsh-Client/1.2"})
            with urllib.request.urlopen(req, timeout=2.2) as resp:
                resp.read(64)
        except Exception:
            try:
                ctx = ssl._create_unverified_context()
                req_tls = urllib.request.Request(f"https://{sub}/", headers={"User-Agent": "Interactsh-Client/1.2"})
                with urllib.request.urlopen(req_tls, timeout=2.2, context=ctx) as resp:
                    resp.read(64)
            except Exception:
                pass
        elapsed = (time.perf_counter() - t0) * 1000.0
        return "proxy-sni", (sub, [], False, elapsed)

    tasks = [_run_sys_v4, _run_sys_v6, _run_qtype65, _run_udp_sys, _run_direct_sni, _run_proxy_sni]
    with ThreadPoolExecutor(max_workers=6) as pool:
        futs = [pool.submit(fn) for fn in tasks]
        for fut in futs:
            vid, tup = fut.result()
            meta[vid] = tup
    return meta


def _run_oast_audit_flow(
    primary_sys_dns: str,
    oast_server: Optional[str] = None,
    oast_token: Optional[str] = None,
) -> Tuple[Optional[InteractshSession], Dict[str, Tuple[str, List[str], bool, float]], List[InteractshInteraction]]:
    """
    Register fastest OAST node -> fire 6 concurrent vectors -> adaptive low-latency poll -> async cleanup.
    """
    session = register_fastest_oast_session(custom_server=oast_server, token=oast_token, timeout=4.5)
    if session is None:
        return None, {}, []

    try:
        vector_meta = _trigger_oast_vectors(session, primary_sys_dns=primary_sys_dns)
        collected: List[InteractshInteraction] = []

        # Adaptive 3-stage poll: exits early after stage 2 if connection vectors already reported back.
        for idx, delay in enumerate((0.30, 0.50, 0.70)):
            time.sleep(delay)
            try:
                batch = session.poll(timeout=3.5)
                if batch:
                    collected.extend(batch)
            except Exception:
                pass
            if idx >= 1:
                seen_tags = {ev.tag for ev in collected if ev.protocol == "dns"}
                if "proxy-sni" in seen_tags and ("direct-sni" in seen_tags or "udp-sys" in seen_tags):
                    break

        return session, vector_meta, collected
    finally:
        session.close_async()


def _probe_bash_ws_fallback(rounds: int = 5) -> List[Tuple[str, str]]:
    """
    Session-based authoritative fallback via bash.ws if all Interactsh OAST nodes are blocked.
    Returns list of (resolver_ip, source_label).
    """
    found: List[Tuple[str, str]] = []
    try:
        req_id = urllib.request.Request("https://bash.ws/id", headers={"User-Agent": "DNSGuard/1.1"})
        with urllib.request.urlopen(req_id, timeout=2.5) as resp:
            test_id = resp.read().decode("utf-8", errors="replace").strip()
        if not test_id or not test_id.isalnum():
            return []

        def _hit_sub(i: int) -> None:
            try:
                socket.getaddrinfo(f"{i}.{test_id}.bash.ws", 80, socket.AF_INET)
            except Exception:
                pass

        with ThreadPoolExecutor(max_workers=rounds) as pool:
            list(pool.map(_hit_sub, range(1, rounds + 1)))

        time.sleep(0.8)
        req_res = urllib.request.Request(
            f"https://bash.ws/dnsleak/test/{test_id}?json",
            headers={"User-Agent": "DNSGuard/1.1"},
        )
        with urllib.request.urlopen(req_res, timeout=3.0) as resp:
            items = json.loads(resp.read().decode("utf-8", errors="replace"))
        if isinstance(items, list):
            for entry in items:
                if isinstance(entry, dict) and entry.get("type") == "dns":
                    ip = str(entry.get("ip") or "").strip()
                    if ip:
                        found.append((ip, "bash.ws 权威会话备援"))
    except Exception:
        pass
    return found


def _probe_edns_http_round(round_idx: int, timeout: float = 2.8) -> Tuple[Optional[str], Optional[str], float, str]:
    """
    Query https://<random32>.edns.ip-api.com/json (with NextDNS fast fallback)
    to capture ECS subnet metadata & provide secondary cross-validation.
    """
    sub = uuid.uuid4().hex
    urls = [
        (f"https://{sub}.edns.ip-api.com/json", "ip-api"),
        (f"https://{sub[:16]}.test.nextdns.io/", "nextdns"),
    ]
    for url, kind in urls:
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "DNSGuard-Checker/1.1",
                "Cache-Control": "no-cache",
            },
        )
        start = time.perf_counter()
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="replace"))
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            if kind == "ip-api":
                dns_obj = data.get("dns") or {}
                edns_obj = data.get("edns") or {}
                res_ip = dns_obj.get("ip")
                ecs_ip = edns_obj.get("ip")
                if res_ip:
                    return (
                        str(res_ip).strip(),
                        (str(ecs_ip).strip() if ecs_ip else None),
                        elapsed_ms,
                        f"EDNS 反射探针 #{round_idx + 1}",
                    )
            else:
                res_ip = data.get("resolver")
                if res_ip:
                    return str(res_ip).strip(), None, elapsed_ms, f"NextDNS 反射探针 #{round_idx + 1}"
        except Exception:
            continue
    return None, None, 0.0, f"HTTP 权威探针 #{round_idx + 1}"


def _probe_authoritative_echo_dns(server_ip: str) -> List[Tuple[str, Optional[str], float, str]]:
    """
    Query Akamai Dual-Stack (whoami.ds.akahelp.net TXT), Google (o-o.myaddr.l.google.com TXT),
    and AWS CloudFront (resolver-identity.cloudfront.net A) through a DNS server.
    """
    found: List[Tuple[str, Optional[str], float, str]] = []

    # 1. Akamai Dual-Stack whoami.ds.akahelp.net TXT (returns ns + ecs)
    res_aka_ds = query_udp(server_ip, "whoami.ds.akahelp.net", qtype=TYPE_TXT, timeout=2.0)
    if res_aka_ds.success and res_aka_ds.answers:
        ns_ip, ecs_cidr = parse_akahelp_txt_answers(res_aka_ds.answers)
        if ns_ip:
            found.append((ns_ip, ecs_cidr, res_aka_ds.latency_ms, f"DNS Echo ({server_ip} -> Akamai DS TXT)"))

    # 2. Google o-o.myaddr.l.google.com TXT
    res_txt = query_udp(server_ip, "o-o.myaddr.l.google.com", qtype=TYPE_TXT, timeout=2.0)
    if res_txt.success and res_txt.answers:
        rec_ip: Optional[str] = None
        ecs_str: Optional[str] = None
        for ans in res_txt.answers:
            clean = ans.strip().strip('"')
            if "client-subnet" in clean.lower():
                # Extract CIDR from 'edns0-client-subnet x.x.x.x/24'
                parts = clean.split()
                ecs_str = parts[-1] if parts else clean
            elif not rec_ip:
                ip_val = _extract_valid_ip(clean)
                if ip_val:
                    rec_ip = ip_val
        if rec_ip:
            found.append((rec_ip, ecs_str, res_txt.latency_ms, f"DNS Echo ({server_ip} -> Google TXT)"))

    # 3. CloudFront resolver-identity.cloudfront.net A (ignore Fake-IP virtual responses)
    res_cf = query_udp(server_ip, "resolver-identity.cloudfront.net", qtype=TYPE_A, timeout=2.0)
    if res_cf.success and res_cf.answers:
        ip_val = _extract_valid_ip(res_cf.answers[0])
        if ip_val and not is_fake_ip(ip_val):
            found.append((ip_val, None, res_cf.latency_ms, f"DNS Echo ({server_ip} -> CloudFront A)"))

    return found


def _detect_local_proxy_udp53_hijack(target_server: str, timeout: float = 1.0) -> Optional[str]:
    """
    Send a Fake-IP canary A query to target_server:53.
    If the response returns a Fake-IP (198.18.0.0/15), UDP-53 is being intercepted by
    the local proxy's dns-hijack / hijack-dns engine (NOT an ISP attack).
    Returns the Fake-IP string if intercepted locally, else None.
    """
    canary = f"dnscheck-canary-{uuid.uuid4().hex[:8]}.invalid"
    res = query_udp(target_server, canary, qtype=TYPE_A, timeout=timeout)
    if res.success and res.answers:
        for ans in res.answers:
            ip_val = _extract_valid_ip(ans)
            if ip_val and is_fake_ip(ip_val):
                return ip_val
    return None


def check_transparent_udp53_hijack(timeout: float = 2.2) -> List[TransparentHijackProbe]:
    """
    Send raw UDP-53 queries directly to 8.8.8.8 and 1.1.1.1 to check whether
    the local network or ISP transparently intercepts port 53 traffic, while
    distinguishing local proxy dns-hijack (Fake-IP canary) from ISP hijacking.
    """
    probes: List[TransparentHijackProbe] = []

    def _probe_google() -> TransparentHijackProbe:
        proxy_fake_ip = _detect_local_proxy_udp53_hijack("8.8.8.8", timeout=1.0)
        res_g = query_udp("8.8.8.8", "o-o.myaddr.l.google.com", qtype=TYPE_TXT, timeout=timeout)
        returned_ip: Optional[str] = None
        latency = res_g.latency_ms
        domain_used = "o-o.myaddr.l.google.com"

        if res_g.success and res_g.answers:
            for ans in res_g.answers:
                if "client-subnet" not in ans.lower():
                    returned_ip = _extract_valid_ip(ans)
                    if returned_ip:
                        break

        if not returned_ip:
            res_ak = query_udp("8.8.8.8", "whoami.akamai.net", qtype=TYPE_A, timeout=timeout)
            latency = res_ak.latency_ms
            domain_used = "whoami.akamai.net"
            if res_ak.success and res_ak.answers:
                cand = _extract_valid_ip(res_ak.answers[0])
                if cand and is_fake_ip(cand):
                    proxy_fake_ip = proxy_fake_ip or cand
                else:
                    returned_ip = cand

        if proxy_fake_ip:
            intel = enrich_ip(returned_ip, timeout=2.2) if returned_ip else None
            if intel and intel.is_cn:
                reason = (
                    f"本机代理 dns-hijack 已接管 8.8.8.8:53（非运营商劫持），"
                    f"但其内部 DNS 将 TXT 转给了国内上游 {intel.display_isp} ({returned_ip})"
                )
            else:
                reason = f"本机代理 (TUN/VIF) 开启了 dns-hijack，已拦截 8.8.8.8:53 ({proxy_fake_ip}，非运营商劫持)"
            return TransparentHijackProbe(
                target_server="8.8.8.8:53",
                target_name="Google Public DNS (UDP 53)",
                probe_domain=domain_used,
                success=True,
                returned_resolver_ip=returned_ip or proxy_fake_ip,
                hijacked=False,
                proxy_hijacked=True,
                reason=reason,
                latency_ms=latency,
                intel=intel,
            )

        if not returned_ip:
            return TransparentHijackProbe(
                target_server="8.8.8.8:53",
                target_name="Google Public DNS (UDP 53)",
                probe_domain=domain_used,
                success=False,
                hijacked=False,
                reason="UDP 53 请求超时或被防火墙丢弃（未收到伪造抢答）",
                latency_ms=latency,
            )

        intel = enrich_ip(returned_ip, timeout=2.2)
        is_google_asn = intel.asn == "AS15169" or "google" in (intel.isp + intel.org).lower()
        hijacked = (intel.is_cn or (intel.is_private and not intel.is_fake_ip)) and not is_google_asn
        reason = (
            f"UDP 53 流量被透明劫持！请求 8.8.8.8 却由 {intel.display_isp} ({returned_ip}) 应答"
            if hijacked
            else (
                "直连应答来自 Google 全球网络 (未发现透明劫持)"
                if is_google_asn
                else f"应答来自非国内节点 ({intel.display_location} / {intel.display_isp}，可能经由代理转发)"
            )
        )
        return TransparentHijackProbe(
            target_server="8.8.8.8:53",
            target_name="Google Public DNS (UDP 53)",
            probe_domain=domain_used,
            success=True,
            returned_resolver_ip=returned_ip,
            hijacked=hijacked,
            reason=reason,
            latency_ms=latency,
            intel=intel,
        )

    def _probe_cloudflare() -> TransparentHijackProbe:
        proxy_fake_ip = _detect_local_proxy_udp53_hijack("1.1.1.1", timeout=1.0)
        res_ch = query_udp("1.1.1.1", "whoami.cloudflare", qtype=TYPE_TXT, qclass=CLASS_CH, timeout=timeout)
        chaos_id = res_ch.answers[0].strip('"') if (res_ch.success and res_ch.answers) else None

        res_ak = query_udp("1.1.1.1", "whoami.akamai.net", qtype=TYPE_A, timeout=timeout)
        cand_ip = _extract_valid_ip(res_ak.answers[0]) if (res_ak.success and res_ak.answers) else None
        if cand_ip and is_fake_ip(cand_ip):
            proxy_fake_ip = proxy_fake_ip or cand_ip
            returned_ip = None
        else:
            returned_ip = cand_ip
        latency = res_ak.latency_ms if res_ak.success else res_ch.latency_ms

        if proxy_fake_ip:
            return TransparentHijackProbe(
                target_server="1.1.1.1:53",
                target_name="Cloudflare DNS (UDP 53)",
                probe_domain="whoami.akamai.net / whoami.cloudflare",
                success=True,
                returned_resolver_ip=returned_ip or proxy_fake_ip,
                chaos_id=chaos_id,
                hijacked=False,
                proxy_hijacked=True,
                reason=f"本机代理 (TUN/VIF) 开启了 dns-hijack，已拦截 1.1.1.1:53 ({proxy_fake_ip}，非运营商劫持)",
                latency_ms=latency,
            )

        if not returned_ip and not chaos_id:
            return TransparentHijackProbe(
                target_server="1.1.1.1:53",
                target_name="Cloudflare DNS (UDP 53)",
                probe_domain="whoami.akamai.net / whoami.cloudflare",
                success=False,
                hijacked=False,
                reason="UDP 53 请求超时或无法直达 1.1.1.1",
                latency_ms=latency,
            )

        intel = enrich_ip(returned_ip, timeout=2.2) if returned_ip else None
        is_cf = bool(
            (intel and (intel.asn == "AS13335" or "cloudflare" in (intel.isp + intel.org).lower()))
            or (chaos_id and len(chaos_id) <= 16)
        )
        hijacked = False
        if intel:
            if (intel.is_cn or (intel.is_private and not intel.is_fake_ip)) and intel.asn != "AS13335":
                hijacked = True

        if hijacked and intel:
            reason = f"UDP 53 流量被透明劫持！请求 1.1.1.1 却由 {intel.display_isp} ({returned_ip}) 应答"
        elif is_cf:
            cf_note = f"节点标识 {chaos_id}" if chaos_id else "Cloudflare 网络"
            reason = f"直连应答来自 {cf_note} (未发现透明劫持)"
        else:
            reason = (
                f"应答来自 {intel.display_location} ({intel.display_isp})"
                if intel
                else "收到非预期 CHAOS 响应"
            )

        return TransparentHijackProbe(
            target_server="1.1.1.1:53",
            target_name="Cloudflare DNS (UDP 53)",
            probe_domain="whoami.akamai.net / whoami.cloudflare",
            success=True,
            returned_resolver_ip=returned_ip,
            chaos_id=chaos_id,
            hijacked=hijacked,
            reason=reason,
            latency_ms=latency,
            intel=intel,
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        f_g = pool.submit(_probe_google)
        f_c = pool.submit(_probe_cloudflare)
        probes.append(f_g.result())
        probes.append(f_c.result())

    return probes


def evaluate_oast_vectors(
    vector_meta: Dict[str, Tuple[str, List[str], bool, float]],
    interactions: List[InteractshInteraction],
    intel_map: Dict[str, IPIntel],
    proxy_active: bool,
) -> Tuple[List[OASTVectorProbe], bool, bool, bool]:
    """
    Build per-channel OAST attribution results and compute root-cause leak flags:
      Returns (vector_probes, concurrent_race_leak, qtype65_leak, direct_bypass_leak).
    """
    by_tag: Dict[str, List[InteractshInteraction]] = {vid: [] for vid, _, _ in OAST_VECTOR_SPECS}
    for ev in interactions:
        if ev.protocol != "dns":
            continue
        if ev.tag in by_tag:
            by_tag[ev.tag].append(ev)

    probes_out: List[OASTVectorProbe] = []
    for vid, vname, default_qtype in OAST_VECTOR_SPECS:
        sub, local_ans, saw_fake, lat = vector_meta.get(vid, ("", [], False, 0.0))
        evs = by_tag.get(vid, [])
        res_ips: List[str] = []
        qtypes_seen: List[str] = []
        ecs_list: List[str] = []
        for ev in evs:
            if ev.remote_ip not in res_ips:
                res_ips.append(ev.remote_ip)
            if ev.q_type and ev.q_type not in qtypes_seen:
                qtypes_seen.append(ev.q_type)
            if ev.ecs_subnet and ev.ecs_subnet not in ecs_list:
                ecs_list.append(ev.ecs_subnet)

        cn_ips = [ip for ip in res_ips if intel_map.get(ip) and intel_map[ip].is_cn]
        ov_ips = [
            ip
            for ip in res_ips
            if intel_map.get(ip) and not intel_map[ip].is_cn and not intel_map[ip].is_private
        ]

        if not proxy_active:
            if res_ips:
                status = "SAFE"
                status_label = "直连正常"
                note = f"捕获 {len(res_ips)} 个递归节点"
            elif saw_fake:
                status = "INTERCEPTED"
                status_label = "本地 Fake-IP"
                note = "被本地虚拟地址拦截"
            else:
                status = "INACTIVE"
                status_label = "未触发"
                note = "当前环境未启用或已丢弃该类型查询"
        else:
            # Overseas proxy is active -> inspect CN vs Overseas hits per vector
            if cn_ips and ov_ips:
                status = "LEAK"
                status_label = "并发抢答泄漏"
                note = f"同一域名同时命中 {len(cn_ips)} 个国内与 {len(ov_ips)} 个海外 DNS!"
            elif cn_ips:
                if vid == "qtype65":
                    status = "WARNING"
                    status_label = "Type-65 穿透"
                    note = "HTTPS(Type 65) 记录绕过 Fake-IP 漏向国内 DNS"
                elif vid in ("direct-sni", "sys-v4", "sys-v6"):
                    status = "WARNING"
                    status_label = "直连通道暴露"
                    note = (
                        "Fake-IP 返回假地址但后台仍向国内预解析"
                        if saw_fake
                        else "未走 TUN 全局接管，系统/非代理进程直连国内 DNS"
                    )
                else:
                    status = "LEAK"
                    status_label = "国内 DNS 泄漏"
                    note = f"上游请求落入国内解析器 ({', '.join(cn_ips[:2])})"
            elif ov_ips:
                status = "SAFE"
                status_label = "海外安全"
                note = f"全部经由 {len(ov_ips)} 个海外受信任节点递归"
            elif saw_fake:
                status = "INTERCEPTED"
                status_label = "Fake-IP 零外泄"
                note = "本地秒回 198.18.x.x 虚拟 IP，未向任何公网 DNS 泄露"
            else:
                status = "INACTIVE"
                status_label = "已阻断 / 未外发"
                note = (
                    "代理已屏蔽 Type-65 查询 (安全)"
                    if vid == "qtype65"
                    else ("未启用 IPv6 解析 (安全)" if vid == "sys-v6" else "未产生公网递归查询")
                )

        probes_out.append(
            OASTVectorProbe(
                vector_id=vid,
                vector_name=vname,
                qtype=default_qtype,
                subdomain=sub,
                local_answers=local_ans,
                is_fake_ip=saw_fake,
                resolver_ips=res_ips,
                cn_ips=cn_ips,
                overseas_ips=ov_ips,
                qtypes_seen=qtypes_seen,
                ecs_subnets=ecs_list,
                latency_ms=lat,
                status=status,
                status_label=status_label,
                note=note,
            )
        )

    probe_by_id = {p.vector_id: p for p in probes_out}
    concurrent_race_leak = False
    qtype65_leak = False
    direct_bypass_leak = False

    if proxy_active:
        # Surge / Fake-IP nuance: if BOTH real connection vectors (direct-sni & proxy-sni)
        # are 100% pure overseas with 0 CN hits, and ONLY raw non-A/AAAA TXT (udp-sys)
        # hit a domestic resolver without concurrent race, downgrade udp-sys from hard LEAK
        # to INFO (standard Surge deadlock-free local DoH behavior for TXT queries).
        p_direct = probe_by_id.get("direct-sni")
        p_proxy = probe_by_id.get("proxy-sni")
        p_udp = probe_by_id.get("udp-sys")
        both_conn_clean_overseas = bool(
            p_proxy
            and p_proxy.overseas_ips
            and not p_proxy.cn_ips
            and p_direct
            and p_direct.overseas_ips
            and not p_direct.cn_ips
        )
        if both_conn_clean_overseas and p_udp and p_udp.cn_ips and not p_udp.overseas_ips:
            p_udp.status = "INFO"
            p_udp.status_label = "本地 TXT 分流"
            p_udp.note = "浏览/连接均 100% 走海外远端解析，仅裸 TXT 查询由本地直连 DNS 应答 (Surge 标准防死锁模式)"

        # 1. Concurrent fallback race: any single overseas OAST probe hit BOTH CN and Overseas resolvers
        concurrent_race_leak = any(bool(p.cn_ips and p.overseas_ips) for p in probes_out)

        # 2. Type-65 leak: qtype65 hit CN while proxy-sni (or overall) did not purely fail
        p65 = probe_by_id.get("qtype65")
        if p65 and p65.cn_ips:
            qtype65_leak = True

        # 3. Direct / OS stub bypass leak: proxy-sni is clean overseas, yet sys-v4/sys-v6/direct-sni leaked to CN
        proxy_clean = bool(p_proxy and p_proxy.overseas_ips and not p_proxy.cn_ips)
        os_cn = any(
            bool(probe_by_id.get(k) and probe_by_id[k].cn_ips)
            for k in ("sys-v4", "sys-v6", "direct-sni")
        )
        if proxy_clean and os_cn:
            direct_bypass_leak = True

    return probes_out, concurrent_race_leak, qtype65_leak, direct_bypass_leak


def run_dns_leak_detection(
    split_report: Optional[SplitRouteReport] = None,
    rounds: int = 6,
    oast_server: Optional[str] = None,
    oast_token: Optional[str] = None,
) -> DNSLeakReport:
    """
    Execute Module 2: Deep DNS Leak Detection via Interactsh OAST + Authoritative Echo + Hijack Audit.
    """
    if split_report is None:
        split_report = run_split_route_diagnostics()

    scutil_defaults, _ = parse_macos_scutil_dns()
    resolv_servers = parse_resolv_conf()
    sys_dns_list: List[str] = []
    for s in scutil_defaults + resolv_servers:
        if s not in sys_dns_list:
            sys_dns_list.append(s)
    if not sys_dns_list:
        sys_dns_list = ["223.5.5.5"]

    primary_sys_dns = sys_dns_list[0]
    probe_dns_targets = sys_dns_list[:2]

    resolver_map: Dict[str, DiscoveredResolver] = {}
    ecs_leaked_subnets: List[str] = []
    rounds_succeeded = 0

    def _record_resolver(
        ip: str,
        source: str,
        latency_ms: float = 0.0,
        ecs_val: Optional[str] = None,
        vector: Optional[str] = None,
        qtype: Optional[str] = None,
    ) -> None:
        ip = ip.strip()
        if not ip:
            return
        if ip not in resolver_map:
            resolver_map[ip] = DiscoveredResolver(
                ip=ip,
                sources=[source],
                vectors=[vector] if vector else [],
                qtypes=[qtype] if qtype else [],
                hits=1,
                ecs_seen=ecs_val,
                latency_ms=latency_ms,
            )
        else:
            entry = resolver_map[ip]
            entry.hits += 1
            if source not in entry.sources:
                entry.sources.append(source)
            if vector and vector not in entry.vectors:
                entry.vectors.append(vector)
            if qtype and qtype not in entry.qtypes:
                entry.qtypes.append(qtype)
            if latency_ms > 0:
                entry.latency_ms = (
                    (entry.latency_ms + latency_ms) / 2.0 if entry.latency_ms > 0 else latency_ms
                )
            if ecs_val and not entry.ecs_seen:
                entry.ecs_seen = ecs_val
        if ecs_val and ecs_val not in ecs_leaked_subnets:
            ecs_leaked_subnets.append(ecs_val)

    # Run OAST session + Echo probes + 2 fast HTTP ECS probes + Transparent Hijack concurrently
    aux_http_rounds = max(2, min(3, rounds))
    with ThreadPoolExecutor(max_workers=6 + aux_http_rounds) as pool:
        oast_fut = pool.submit(_run_oast_audit_flow, primary_sys_dns, oast_server, oast_token)
        echo_futs = [pool.submit(_probe_authoritative_echo_dns, srv) for srv in probe_dns_targets]
        http_futs = [pool.submit(_probe_edns_http_round, idx) for idx in range(aux_http_rounds)]
        hijack_fut = pool.submit(check_transparent_udp53_hijack)

        oast_session, vector_meta, oast_interactions = oast_fut.result()

        for fut in echo_futs:
            for res_ip, ecs_str, lat, src in fut.result():
                _record_resolver(res_ip, src, lat, ecs_str)

        for fut in http_futs:
            res_ip, ecs_ip, lat, src = fut.result()
            if res_ip:
                rounds_succeeded += 1
                _record_resolver(res_ip, src, lat, ecs_ip)

        hijack_probes = hijack_fut.result()

    oast_enabled = oast_session is not None
    oast_srv_name = oast_session.server if oast_session else None
    oast_reg_ms = oast_session.register_latency_ms if oast_session else 0.0
    dns_oast_events = [ev for ev in oast_interactions if ev.protocol == "dns"]

    if oast_enabled:
        for ev in dns_oast_events:
            v_lat = vector_meta.get(ev.tag, ("", [], False, 0.0))[3]
            _record_resolver(
                ip=ev.remote_ip,
                source=f"OAST 权威抓包 ({ev.tag})",
                latency_ms=v_lat,
                ecs_val=ev.ecs_subnet,
                vector=ev.tag,
                qtype=ev.q_type,
            )
        if dns_oast_events:
            rounds_succeeded += len(OAST_VECTOR_SPECS)
    else:
        # Fallback to bash.ws session aggregation when all OAST nodes are blocked
        for fb_ip, fb_src in _probe_bash_ws_fallback(rounds=min(5, max(3, rounds))):
            rounds_succeeded += 1
            _record_resolver(fb_ip, fb_src)

    # Batch enrich all discovered resolvers (including any OAST IPs)
    all_ips: Set[str] = set(resolver_map.keys())
    for ev in dns_oast_events:
        all_ips.add(ev.remote_ip)
    intel_map = enrich_ips_batch(list(all_ips)) if all_ips else {}

    for ip, entry in resolver_map.items():
        entry.intel = intel_map.get(ip) or enrich_ip(ip)

    proxy_active = split_report.proxy_detected

    vector_probes: List[OASTVectorProbe] = []
    concurrent_race_leak = False
    qtype65_leak = False
    direct_bypass_leak = False

    if oast_enabled:
        vector_probes, concurrent_race_leak, qtype65_leak, direct_bypass_leak = evaluate_oast_vectors(
            vector_meta=vector_meta,
            interactions=oast_interactions,
            intel_map=intel_map,
            proxy_active=proxy_active,
        )

    resolvers = sorted(resolver_map.values(), key=lambda r: (len(r.vectors) > 0, r.hits), reverse=True)
    transparent_hijack = any(h.hijacked for h in hijack_probes)

    cn_resolvers = [r for r in resolvers if r.intel and r.intel.is_cn]
    overseas_resolvers = [
        r for r in resolvers if r.intel and not r.intel.is_cn and not r.intel.is_private
    ]

    # Risk Scoring & Root-Cause Verdict Logic
    score = 100
    findings: List[dict] = []

    if oast_enabled:
        if len(dns_oast_events) > 0:
            findings.append(
                {
                    "level": "info",
                    "title": f"Interactsh OAST 权威带外抓包已就绪 ({oast_srv_name} · 握手 {oast_reg_ms:.0f}ms)",
                    "detail": f"共并发投递 {len(OAST_VECTOR_SPECS)} 组带标签子域探针，权威 NS 实时捕获 {len(dns_oast_events)} 个原始 DNS 查询报文。",
                }
            )
        else:
            findings.append(
                {
                    "level": "warning",
                    "title": f"Interactsh OAST ({oast_srv_name}) 握手成功但未收到 DNS 回调报文",
                    "detail": "可能是当前代理节点连接超时、或出口屏蔽了 OAST 测试域名；已自动结合 EDNS 反射与权威回显结果进行综合判定（不会误报 OAST 满分通过）。",
                }
            )

    if transparent_hijack:
        score -= 35
        hijacked_names = [h.target_server for h in hijack_probes if h.hijacked]
        findings.append(
            {
                "level": "danger",
                "title": f"检测到透明 DNS 53 端口劫持 ({', '.join(hijacked_names)})",
                "detail": "本地网络或运营商正在强制拦截发往海外公共 DNS 的明文 UDP 53 请求并代为应答。强烈建议启用 DoH / DoT 加密 DNS 或通过代理隧道转发 DNS。",
            }
        )

    if proxy_active:
        # Check OAST root-cause findings first!
        if concurrent_race_leak:
            score -= 35
            leaked_vecs = [p.vector_id for p in vector_probes if p.cn_ips and p.overseas_ips]
            findings.append(
                {
                    "level": "danger",
                    "title": f"实锤并发抢答泄漏 (Concurrent Fallback Leak: {', '.join(leaked_vecs)})",
                    "detail": (
                        "OAST 权威服务器在同一海外随机子域上同时收到了「国内 DNS」与「海外 DNS」的查询报文！"
                        "这说明代理内核配置了 nameserver(国内) + fallback(海外) 并发竞速，或 IP 规则漏加 no-resolve，导致每次访问未知海外域名都会向国内运营商同步泄露明文记录。"
                    ),
                }
            )

        if qtype65_leak:
            score -= 20
            findings.append(
                {
                    "level": "warning",
                    "title": "检测到 HTTPS 记录 (Type 65) 穿透 Fake-IP 泄漏",
                    "detail": (
                        "macOS 与现代浏览器默认并发发起的 DNS Type 65 (HTTPS) 查询未被 Fake-IP 拦截，直接穿透到了国内递归 DNS。"
                        "建议在 Mihomo / Clash 上游配置中添加 #disable-qtype-65=true 或完善 nameserver-policy。"
                    ),
                }
            )

        if direct_bypass_leak:
            score -= 20
            findings.append(
                {
                    "level": "warning",
                    "title": "代理通道内安全，但系统直连 / 非代理进程存在 DNS 泄漏",
                    "detail": (
                        "走代理通道 (proxy-sni) 的解析已由海外节点接管，但系统默认解析器或绕过 HTTP 代理的进程 (sys-v4 / direct-sni) 仍在直连国内 DNS。"
                        "建议开启代理软件的 TUN 虚拟网卡 + Fake-IP 全局接管模式。"
                    ),
                }
            )

        if cn_resolvers and not overseas_resolvers:
            leak_status = "LEAK"
            leak_status_label = "高危泄漏 (DNS Leak Detected)"
            score -= 55
            cn_desc = ", ".join(f"{r.ip} ({r.intel.display_isp if r.intel else ''})" for r in cn_resolvers[:3])
            findings.append(
                {
                    "level": "danger",
                    "title": "严重 DNS 泄漏：已开启海外代理，但 DNS 解析仍全部走国内服务器",
                    "detail": f"检测到海外流量已走代理出口 ({split_report.global_ip})，但上游递归 DNS 全部位于中国境内：{cn_desc}。",
                }
            )
        elif concurrent_race_leak:
            leak_status = "LEAK"
            leak_status_label = "并发抢答泄漏 (Fallback Race Leak)"
        elif qtype65_leak or direct_bypass_leak:
            leak_status = "WARNING"
            leak_status_label = "局部通道泄漏 (Channel Bypass Leak)"
        elif cn_resolvers and overseas_resolvers:
            # Strict OAST verification gate: must actually capture >= 1 real overseas hit on OAST
            # AND have 0 real connection-vector CN hits (ignoring clean Surge TXT-only INFO nuance).
            oast_overseas_any = any(bool(p.overseas_ips) for p in vector_probes)
            oast_real_leak_any = any(
                bool(p.cn_ips) and p.status in ("LEAK", "WARNING") for p in vector_probes
            )
            if oast_enabled and len(dns_oast_events) > 0 and oast_overseas_any and not oast_real_leak_any:
                leak_status = "SAFE" if not transparent_hijack else "WARNING"
                leak_status_label = (
                    "安全分流无泄漏 (OAST 权威验证通过)" if leak_status == "SAFE" else "存在透明劫持风险"
                )
                findings.append(
                    {
                        "level": "ok",
                        "title": "OAST 逐包验证通过：未知海外域名连接均 100% 走海外远端解析无泄漏",
                        "detail": (
                            f"权威服务器实收 {len(dns_oast_events)} 个原始报文，所有海外连接探针 (Direct/Proxy/Fake-IP) 均未泄露至国内解析器。"
                        ),
                    }
                )
            else:
                leak_status = "WARNING"
                leak_status_label = "分流警告 (Mixed Resolvers)"
                score -= 20
                findings.append(
                    {
                        "level": "warning",
                        "title": "检测到国内外混合递归 DNS 解析",
                        "detail": (
                            f"共发现 {len(overseas_resolvers)} 个海外 DNS 节点与 {len(cn_resolvers)} 个国内 DNS 节点。"
                            "建议核查代理规则 IP 类条目是否漏加 no-resolve，或 nameserver-policy 是否对未知海外域名启用了国内并发解析。"
                        ),
                    }
                )
        elif overseas_resolvers or (oast_enabled and any(p.is_fake_ip for p in vector_probes)):
            leak_status = "SAFE" if not transparent_hijack else "WARNING"
            leak_status_label = "安全无泄漏 (No DNS Leak)" if leak_status == "SAFE" else "存在透明劫持风险"
            findings.append(
                {
                    "level": "ok",
                    "title": "未检测到 DNS 泄漏：海外探测域名均由海外递归节点或 Fake-IP 安全接管",
                    "detail": f"共验证 {len(overseas_resolvers)} 个海外受信任递归 DNS 节点，未发现任何国内明文解析泄漏。",
                }
            )
        else:
            leak_status = "WARNING"
            leak_status_label = "探测结果有限 (Partial Probe)"
            score -= 15
            findings.append(
                {
                    "level": "warning",
                    "title": "未能收集到足够的公网递归 DNS 节点信息",
                    "detail": "可能是防火墙拦截了探测域名或网络离线，建议检查网络连通性。",
                }
            )
    else:
        # Pure direct connection (no overseas proxy active)
        if transparent_hijack:
            leak_status = "LEAK"
            leak_status_label = "存在 DNS 透明劫持 (UDP-53 Hijack)"
            score -= 25
        elif resolvers:
            leak_status = "SAFE"
            leak_status_label = "直连正常 (Direct Network)"
            findings.append(
                {
                    "level": "info",
                    "title": "当前处于直连网络环境，上游 DNS 与本地出口归属一致",
                    "detail": f"共发现 {len(resolvers)} 个递归 DNS 解析节点，未开启海外分流代理，不存在跨代理泄漏。",
                }
            )
        else:
            leak_status = "WARNING"
            leak_status_label = "探测受限 (No Resolvers Found)"
            score -= 20

    # Check if an OVERSEAS resolver exposed a domestic subnet via ECS while proxy is active
    # (Domestic resolvers like AliDNS attaching CN ECS for domestic CDN optimization is normal.)
    if proxy_active:
        for r in overseas_resolvers:
            if not r.ecs_seen:
                continue
            sub_ip = r.ecs_seen.split("/")[0].strip("[]")
            sub_intel = enrich_ip(sub_ip)
            if sub_intel.is_cn:
                score -= 10
                findings.append(
                    {
                        "level": "warning",
                        "title": f"海外 DNS ({r.ip}) 通过 ECS 暴露国内子网: {r.ecs_seen}",
                        "detail": "即使请求经过海外递归 DNS，ECS 扩展字段仍向权威服务器附带了您的国内 IP 前缀，可能泄露真实地理位置。",
                    }
                )
                break

    if split_report.ipv6_leak_risk:
        score -= 15

    score = max(0, min(100, score))

    return DNSLeakReport(
        resolvers=resolvers,
        hijack_probes=hijack_probes,
        transparent_hijack_detected=transparent_hijack,
        leak_status=leak_status,
        leak_status_label=leak_status_label,
        risk_score=score,
        proxy_detected=proxy_active,
        cn_resolver_count=len(cn_resolvers),
        overseas_resolver_count=len(overseas_resolvers),
        ecs_leaked_subnets=ecs_leaked_subnets,
        rounds_attempted=rounds + (len(OAST_VECTOR_SPECS) if oast_enabled else 0),
        rounds_succeeded=rounds_succeeded,
        findings=findings,
        oast_enabled=oast_enabled,
        oast_server=oast_srv_name,
        oast_register_ms=oast_reg_ms,
        oast_events_count=len(dns_oast_events),
        vector_probes=vector_probes,
        concurrent_race_leak=concurrent_race_leak,
        qtype65_leak=qtype65_leak,
        direct_bypass_leak=direct_bypass_leak,
    )
