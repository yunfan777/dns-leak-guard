"""
Module 5: DNS Pollution / Poisoning Detection & Multi-Protocol DNS Benchmark.
Part A - Pollution & Hijacking Detection:
  - Establishes clean baseline via trusted DoH endpoints
  - Probes sensitive domains over plain UDP-53 to system DNS, domestic public DNS (114/AliDNS),
    and cross-border plain UDP (8.8.8.8 / 1.1.1.1) to catch on-path GFW UDP-53 poisoning
  - Checks known bogon/blackhole IPs, classic GFW forged IP signatures, anomalous fast replies (<12ms
    to overseas 8.8.8.8/1.1.1.1 returning wrong ASN), and Fake-IP range (198.18.0.0/15)
Part B - Multi-Protocol DNS Benchmark:
  - Compares UDP-53, DoT (TLS-853), and DoH (HTTPS-443) across domestic & global public DNS servers
"""

from __future__ import annotations

import ipaddress
import statistics
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from dnscheck.detectors.system_env import parse_macos_scutil_dns, parse_resolv_conf
from dnscheck.enricher.ip_intel import IPIntel, enrich_ip, enrich_ips_batch, is_fake_ip
from dnscheck.protocol.dns_packet import TYPE_A
from dnscheck.protocol.transports import DNSQueryResult, query_doh, query_dot, query_udp

POLLUTION_TEST_DOMAINS: List[Tuple[str, str]] = [
    ("www.google.com", "Google 搜索"),
    ("www.youtube.com", "YouTube 视频"),
    ("x.com", "X (Twitter)"),
    ("telegram.org", "Telegram"),
    ("github.com", "GitHub"),
]

# Classic known GFW DNS poisoning IP prefixes & exact addresses (often forged for unrelated domains)
KNOWN_POISONED_EXACT_IPS: Set[str] = {
    "0.0.0.0",
    "127.0.0.1",
    "127.0.0.2",
    "46.82.174.68",
    "59.24.3.173",
    "78.16.49.15",
    "8.7.198.45",
    "93.46.8.89",
    "203.98.7.65",
    "243.185.187.39",
    "37.61.54.158",
    "159.106.121.75",
    "4.36.66.178",
    "216.234.179.13",
}

# Classic Facebook / Dropbox / Twitter prefixes injected for unrelated domains (like Google/YouTube)
FORGED_CROSS_BRAND_PREFIXES = (
    "31.13.",
    "157.240.",
    "179.60.",
    "185.60.",
    "162.125.",
    "108.160.",
)

# Benchmark Matrix Definition
BENCHMARK_TARGETS: List[dict] = [
    {"id": "ali_udp", "name": "阿里 AliDNS", "proto": "udp", "server": "223.5.5.5", "region": "国内"},
    {"id": "ali_dot", "name": "阿里 AliDNS (DoT)", "proto": "dot", "server": "223.5.5.5", "tls_host": "dns.alidns.com", "region": "国内"},
    {"id": "ali_doh", "name": "阿里 AliDNS (DoH)", "proto": "doh", "server": "https://dns.alidns.com/dns-query", "region": "国内"},
    {"id": "tx_udp", "name": "腾讯 DNSPod", "proto": "udp", "server": "119.29.29.29", "region": "国内"},
    {"id": "tx_dot", "name": "腾讯 DNSPod (DoT)", "proto": "dot", "server": "1.12.12.12", "tls_host": "dot.pub", "region": "国内"},
    {"id": "tx_doh", "name": "腾讯 DNSPod (DoH)", "proto": "doh", "server": "https://doh.pub/dns-query", "region": "国内"},
    {"id": "114_udp", "name": "114DNS", "proto": "udp", "server": "114.114.114.114", "region": "国内"},
    {"id": "cf_udp", "name": "Cloudflare 1.1.1.1", "proto": "udp", "server": "1.1.1.1", "region": "海外"},
    {"id": "cf_dot", "name": "Cloudflare (DoT)", "proto": "dot", "server": "1.1.1.1", "tls_host": "one.one.one.one", "region": "海外"},
    {"id": "cf_doh", "name": "Cloudflare (DoH)", "proto": "doh", "server": "https://cloudflare-dns.com/dns-query", "region": "海外"},
    {"id": "gg_udp", "name": "Google 8.8.8.8", "proto": "udp", "server": "8.8.8.8", "region": "海外"},
    {"id": "gg_dot", "name": "Google (DoT)", "proto": "dot", "server": "8.8.8.8", "tls_host": "dns.google", "region": "海外"},
    {"id": "gg_doh", "name": "Google (DoH)", "proto": "doh", "server": "https://dns.google/dns-query", "region": "海外"},
]


@dataclass
class PollutionCell:
    """Pollution verdict for a (domain, server) pair."""
    server_label: str
    server_ip: str
    status: str  # "CLEAN", "FAKE_IP", "POISONED", "TIMEOUT"
    answers: List[str]
    latency_ms: float
    detail: str = ""

    def to_dict(self) -> dict:
        return {
            "server_label": self.server_label,
            "server_ip": self.server_ip,
            "status": self.status,
            "answers": self.answers,
            "latency_ms": round(self.latency_ms, 2),
            "detail": self.detail,
        }


@dataclass
class DomainPollutionRow:
    """Pollution audit row for one test domain across baseline and UDP servers."""
    domain: str
    label: str
    baseline_ips: List[str]
    baseline_source: str
    results: List[PollutionCell]
    polluted_count: int

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "label": self.label,
            "baseline_ips": self.baseline_ips,
            "baseline_source": self.baseline_source,
            "results": [r.to_dict() for r in self.results],
            "polluted_count": self.polluted_count,
        }


@dataclass
class PollutionReport:
    """Module 5 Part A output."""
    rows: List[DomainPollutionRow]
    total_checks: int
    poisoned_count: int
    fake_ip_count: int
    timeout_count: int
    pollution_detected: bool
    summary: str
    findings: List[dict]

    def to_dict(self) -> dict:
        return {
            "rows": [r.to_dict() for r in self.rows],
            "total_checks": self.total_checks,
            "poisoned_count": self.poisoned_count,
            "fake_ip_count": self.fake_ip_count,
            "timeout_count": self.timeout_count,
            "pollution_detected": self.pollution_detected,
            "summary": self.summary,
            "findings": self.findings,
        }


@dataclass
class BenchmarkEntry:
    """Aggregated benchmark metrics for a single DNS resolver/protocol."""
    id: str
    name: str
    protocol: str
    server: str
    region: str
    available: bool
    success_rate: float
    min_ms: float
    avg_ms: float
    max_ms: float
    dnssec_ad: bool
    sample_answers: List[str] = field(default_factory=list)
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "protocol": self.protocol.upper(),
            "server": self.server,
            "region": self.region,
            "available": self.available,
            "success_rate": round(self.success_rate, 1),
            "min_ms": round(self.min_ms, 2),
            "avg_ms": round(self.avg_ms, 2),
            "max_ms": round(self.max_ms, 2),
            "dnssec_ad": self.dnssec_ad,
            "sample_answers": self.sample_answers,
            "error": self.error,
        }


@dataclass
class BenchmarkReport:
    """Module 5 Part B output."""
    entries: List[BenchmarkEntry]
    fastest_domestic: Optional[BenchmarkEntry]
    fastest_overseas: Optional[BenchmarkEntry]
    fastest_encrypted: Optional[BenchmarkEntry]

    def to_dict(self) -> dict:
        return {
            "entries": [e.to_dict() for e in self.entries],
            "fastest_domestic": self.fastest_domestic.to_dict() if self.fastest_domestic else None,
            "fastest_overseas": self.fastest_overseas.to_dict() if self.fastest_overseas else None,
            "fastest_encrypted": self.fastest_encrypted.to_dict() if self.fastest_encrypted else None,
        }


def is_bogon_or_forged_ip(ip_str: str, domain: str) -> Optional[str]:
    """
    Check if an IP returned for a public domain is a known bogon, blackhole,
    or classic GFW poisoned IP. Returns reason string if poisoned, else None.
    """
    if ip_str in KNOWN_POISONED_EXACT_IPS:
        return f"命中已知黑洞/污染 IP ({ip_str})"

    try:
        addr = ipaddress.ip_address(ip_str)
        if addr.is_loopback or addr.is_unspecified or addr.is_multicast:
            return f"返回无效回环/保留地址 ({ip_str})"
        if addr.is_private and not is_fake_ip(ip_str):
            return f"返回内网私有地址 ({ip_str})"
    except ValueError:
        return f"无效 IP 格式 ({ip_str})"

    # Cross-brand poisoning: e.g., Google/YouTube/Telegram returning Meta/Facebook or Dropbox IPs
    if any(ip_str.startswith(pfx) for pfx in FORGED_CROSS_BRAND_PREFIXES):
        if not any(k in domain for k in ("facebook", "fb.", "instagram", "dropbox")):
            return f"疑似 GFW 跨品牌抢答伪造 IP ({ip_str})"

    return None


def classify_pollution_result(
    domain: str,
    server_label: str,
    server_ip: str,
    res: DNSQueryResult,
    baseline_ips: List[str],
    baseline_asns: Set[str],
    intel_map: Dict[str, IPIntel],
) -> PollutionCell:
    """Classify a single DNS query result for pollution / Fake-IP / Clean."""
    if not res.success or not res.answers:
        return PollutionCell(
            server_label=server_label,
            server_ip=server_ip,
            status="TIMEOUT",
            answers=[],
            latency_ms=res.latency_ms,
            detail=res.error or f"无 A 记录 ({res.rcode})",
        )

    ans_ips = [a for a in res.answers if _is_valid_ip(a)]
    if not ans_ips:
        return PollutionCell(
            server_label=server_label,
            server_ip=server_ip,
            status="TIMEOUT",
            answers=res.answers,
            latency_ms=res.latency_ms,
            detail="仅返回 CNAME 或空记录",
        )

    # Check Fake-IP first
    if any(is_fake_ip(ip) for ip in ans_ips):
        return PollutionCell(
            server_label=server_label,
            server_ip=server_ip,
            status="FAKE_IP",
            answers=ans_ips,
            latency_ms=res.latency_ms,
            detail="代理内核 Fake-IP 接管",
        )

    # Check static poisoned signatures & bogons
    for ip in ans_ips:
        reason = is_bogon_or_forged_ip(ip, domain)
        if reason:
            return PollutionCell(
                server_label=server_label,
                server_ip=server_ip,
                status="POISONED",
                answers=ans_ips,
                latency_ms=res.latency_ms,
                detail=reason,
            )

    # Compare against trusted DoH baseline if available
    if baseline_ips:
        if set(ans_ips) & set(baseline_ips):
            return PollutionCell(
                server_label=server_label,
                server_ip=server_ip,
                status="CLEAN",
                answers=ans_ips,
                latency_ms=res.latency_ms,
                detail="与可信 DoH 基准一致",
            )

        ans_asns = {
            intel_map[ip].asn for ip in ans_ips if ip in intel_map and intel_map[ip].asn
        }
        # If both baseline and answer have ASNs and they are completely disjoint:
        if baseline_asns and ans_asns and not (ans_asns & baseline_asns):
            # If any answer resolves inside China for an overseas domain, or ultra-fast forged packet to 8.8.8.8/1.1.1.1
            is_domestic_ans = any(
                ip in intel_map and intel_map[ip].is_cn for ip in ans_ips
            )
            if is_domestic_ans:
                return PollutionCell(
                    server_label=server_label,
                    server_ip=server_ip,
                    status="POISONED",
                    answers=ans_ips,
                    latency_ms=res.latency_ms,
                    detail=f"被重定向至国内 IP ({', '.join(ans_asns)})，与可信基准 ({', '.join(baseline_asns)}) 不符",
                )
            if server_ip in ("8.8.8.8", "1.1.1.1") and res.latency_ms < 20.0:
                return PollutionCell(
                    server_label=server_label,
                    server_ip=server_ip,
                    status="POISONED",
                    answers=ans_ips,
                    latency_ms=res.latency_ms,
                    detail=f"疑似 UDP-53 抢答投毒 (耗时仅 {res.latency_ms:.1f}ms，ASN {', '.join(ans_asns)} 与基准不符)",
                )
            return PollutionCell(
                server_label=server_label,
                server_ip=server_ip,
                status="POISONED",
                answers=ans_ips,
                latency_ms=res.latency_ms,
                detail=f"ASN 偏离可信基准 (返回 {', '.join(ans_asns)} vs 基准 {', '.join(baseline_asns)})",
            )

    return PollutionCell(
        server_label=server_label,
        server_ip=server_ip,
        status="CLEAN",
        answers=ans_ips,
        latency_ms=res.latency_ms,
        detail="解析结果正常",
    )


def _is_valid_ip(val: str) -> bool:
    try:
        ipaddress.ip_address(val)
        return True
    except ValueError:
        return False


def _get_doh_baseline(domain: str) -> Tuple[List[str], str]:
    """Query trusted DoH providers to get clean baseline IP answers."""
    doh_endpoints = [
        ("Cloudflare DoH", "https://cloudflare-dns.com/dns-query"),
        ("Google DoH", "https://dns.google/dns-query"),
        ("阿里 AliDNS DoH", "https://dns.alidns.com/dns-query"),
    ]
    for name, url in doh_endpoints:
        res = query_doh(url, domain, qtype=TYPE_A, timeout=3.0)
        ips = [a for a in res.answers if _is_valid_ip(a) and not is_fake_ip(a)]
        if res.success and ips:
            return ips, name
    return [], "无可用 DoH 基准"


def run_pollution_detection() -> PollutionReport:
    """Execute Module 5 Part A: DNS Pollution / Poisoning Detection."""
    scutil_defaults, _ = parse_macos_scutil_dns()
    resolv_servers = parse_resolv_conf()
    sys_dns = (scutil_defaults + resolv_servers or ["127.0.0.1"])[0]

    test_servers: List[Tuple[str, str]] = [
        (f"系统默认 ({sys_dns})", sys_dns),
        ("114DNS (UDP)", "114.114.114.114"),
        ("阿里 AliDNS (UDP)", "223.5.5.5"),
        ("Google (明文 UDP-53)", "8.8.8.8"),
        ("Cloudflare (明文 UDP-53)", "1.1.1.1"),
    ]

    # Step 1: Fetch DoH baselines & raw UDP probe results concurrently
    baselines: Dict[str, Tuple[List[str], str]] = {}
    probe_matrix: Dict[Tuple[str, str], DNSQueryResult] = {}

    with ThreadPoolExecutor(max_workers=12) as pool:
        base_futs = {pool.submit(_get_doh_baseline, dom): dom for dom, _ in POLLUTION_TEST_DOMAINS}
        udp_futs = {
            pool.submit(query_udp, srv_ip, dom, TYPE_A, 1, 53, 2.2): (dom, srv_label, srv_ip)
            for dom, _ in POLLUTION_TEST_DOMAINS
            for srv_label, srv_ip in test_servers
        }

        for fut, dom in base_futs.items():
            baselines[dom] = fut.result()

        for fut, (dom, _, srv_ip) in udp_futs.items():
            probe_matrix[(dom, srv_ip)] = fut.result()

    # Step 2: Enrich all discovered IPs to compare ASNs accurately
    ips_to_enrich: Set[str] = set()
    for b_ips, _ in baselines.values():
        ips_to_enrich.update(b_ips)
    for res in probe_matrix.values():
        for a in res.answers:
            if _is_valid_ip(a) and not is_fake_ip(a):
                ips_to_enrich.add(a)

    intel_map = enrich_ips_batch(ips_to_enrich)

    # Step 3: Evaluate every domain row
    rows: List[DomainPollutionRow] = []
    total_checks = 0
    poisoned_count = 0
    fake_ip_count = 0
    timeout_count = 0

    for dom, label in POLLUTION_TEST_DOMAINS:
        b_ips, b_src = baselines.get(dom, ([], "无"))
        b_asns = {intel_map[ip].asn for ip in b_ips if ip in intel_map and intel_map[ip].asn}
        cells: List[PollutionCell] = []
        row_poisoned = 0

        for srv_label, srv_ip in test_servers:
            res = probe_matrix[(dom, srv_ip)]
            cell = classify_pollution_result(dom, srv_label, srv_ip, res, b_ips, b_asns, intel_map)
            cells.append(cell)
            total_checks += 1
            if cell.status == "POISONED":
                poisoned_count += 1
                row_poisoned += 1
            elif cell.status == "FAKE_IP":
                fake_ip_count += 1
            elif cell.status == "TIMEOUT":
                timeout_count += 1

        rows.append(
            DomainPollutionRow(
                domain=dom,
                label=label,
                baseline_ips=b_ips,
                baseline_source=b_src,
                results=cells,
                polluted_count=row_poisoned,
            )
        )

    pollution_detected = poisoned_count > 0
    findings: List[dict] = []

    if pollution_detected:
        summary = f"在 {total_checks} 次探测中发现 {poisoned_count} 次明文 DNS 污染/抢答投毒"
        findings.append(
            {
                "level": "danger",
                "title": summary,
                "detail": "向传统 UDP 53 端口发送明文查询时收到伪造 IP 或黑洞应答。切勿在跨境场景直接依赖明文 UDP 53 DNS，请使用 DoH / DoT 或代理远端解析。",
            }
        )
    else:
        summary = "明文探测未触发典型投毒特征（或已被代理 TUN/Fake-IP 接管）"
        findings.append(
            {
                "level": "ok",
                "title": summary,
                "detail": "所有有效响应均与 DoH 基准一致，或已由本地代理 Fake-IP 接管保护。",
            }
        )

    if fake_ip_count > 0:
        findings.append(
            {
                "level": "info",
                "title": f"系统默认 DNS 返回了 {fake_ip_count} 次 Fake-IP 映射",
                "detail": "代理客户端的 TUN/Fake-IP 机制已接管本地系统查询，能够免疫传统 UDP DNS 污染。",
            }
        )

    return PollutionReport(
        rows=rows,
        total_checks=total_checks,
        poisoned_count=poisoned_count,
        fake_ip_count=fake_ip_count,
        timeout_count=timeout_count,
        pollution_detected=pollution_detected,
        summary=summary,
        findings=findings,
    )


def _benchmark_single_target(target: dict, rounds: int = 2) -> BenchmarkEntry:
    """Benchmark one DNS resolver entry across multiple queries."""
    test_domains = ["www.baidu.com", "www.cloudflare.com"]
    latencies: List[float] = []
    dnssec_ad = False
    sample_answers: List[str] = []
    last_err: Optional[str] = None
    successes = 0

    proto = target["proto"]
    server = target["server"]
    total_attempts = rounds

    for i in range(total_attempts):
        dom = test_domains[i % len(test_domains)]
        if proto == "udp":
            res = query_udp(server, dom, qtype=TYPE_A, edns_do=True, timeout=2.5)
        elif proto == "dot":
            res = query_dot(
                server,
                dom,
                qtype=TYPE_A,
                tls_hostname=target.get("tls_host"),
                edns_do=True,
                timeout=3.0,
            )
        elif proto == "doh":
            res = query_doh(server, dom, qtype=TYPE_A, edns_do=True, timeout=3.0)
        else:
            continue

        if res.success:
            successes += 1
            latencies.append(res.latency_ms)
            if res.dnssec_ad:
                dnssec_ad = True
            if not sample_answers and res.answers:
                sample_answers = res.answers[:3]
        else:
            last_err = res.error

    available = successes > 0
    success_rate = (successes / total_attempts) * 100.0 if total_attempts else 0.0
    if latencies:
        min_ms = min(latencies)
        avg_ms = statistics.mean(latencies)
        max_ms = max(latencies)
    else:
        min_ms = avg_ms = max_ms = 0.0

    return BenchmarkEntry(
        id=target["id"],
        name=target["name"],
        protocol=proto,
        server=server,
        region=target["region"],
        available=available,
        success_rate=success_rate,
        min_ms=min_ms,
        avg_ms=avg_ms,
        max_ms=max_ms,
        dnssec_ad=dnssec_ad,
        sample_answers=sample_answers,
        error=last_err if not available else None,
    )


def run_dns_benchmark(rounds: int = 2) -> BenchmarkReport:
    """Execute Module 5 Part B: Multi-Protocol DNS Speed & DNSSEC Benchmark."""
    with ThreadPoolExecutor(max_workers=len(BENCHMARK_TARGETS)) as pool:
        futs = [pool.submit(_benchmark_single_target, t, rounds) for t in BENCHMARK_TARGETS]
        entries = [f.result() for f in futs]

    # Sort available entries first by avg_ms ascending, unavailable at the bottom
    entries.sort(key=lambda e: (not e.available, e.avg_ms if e.available else 999999.0))

    avail = [e for e in entries if e.available]
    fastest_domestic = next((e for e in avail if e.region == "国内"), None)
    fastest_overseas = next((e for e in avail if e.region == "海外"), None)
    fastest_encrypted = next((e for e in avail if e.protocol in ("dot", "doh")), None)

    return BenchmarkReport(
        entries=entries,
        fastest_domestic=fastest_domestic,
        fastest_overseas=fastest_overseas,
        fastest_encrypted=fastest_encrypted,
    )
