"""
Core DNS diagnostic, Interactsh OAST leak attribution, split-routing, WebRTC/STUN,
pollution/benchmark, and AI service unlock modules, plus the unified orchestrator.
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Optional

from dnscheck.detectors.ai_services import AIServicesReport, run_ai_services_diagnostics
from dnscheck.detectors.dns_leak import DNSLeakReport, run_dns_leak_detection
from dnscheck.detectors.pollution_bench import (
    BenchmarkReport,
    PollutionReport,
    run_dns_benchmark,
    run_pollution_detection,
)
from dnscheck.detectors.proxy_audit import ProxyAuditReport, run_proxy_config_audit
from dnscheck.detectors.split_route import SplitRouteReport, run_split_route_diagnostics
from dnscheck.detectors.system_env import SystemEnvReport, run_system_env_diagnostics
from dnscheck.detectors.webrtc_ipv6 import WebRTCLeakReport, run_webrtc_ipv6_diagnostics
from dnscheck.enricher.ip_intel import enrich_ips_batch
from dnscheck.protocol.dns_packet import NAME_TO_TYPE, TYPE_A
from dnscheck.protocol.transports import (
    DNSQueryResult,
    query_doh,
    query_dot,
    query_system_resolver,
    query_tcp,
    query_udp,
)

__all__ = [
    "run_system_env_diagnostics",
    "run_split_route_diagnostics",
    "run_dns_leak_detection",
    "run_webrtc_ipv6_diagnostics",
    "run_pollution_detection",
    "run_dns_benchmark",
    "AIServicesReport",
    "run_ai_services_diagnostics",
    "ProxyAuditReport",
    "run_proxy_config_audit",
    "run_full_audit",
    "run_custom_dig",
]


def run_full_audit(
    oast_server: Optional[str] = None,
    oast_token: Optional[str] = None,
) -> dict:
    """
    Execute all diagnostic modules concurrently where independent, compute overall
    security score & actionable recommendations, and return a serializable dict.
    """
    t0 = time.perf_counter()

    # Phase 1: System Env, Split-Routing & Read-Only Proxy Rule Audit (fast, needed as context)
    with ThreadPoolExecutor(max_workers=3) as pool:
        f_env = pool.submit(run_system_env_diagnostics)
        f_split = pool.submit(run_split_route_diagnostics)
        f_paudit = pool.submit(run_proxy_config_audit)
        env_report: SystemEnvReport = f_env.result()
        split_report: SplitRouteReport = f_split.result()
        proxy_audit: ProxyAuditReport = f_paudit.result()

    # Phase 2: Deep DNS Leak (OAST), WebRTC/STUN, Pollution Detection, Benchmark, and AI Services
    with ThreadPoolExecutor(max_workers=5) as pool:
        f_leak = pool.submit(run_dns_leak_detection, split_report, 6, oast_server, oast_token)
        f_rtc = pool.submit(run_webrtc_ipv6_diagnostics, split_report)
        f_pol = pool.submit(run_pollution_detection)
        f_bench = pool.submit(run_dns_benchmark, 2)
        f_ai = pool.submit(run_ai_services_diagnostics, split_report)

        leak_report: DNSLeakReport = f_leak.result()
        rtc_report: WebRTCLeakReport = f_rtc.result()
        pol_report: PollutionReport = f_pol.result()
        bench_report: BenchmarkReport = f_bench.result()
        ai_report: AIServicesReport = f_ai.result()

    # Compute overall composite security score (0-100)
    score = leak_report.risk_score
    if rtc_report.webrtc_udp_leak:
        score -= 20
    if rtc_report.ipv6_leak:
        score -= 10
    if pol_report.pollution_detected:
        # Plain UDP-53 pollution is expected in CN networks, penalize more if system default DNS itself is poisoned
        sys_poisoned = any(
            row.results and row.results[0].status == "POISONED" for row in pol_report.rows
        )
        score -= 25 if sys_poisoned else 5

    overall_score = max(0, min(100, score))

    if overall_score >= 85 and leak_report.leak_status == "SAFE" and not rtc_report.webrtc_udp_leak:
        verdict = "SAFE"
        verdict_label = "安全优秀 (无 DNS / WebRTC 泄漏)"
    elif overall_score >= 60:
        verdict = "WARNING"
        verdict_label = "存在分流或潜在泄漏风险 (建议检查告警项)"
    else:
        verdict = "LEAK"
        verdict_label = "高危泄漏风险 (请立即修复 DNS / 代理配置)"

    # Build deduplicated actionable recommendations
    recommendations = []
    if leak_report.concurrent_race_leak:
        recommendations.append(
            "检测到代理 DNS 并发抢答泄漏 (nameserver + fallback 竞速)，请配置严格的 nameserver-policy 按国内外域名分流，并在 IP 规则末尾添加 ,no-resolve。"
        )
    if leak_report.qtype65_leak:
        recommendations.append(
            "检测到 DNS Type 65 (HTTPS 记录) 穿透 Fake-IP 泄漏，请在 Mihomo / Clash 上游服务器后添加 #disable-qtype-65=true。"
        )
    if leak_report.direct_bypass_leak:
        recommendations.append(
            "当前仅代理通道安全而本机系统解析仍在直连国内 DNS，请开启代理客户端的 TUN 虚拟网卡 + Fake-IP 全局接管。"
        )
    if leak_report.leak_status == "LEAK" and not leak_report.concurrent_race_leak:
        recommendations.append(
            "开启代理客户端的 TUN 模式或 Fake-IP 模式，确保系统及终端的 DNS 查询走加密通道或远端解析。"
        )
    if leak_report.transparent_hijack_detected:
        recommendations.append(
            "本地网络存在 UDP 53 端口透明劫持，请将明文 DNS 切换为 DoH (HTTPS) 或 DoT (TLS) 加密协议。"
        )
    if rtc_report.webrtc_udp_leak:
        recommendations.append(
            "已检测到 UDP / STUN 真实 IP 泄漏，请在代理工具中开启 UDP 转发，并在浏览器配置禁用非代理 WebRTC UDP。"
        )
    if rtc_report.ipv6_leak:
        recommendations.append(
            "检测到 IPv6 双栈绕过代理暴露国内真实 IP，建议在代理软件接管 IPv6 流量或关闭本机公网 IPv6。"
        )
    if env_report.ecs_exposes_cn_subnet and split_report.proxy_detected:
        recommendations.append(
            "当前递归 DNS 启用了 ECS 并暴露国内 IP 段，如需更强隐私，可改用不传递 ECS 的隐私 DNS（如 Cloudflare 1.1.1.1 / Quad9）。"
        )
    if ai_report.region_blocked_count > 0:
        recommendations.append(
            f"检测到 {ai_report.region_blocked_count} 项一线 AI 服务受出口地区限制 (CN/HK 锁区)，建议将 OpenAI/Claude/Gemini 规则切换至美/日/新/台节点。"
        )
    if ai_report.unreachable_count > 0:
        recommendations.append(
            f"检测到 {ai_report.unreachable_count} 项 AI 端点无法连通，请检查代理规则覆盖或本地 DNS 污染情况。"
        )
    if bench_report.fastest_encrypted:
        fe = bench_report.fastest_encrypted
        recommendations.append(
            f"当前测速最快的加密 DNS 为 {fe.name} ({fe.avg_ms:.1f}ms)，建议优先选用。"
        )

    if proxy_audit.client_detected and proxy_audit.rule_explain and proxy_audit.rule_explain.triggered_local_dns:
        trig = proxy_audit.rule_explain.trigger_rule or "IP 规则"
        recommendations.insert(
            0,
            f"检测到 {proxy_audit.client_name} 配置 `{proxy_audit.active_profile}` 命中 `{trig}` 触发本地 DNS 预解析，请为该规则及所有 IP/GEOIP 规则补齐 `,no-resolve`。",
        )

    elapsed_ms = (time.perf_counter() - t0) * 1000.0

    return {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "elapsed_ms": round(elapsed_ms, 2),
        "overall_score": overall_score,
        "overall_verdict": verdict,
        "overall_verdict_label": verdict_label,
        "recommendations": recommendations,
        "env": env_report.to_dict(),
        "proxy_audit": proxy_audit.to_dict(),
        "split": split_report.to_dict(),
        "leak": leak_report.to_dict(),
        "webrtc": rtc_report.to_dict(),
        "pollution": pol_report.to_dict(),
        "benchmark": bench_report.to_dict(),
        "ai": ai_report.to_dict(),
    }


def run_custom_dig(
    domain: str,
    server: str = "223.5.5.5",
    proto: str = "udp",
    qtype_name: str = "A",
    ecs: Optional[str] = None,
    edns_do: bool = True,
) -> dict:
    """Execute a custom DNS query (dig-style) over UDP, TCP, DoT, DoH, or System stub."""
    qtype = NAME_TO_TYPE.get(qtype_name.upper(), TYPE_A)
    proto = proto.lower().strip()

    ecs_ip: Optional[str] = None
    ecs_prefix: Optional[int] = None
    if ecs:
        if "/" in ecs:
            ecs_ip, pfx_str = ecs.split("/", 1)
            ecs_prefix = int(pfx_str)
        else:
            ecs_ip = ecs.strip()

    if proto == "system":
        res: DNSQueryResult = query_system_resolver(domain, qtype=qtype)
    elif proto == "tcp":
        res = query_tcp(domain=domain, server=server, qtype=qtype, edns_do=edns_do, ecs_ip=ecs_ip, ecs_prefix=ecs_prefix)
    elif proto == "dot":
        tls_host = None
        if server in ("1.1.1.1", "1.0.0.1"):
            tls_host = "one.one.one.one"
        elif server in ("8.8.8.8", "8.8.4.4"):
            tls_host = "dns.google"
        elif server in ("223.5.5.5", "223.6.6.6"):
            tls_host = "dns.alidns.com"
        elif server in ("1.12.12.12", "120.53.53.53"):
            tls_host = "dot.pub"
        res = query_dot(
            server=server,
            domain=domain,
            qtype=qtype,
            tls_hostname=tls_host,
            edns_do=edns_do,
            ecs_ip=ecs_ip,
            ecs_prefix=ecs_prefix,
        )
    elif proto == "doh":
        url = server
        if not server.startswith("http"):
            preset = {
                "1.1.1.1": "https://cloudflare-dns.com/dns-query",
                "8.8.8.8": "https://dns.google/dns-query",
                "223.5.5.5": "https://dns.alidns.com/dns-query",
                "119.29.29.29": "https://doh.pub/dns-query",
            }
            url = preset.get(server, f"https://{server}/dns-query")
        res = query_doh(
            endpoint_url=url,
            domain=domain,
            qtype=qtype,
            edns_do=edns_do,
            ecs_ip=ecs_ip,
            ecs_prefix=ecs_prefix,
        )
    else:
        res = query_udp(domain=domain, server=server, qtype=qtype, edns_do=edns_do, ecs_ip=ecs_ip, ecs_prefix=ecs_prefix)

    # Enrich IP answers if any
    ip_answers = [a for a in res.answers if "." in a or ":" in a]
    intel_map = enrich_ips_batch(ip_answers) if ip_answers else {}

    out = res.to_dict()
    out["answer_intel"] = {ip: intel.to_dict() for ip, intel in intel_map.items()}
    if res.packet:
        out["packet_flags"] = res.packet.to_dict()["flags"]
        out["edns_udp_size"] = res.packet.edns_udp_size
    return out
