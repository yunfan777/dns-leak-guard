"""
Module 4: WebRTC / STUN UDP Public IP Leak & IPv6 Dual-Stack Leak Detection.
Uses pure-Python RFC 5389 STUN Binding Requests over raw UDP sockets to uncover
whether UDP traffic bypasses HTTP/TCP proxies and exposes the user's real domestic ISP IP,
plus enumerates local LAN interface addresses (equivalent to WebRTC host/srflx candidates).
"""

from __future__ import annotations

import re
import subprocess
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from dnscheck.detectors.split_route import SplitRouteReport
from dnscheck.enricher.ip_intel import IPIntel, enrich_ip, enrich_ips_batch
from dnscheck.protocol.stun import DEFAULT_STUN_SERVERS, STUNProbeResult, probe_stun_server


@dataclass
class LocalInterfaceIP:
    """Local LAN or virtual interface IP address."""
    interface: str
    ip: str
    family: str  # "IPv4" or "IPv6"

    def to_dict(self) -> dict:
        return {
            "interface": self.interface,
            "ip": self.ip,
            "family": self.family,
        }


@dataclass
class WebRTCLeakReport:
    """Report of STUN/UDP public IP exposure, LAN host candidates, and IPv6 leak state."""
    local_lan_ips: List[LocalInterfaceIP]
    stun_probes: List[dict]
    overseas_stun_ips: List[str]
    domestic_stun_ips: List[str]
    webrtc_udp_leak: bool
    ipv6_leak: bool
    ipv6_addresses: List[str]
    verdict_label: str
    findings: List[dict]

    def to_dict(self) -> dict:
        return {
            "local_lan_ips": [l.to_dict() for l in self.local_lan_ips],
            "stun_probes": self.stun_probes,
            "overseas_stun_ips": self.overseas_stun_ips,
            "domestic_stun_ips": self.domestic_stun_ips,
            "webrtc_udp_leak": self.webrtc_udp_leak,
            "ipv6_leak": self.ipv6_leak,
            "ipv6_addresses": self.ipv6_addresses,
            "verdict_label": self.verdict_label,
            "findings": self.findings,
        }


def get_local_lan_ips() -> List[LocalInterfaceIP]:
    """Enumerate local non-loopback IPv4 and global/ULA IPv6 addresses via `ifconfig`."""
    results: List[LocalInterfaceIP] = []
    try:
        proc = subprocess.run(
            ["ifconfig"],
            capture_output=True,
            text=True,
            timeout=3.0,
            check=False,
        )
        out = proc.stdout or ""
    except Exception:
        return results

    current_iface: Optional[str] = None
    for line in out.splitlines():
        m_header = re.match(r"^([a-zA-Z0-9_]+):\s+flags=", line)
        if m_header:
            current_iface = m_header.group(1)
            continue
        if not current_iface or current_iface.startswith("lo"):
            continue

        m_v4 = re.search(r"\binet\s+(\d+\.\d+\.\d+\.\d+)", line)
        if m_v4:
            ip = m_v4.group(1)
            if not ip.startswith("127."):
                results.append(LocalInterfaceIP(interface=current_iface, ip=ip, family="IPv4"))

        m_v6 = re.search(r"\binet6\s+([0-9a-fA-F:]+)", line)
        if m_v6:
            v6 = m_v6.group(1)
            if not v6.startswith("fe80:") and v6 != "::1":
                results.append(LocalInterfaceIP(interface=current_iface, ip=v6, family="IPv6"))

    return results


def run_webrtc_ipv6_diagnostics(
    split_report: Optional[SplitRouteReport] = None,
    timeout: float = 2.0,
) -> WebRTCLeakReport:
    """Execute Module 4: STUN/WebRTC UDP Leak & IPv6 Dual-Stack Leak Detection."""
    local_ips = get_local_lan_ips()

    probe_results: List[STUNProbeResult] = []
    # Run IPv4 STUN probes concurrently + IPv6 STUN probe to Google/Cloudflare
    with ThreadPoolExecutor(max_workers=len(DEFAULT_STUN_SERVERS) + 2) as pool:
        v4_futs = [
            pool.submit(probe_stun_server, name, host, port, region, timeout, False)
            for name, host, port, region in DEFAULT_STUN_SERVERS
        ]
        v6_futs = [
            pool.submit(probe_stun_server, "Google STUN (IPv6)", "stun.l.google.com", 19302, "GLOBAL", timeout, True),
            pool.submit(probe_stun_server, "Cloudflare STUN (IPv6)", "stun.cloudflare.com", 3478, "GLOBAL", timeout, True),
        ]
        for f in v4_futs + v6_futs:
            probe_results.append(f.result())

    mapped_ips = [p.mapped_ip for p in probe_results if p.success and p.mapped_ip]
    intel_map: Dict[str, IPIntel] = enrich_ips_batch(mapped_ips)

    enriched_probes: List[dict] = []
    overseas_stun_ips: List[str] = []
    domestic_stun_ips: List[str] = []
    ipv6_addresses: List[str] = []

    for p in probe_results:
        p_dict = p.to_dict()
        intel: Optional[IPIntel] = None
        if p.success and p.mapped_ip:
            intel = intel_map.get(p.mapped_ip) or enrich_ip(p.mapped_ip)
            p_dict["intel"] = intel.to_dict()
            if p.ip_version == 6 and p.mapped_ip not in ipv6_addresses:
                ipv6_addresses.append(p.mapped_ip)

            if p.region == "GLOBAL":
                if p.mapped_ip not in overseas_stun_ips:
                    overseas_stun_ips.append(p.mapped_ip)
            else:
                if p.mapped_ip not in domestic_stun_ips:
                    domestic_stun_ips.append(p.mapped_ip)
        else:
            p_dict["intel"] = None
        enriched_probes.append(p_dict)

    # Evaluate WebRTC / UDP Leak
    webrtc_udp_leak = False
    leaked_cn_ips: List[str] = []
    proxy_active = bool(split_report and split_report.proxy_detected)

    if proxy_active:
        for p_dict in enriched_probes:
            if p_dict["success"] and p_dict["region"] == "GLOBAL" and p_dict["intel"]:
                if p_dict["intel"]["is_cn"]:
                    webrtc_udp_leak = True
                    if p_dict["mapped_ip"] not in leaked_cn_ips:
                        leaked_cn_ips.append(p_dict["mapped_ip"])

    # Evaluate IPv6 Leak
    ipv6_leak = bool(split_report and split_report.ipv6_leak_risk)
    if split_report and split_report.ipv6_ip and split_report.ipv6_ip not in ipv6_addresses:
        ipv6_addresses.insert(0, split_report.ipv6_ip)

    if proxy_active and not ipv6_leak:
        for p_dict in enriched_probes:
            if p_dict["success"] and p_dict["ip_version"] == 6 and p_dict["intel"] and p_dict["intel"]["is_cn"]:
                ipv6_leak = True

    findings: List[dict] = []
    if webrtc_udp_leak:
        findings.append(
            {
                "level": "danger",
                "title": f"检测到 UDP / WebRTC 真实公网 IP 泄漏: {', '.join(leaked_cn_ips)}",
                "detail": (
                    "海外 HTTP/TCP 流量已走代理出口，但发往海外 STUN 服务器的 UDP 穿透包绕过了代理直连国内宽带出口。"
                    "浏览器中的 WebRTC 视频/语音连接或 STUN 请求会直接暴露您的真实公网 IP，建议开启代理的 TUN 模式并启用 UDP 转发，或在浏览器中禁用非代理 WebRTC UDP。"
                ),
            }
        )
    elif proxy_active:
        if overseas_stun_ips:
            findings.append(
                {
                    "level": "ok",
                    "title": "UDP / STUN 穿透已由代理接管，未发现公网 IP 泄漏",
                    "detail": f"海外 STUN 服务器看到的 UDP 公网映射 IP 为 {', '.join(overseas_stun_ips)}，无国内真实宽带 IP 暴露。",
                }
            )
        else:
            findings.append(
                {
                    "level": "info",
                    "title": "海外 STUN UDP 探测未通（UDP 已被拦截或代理未转发 UDP）",
                    "detail": "未能通过 UDP 直连海外 STUN 服务器，因此在系统层面不会通过 STUN 泄漏真实公网 IP；建议在 Web 面板中同步验证浏览器 WebRTC。",
                }
            )
    else:
        findings.append(
            {
                "level": "info",
                "title": "当前未开启海外代理，STUN 映射反映本地直连出口",
                "detail": (
                    f"STUN 检测到的公网 UDP IP 为 {', '.join(overseas_stun_ips or domestic_stun_ips or ['无'])}。"
                    f"共发现 {len(local_ips)} 个本地网卡地址（WebRTC Host 候选）。"
                ),
            }
        )

    if ipv6_leak:
        findings.append(
            {
                "level": "danger",
                "title": f"存在 IPv6 双栈绕过泄漏: {', '.join(ipv6_addresses)}",
                "detail": "系统同时拥有国内运营商公网 IPv6 地址，访问双栈海外站点时可能绕过 IPv4 代理直连暴露。",
            }
        )

    if webrtc_udp_leak or ipv6_leak:
        verdict_label = "存在真实 IP 泄漏风险 (WebRTC/UDP 或 IPv6)"
    elif proxy_active:
        verdict_label = "UDP / IPv6 防护正常 (无真实 IP 泄漏)"
    else:
        verdict_label = "直连模式 (本地 UDP/IPv6 状态正常)"

    return WebRTCLeakReport(
        local_lan_ips=local_ips,
        stun_probes=enriched_probes,
        overseas_stun_ips=overseas_stun_ips,
        domestic_stun_ips=domestic_stun_ips,
        webrtc_udp_leak=webrtc_udp_leak,
        ipv6_leak=ipv6_leak,
        ipv6_addresses=ipv6_addresses,
        verdict_label=verdict_label,
        findings=findings,
    )
