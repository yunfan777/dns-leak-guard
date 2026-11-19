"""
Module 1: Local System DNS Environment & Proxy/TUN Architecture Diagnostics.
- Parses /etc/resolv.conf and macOS `scutil --dns`
- Parses macOS `scutil --proxy` and environment proxy settings
- Scans active network interfaces (`ifconfig`) for TUN/utun virtual adapters
- Detects Fake-IP vs Redir-Host / Real-IP mode
- Evaluates EDNS Client Subnet (ECS) behavior
"""

from __future__ import annotations

import os
import platform
import re
import subprocess
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from dnscheck.enricher.ip_intel import IPIntel, enrich_ip, enrich_ips_batch, is_fake_ip
from dnscheck.protocol.dns_packet import TYPE_A, TYPE_TXT
from dnscheck.protocol.transports import query_system_resolver, query_udp


@dataclass
class TUNInterfaceInfo:
    """Detected TUN/virtual network interface."""
    name: str
    ipv4: List[str] = field(default_factory=list)
    ipv6: List[str] = field(default_factory=list)
    is_fake_ip_tun: bool = False
    likely_client: str = "Unknown Virtual Adapter"

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "ipv4": self.ipv4,
            "ipv6": self.ipv6,
            "is_fake_ip_tun": self.is_fake_ip_tun,
            "likely_client": self.likely_client,
        }


@dataclass
class SystemEnvReport:
    """Comprehensive report of the local system DNS & network environment."""
    os_name: str
    resolv_conf_servers: List[str]
    scutil_default_servers: List[str]
    scutil_scoped_resolvers: List[dict]
    configured_dns_details: List[dict]
    tun_interfaces: List[TUNInterfaceInfo]
    system_proxy: dict
    dns_mode: str  # "Fake-IP (TUN/代理接管)", "TUN 真实 IP / Redir-Host", "系统代理 (System Proxy)", "标准直连 (Direct)"
    fake_ip_active: bool
    fake_ip_samples: List[dict]
    ecs_supported: bool
    ecs_subnet: Optional[str]
    ecs_exposes_cn_subnet: bool
    findings: List[dict]

    def to_dict(self) -> dict:
        return {
            "os_name": self.os_name,
            "resolv_conf_servers": self.resolv_conf_servers,
            "scutil_default_servers": self.scutil_default_servers,
            "scutil_scoped_resolvers": self.scutil_scoped_resolvers,
            "configured_dns_details": self.configured_dns_details,
            "tun_interfaces": [t.to_dict() for t in self.tun_interfaces],
            "system_proxy": self.system_proxy,
            "dns_mode": self.dns_mode,
            "fake_ip_active": self.fake_ip_active,
            "fake_ip_samples": self.fake_ip_samples,
            "ecs_supported": self.ecs_supported,
            "ecs_subnet": self.ecs_subnet,
            "ecs_exposes_cn_subnet": self.ecs_exposes_cn_subnet,
            "findings": self.findings,
        }


def parse_resolv_conf(path: str = "/etc/resolv.conf") -> List[str]:
    """Read nameserver entries from /etc/resolv.conf."""
    servers: List[str] = []
    if not os.path.exists(path):
        return servers
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) >= 2 and parts[0].lower() == "nameserver":
                    ip = parts[1].split("%")[0]
                    if ip not in servers:
                        servers.append(ip)
    except Exception:
        pass
    return servers


def parse_macos_scutil_dns() -> Tuple[List[str], List[dict]]:
    """Parse macOS `scutil --dns` output for default and interface-scoped DNS resolvers."""
    default_servers: List[str] = []
    scoped_resolvers: List[dict] = []
    if platform.system() != "Darwin":
        return default_servers, scoped_resolvers

    try:
        proc = subprocess.run(
            ["scutil", "--dns"],
            capture_output=True,
            text=True,
            timeout=3.0,
            check=False,
        )
        output = proc.stdout or ""
    except Exception:
        return default_servers, scoped_resolvers

    # Split into resolver blocks
    blocks = re.split(r"\n(?=resolver #\d+)", output)
    for block in blocks:
        m_id = re.search(r"resolver #(\d+)", block)
        if not m_id:
            continue
        res_id = m_id.group(1)
        nameservers = re.findall(r"nameserver\[\d+\]\s*:\s*([^\s]+)", block)
        nameservers = [ns.split("%")[0] for ns in nameservers]
        if not nameservers:
            continue

        m_iface = re.search(r"if_index\s*:\s*\d+\s*\(([^)]+)\)", block)
        iface = m_iface.group(1) if m_iface else None
        m_domain = re.search(r"domain\s*:\s*([^\s]+)", block)
        domain = m_domain.group(1) if m_domain else None
        flags_m = re.search(r"flags\s*:\s*(.+)", block)
        flags_str = flags_m.group(1).strip() if flags_m else ""

        if "Scoped" not in flags_str and not domain:
            for ns in nameservers:
                if ns not in default_servers:
                    default_servers.append(ns)

        scoped_resolvers.append(
            {
                "resolver_id": f"#{res_id}",
                "interface": iface or "global",
                "domain": domain or "*",
                "nameservers": nameservers,
                "flags": flags_str,
            }
        )

    return default_servers, scoped_resolvers


def parse_system_proxy() -> dict:
    """Detect macOS `scutil --proxy` settings and standard environment variables."""
    proxy_info = {
        "http_enabled": False,
        "http_proxy": None,
        "https_enabled": False,
        "https_proxy": None,
        "socks_enabled": False,
        "socks_proxy": None,
        "env_proxy": os.environ.get("ALL_PROXY") or os.environ.get("HTTPS_PROXY") or os.environ.get("HTTP_PROXY"),
    }

    if platform.system() == "Darwin":
        try:
            proc = subprocess.run(
                ["scutil", "--proxy"],
                capture_output=True,
                text=True,
                timeout=2.5,
                check=False,
            )
            out = proc.stdout or ""
            def _extract(key: str) -> Optional[str]:
                m = re.search(rf"\b{key}\s*:\s*([^\s]+)", out)
                return m.group(1) if m else None

            if _extract("HTTPEnable") == "1":
                h_host = _extract("HTTPProxy")
                h_port = _extract("HTTPPort")
                if h_host:
                    proxy_info["http_enabled"] = True
                    proxy_info["http_proxy"] = f"{h_host}:{h_port}" if h_port else h_host

            if _extract("HTTPSEnable") == "1":
                s_host = _extract("HTTPSProxy")
                s_port = _extract("HTTPSPort")
                if s_host:
                    proxy_info["https_enabled"] = True
                    proxy_info["https_proxy"] = f"{s_host}:{s_port}" if s_port else s_host

            if _extract("SOCKSEnable") == "1":
                k_host = _extract("SOCKSProxy")
                k_port = _extract("SOCKSPort")
                if k_host:
                    proxy_info["socks_enabled"] = True
                    proxy_info["socks_proxy"] = f"{k_host}:{k_port}" if k_port else k_host
        except Exception:
            pass

    proxy_info["any_active"] = bool(
        proxy_info["http_enabled"]
        or proxy_info["https_enabled"]
        or proxy_info["socks_enabled"]
        or proxy_info["env_proxy"]
    )
    return proxy_info


def detect_tun_interfaces() -> List[TUNInterfaceInfo]:
    """Scan `ifconfig` output for active TUN/TAP/utun virtual network interfaces."""
    tuns: List[TUNInterfaceInfo] = []
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
        return tuns

    current_iface: Optional[str] = None
    current_v4: List[str] = []
    current_v6: List[str] = []

    def _flush():
        if not current_iface:
            return
        if not re.match(r"^(utun|tun|tap|wg|ppp)\d+", current_iface):
            return
        if not current_v4 and not current_v6:
            return
        has_fake_ip = any(
            ip.startswith("198.18.") or ip.startswith("198.19.") or ip.startswith("28.")
            for ip in current_v4
        )
        likely = "系统/VPN 虚拟隧道"
        if has_fake_ip:
            likely = "Clash / Sing-box / Surge (Fake-IP TUN 网卡)"
        elif any(ip.startswith("172.19.") for ip in current_v4):
            likely = "Sing-box / Clash Meta TUN 虚拟网卡"
        elif any(ip.startswith("100.64.") or ip.startswith("100.") for ip in current_v4):
            likely = "Tailscale / WireGuard / CGNAT 虚拟网卡"
        elif any(ip.startswith("10.") or ip.startswith("172.") for ip in current_v4):
            likely = "代理 TUN 虚拟网卡 / 企业 VPN"

        tuns.append(
            TUNInterfaceInfo(
                name=current_iface,
                ipv4=list(current_v4),
                ipv6=list(current_v6),
                is_fake_ip_tun=has_fake_ip,
                likely_client=likely,
            )
        )

    for line in out.splitlines():
        m_header = re.match(r"^([a-zA-Z0-9_]+):\s+flags=", line)
        if m_header:
            _flush()
            current_iface = m_header.group(1)
            current_v4 = []
            current_v6 = []
            continue
        m_v4 = re.search(r"\binet\s+(\d+\.\d+\.\d+\.\d+)", line)
        if m_v4:
            current_v4.append(m_v4.group(1))
        m_v6 = re.search(r"\binet6\s+([0-9a-fA-F:]+)", line)
        if m_v6:
            v6 = m_v6.group(1)
            if not v6.startswith("fe80:"):
                current_v6.append(v6)
    _flush()
    return tuns


def probe_fake_ip_and_ecs(system_dns_servers: List[str]) -> Tuple[bool, List[dict], bool, Optional[str], bool]:
    """
    1. Probe Fake-IP behavior by resolving overseas & random synthetic domains via system resolver.
    2. Probe EDNS Client Subnet (ECS) behavior via o-o.myaddr.l.google.com TXT record.
    """
    probe_domains = [
        ("www.google.com", "海外受限域名"),
        ("www.youtube.com", "海外流媒体域名"),
        (f"fakeip-probe-{uuid.uuid4().hex[:8]}.example.invalid", "随机不存在域名 (Fake-IP 嗅探)"),
    ]
    fake_ip_samples: List[dict] = []
    fake_ip_detected = False

    for dom, desc in probe_domains:
        res = query_system_resolver(dom, TYPE_A)
        has_fake = any(is_fake_ip(ip) for ip in res.answers)
        if has_fake:
            fake_ip_detected = True
        fake_ip_samples.append(
            {
                "domain": dom,
                "description": desc,
                "answers": res.answers,
                "latency_ms": round(res.latency_ms, 2),
                "is_fake_ip": has_fake,
            }
        )

    # Probe ECS via o-o.myaddr.l.google.com TXT
    ecs_supported = False
    ecs_subnet: Optional[str] = None
    ecs_exposes_cn = False

    target_dns = system_dns_servers[0] if system_dns_servers else "223.5.5.5"
    txt_res = query_udp(target_dns, "o-o.myaddr.l.google.com", qtype=TYPE_TXT, timeout=2.0)
    if not txt_res.success:
        txt_res = query_udp("223.5.5.5", "o-o.myaddr.l.google.com", qtype=TYPE_TXT, timeout=2.0)

    for txt in txt_res.answers:
        # Format: edns0-client-subnet 114.xxx.xxx.0/24
        if "client-subnet" in txt.lower():
            ecs_supported = True
            parts = txt.replace('"', "").split()
            for p in parts:
                if "/" in p:
                    ecs_subnet = p
                    subnet_ip = p.split("/")[0]
                    intel = enrich_ip(subnet_ip)
                    if intel.is_cn:
                        ecs_exposes_cn = True

    return fake_ip_detected, fake_ip_samples, ecs_supported, ecs_subnet, ecs_exposes_cn


def run_system_env_diagnostics() -> SystemEnvReport:
    """Execute Module 1: Local System DNS Environment Diagnostics."""
    os_name = f"{platform.system()} {platform.release()} ({platform.machine()})"
    resolv_servers = parse_resolv_conf()
    scutil_defaults, scutil_scoped = parse_macos_scutil_dns()
    tun_ifaces = detect_tun_interfaces()
    sys_proxy = parse_system_proxy()

    all_sys_dns: List[str] = []
    for s in scutil_defaults + resolv_servers:
        if s not in all_sys_dns:
            all_sys_dns.append(s)

    intel_map: Dict[str, IPIntel] = enrich_ips_batch(all_sys_dns)
    configured_details = []
    for ip in all_sys_dns:
        info = intel_map.get(ip) or enrich_ip(ip)
        configured_details.append(info.to_dict())

    fake_ip_active, fake_samples, ecs_ok, ecs_subnet, ecs_cn = probe_fake_ip_and_ecs(all_sys_dns)
    if any(t.is_fake_ip_tun for t in tun_ifaces):
        fake_ip_active = True

    # Classify overall DNS operating mode
    if fake_ip_active:
        dns_mode = "Fake-IP 虚拟接管模式 (TUN / 代理内核接管)"
    elif tun_ifaces:
        dns_mode = "TUN 虚拟网卡接管模式 (Redir-Host / 真实 IP 映射)"
    elif sys_proxy["any_active"]:
        dns_mode = "系统代理模式 (HTTP/SOCKS 代理生效，未开启 TUN 网卡)"
    else:
        dns_mode = "标准系统直连模式 (未检测到 TUN 虚拟网卡或系统代理)"

    findings: List[dict] = []

    if fake_ip_active:
        findings.append(
            {
                "level": "info",
                "title": "检测到 Fake-IP 代理 DNS 模式已激活",
                "detail": "系统域名解析返回 198.18.0.0/15 等虚拟地址，实际 DNS 解析将由代理节点在远端完成，能有效防止本地 DNS 污染。",
            }
        )
    elif sys_proxy["any_active"] and not tun_ifaces:
        findings.append(
            {
                "level": "warning",
                "title": "当前仅开启系统 HTTP/SOCKS 代理，未开启 TUN 虚拟网卡",
                "detail": "浏览器流量通常会走系统代理，但终端命令行工具或直接调用系统 UDP 53 DNS 的应用可能绕过代理直连本地 ISP DNS，产生 DNS 泄漏风险。",
            }
        )

    for info in configured_details:
        if info["is_cn"]:
            findings.append(
                {
                    "level": "warning" if (sys_proxy["any_active"] or tun_ifaces) else "info",
                    "title": f"系统主 DNS 包含国内服务器: {info['ip']} ({info['display_isp']})",
                    "detail": "若未配置严格的分流或 Fake-IP 接管，访问海外域名时可能首先向该国内 DNS 发起明文查询，导致域名访问轨迹暴露。",
                }
            )

    if ecs_ok and ecs_subnet:
        findings.append(
            {
                "level": "warning" if ecs_cn else "info",
                "title": f"检测到 EDNS Client Subnet (ECS) 已启用: {ecs_subnet}",
                "detail": (
                    "递归 DNS 会向权威服务器附带您的国内真实子网前缀，有助于国内 CDN 就近调度，但在跨境访问时可能暴露您的真实地理区域。"
                    if ecs_cn
                    else f"递归 DNS 向权威服务器传递子网前缀 {ecs_subnet} 以优化 CDN 调度。"
                ),
            }
        )

    return SystemEnvReport(
        os_name=os_name,
        resolv_conf_servers=resolv_servers,
        scutil_default_servers=scutil_defaults,
        scutil_scoped_resolvers=scutil_scoped[:8],
        configured_dns_details=configured_details,
        tun_interfaces=tun_ifaces,
        system_proxy=sys_proxy,
        dns_mode=dns_mode,
        fake_ip_active=fake_ip_active,
        fake_ip_samples=fake_samples,
        ecs_supported=ecs_ok,
        ecs_subnet=ecs_subnet,
        ecs_exposes_cn_subnet=ecs_cn,
        findings=findings,
    )
