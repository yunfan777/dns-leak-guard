"""
Module 3: Domestic vs. Overseas Network Split-Tunneling & Multi-Exit IP Matrix.
Probes 4 traffic routing dimensions concurrently:
1. Domestic Direct Exit (CN Direct: 4.ipw.cn / myip.ipip.net / ip.useragentinfo.com)
2. Overseas Common Exit (Global Proxy: ipinfo.io / ipwho.is / api.ipify.org)
3. International CDN / AI Exit (Cloudflare Anycast trace: www.cloudflare.com/cdn-cgi/trace)
4. IPv6 Independent Exit (6.ipw.cn / api6.ipify.org)
"""

from __future__ import annotations

import json
import re
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from dnscheck.enricher.ip_intel import IPIntel, enrich_ip, enrich_ips_batch

IPV4_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


@dataclass
class ExitNodeProbe:
    """Result for one routing category in the split-routing matrix."""
    category_id: str  # "cn_direct", "global_proxy", "cdn_cloudflare", "ipv6_exit"
    category_name: str
    target_used: str
    success: bool
    latency_ms: float
    ip: Optional[str] = None
    intel: Optional[IPIntel] = None
    extra_meta: dict = field(default_factory=dict)
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "category_id": self.category_id,
            "category_name": self.category_name,
            "target_used": self.target_used,
            "success": self.success,
            "latency_ms": round(self.latency_ms, 2),
            "ip": self.ip,
            "intel": self.intel.to_dict() if self.intel else None,
            "extra_meta": self.extra_meta,
            "error": self.error,
        }


@dataclass
class SplitRouteReport:
    """Complete analysis of domestic/overseas split-tunneling & exit IPs."""
    exits: List[ExitNodeProbe]
    routing_mode: str  # "国内外智能分流 (Split-Tunneling)", "全局海外代理 (Global Proxy)", "纯国内直连 (Direct Only)", "未知/离线"
    proxy_detected: bool
    cn_ip: Optional[str]
    global_ip: Optional[str]
    ipv6_ip: Optional[str]
    ipv6_leak_risk: bool
    findings: List[dict]

    def to_dict(self) -> dict:
        return {
            "exits": [e.to_dict() for e in self.exits],
            "routing_mode": self.routing_mode,
            "proxy_detected": self.proxy_detected,
            "cn_ip": self.cn_ip,
            "global_ip": self.global_ip,
            "ipv6_ip": self.ipv6_ip,
            "ipv6_leak_risk": self.ipv6_leak_risk,
            "findings": self.findings,
        }


def _http_get_text(url: str, timeout: float = 3.0) -> Tuple[str, float]:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "curl/8.4.0 DNSGuard/1.0",
            "Accept": "*/*",
        },
    )
    start = time.perf_counter()
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read().decode("utf-8", errors="replace").strip()
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    return body, elapsed_ms


def _probe_cn_direct(timeout: float = 3.0) -> ExitNodeProbe:
    """Probe domestic direct exit IP using domestic endpoints."""
    endpoints = [
        ("4.ipw.cn", "https://4.ipw.cn"),
        ("ip.useragentinfo.com", "https://ip.useragentinfo.com/json"),
        ("myip.ipip.net", "http://myip.ipip.net"),
    ]
    last_err = "Timeout"
    for label, url in endpoints:
        try:
            text, latency = _http_get_text(url, timeout=timeout)
            m = IPV4_REGEX.search(text)
            if m:
                return ExitNodeProbe(
                    category_id="cn_direct",
                    category_name="国内直连出口 (CN Direct)",
                    target_used=label,
                    success=True,
                    latency_ms=latency,
                    ip=m.group(0),
                )
        except Exception as exc:
            last_err = str(exc)

    return ExitNodeProbe(
        category_id="cn_direct",
        category_name="国内直连出口 (CN Direct)",
        target_used="4.ipw.cn",
        success=False,
        latency_ms=0.0,
        error=last_err,
    )


def _probe_global_proxy(timeout: float = 3.0) -> ExitNodeProbe:
    """Probe international exit IP using overseas endpoints."""
    endpoints = [
        ("ipinfo.io", "https://ipinfo.io/json"),
        ("ipwho.is", "https://ipwho.is/"),
        ("api.ipify.org", "https://api.ipify.org?format=json"),
    ]
    last_err = "Timeout"
    for label, url in endpoints:
        try:
            text, latency = _http_get_text(url, timeout=timeout)
            ip_val = None
            try:
                j = json.loads(text)
                ip_val = j.get("ip")
            except Exception:
                m = IPV4_REGEX.search(text)
                if m:
                    ip_val = m.group(0)
            if ip_val:
                return ExitNodeProbe(
                    category_id="global_proxy",
                    category_name="海外通用出口 (Global Route)",
                    target_used=label,
                    success=True,
                    latency_ms=latency,
                    ip=ip_val.strip(),
                )
        except Exception as exc:
            last_err = str(exc)

    return ExitNodeProbe(
        category_id="global_proxy",
        category_name="海外通用出口 (Global Route)",
        target_used="ipinfo.io",
        success=False,
        latency_ms=0.0,
        error=last_err,
    )


def _probe_cloudflare_cdn(timeout: float = 3.0) -> ExitNodeProbe:
    """Probe Cloudflare Anycast CDN trace endpoint."""
    endpoints = [
        ("www.cloudflare.com", "https://www.cloudflare.com/cdn-cgi/trace"),
        ("1.1.1.1", "https://1.1.1.1/cdn-cgi/trace"),
    ]
    last_err = "Timeout"
    for label, url in endpoints:
        try:
            text, latency = _http_get_text(url, timeout=timeout)
            kv: Dict[str, str] = {}
            for line in text.splitlines():
                if "=" in line:
                    k, v = line.split("=", 1)
                    kv[k.strip()] = v.strip()
            ip_val = kv.get("ip")
            if ip_val:
                return ExitNodeProbe(
                    category_id="cdn_cloudflare",
                    category_name="国际 CDN 出口 (Cloudflare Trace)",
                    target_used=label,
                    success=True,
                    latency_ms=latency,
                    ip=ip_val,
                    extra_meta={
                        "colo": kv.get("colo", ""),
                        "loc": kv.get("loc", ""),
                        "warp": kv.get("warp", "off"),
                        "tls": kv.get("tls", ""),
                    },
                )
        except Exception as exc:
            last_err = str(exc)

    return ExitNodeProbe(
        category_id="cdn_cloudflare",
        category_name="国际 CDN 出口 (Cloudflare Trace)",
        target_used="www.cloudflare.com",
        success=False,
        latency_ms=0.0,
        error=last_err,
    )


def _probe_ipv6_exit(timeout: float = 2.5) -> ExitNodeProbe:
    """Probe IPv6 exit connectivity."""
    endpoints = [
        ("6.ipw.cn", "https://6.ipw.cn"),
        ("api6.ipify.org", "https://api6.ipify.org"),
    ]
    last_err = "当前网络未启用公网 IPv6"
    for label, url in endpoints:
        try:
            text, latency = _http_get_text(url, timeout=timeout)
            if ":" in text and len(text) <= 64:
                return ExitNodeProbe(
                    category_id="ipv6_exit",
                    category_name="IPv6 双栈出口 (IPv6 Exit)",
                    target_used=label,
                    success=True,
                    latency_ms=latency,
                    ip=text.splitlines()[0].strip(),
                )
        except Exception as exc:
            last_err = str(exc)

    return ExitNodeProbe(
        category_id="ipv6_exit",
        category_name="IPv6 双栈出口 (IPv6 Exit)",
        target_used="6.ipw.cn",
        success=False,
        latency_ms=0.0,
        error=last_err,
    )


def run_split_route_diagnostics() -> SplitRouteReport:
    """Execute Module 3: Domestic/Overseas Split-Tunneling & Multi-Exit IP Comparison."""
    with ThreadPoolExecutor(max_workers=4) as pool:
        f_cn = pool.submit(_probe_cn_direct)
        f_gl = pool.submit(_probe_global_proxy)
        f_cf = pool.submit(_probe_cloudflare_cdn)
        f_v6 = pool.submit(_probe_ipv6_exit)

        p_cn = f_cn.result()
        p_gl = f_gl.result()
        p_cf = f_cf.result()
        p_v6 = f_v6.result()

    exits = [p_cn, p_gl, p_cf, p_v6]
    discovered_ips = [e.ip for e in exits if e.ip]
    intel_map = enrich_ips_batch(discovered_ips)

    for e in exits:
        if e.ip:
            e.intel = intel_map.get(e.ip) or enrich_ip(e.ip)

    cn_is_domestic = bool(p_cn.intel and p_cn.intel.is_cn)
    gl_is_overseas = bool(p_gl.intel and not p_gl.intel.is_cn and p_gl.intel.country_code != "UNKNOWN")
    cf_is_overseas = bool(p_cf.intel and not p_cf.intel.is_cn and p_cf.intel.country_code != "UNKNOWN")

    proxy_detected = gl_is_overseas or cf_is_overseas or (
        bool(p_cn.ip and p_gl.ip and p_cn.ip != p_gl.ip)
    )

    if cn_is_domestic and (gl_is_overseas or cf_is_overseas):
        routing_mode = "国内外智能分流模式 (Rule-based Split-Tunneling)"
    elif not cn_is_domestic and (gl_is_overseas or cf_is_overseas):
        routing_mode = "全局海外代理模式 (Global Proxy)"
    elif cn_is_domestic and not gl_is_overseas:
        routing_mode = "纯国内直连模式 (Direct Only)"
    else:
        routing_mode = "自定义路由模式"

    # Evaluate IPv6 leak risk: overseas IPv4 proxy active, but IPv6 exit is domestic China ISP
    ipv6_leak_risk = False
    if proxy_detected and p_v6.success and p_v6.intel and p_v6.intel.is_cn:
        ipv6_leak_risk = True

    findings: List[dict] = []
    if routing_mode.startswith("国内外智能分流"):
        findings.append(
            {
                "level": "ok",
                "title": "国内外分流策略工作正常",
                "detail": (
                    f"国内出口为 {p_cn.ip} ({p_cn.intel.display_location if p_cn.intel else ''})，"
                    f"海外出口为 {p_gl.ip or p_cf.ip} ({(p_gl.intel or p_cf.intel).display_location if (p_gl.intel or p_cf.intel) else ''})。"
                ),
            }
        )
    elif routing_mode.startswith("全局海外代理"):
        findings.append(
            {
                "level": "info",
                "title": "当前处于全局代理模式",
                "detail": "国内外探测端点均通过海外代理节点出口，访问国内网站可能会增加延迟。",
            }
        )
    elif routing_mode.startswith("纯国内直连"):
        findings.append(
            {
                "level": "info",
                "title": "未检测到海外分流代理，所有出口均为国内直连",
                "detail": f"当前公网出口 IP 为 {p_cn.ip or p_gl.ip}。",
            }
        )

    if ipv6_leak_risk:
        findings.append(
            {
                "level": "danger",
                "title": f"检测到 IPv6 分流泄漏风险: {p_v6.ip}",
                "detail": (
                    f"IPv4 海外流量已走代理，但 IPv6 流量直接暴露了国内运营商地址 ({p_v6.intel.display_isp if p_v6.intel else ''})。"
                    "当访问支持双栈的海外网站时，浏览器可能优先通过 IPv6 直连从而暴露真实身份。"
                ),
            }
        )

    return SplitRouteReport(
        exits=exits,
        routing_mode=routing_mode,
        proxy_detected=proxy_detected,
        cn_ip=p_cn.ip,
        global_ip=p_gl.ip or p_cf.ip,
        ipv6_ip=p_v6.ip,
        ipv6_leak_risk=ipv6_leak_risk,
        findings=findings,
    )
