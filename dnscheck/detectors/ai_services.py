"""
Module 6: First-Tier AI Services DNS, Split-Routing & Region Unlock Diagnostics.
Covers OpenAI, Anthropic Claude, Google Gemini, xAI Grok, Perplexity,
Microsoft/GitHub Copilot, Cursor, OpenRouter, Groq, HuggingFace,
and Domestic AI Baselines (DeepSeek, Kimi).
"""

from __future__ import annotations

import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

from dnscheck.detectors.pollution_bench import is_bogon_or_forged_ip
from dnscheck.detectors.split_route import SplitRouteReport, run_split_route_diagnostics
from dnscheck.enricher.ip_intel import COUNTRY_CN_MAP, IPIntel, enrich_ip, is_fake_ip
from dnscheck.protocol.dns_packet import TYPE_A
from dnscheck.protocol.transports import query_system_resolver

SANCTIONED_PLUS_HK_CCS: Set[str] = {"CN", "HK", "MO", "RU", "BY", "IR", "KP"}
SANCTIONED_ONLY_CCS: Set[str] = {"CN", "RU", "BY", "IR", "KP"}

AI_TARGETS: List[dict] = [
    {
        "id": "openai_web",
        "provider": "OpenAI",
        "name": "ChatGPT Web",
        "domain": "chatgpt.com",
        "probe_url": "https://chatgpt.com/",
        "category": "overseas",
        "try_cf_trace": True,
        "unsupported_ccs": SANCTIONED_PLUS_HK_CCS,
    },
    {
        "id": "openai_api",
        "provider": "OpenAI",
        "name": "OpenAI API",
        "domain": "api.openai.com",
        "probe_url": "https://api.openai.com/v1/models",
        "category": "overseas",
        "try_cf_trace": True,
        "unsupported_ccs": SANCTIONED_PLUS_HK_CCS,
    },
    {
        "id": "claude_web",
        "provider": "Anthropic",
        "name": "Claude Web",
        "domain": "claude.ai",
        "probe_url": "https://claude.ai/",
        "category": "overseas",
        "try_cf_trace": True,
        "unsupported_ccs": SANCTIONED_PLUS_HK_CCS,
    },
    {
        "id": "claude_api",
        "provider": "Anthropic",
        "name": "Anthropic API",
        "domain": "api.anthropic.com",
        "probe_url": "https://api.anthropic.com/v1/messages",
        "category": "overseas",
        "try_cf_trace": True,
        "unsupported_ccs": SANCTIONED_PLUS_HK_CCS,
    },
    {
        "id": "gemini_web",
        "provider": "Google",
        "name": "Gemini Web",
        "domain": "gemini.google.com",
        "probe_url": "https://gemini.google.com/",
        "category": "overseas",
        "try_cf_trace": False,
        "unsupported_ccs": SANCTIONED_PLUS_HK_CCS,
    },
    {
        "id": "gemini_api",
        "provider": "Google",
        "name": "Gemini API",
        "domain": "generativelanguage.googleapis.com",
        "probe_url": "https://generativelanguage.googleapis.com/",
        "category": "overseas",
        "try_cf_trace": False,
        "unsupported_ccs": SANCTIONED_PLUS_HK_CCS,
    },
    {
        "id": "grok_web",
        "provider": "xAI",
        "name": "Grok Web",
        "domain": "grok.com",
        "probe_url": "https://grok.com/",
        "category": "overseas",
        "try_cf_trace": True,
        "unsupported_ccs": SANCTIONED_PLUS_HK_CCS,
    },
    {
        "id": "grok_api",
        "provider": "xAI",
        "name": "xAI API",
        "domain": "api.x.ai",
        "probe_url": "https://api.x.ai/v1/models",
        "category": "overseas",
        "try_cf_trace": True,
        "unsupported_ccs": SANCTIONED_PLUS_HK_CCS,
    },
    {
        "id": "perplexity",
        "provider": "Perplexity",
        "name": "Perplexity AI",
        "domain": "www.perplexity.ai",
        "probe_url": "https://www.perplexity.ai/",
        "category": "overseas",
        "try_cf_trace": True,
        "unsupported_ccs": SANCTIONED_ONLY_CCS,
    },
    {
        "id": "ms_copilot",
        "provider": "Microsoft",
        "name": "Microsoft Copilot",
        "domain": "copilot.microsoft.com",
        "probe_url": "https://copilot.microsoft.com/",
        "category": "overseas",
        "try_cf_trace": False,
        "unsupported_ccs": SANCTIONED_PLUS_HK_CCS,
    },
    {
        "id": "gh_copilot",
        "provider": "GitHub",
        "name": "GitHub Copilot API",
        "domain": "api.githubcopilot.com",
        "probe_url": "https://api.githubcopilot.com/",
        "category": "overseas",
        "try_cf_trace": False,
        "unsupported_ccs": set(),
    },
    {
        "id": "cursor_api",
        "provider": "Cursor",
        "name": "Cursor AI IDE",
        "domain": "api2.cursor.sh",
        "probe_url": "https://api2.cursor.sh/",
        "category": "overseas",
        "try_cf_trace": False,
        "unsupported_ccs": set(),
    },
    {
        "id": "openrouter",
        "provider": "OpenRouter",
        "name": "OpenRouter API",
        "domain": "openrouter.ai",
        "probe_url": "https://openrouter.ai/",
        "category": "overseas",
        "try_cf_trace": True,
        "unsupported_ccs": set(),
    },
    {
        "id": "groq_api",
        "provider": "Groq",
        "name": "Groq Cloud API",
        "domain": "api.groq.com",
        "probe_url": "https://api.groq.com/openai/v1/models",
        "category": "overseas",
        "try_cf_trace": True,
        "unsupported_ccs": SANCTIONED_PLUS_HK_CCS,
    },
    {
        "id": "huggingface",
        "provider": "HuggingFace",
        "name": "HuggingFace Hub",
        "domain": "huggingface.co",
        "probe_url": "https://huggingface.co/",
        "category": "overseas",
        "try_cf_trace": False,
        "unsupported_ccs": set(),
    },
    {
        "id": "deepseek",
        "provider": "DeepSeek",
        "name": "DeepSeek Web",
        "domain": "chat.deepseek.com",
        "probe_url": "https://chat.deepseek.com/",
        "category": "domestic",
        "try_cf_trace": False,
        "unsupported_ccs": set(),
    },
    {
        "id": "kimi",
        "provider": "Moonshot",
        "name": "Kimi 智能助手",
        "domain": "kimi.moonshot.cn",
        "probe_url": "https://kimi.moonshot.cn/",
        "category": "domestic",
        "try_cf_trace": False,
        "unsupported_ccs": set(),
    },
]


@dataclass
class AIServiceProbeResult:
    """Diagnostic result for a single AI platform endpoint."""
    id: str
    provider: str
    name: str
    domain: str
    category: str
    dns_status: str  # "FAKE_IP", "CLEAN", "POISONED", "NXDOMAIN"
    resolved_ip: Optional[str]
    exit_ip: Optional[str]
    exit_country_code: str
    exit_location: str
    colo: str
    tls_ok: bool
    http_status: Optional[int]
    latency_ms: float
    availability: str  # "AVAILABLE", "REGION_BLOCKED", "RISK_CHALLENGE", "UNREACHABLE"
    availability_label: str
    note: str

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "provider": self.provider,
            "name": self.name,
            "domain": self.domain,
            "category": self.category,
            "dns_status": self.dns_status,
            "resolved_ip": self.resolved_ip,
            "exit_ip": self.exit_ip,
            "exit_country_code": self.exit_country_code,
            "exit_location": self.exit_location,
            "colo": self.colo,
            "tls_ok": self.tls_ok,
            "http_status": self.http_status,
            "latency_ms": round(self.latency_ms, 2),
            "availability": self.availability,
            "availability_label": self.availability_label,
            "note": self.note,
        }


@dataclass
class AIServicesReport:
    """Aggregated report across all first-tier AI services."""
    services: List[AIServiceProbeResult]
    total_count: int
    available_count: int
    region_blocked_count: int
    challenge_count: int
    unreachable_count: int
    findings: List[dict]

    def to_dict(self) -> dict:
        return {
            "services": [s.to_dict() for s in self.services],
            "total_count": self.total_count,
            "available_count": self.available_count,
            "region_blocked_count": self.region_blocked_count,
            "challenge_count": self.challenge_count,
            "unreachable_count": self.unreachable_count,
            "findings": self.findings,
        }


def classify_ai_probe(
    dns_status: str,
    tls_ok: bool,
    exit_country_code: str,
    unsupported_ccs: Set[str],
    explicit_region_block: bool,
    cf_challenge: bool,
) -> Tuple[str, str]:
    """
    Classify availability state for an AI service endpoint.
    Returns (availability_code, availability_label).
    """
    if dns_status == "POISONED" or not tls_ok:
        return "UNREACHABLE", "连接失败 / 阻断"

    if explicit_region_block or (
        exit_country_code and exit_country_code != "UNKNOWN" and exit_country_code in unsupported_ccs
    ):
        cc_desc = f"{exit_country_code} 锁区" if exit_country_code and exit_country_code != "UNKNOWN" else "锁区"
        return "REGION_BLOCKED", f"地区受限 ({cc_desc})"

    if cf_challenge:
        return "RISK_CHALLENGE", "可连通 (触发 CF 盾/风控)"

    return "AVAILABLE", "正常解锁可用"


def _fetch_cf_trace_for_domain(domain: str, timeout: float = 2.8) -> Optional[Dict[str, str]]:
    """Fetch https://<domain>/cdn-cgi/trace if the service is fronted by Cloudflare."""
    url = f"https://{domain}/cdn-cgi/trace"
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/126.0.0.0 Safari/537.36",
            "Accept": "text/plain,*/*",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            text = resp.read(2048).decode("utf-8", errors="replace")
        kv: Dict[str, str] = {}
        for line in text.splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                kv[k.strip()] = v.strip()
        if "ip" in kv and "loc" in kv:
            return kv
    except Exception:
        pass
    return None


def _probe_http_endpoint(url: str, timeout: float = 3.5) -> Tuple[bool, Optional[int], float, str, str, dict]:
    """
    Perform an HTTPS GET probe against an AI endpoint.
    Returns (tls_ok, http_status, latency_ms, body_snippet, final_url, headers_lower).
    """
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
            ),
            "Accept": "text/html,application/json,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        },
        method="GET",
    )
    start = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            body = resp.read(4096).decode("utf-8", errors="ignore")
            hdrs = {k.lower(): v for k, v in resp.headers.items()}
            return True, resp.status, elapsed_ms, body, resp.geturl(), hdrs
    except urllib.error.HTTPError as err:
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        try:
            body = err.read(4096).decode("utf-8", errors="ignore")
        except Exception:
            body = ""
        hdrs = {k.lower(): v for k, v in (err.headers.items() if err.headers else [])}
        return True, err.code, elapsed_ms, body, err.geturl() or url, hdrs
    except Exception as exc:
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        return False, None, elapsed_ms, str(exc), url, {}


def _probe_single_ai_target(
    target: dict,
    split_report: Optional[SplitRouteReport],
    cn_intel: Optional[IPIntel],
    global_intel: Optional[IPIntel],
) -> AIServiceProbeResult:
    """Probe DNS, per-domain CF trace, and HTTPS reachability/region lock for one AI service."""
    domain = target["domain"]
    category = target["category"]
    unsupported_ccs: Set[str] = set(target.get("unsupported_ccs") or set())

    # 1. System DNS Resolution check
    dns_res = query_system_resolver(domain, TYPE_A)
    resolved_ip = dns_res.answers[0] if dns_res.answers else None
    if not resolved_ip:
        dns_status = "NXDOMAIN"
    elif is_fake_ip(resolved_ip):
        dns_status = "FAKE_IP"
    elif is_bogon_or_forged_ip(resolved_ip, domain):
        dns_status = "POISONED"
    else:
        dns_status = "CLEAN"

    # 2. Optional per-domain Cloudflare trace (catches per-domain proxy rule differences)
    cf_trace = _fetch_cf_trace_for_domain(domain) if (target.get("try_cf_trace") and dns_status != "POISONED") else None

    # 3. HTTPS Reachability & Region Block check
    if dns_status == "POISONED":
        tls_ok, http_status, latency_ms, body, final_url, hdrs = False, None, dns_res.latency_ms, "", target["probe_url"], {}
    else:
        tls_ok, http_status, latency_ms, body, final_url, hdrs = _probe_http_endpoint(target["probe_url"])

    body_lower = body.lower()
    final_lower = final_url.lower()

    explicit_region_block = any(
        sig in body_lower
        for sig in (
            "unsupported_country_region_territory",
            "unavailable in your region",
            "not available in your country",
            "service is not available in your region",
        )
    )
    if domain == "gemini.google.com" and "/faq" in final_lower:
        explicit_region_block = True

    cf_challenge = (
        hdrs.get("cf-mitigated", "").lower() == "challenge"
        or (
            http_status == 403
            and any(sig in body_lower for sig in ("just a moment", "cf-chl", "attention required", "enable javascript and cookies"))
        )
    )

    # 4. Determine effective exit IP & region
    exit_ip: Optional[str] = None
    exit_cc = "UNKNOWN"
    exit_location = "-"
    colo = ""

    if cf_trace:
        exit_ip = cf_trace.get("ip")
        trace_cc = cf_trace.get("loc", "").upper()
        colo = cf_trace.get("colo", "")
        if exit_ip:
            intel = enrich_ip(exit_ip, timeout=2.0)
            exit_cc = intel.country_code if intel.country_code != "UNKNOWN" else (trace_cc or "UNKNOWN")
            exit_location = intel.display_location if intel.country_code != "UNKNOWN" else COUNTRY_CN_MAP.get(trace_cc, trace_cc or "-")
        elif trace_cc:
            exit_cc = trace_cc
            exit_location = COUNTRY_CN_MAP.get(trace_cc, trace_cc)
    elif category == "domestic":
        # Domestic AI services normally bypass proxy and exit directly via CN ISP
        if split_report and split_report.cn_ip and cn_intel:
            exit_ip = split_report.cn_ip
            exit_cc = cn_intel.country_code
            exit_location = cn_intel.display_location
        elif resolved_ip and not is_fake_ip(resolved_ip):
            if split_report and split_report.global_ip and global_intel and not split_report.proxy_detected:
                exit_ip = split_report.global_ip
                exit_cc = global_intel.country_code
                exit_location = global_intel.display_location
    else:
        # Overseas AI service without CF trace: infer from Fake-IP/proxy or global exit
        if (dns_status == "FAKE_IP" or (split_report and split_report.proxy_detected)) and split_report and split_report.global_ip:
            exit_ip = split_report.global_ip
            if global_intel:
                exit_cc = global_intel.country_code
                exit_location = global_intel.display_location
        elif split_report and split_report.cn_ip and cn_intel and not (split_report.proxy_detected):
            exit_ip = split_report.cn_ip
            exit_cc = cn_intel.country_code
            exit_location = cn_intel.display_location

    availability, availability_label = classify_ai_probe(
        dns_status=dns_status,
        tls_ok=tls_ok,
        exit_country_code=exit_cc,
        unsupported_ccs=unsupported_ccs,
        explicit_region_block=explicit_region_block,
        cf_challenge=cf_challenge,
    )

    # Compose explanatory note
    if dns_status == "POISONED":
        note = f"DNS 疑似被污染 ({resolved_ip})"
    elif not tls_ok:
        note = f"TLS/HTTPS 连接失败 ({body[:60]})" if body else "TLS/HTTPS 连接超时"
    elif availability == "REGION_BLOCKED":
        note = "服务返回地区不可用提示" if explicit_region_block else f"出口归属 {exit_cc}，位于官方限制区"
    elif availability == "RISK_CHALLENGE":
        note = f"HTTP {http_status} 触发 Cloudflare 盾/人机验证（网络已通）"
    else:
        status_note = f"HTTP {http_status}" if http_status else "TLS OK"
        note = f"{status_note} · 节点可正常访问"

    return AIServiceProbeResult(
        id=target["id"],
        provider=target["provider"],
        name=target["name"],
        domain=domain,
        category=category,
        dns_status=dns_status,
        resolved_ip=resolved_ip,
        exit_ip=exit_ip,
        exit_country_code=exit_cc,
        exit_location=exit_location,
        colo=colo,
        tls_ok=tls_ok,
        http_status=http_status,
        latency_ms=latency_ms,
        availability=availability,
        availability_label=availability_label,
        note=note,
    )


def run_ai_services_diagnostics(split_report: Optional[SplitRouteReport] = None) -> AIServicesReport:
    """Execute Module 6: First-Tier AI Services DNS, Split-Routing & Region Unlock Audit."""
    if split_report is None:
        split_report = run_split_route_diagnostics()

    cn_intel: Optional[IPIntel] = None
    global_intel: Optional[IPIntel] = None
    for ex in split_report.exits:
        if ex.category_id == "cn_direct" and ex.intel:
            cn_intel = ex.intel
        elif ex.category_id == "global_proxy" and ex.intel:
            global_intel = ex.intel
        elif ex.category_id == "cdn_cloudflare" and ex.intel and global_intel is None:
            global_intel = ex.intel

    if cn_intel is None and split_report.cn_ip:
        cn_intel = enrich_ip(split_report.cn_ip)
    if global_intel is None and split_report.global_ip:
        global_intel = enrich_ip(split_report.global_ip)

    with ThreadPoolExecutor(max_workers=10) as pool:
        futs = [
            pool.submit(_probe_single_ai_target, t, split_report, cn_intel, global_intel)
            for t in AI_TARGETS
        ]
        services = [f.result() for f in futs]

    available_count = sum(1 for s in services if s.availability == "AVAILABLE")
    region_blocked_count = sum(1 for s in services if s.availability == "REGION_BLOCKED")
    challenge_count = sum(1 for s in services if s.availability == "RISK_CHALLENGE")
    unreachable_count = sum(1 for s in services if s.availability == "UNREACHABLE")

    findings: List[dict] = []

    blocked_services = [s for s in services if s.availability == "REGION_BLOCKED"]
    if blocked_services:
        names = ", ".join(s.name for s in blocked_services[:5])
        ccs = sorted({s.exit_country_code for s in blocked_services if s.exit_country_code != "UNKNOWN"})
        findings.append(
            {
                "level": "danger",
                "title": f"{len(blocked_services)} 项一线 AI 服务受地区限制不可用: {names}",
                "detail": (
                    f"检测到相关 AI 流量出口区域为 {', '.join(ccs) or '受限地区'}（OpenAI / Claude / Gemini 等均屏蔽中国内地及香港节点），"
                    "建议将 AI 域名分流规则调整至美国、日本、新加坡或台湾等支持地区的干净节点。"
                ),
            }
        )

    unreachable_overseas = [s for s in services if s.availability == "UNREACHABLE" and s.category == "overseas"]
    if unreachable_overseas:
        names = ", ".join(s.name for s in unreachable_overseas[:5])
        findings.append(
            {
                "level": "warning",
                "title": f"{len(unreachable_overseas)} 项海外 AI 服务连接失败或超时: {names}",
                "detail": "请检查代理规则是否包含上述域名（如 gemini.google.com、api.x.ai、api2.cursor.sh 等），或是否存在本地 DNS 污染。",
            }
        )

    challenge_services = [s for s in services if s.availability == "RISK_CHALLENGE"]
    if challenge_services:
        names = ", ".join(s.name for s in challenge_services[:5])
        findings.append(
            {
                "level": "warning",
                "title": f"{len(challenge_services)} 项 AI 服务触发 Cloudflare 盾/人机风控 ({names})",
                "detail": "网络链路本身已连通且未锁区，但当前代理出口 IP 声誉触发了 Web WAF 验证（API 端点通常不受影响，Web 端可能需要更换低风控住宅/原生节点）。",
            }
        )

    # Check if domestic AI services accidentally went through overseas proxy
    domestic_over_proxy = [
        s for s in services
        if s.category == "domestic" and s.dns_status == "FAKE_IP" and s.exit_country_code not in ("CN", "UNKNOWN")
    ]
    if domestic_over_proxy:
        names = ", ".join(s.name for s in domestic_over_proxy)
        findings.append(
            {
                "level": "info",
                "title": f"国内 AI ({names}) 走了 Fake-IP 代理规则",
                "detail": "建议将 DeepSeek / Kimi 加入国内直连规则，以获得最低响应延迟。",
            }
        )

    if not blocked_services and not unreachable_overseas:
        findings.append(
            {
                "level": "ok",
                "title": "主流一线海外 AI 服务 (OpenAI / Claude / Gemini / Grok 等) 均已解锁连通",
                "detail": f"共检测 {len(services)} 项 AI 端点，其中 {available_count} 项直接可用，{challenge_count} 项可连通(触发Web盾)。",
            }
        )

    return AIServicesReport(
        services=services,
        total_count=len(services),
        available_count=available_count,
        region_blocked_count=region_blocked_count,
        challenge_count=challenge_count,
        unreachable_count=unreachable_count,
        findings=findings,
    )
