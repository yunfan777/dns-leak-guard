"""
Module 9: Claude Full-Chain Split-Routing & Anti-Fraud Consistency Auditor (`dnscheck claude`).

Only proxying `claude.ai` and `anthropic.com` is NOT enough: Claude also connects to
12+ companion domains (Artifacts/MCP content, Intercom support, Datadog/Sentry telemetry,
Stripe billing, Sift anti-fraud, Firebase FCM) and GCP CIDR `34.8.0.0/16`.
If even one leaks via DIRECT or drifts to a different exit IP/country than `claude.ai`,
risk-control systems see simultaneous multi-region IPs on the same account.

Combines:
1. White-box exact outbound policy comparison via `surge-cli rule explain` (when Surge is active).
2. Black-box OS DNS (Fake-IP vs Real-IP) & Cloudflare `/cdn-cgi/trace` exit IP consistency checks
   (works on Clash / Mihomo / Sing-box / Shadowrocket / any platform).
3. One-click unified rule generator for Surge, Clash/Mihomo, and Shadowrocket.
"""

from __future__ import annotations

import ipaddress
import subprocess
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from dnscheck.detectors.ai_services import SANCTIONED_PLUS_HK_CCS, _fetch_cf_trace_for_domain
from dnscheck.detectors.proxy_audit import find_surge_cli, parse_surge_rule_explain
from dnscheck.enricher.ip_intel import is_fake_ip
from dnscheck.protocol.dns_packet import TYPE_A
from dnscheck.protocol.transports import query_system_resolver

# 14 Domains + 1 IP CIDR that must share the exact same clean fixed exit policy
CLAUDE_CHAIN_TARGETS: Tuple[dict, ...] = (
    {"target": "claude.ai", "rule_type": "DOMAIN-SUFFIX", "role": "核心 Web 主站", "risk": "CRITICAL", "cf_trace": True},
    {"target": "anthropic.com", "rule_type": "DOMAIN-SUFFIX", "role": "Anthropic 核心 / API", "risk": "CRITICAL", "cf_trace": True},
    {"target": "claude.com", "rule_type": "DOMAIN-SUFFIX", "role": "Claude 官方主域", "risk": "HIGH", "cf_trace": True},
    {"target": "claudeusercontent.com", "rule_type": "DOMAIN-SUFFIX", "role": "Artifacts 内容域", "risk": "HIGH", "cf_trace": True},
    {"target": "claude.app", "rule_type": "DOMAIN-SUFFIX", "role": "桌面 / 移动端域名", "risk": "HIGH", "cf_trace": False},
    {"target": "claudemcpcontent.com", "rule_type": "DOMAIN-SUFFIX", "role": "MCP 扩展内容域", "risk": "HIGH", "cf_trace": False},
    {"target": "clau.de", "rule_type": "DOMAIN-SUFFIX", "role": "官方短链跳转域", "risk": "MEDIUM", "cf_trace": True},
    {"target": "api-iam.intercom.io", "rule_type": "DOMAIN", "role": "客服鉴权 (Intercom)", "risk": "HIGH", "cf_trace": False},
    {"target": "nexus-websocket-a.intercom.io", "rule_type": "DOMAIN", "role": "客服 WebSocket", "risk": "HIGH", "cf_trace": False},
    {"target": "us5.datadoghq.com", "rule_type": "DOMAIN", "role": "遥测监控 (Datadog)", "risk": "HIGH", "cf_trace": False},
    {"target": "r.stripe.com", "rule_type": "DOMAIN", "role": "支付风控 (Stripe)", "risk": "CRITICAL", "cf_trace": False},
    {"target": "us.sentry.io", "rule_type": "DOMAIN", "role": "异常上报 (Sentry)", "risk": "HIGH", "cf_trace": False},
    {"target": "siftscience.com", "rule_type": "DOMAIN-SUFFIX", "role": "反欺诈指纹 (Sift)", "risk": "CRITICAL", "cf_trace": True},
    {"target": "fcmtoken.googleapis.com", "rule_type": "DOMAIN", "role": "推送令牌 (FCM)", "risk": "MEDIUM", "cf_trace": False},
    {"target": "34.8.0.0/16", "rule_type": "IP-CIDR", "probe_ip": "34.8.0.1", "role": "GCP 后端 IP 段", "risk": "HIGH", "cf_trace": False},
)


@dataclass
class ClaudeTargetCheck:
    """Consistency audit result for one Claude companion domain or IP CIDR."""
    target: str
    rule_type: str
    role: str
    risk: str
    dns_status: str = "N/A"  # "FAKE_IP", "REAL_IP", "NXDOMAIN", "IP_CIDR"
    resolved_ip: Optional[str] = None
    matched_rule: str = ""
    final_policy: str = ""
    triggered_local_dns: bool = False
    cf_exit_ip: Optional[str] = None
    cf_exit_cc: str = ""
    status: str = "INFO"  # "CONSISTENT", "DIRECT_LEAK", "SPLIT_DRIFT", "REGION_BLOCKED", "INFO"
    status_label: str = ""
    note: str = ""

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "rule_type": self.rule_type,
            "role": self.role,
            "risk": self.risk,
            "dns_status": self.dns_status,
            "resolved_ip": self.resolved_ip,
            "matched_rule": self.matched_rule,
            "final_policy": self.final_policy,
            "triggered_local_dns": self.triggered_local_dns,
            "cf_exit_ip": self.cf_exit_ip,
            "cf_exit_cc": self.cf_exit_cc,
            "status": self.status,
            "status_label": self.status_label,
            "note": self.note,
        }


@dataclass
class ClaudeSplitAuditReport:
    """Aggregated full-chain consistency report for Claude (14 domains + 1 IP CIDR)."""
    whitebox_client: Optional[str]
    baseline_policy: Optional[str]
    baseline_exit_ip: Optional[str]
    baseline_exit_cc: str
    targets: List[ClaudeTargetCheck]
    total_count: int
    consistent_count: int
    direct_leak_count: int
    split_drift_count: int
    region_blocked_count: int
    score: int
    verdict: str  # "SAFE", "WARNING", "RISK"
    verdict_label: str
    findings: List[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "whitebox_client": self.whitebox_client,
            "baseline_policy": self.baseline_policy,
            "baseline_exit_ip": self.baseline_exit_ip,
            "baseline_exit_cc": self.baseline_exit_cc,
            "targets": [t.to_dict() for t in self.targets],
            "total_count": self.total_count,
            "consistent_count": self.consistent_count,
            "direct_leak_count": self.direct_leak_count,
            "split_drift_count": self.split_drift_count,
            "region_blocked_count": self.region_blocked_count,
            "score": self.score,
            "verdict": self.verdict,
            "verdict_label": self.verdict_label,
            "findings": self.findings,
        }


def generate_claude_rules(fmt: str = "surge", policy: str = "Claude") -> str:
    """
    Generate ready-to-paste unified Claude anti-risk-control rules (14 domains + 34.8.0.0/16)
    for Surge, Clash/Mihomo, or Shadowrocket. Place ABOVE generic/Google/FINAL rules.
    """
    fmt_low = fmt.lower().strip()
    quoted_pol = f'"{policy}"' if (" " in policy and not policy.startswith('"')) else policy

    if fmt_low in ("clash", "mihomo"):
        lines = [
            "# Claude 全链路统一出口规则（置于通用规则 / Google 规则之前，指向同一个固定出口）",
            "rules:",
        ]
        for item in CLAUDE_CHAIN_TARGETS:
            rtype = item["rule_type"]
            tgt = item["target"]
            if rtype == "IP-CIDR":
                lines.append(f"  - IP-CIDR,{tgt},{policy},no-resolve  # {item['role']}")
            else:
                lines.append(f"  - {rtype},{tgt},{policy}  # {item['role']}")
        return "\n".join(lines)

    # Surge & Shadowrocket share INI rule syntax
    header = (
        "# Claude 全链路统一出口规则 (Surge / Shadowrocket)\n"
        "# 请放置在 [Rule] 靠前位置（通用规则、Google 规则、iTerm/LAN 规则之前），全部指向同一个固定住宅/原生节点"
    )
    lines = [header]
    for item in CLAUDE_CHAIN_TARGETS:
        rtype = item["rule_type"]
        tgt = item["target"]
        if rtype == "IP-CIDR":
            lines.append(f"IP-CIDR,{tgt},{quoted_pol},no-resolve")
        else:
            lines.append(f"{rtype},{tgt},{quoted_pol}")
    return "\n".join(lines)


def _normalize_policy_name(raw_policy: str) -> str:
    """Strip transport suffix like ' (Shadowsocks)' or ' (DIRECT)' for policy comparison."""
    p = (raw_policy or "").strip()
    if p.endswith(")") and " (" in p:
        p = p.rsplit(" (", 1)[0].strip()
    return p


def _surge_explain_target(surge_cli: str, target_host: str) -> Tuple[str, str, bool]:
    """Run `surge-cli rule explain <target>` and return (matched_rule, final_policy, triggered_dns)."""
    try:
        proc = subprocess.run(
            [surge_cli, "rule", "explain", target_host],
            capture_output=True,
            text=True,
            timeout=4.0,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            parsed = parse_surge_rule_explain(target_host, proc.stdout)
            return parsed.matched_rule, parsed.final_policy, parsed.triggered_local_dns
    except Exception:
        pass
    return "", "", False


def evaluate_claude_consistency(
    checks: List[ClaudeTargetCheck],
    whitebox_client: Optional[str] = None,
) -> ClaudeSplitAuditReport:
    """
    Pure evaluation function comparing all 15 Claude companion targets against the `claude.ai` baseline.
    """
    base_check = next((c for c in checks if c.target == "claude.ai"), checks[0] if checks else None)
    base_policy = _normalize_policy_name(base_check.final_policy) if base_check and base_check.final_policy else None
    base_exit_ip = base_check.cf_exit_ip if base_check else None
    base_exit_cc = base_check.cf_exit_cc if base_check else ""
    base_uses_fake_ip = bool(base_check and base_check.dns_status == "FAKE_IP")

    consistent_count = 0
    direct_leak_count = 0
    split_drift_count = 0
    region_blocked_count = 0

    for c in checks:
        pol_norm = _normalize_policy_name(c.final_policy)

        # 1. White-box evaluation (exact Surge policy match)
        if whitebox_client and pol_norm:
            if pol_norm.upper() == "DIRECT":
                c.status = "DIRECT_LEAK"
                c.status_label = "直连泄漏!"
                c.note = f"命中 `{c.matched_rule}` 走 DIRECT，会暴露本机真实 IP 给 {c.role}"
                direct_leak_count += 1
            elif c.cf_exit_cc and c.cf_exit_cc in SANCTIONED_PLUS_HK_CCS:
                c.status = "REGION_BLOCKED"
                c.status_label = f"受限区 ({c.cf_exit_cc})"
                c.note = f"出口地区 {c.cf_exit_cc} 位于 Anthropic 限制区"
                region_blocked_count += 1
            elif base_policy and base_policy.upper() != "DIRECT" and pol_norm != base_policy:
                c.status = "SPLIT_DRIFT"
                c.status_label = "出口漂移!"
                c.note = f"走了 `{pol_norm}`（与 claude.ai 的 `{base_policy}` 不一致，存在多 IP 关联风控）"
                split_drift_count += 1
            else:
                c.status = "CONSISTENT"
                c.status_label = "出口一致"
                extra = f" · CF:{c.cf_exit_cc}" if c.cf_exit_cc else ""
                c.note = f"统一出口 `{pol_norm}`{extra}"
                consistent_count += 1
            continue

        # 2. Black-box evaluation (DNS Fake-IP + CF Trace exit IP/CC comparison)
        if c.cf_exit_cc and c.cf_exit_cc in SANCTIONED_PLUS_HK_CCS:
            c.status = "REGION_BLOCKED"
            c.status_label = f"受限区 ({c.cf_exit_cc})"
            c.note = f"CF Trace 出口为 {c.cf_exit_cc} ({c.cf_exit_ip})，位于限制区"
            region_blocked_count += 1
        elif base_exit_ip and c.cf_exit_ip and c.cf_exit_ip != base_exit_ip:
            c.status = "SPLIT_DRIFT"
            c.status_label = "出口漂移!"
            c.note = f"出口 IP {c.cf_exit_ip} ({c.cf_exit_cc}) 与 claude.ai ({base_exit_ip}) 不一致"
            split_drift_count += 1
        elif c.rule_type != "IP-CIDR" and base_uses_fake_ip and c.dns_status == "REAL_IP":
            c.status = "DIRECT_LEAK"
            c.status_label = "疑似直连"
            c.note = f"claude.ai 走 Fake-IP，但本域名返回真实 IP ({c.resolved_ip})，可能命中直连或绕过规则"
            direct_leak_count += 1
        elif (c.cf_exit_ip and base_exit_ip and c.cf_exit_ip == base_exit_ip) or (
            base_uses_fake_ip and c.dns_status == "FAKE_IP"
        ):
            c.status = "CONSISTENT"
            c.status_label = "代理接管一致"
            c.note = (
                f"出口 IP 与 claude.ai 一致 ({c.cf_exit_ip} · {c.cf_exit_cc})"
                if c.cf_exit_ip
                else "已由 Fake-IP 虚拟网卡统一接管"
            )
            consistent_count += 1
        else:
            c.status = "INFO"
            c.status_label = "需规则核验"
            c.note = (
                "黑盒模式无法直测 IP 段策略，请核对已配置 IP-CIDR,34.8.0.0/16,...,no-resolve"
                if c.rule_type == "IP-CIDR"
                else "建议配置显式分流规则指向 Claude 固定出口"
            )

    score = 100
    score -= direct_leak_count * 18
    score -= split_drift_count * 10
    score -= region_blocked_count * 20
    score = max(0, min(100, score))

    findings: List[dict] = []
    if direct_leak_count > 0:
        leaked = [c.target for c in checks if c.status == "DIRECT_LEAK"]
        findings.append(
            {
                "level": "danger",
                "title": f"高危关联风控：{direct_leak_count} 项 Claude 伴生域名/IP 正在直连暴露真实 IP",
                "detail": (
                    f"直连项: {', '.join(leaked[:6])}。"
                    "这会导致 Claude 客服/风控/支付/遥测接口看到你的本地真实 IP，与代理 IP 形成双地并发登录，极易触发封号！"
                ),
            }
        )
    if split_drift_count > 0:
        drifted = [f"{c.target} -> {_normalize_policy_name(c.final_policy) or c.cf_exit_ip}" for c in checks if c.status == "SPLIT_DRIFT"]
        findings.append(
            {
                "level": "warning",
                "title": f"检测到 {split_drift_count} 项 Claude 关联域名发生出口节点漂移（与 claude.ai 不一致）",
                "detail": (
                    f"漂移示例: {' ; '.join(drifted[:5])}。"
                    "请运行 `python3 dnscheck.py claude --export surge`（或 clash / shadowrocket）生成 14 域名 + 34.8.0.0/16 统一规则并置顶至通用规则之前。"
                ),
            }
        )
    if region_blocked_count > 0:
        blk = [f"{c.target} ({c.cf_exit_cc})" for c in checks if c.status == "REGION_BLOCKED"]
        findings.append(
            {
                "level": "danger",
                "title": f"{region_blocked_count} 项 Claude 端点落入 Anthropic 限制地区 (CN/HK 等)",
                "detail": f"受限项: {', '.join(blk)}。请切换至美国、日本、新加坡或台湾等支持地区的固定节点。",
            }
        )

    if direct_leak_count == 0 and split_drift_count == 0 and region_blocked_count == 0:
        verdict = "SAFE"
        verdict_label = "全链路出口统一 (低风控)"
        findings.append(
            {
                "level": "ok",
                "title": f"Claude 全链路 15 项域名与 IP 段均保持统一出口 ({base_policy or base_exit_ip or 'Fake-IP'})",
                "detail": "客服 (Intercom)、支付 (Stripe)、反欺诈 (Sift)、遥测 (Datadog/Sentry) 与主站共享同一固定出口，无双 IP 关联风险。",
            }
        )
    elif direct_leak_count > 0 or region_blocked_count > 0:
        verdict = "RISK"
        verdict_label = "高危风控 (存在直连或锁区泄漏)"
    else:
        verdict = "WARNING"
        verdict_label = "出口分裂警告 (多节点漂移)"

    return ClaudeSplitAuditReport(
        whitebox_client=whitebox_client,
        baseline_policy=base_policy,
        baseline_exit_ip=base_exit_ip,
        baseline_exit_cc=base_exit_cc,
        targets=checks,
        total_count=len(checks),
        consistent_count=consistent_count,
        direct_leak_count=direct_leak_count,
        split_drift_count=split_drift_count,
        region_blocked_count=region_blocked_count,
        score=score,
        verdict=verdict,
        verdict_label=verdict_label,
        findings=findings,
    )


def run_claude_split_audit() -> ClaudeSplitAuditReport:
    """
    Execute Module 9: Audit all 14 Claude domains + `34.8.0.0/16` concurrently for
    split-routing consistency, DIRECT leaks, and exit-node drift.
    """
    surge_cli = find_surge_cli()
    whitebox_client: Optional[str] = None
    if surge_cli:
        try:
            st = subprocess.run([surge_cli, "status"], capture_output=True, text=True, timeout=2.5)
            if st.returncode == 0 and st.stdout.strip():
                whitebox_client = st.stdout.splitlines()[0].strip()
        except Exception:
            surge_cli = None

    def _check_one(item: dict) -> ClaudeTargetCheck:
        target = item["target"]
        rtype = item["rule_type"]
        probe_host = item.get("probe_ip") or target

        dns_status = "IP_CIDR" if rtype == "IP-CIDR" else "NXDOMAIN"
        resolved_ip: Optional[str] = None
        if rtype != "IP-CIDR":
            dns_res = query_system_resolver(target, qtype=TYPE_A)
            if dns_res.success and dns_res.answers:
                resolved_ip = dns_res.answers[0]
                dns_status = "FAKE_IP" if is_fake_ip(resolved_ip) else "REAL_IP"

        matched_rule = ""
        final_policy = ""
        trig_dns = False
        if surge_cli and whitebox_client:
            matched_rule, final_policy, trig_dns = _surge_explain_target(surge_cli, probe_host)

        cf_ip: Optional[str] = None
        cf_cc = ""
        if item.get("cf_trace"):
            trace = _fetch_cf_trace_for_domain(target, timeout=2.2)
            if trace:
                cf_ip = trace.get("ip")
                cf_cc = (trace.get("loc") or "").upper()

        return ClaudeTargetCheck(
            target=target,
            rule_type=rtype,
            role=item["role"],
            risk=item["risk"],
            dns_status=dns_status,
            resolved_ip=resolved_ip,
            matched_rule=matched_rule,
            final_policy=final_policy,
            triggered_local_dns=trig_dns,
            cf_exit_ip=cf_ip,
            cf_exit_cc=cf_cc,
        )

    with ThreadPoolExecutor(max_workers=10) as pool:
        checks = list(pool.map(_check_one, CLAUDE_CHAIN_TARGETS))

    return evaluate_claude_consistency(checks, whitebox_client=whitebox_client)
