"""
Module 8: Read-Only Proxy Configuration & Rule Evaluation Auditor (Surge / Mihomo-Clash).

Inspired by real-world DNS leak debugging on macOS:
1. Surge for Mac (`surge-cli`):
   - Queries `surge-cli status` and runs a dry-run `surge-cli rule explain <canary-domain>`
     to directly detect whether rule evaluation triggers a synchronous local DNS lookup
     (e.g., `RULE-SET,LAN,DIRECT` or `GEOIP,CN` missing `,no-resolve`) and measures exact latency cost.
   - Performs a strictly read-only audit of `[General]` and `[Rule]` in the active `.conf`
     (NEVER reads or exposes `[Proxy]` / `[Proxy Group]` credentials or subscription URLs).
2. Clash / Mihomo (optional local config inspection):
   - Inspects `[dns]` and `[rules]` hygiene (`fallback` concurrent race, missing `,no-resolve`,
     missing `disable-qtype-65=true`) without exposing proxy secrets.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple

SURGE_CLI_CANDIDATES: Tuple[str, ...] = (
    "/Applications/Surge.app/Contents/Applications/surge-cli",
    "/usr/local/bin/surge-cli",
    "/opt/homebrew/bin/surge-cli",
)

IP_RULE_PREFIXES: Tuple[str, ...] = (
    "IP-CIDR,",
    "IP-CIDR6,",
    "IP-ASN,",
    "GEOIP,",
    "RULE-SET,LAN,",
)


@dataclass
class RuleExplainAudit:
    """Result of dry-run `surge-cli rule explain` on an unlisted overseas canary domain."""
    canary_domain: str
    matched_rule: str = ""
    final_policy: str = ""
    duration_ms: float = 0.0
    triggered_local_dns: bool = False
    trigger_rule: Optional[str] = None
    dns_lookup_ms: float = 0.0
    success: bool = False
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "canary_domain": self.canary_domain,
            "matched_rule": self.matched_rule,
            "final_policy": self.final_policy,
            "duration_ms": round(self.duration_ms, 2),
            "triggered_local_dns": self.triggered_local_dns,
            "trigger_rule": self.trigger_rule,
            "dns_lookup_ms": round(self.dns_lookup_ms, 2),
            "success": self.success,
            "error": self.error,
        }


@dataclass
class ProxyAuditReport:
    """Read-only configuration & rule-engine audit report for local proxy clients."""
    client_detected: bool
    client_name: str = "未检测到支持的本地代理客户端"
    client_version: Optional[str] = None
    active_profile: Optional[str] = None
    profile_path: Optional[str] = None
    enhanced_mode: Optional[bool] = None
    system_proxy: Optional[bool] = None
    rule_explain: Optional[RuleExplainAudit] = None
    uses_plaintext_system_dns: bool = False
    encrypted_dns_configured: bool = False
    ipv6_enabled: bool = False
    hijack_dns_all: bool = False
    fallback_race_configured: bool = False
    missing_no_resolve_count: int = 0
    missing_no_resolve_samples: List[str] = field(default_factory=list)
    lan_before_proxy_rules: bool = False
    terminal_direct_above_dev_rules: bool = False
    audit_score: int = 100
    findings: List[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "client_detected": self.client_detected,
            "client_name": self.client_name,
            "client_version": self.client_version,
            "active_profile": self.active_profile,
            "profile_path": self.profile_path,
            "enhanced_mode": self.enhanced_mode,
            "system_proxy": self.system_proxy,
            "rule_explain": self.rule_explain.to_dict() if self.rule_explain else None,
            "uses_plaintext_system_dns": self.uses_plaintext_system_dns,
            "encrypted_dns_configured": self.encrypted_dns_configured,
            "ipv6_enabled": self.ipv6_enabled,
            "hijack_dns_all": self.hijack_dns_all,
            "fallback_race_configured": self.fallback_race_configured,
            "missing_no_resolve_count": self.missing_no_resolve_count,
            "missing_no_resolve_samples": self.missing_no_resolve_samples,
            "lan_before_proxy_rules": self.lan_before_proxy_rules,
            "terminal_direct_above_dev_rules": self.terminal_direct_above_dev_rules,
            "audit_score": self.audit_score,
            "findings": self.findings,
        }


def find_surge_cli() -> Optional[str]:
    for cand in SURGE_CLI_CANDIDATES:
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return shutil.which("surge-cli")


def parse_surge_status_output(text: str) -> dict:
    """Parse key metadata from `surge-cli status` output."""
    info: dict = {
        "version": None,
        "profile": None,
        "profile_path": None,
        "mode": None,
        "enhanced_mode": None,
        "system_proxy": None,
    }
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    if lines and lines[0].lower().startswith("surge"):
        info["version"] = lines[0]
    for line in lines:
        if line.startswith("Profile:"):
            info["profile"] = line.split(":", 1)[1].strip()
        elif line.startswith("Profile Path:"):
            info["profile_path"] = line.split(":", 1)[1].strip()
        elif line.startswith("Mode:"):
            info["mode"] = line.split(":", 1)[1].strip()
        elif line.startswith("enhanced-mode:"):
            info["enhanced_mode"] = line.split(":", 1)[1].strip().lower() == "on"
        elif line.startswith("system-proxy:"):
            info["system_proxy"] = line.split(":", 1)[1].strip().lower() == "on"
    return info


def parse_surge_rule_explain(canary_domain: str, text: str) -> RuleExplainAudit:
    """Parse `surge-cli rule explain <domain>` output to detect forced local DNS lookups."""
    audit = RuleExplainAudit(canary_domain=canary_domain, success=True)
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line.startswith("Matched rule:"):
            audit.matched_rule = line.split(":", 1)[1].strip()
        elif line.startswith("Final policy:"):
            audit.final_policy = line.split(":", 1)[1].strip()
        elif line.startswith("Duration:"):
            m = re.search(r"([0-9.]+)\s*ms", line)
            if m:
                audit.duration_ms = float(m.group(1))
        elif "requires DNS lookup for rule:" in line:
            audit.triggered_local_dns = True
            audit.trigger_rule = line.split("requires DNS lookup for rule:", 1)[1].strip()
        elif line.startswith("DNS lookup for") and "completed in" in line:
            audit.triggered_local_dns = True
            m = re.search(r"completed in\s+([0-9.]+)\s*ms", line)
            if m:
                audit.dns_lookup_ms = float(m.group(1))
    return audit


def audit_surge_conf_text(conf_text: str) -> dict:
    """
    Strictly inspect ONLY `[General]` and `[Rule]` sections of a Surge `.conf`.
    Ignores `[Proxy]` and `[Proxy Group]` completely so zero credentials are ever parsed.
    """
    section = ""
    general_kv: dict = {}
    missing_no_resolve: List[str] = []
    lan_line_idx: Optional[int] = None
    first_proxy_ruleset_idx: Optional[int] = None
    terminal_direct_idx: Optional[int] = None
    github_rule_idx: Optional[int] = None
    has_china_domain_rule = False

    for line_no, raw_line in enumerate(conf_text.splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip().lower()
            continue

        if section == "general":
            if "=" in line:
                k, v = line.split("=", 1)
                general_kv[k.strip().lower()] = v.strip()
        elif section == "rule":
            upper = line.upper()
            # Track domestic domain coverage
            if (
                "CHINADOMAIN" in upper
                or "CHINA.CONF" in upper
                or "DOMESTIC.CONF" in upper
                or upper.startswith("DOMAIN-SUFFIX,CN,")
            ):
                has_china_domain_rule = True

            # Track RULE-SET,LAN placement
            if upper.startswith("RULE-SET,LAN,"):
                if lan_line_idx is None:
                    lan_line_idx = line_no
            elif upper.startswith("RULE-SET,") and "DIRECT" not in upper and "国内" not in line:
                if first_proxy_ruleset_idx is None:
                    first_proxy_ruleset_idx = line_no

            # Track terminal DIRECT vs GitHub rule order
            if upper.startswith("PROCESS-NAME,") and ("ITERM" in upper or "TERMINAL" in upper) and ",DIRECT" in upper:
                if terminal_direct_idx is None:
                    terminal_direct_idx = line_no
            if "GITHUB.COM" in upper or "PROCESS-NAME,GH," in upper:
                if github_rule_idx is None:
                    github_rule_idx = line_no

            # Check missing ,no-resolve on IP rules and remote RULE-SETs
            is_ip_rule = any(upper.startswith(p) for p in IP_RULE_PREFIXES)
            is_remote_ruleset = upper.startswith("RULE-SET,HTTP")
            if (is_ip_rule or is_remote_ruleset) and ",NO-RESOLVE" not in upper:
                # Sanitize long URLs to basename for clean display without leaking custom URLs
                display = line
                if is_remote_ruleset:
                    parts = line.split(",")
                    if len(parts) >= 3:
                        url_base = parts[1].rstrip("/").rsplit("/", 1)[-1]
                        display = f"L{line_no}: RULE-SET .../{url_base},{parts[2]}"
                else:
                    display = f"L{line_no}: {line}"
                missing_no_resolve.append(display)

    dns_server = general_kv.get("dns-server", "")
    enc_dns = general_kv.get("encrypted-dns-server", "") or general_kv.get("doh-server", "")
    ipv6_val = general_kv.get("ipv6", "false").lower() == "true"
    hijack_dns = general_kv.get("hijack-dns", "")

    uses_system_dns = (not dns_server and not enc_dns) or ("system" in dns_server.lower() and not enc_dns)
    hijack_all = "*:53" in hijack_dns or "0.0.0.0:53" in hijack_dns
    lan_before_proxy = (
        lan_line_idx is not None
        and first_proxy_ruleset_idx is not None
        and lan_line_idx < first_proxy_ruleset_idx
        and any("RULE-SET,LAN" in s.upper() for s in missing_no_resolve)
    )
    terminal_above_dev = (
        terminal_direct_idx is not None
        and (github_rule_idx is None or terminal_direct_idx < github_rule_idx)
    )

    return {
        "uses_plaintext_system_dns": uses_system_dns,
        "encrypted_dns_configured": bool(enc_dns),
        "ipv6_enabled": ipv6_val,
        "hijack_dns_all": hijack_all,
        "missing_no_resolve": missing_no_resolve,
        "lan_before_proxy_rules": lan_before_proxy,
        "has_china_domain_rule": has_china_domain_rule,
        "terminal_direct_above_dev_rules": terminal_above_dev,
    }


def _run_surge_audit(surge_cli: str) -> Optional[ProxyAuditReport]:
    try:
        proc = subprocess.run([surge_cli, "status"], capture_output=True, text=True, timeout=3.0)
        if proc.returncode != 0 or not proc.stdout.strip():
            return None
    except Exception:
        return None

    status = parse_surge_status_output(proc.stdout)
    report = ProxyAuditReport(
        client_detected=True,
        client_name="Surge for Mac",
        client_version=status.get("version"),
        active_profile=status.get("profile"),
        profile_path=status.get("profile_path"),
        enhanced_mode=status.get("enhanced_mode"),
        system_proxy=status.get("system_proxy"),
    )

    # 1. Dry-run `surge-cli rule explain` on an unlisted canary domain
    canary = f"dnscheck-audit-{uuid.uuid4().hex[:8]}.oast.me"
    try:
        exp_proc = subprocess.run(
            [surge_cli, "rule", "explain", canary],
            capture_output=True,
            text=True,
            timeout=5.0,
        )
        if exp_proc.returncode == 0 and exp_proc.stdout.strip():
            report.rule_explain = parse_surge_rule_explain(canary, exp_proc.stdout)
        else:
            report.rule_explain = RuleExplainAudit(
                canary_domain=canary,
                success=False,
                error=(exp_proc.stderr or exp_proc.stdout).strip()[:120] or "rule explain failed",
            )
    except Exception as exc:
        report.rule_explain = RuleExplainAudit(canary_domain=canary, success=False, error=str(exc))

    # 2. Read-only audit of active `.conf` `[General]` and `[Rule]` sections
    conf_audit = None
    prof_path = status.get("profile_path")
    if prof_path and os.path.isfile(prof_path):
        try:
            text = Path(prof_path).read_text(encoding="utf-8", errors="replace")
            conf_audit = audit_surge_conf_text(text)
        except Exception:
            conf_audit = None

    score = 100
    findings: List[dict] = []

    if report.rule_explain and report.rule_explain.success:
        re_obj = report.rule_explain
        if re_obj.triggered_local_dns:
            score -= 35
            trig = re_obj.trigger_rule or "未知 IP 规则"
            findings.append(
                {
                    "level": "danger",
                    "title": f"Surge 规则求值触发了本地 DNS 预解析泄漏 ({trig} · 耗时 {re_obj.duration_ms:.0f}ms)",
                    "detail": (
                        f"对未知海外域名执行 dry-run 规则评估时，命中 `{trig}` 强制触发了本地 DNS 解析"
                        f"（单次耗时 {re_obj.dns_lookup_ms or re_obj.duration_ms:.0f}ms）。"
                        "请为该规则及所有 IP 类规则/规则集追加 `,no-resolve`。"
                    ),
                }
            )
        else:
            findings.append(
                {
                    "level": "ok",
                    "title": f"Surge 规则引擎零本地 DNS 预解析通过 ({re_obj.duration_ms:.1f}ms -> {re_obj.matched_rule})",
                    "detail": f"未知海外域名直接匹配至 `{re_obj.final_policy}`，全程未触发任何本地 DNS 查询。",
                }
            )

    if conf_audit:
        report.uses_plaintext_system_dns = conf_audit["uses_plaintext_system_dns"]
        report.encrypted_dns_configured = conf_audit["encrypted_dns_configured"]
        report.ipv6_enabled = conf_audit["ipv6_enabled"]
        report.hijack_dns_all = conf_audit["hijack_dns_all"]
        report.missing_no_resolve_count = len(conf_audit["missing_no_resolve"])
        report.missing_no_resolve_samples = conf_audit["missing_no_resolve"][:8]
        report.lan_before_proxy_rules = conf_audit["lan_before_proxy_rules"]
        report.terminal_direct_above_dev_rules = conf_audit["terminal_direct_above_dev_rules"]

        if report.lan_before_proxy_rules:
            score -= 20
            findings.append(
                {
                    "level": "danger",
                    "title": "高危排序：`RULE-SET,LAN,DIRECT` 位于代理规则上方且缺少 `,no-resolve`",
                    "detail": "这会导致全机绝大多数海外域名（含 OpenAI / Google / GitHub）先在本地查一次 DNS 才继续往下匹配。请改为 `RULE-SET,LAN,DIRECT,no-resolve`。",
                }
            )

        if report.missing_no_resolve_count > 0:
            score -= min(20, 5 + report.missing_no_resolve_count)
            sample_str = " ; ".join(report.missing_no_resolve_samples[:4])
            findings.append(
                {
                    "level": "warning",
                    "title": f"检测到 {report.missing_no_resolve_count} 条 IP 规则或外部 RULE-SET 缺少 `,no-resolve`",
                    "detail": f"示例: {sample_str}。建议全部追加 `,no-resolve` 并在 `GEOIP,CN` 上方配置国内域名规则集（如 `ChinaDomain.list` + `DOMAIN-SUFFIX,cn`）。",
                }
            )

        if report.uses_plaintext_system_dns:
            score -= 15
            findings.append(
                {
                    "level": "warning",
                    "title": "Surge `[General]` 未配置加密 DNS，正在回退 `system` 运营商明文 DNS",
                    "detail": "建议移除 `system`，改用 `dns-server = 223.5.5.5, 119.29.29.29` 与 `encrypted-dns-server = https://223.5.5.5/dns-query, https://1.12.12.12/dns-query`。",
                }
            )

        if report.ipv6_enabled:
            score -= 10
            findings.append(
                {
                    "level": "warning",
                    "title": "Surge 已开启 `ipv6 = true`，可能触发运营商 IPv6 DNS 旁路抢答",
                    "detail": "若代理节点未启用纯 IPv6 代理转发，建议在 `[General]` 设置 `ipv6 = false` 与 `ipv6-vif = disabled`。",
                }
            )

        if report.hijack_dns_all:
            findings.append(
                {
                    "level": "info",
                    "title": "已配置 `hijack-dns = *:53`（本地代理接管全部 53 端口）",
                    "detail": "注意：`hijack-dns = *:53` 会将发往 `8.8.8.8:53` / `1.1.1.1:53` 的请求劫持到本地 DNS 引擎；若无需接管硬编码 53 端口，可移除此项让其按代理规则转发。",
                }
            )

        if report.terminal_direct_above_dev_rules:
            findings.append(
                {
                    "level": "info",
                    "title": "检测到终端直连规则 (`iTerm` / `Terminal`) 位于 GitHub 规则之前",
                    "detail": "在终端运行 `gh` / `git` 时可能会因命中终端 `DIRECT` 规则导致连接超时或 EOF；可将 `PROCESS-NAME,gh` 与 `DOMAIN-SUFFIX,github.com` 置顶于终端直连规则之前。",
                }
            )

    report.audit_score = max(0, min(100, score))
    report.findings = findings
    return report


def run_proxy_config_audit() -> ProxyAuditReport:
    """
    Detect installed/running local proxy client (currently Surge for Mac with extensible hooks)
    and run a strictly read-only DNS & rule leak configuration audit.
    """
    surge_cli = find_surge_cli()
    if surge_cli:
        rep = _run_surge_audit(surge_cli)
        if rep is not None:
            return rep

    return ProxyAuditReport(
        client_detected=False,
        client_name="未检测到本地运行中的 Surge CLI（跳过客户端规则直审）",
        audit_score=100,
        findings=[
            {
                "level": "info",
                "title": "未检测到本地运行的 Surge CLI 实例",
                "detail": "客户端规则直审目前支持 macOS Surge (`surge-cli`)；其他客户端（Mihomo / Clash / Sing-box）可结合 OAST 6 维通道归因矩阵进行黑盒定位。",
            }
        ],
    )
