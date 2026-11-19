"""
Rich terminal ANSI renderer with CJK-aware Unicode box-drawing tables,
latency bar charts, risk badges, and structured diagnostic reports.
"""

from __future__ import annotations

import os
import re
import sys
import unicodedata
from typing import Dict, List, Optional

from dnscheck import __version__

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _supports_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


class C:
    """ANSI color palette."""
    ENABLED = _supports_color()

    RESET = "\033[0m" if ENABLED else ""
    BOLD = "\033[1m" if ENABLED else ""
    DIM = "\033[2m" if ENABLED else ""
    CYAN = "\033[36m" if ENABLED else ""
    BLUE = "\033[34m" if ENABLED else ""
    GREEN = "\033[32m" if ENABLED else ""
    YELLOW = "\033[33m" if ENABLED else ""
    RED = "\033[31m" if ENABLED else ""
    MAGENTA = "\033[35m" if ENABLED else ""
    WHITE = "\033[97m" if ENABLED else ""
    BG_GREEN = "\033[42;30m" if ENABLED else ""
    BG_YELLOW = "\033[43;30m" if ENABLED else ""
    BG_RED = "\033[41;97m" if ENABLED else ""
    BG_CYAN = "\033[46;30m" if ENABLED else ""


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text)


def display_width(text: str) -> int:
    """Compute exact terminal column width accounting for CJK double-width characters."""
    clean = strip_ansi(text)
    w = 0
    for ch in clean:
        if unicodedata.combining(ch):
            continue
        eaw = unicodedata.east_asian_width(ch)
        w += 2 if eaw in ("W", "F") else 1
    return w


def truncate_display(text: str, max_width: int) -> str:
    """Truncate plain or ANSI-free text cleanly to fit max_width columns."""
    clean = strip_ansi(text)
    if display_width(clean) <= max_width:
        return text
    if max_width <= 3:
        return "." * max_width
    out: List[str] = []
    cur_w = 0
    for ch in clean:
        if unicodedata.combining(ch):
            continue
        cw = 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1
        if cur_w + cw > max_width - 1:
            break
        out.append(ch)
        cur_w += cw
    return "".join(out) + "…"


def pad_display(text: str, width: int, align: str = "left") -> str:
    """Pad text (possibly containing ANSI escapes & CJK chars) to exact column width."""
    vis_w = display_width(text)
    if vis_w > width:
        text = truncate_display(text, width)
        vis_w = display_width(text)
    pad = max(0, width - vis_w)
    if align == "right":
        return (" " * pad) + text
    if align == "center":
        left = pad // 2
        right = pad - left
        return (" " * left) + text + (" " * right)
    return text + (" " * pad)


def render_table(
    headers: List[str],
    rows: List[List[str]],
    max_col_widths: Optional[List[int]] = None,
    alignments: Optional[List[str]] = None,
) -> str:
    """Render a clean Unicode box-drawing table with proper CJK alignment."""
    num_cols = len(headers)
    col_widths = [display_width(h) for h in headers]

    for row in rows:
        for i in range(min(num_cols, len(row))):
            w = display_width(str(row[i]))
            if w > col_widths[i]:
                col_widths[i] = w

    if max_col_widths:
        for i, mw in enumerate(max_col_widths):
            if i < num_cols and mw > 0:
                col_widths[i] = min(col_widths[i], mw)

    aligns = alignments or ["left"] * num_cols

    top = "┌" + "┬".join("─" * (w + 2) for w in col_widths) + "┐"
    mid = "├" + "┼".join("─" * (w + 2) for w in col_widths) + "┤"
    bot = "└" + "┴".join("─" * (w + 2) for w in col_widths) + "┘"

    def _fmt_row(cells: List[str], is_header: bool = False) -> str:
        parts = []
        for i in range(num_cols):
            val = str(cells[i]) if i < len(cells) else ""
            padded = pad_display(val, col_widths[i], aligns[i] if not is_header else "left")
            if is_header:
                padded = f"{C.BOLD}{C.CYAN}{padded}{C.RESET}"
            parts.append(f" {padded} ")
        return "│" + "│".join(parts) + "│"

    lines = [top, _fmt_row(headers, is_header=True), mid]
    for r in rows:
        lines.append(_fmt_row(r))
    lines.append(bot)
    return "\n".join(lines)


def render_latency_bar(ms: float, max_ms: float = 250.0, width: int = 18) -> str:
    """Render a horizontal latency bar with color thresholds."""
    if ms <= 0:
        return f"{C.DIM}{'-' * width}{C.RESET}"
    ratio = min(1.0, ms / max(1.0, max_ms))
    filled = max(1, int(round(ratio * width)))
    empty = width - filled
    color = C.GREEN if ms < 50 else (C.YELLOW if ms < 140 else C.RED)
    return f"{color}{'█' * filled}{C.DIM}{'░' * empty}{C.RESET}"


def badge_level(level: str, text: str) -> str:
    lvl = level.lower()
    if lvl in ("ok", "safe", "clean"):
        return f"{C.GREEN}✔ {text}{C.RESET}"
    if lvl in ("warning", "warn", "fake_ip"):
        return f"{C.YELLOW}▲ {text}{C.RESET}"
    if lvl in ("danger", "leak", "poisoned", "error"):
        return f"{C.RED}✖ {text}{C.RESET}"
    return f"{C.CYAN}ℹ {text}{C.RESET}"


def render_section_header(title: str) -> str:
    bar = "━" * 72
    return f"\n{C.CYAN}{C.BOLD}{bar}\n  {title}\n{bar}{C.RESET}"


def render_banner() -> str:
    title = f"DNSGuard (dnscheck) · DNS 泄漏深度诊断 & 网络安全审计套件 v{__version__}"
    inner_w = 70
    padded = pad_display(title, inner_w, align="center")
    return (
        f"{C.CYAN}{C.BOLD}"
        f"╔{'═' * inner_w}╗\n"
        f"║{padded}║\n"
        f"╚{'═' * inner_w}╝"
        f"{C.RESET}"
    )


def render_findings(findings: List[dict]) -> str:
    if not findings:
        return ""
    lines = []
    for f in findings:
        lines.append("  " + badge_level(f.get("level", "info"), f"{C.BOLD}{f.get('title', '')}{C.RESET}"))
        if f.get("detail"):
            lines.append(f"    {C.DIM}{f['detail']}{C.RESET}")
    return "\n".join(lines)


def render_env_section(env: dict) -> str:
    out = [render_section_header("1. 本机系统 DNS 环境与代理架构诊断")]
    out.append(f"  操作系统 : {C.WHITE}{env['os_name']}{C.RESET}")
    out.append(f"  工作模式 : {C.CYAN}{C.BOLD}{env['dns_mode']}{C.RESET}")
    ecs_text = (
        f"{C.YELLOW}已启用 ({env['ecs_subnet']}){C.RESET}"
        if env["ecs_supported"]
        else f"{C.GREEN}未暴露 / 未启用{C.RESET}"
    )
    out.append(f"  ECS 状态 : {ecs_text}")

    # System Proxy info
    sp = env.get("system_proxy", {})
    proxy_parts = []
    if sp.get("http_enabled"):
        proxy_parts.append(f"HTTP={sp['http_proxy']}")
    if sp.get("https_enabled"):
        proxy_parts.append(f"HTTPS={sp['https_proxy']}")
    if sp.get("socks_enabled"):
        proxy_parts.append(f"SOCKS={sp['socks_proxy']}")
    if sp.get("env_proxy"):
        proxy_parts.append(f"ENV={sp['env_proxy']}")
    out.append(f"  系统代理 : {', '.join(proxy_parts) if proxy_parts else '未开启'}")

    # Configured DNS Table
    dns_rows = []
    for d in env.get("configured_dns_details", []):
        tag = "国内" if d.get("is_cn") else ("本地/虚拟" if d.get("is_private") else "海外/全球")
        dns_rows.append([d["ip"], tag, d.get("location", "-"), d.get("display_isp", "-")])
    if dns_rows:
        out.append("\n  " + f"{C.BOLD}系统主 DNS 服务器:{C.RESET}")
        out.append(render_table(["DNS IP", "属性", "归属地", "运营商 / 标识"], dns_rows, [28, 12, 20, 34]))

    # TUN Adapters
    tuns = env.get("tun_interfaces", [])
    if tuns:
        tun_rows = [
            [
                t["name"],
                ", ".join(t["ipv4"] or t["ipv6"]),
                "是 (Fake-IP)" if t["is_fake_ip_tun"] else "否",
                t["likely_client"],
            ]
            for t in tuns
        ]
        out.append("\n  " + f"{C.BOLD}检测到的虚拟隧道网卡 (TUN/VPN):{C.RESET}")
        out.append(render_table(["网卡", "分配地址", "Fake-IP", "推测客户端"], tun_rows, [12, 24, 14, 34]))

    # Fake-IP samples
    f_rows = [
        [
            s["domain"],
            ", ".join(s["answers"]) if s["answers"] else "(无响应)",
            f"{s['latency_ms']:.1f}ms",
            f"{C.CYAN}Fake-IP{C.RESET}" if s["is_fake_ip"] else "真实解析",
        ]
        for s in env.get("fake_ip_samples", [])
    ]
    if f_rows:
        out.append("\n  " + f"{C.BOLD}Fake-IP 行为探针:{C.RESET}")
        out.append(render_table(["测试域名", "系统解析返回 IP", "耗时", "判定"], f_rows, [38, 22, 10, 14], ["left", "left", "right", "left"]))

    findings_txt = render_findings(env.get("findings", []))
    if findings_txt:
        out.append("\n" + findings_txt)
    return "\n".join(out)


def render_split_section(split: dict) -> str:
    out = [render_section_header("2. 国内外分流与多出口 IP 对比矩阵")]
    out.append(f"  路由模式 : {C.CYAN}{C.BOLD}{split['routing_mode']}{C.RESET}")

    rows = []
    for ex in split.get("exits", []):
        intel = ex.get("intel") or {}
        if ex["success"]:
            loc = intel.get("location", "-")
            isp = intel.get("display_isp", "-")
            extra = ""
            if ex.get("extra_meta") and ex["extra_meta"].get("colo"):
                extra = f" [POP:{ex['extra_meta']['colo']}]"
            status_str = f"{C.GREEN}{ex['latency_ms']:.0f}ms{C.RESET}"
            ip_str = ex["ip"] or "-"
        else:
            loc = "-"
            isp = ex.get("error") or "不可达"
            extra = ""
            status_str = f"{C.DIM}超时/未启用{C.RESET}"
            ip_str = "-"
        rows.append([ex["category_name"], ip_str, loc + extra, isp, status_str])

    out.append(render_table(["出口通道", "出口 IP", "归属地 / POP", "运营商 / ASN", "延迟"], rows, [28, 26, 22, 30, 12], ["left", "left", "left", "left", "right"]))
    findings_txt = render_findings(split.get("findings", []))
    if findings_txt:
        out.append("\n" + findings_txt)
    return "\n".join(out)


def render_leak_section(leak: dict) -> str:
    out = [render_section_header("3. DNS 泄漏深度检测 (Interactsh OAST 带外权威抓包 & 透明劫持审计)")]
    status = leak["leak_status"]
    badge_bg = C.BG_GREEN if status == "SAFE" else (C.BG_YELLOW if status == "WARNING" else C.BG_RED)
    out.append(
        f"  泄漏评级 : {badge_bg} {leak['leak_status_label']} {C.RESET}   "
        f"安全评分: {C.BOLD}{leak['risk_score']}/100{C.RESET}   "
        f"(国内DNS: {leak['cn_resolver_count']} / 海外DNS: {leak['overseas_resolver_count']})"
    )
    if leak.get("oast_enabled"):
        out.append(
            f"  OAST 引擎: {C.GREEN}✔ 已连接 {leak.get('oast_server')}{C.RESET} "
            f"{C.DIM}(最快节点握手 {leak.get('oast_register_ms', 0):.0f}ms · 权威捕获 {leak.get('oast_events_count', 0)} 个原始 DNS 报文){C.RESET}"
        )
    else:
        out.append(
            f"  OAST 引擎: {C.YELLOW}▲ 公网 OAST 集群受限，已自动降级至多源会话/反射备援模式{C.RESET}"
        )

    vec_rows = []
    for v in leak.get("vector_probes", []):
        st = v.get("status", "INFO")
        if st == "SAFE":
            st_str = f"{C.GREEN}✔ {v['status_label']}{C.RESET}"
        elif st == "INTERCEPTED":
            st_str = f"{C.CYAN}◆ {v['status_label']}{C.RESET}"
        elif st == "WARNING":
            st_str = f"{C.YELLOW}▲ {v['status_label']}{C.RESET}"
        elif st == "LEAK":
            st_str = f"{C.RED}✖ {v['status_label']}{C.RESET}"
        else:
            st_str = f"{C.DIM}○ {v['status_label']}{C.RESET}"

        if v.get("resolver_ips"):
            captured_str = ", ".join(v["resolver_ips"][:2])
            if len(v["resolver_ips"]) > 2:
                captured_str += f" (+{len(v['resolver_ips']) - 2})"
        elif v.get("is_fake_ip") and v.get("local_answers"):
            captured_str = f"本地 {v['local_answers'][0]}"
        else:
            captured_str = "(零公网触发)"

        vec_rows.append([
            v["vector_name"],
            v["qtype"],
            captured_str,
            st_str,
            v.get("note", ""),
        ])

    if vec_rows:
        out.append("\n  " + f"{C.BOLD}OAST 多维通道带外归因矩阵 (逐包追踪):{C.RESET}")
        out.append(
            render_table(
                ["探测通道", "类型", "权威捕获递归 IP / 拦截", "通道判定", "归因说明"],
                vec_rows,
                [26, 8, 26, 18, 40],
                ["left", "center", "left", "left", "left"],
            )
        )

    res_rows = []
    for r in leak.get("resolvers", []):
        intel = r.get("intel") or {}
        region_tag = f"{C.YELLOW}国内{C.RESET}" if intel.get("is_cn") else f"{C.GREEN}海外{C.RESET}"
        if intel.get("is_private"):
            region_tag = f"{C.CYAN}本地{C.RESET}"
        res_rows.append([
            r["ip"],
            region_tag,
            intel.get("location", "-"),
            intel.get("display_isp", "-"),
            str(r["hits"]),
            ", ".join(r["sources"][:2]),
        ])

    if res_rows:
        out.append("\n  " + f"{C.BOLD}发现的上游递归 DNS 服务器:{C.RESET}")
        out.append(render_table(["递归 DNS IP", "区域", "地理位置", "运营商 / ASN", "命中", "探测来源"], res_rows, [26, 8, 20, 30, 6, 30], ["left", "center", "left", "left", "right", "left"]))

    # Transparent Hijack Probes
    h_rows = []
    for h in leak.get("hijack_probes", []):
        if not h["success"]:
            verdict = f"{C.DIM}超时未阻断{C.RESET}"
            ret = "-"
        elif h.get("proxy_hijacked"):
            verdict = f"{C.CYAN}◆ 代理接管{C.RESET}"
            ret = h["returned_resolver_ip"] or "-"
        elif h["hijacked"]:
            verdict = f"{C.RED}✖ 被透明劫持{C.RESET}"
            ret = h["returned_resolver_ip"] or "-"
        else:
            verdict = f"{C.GREEN}✔ 正常直连/转发{C.RESET}"
            ret = h["returned_resolver_ip"] or h.get("chaos_id") or "-"
        h_rows.append([h["target_server"], ret, verdict, h["reason"]])

    if h_rows:
        out.append("\n  " + f"{C.BOLD}明文 UDP-53 透明劫持探测 (直连 8.8.8.8 / 1.1.1.1):{C.RESET}")
        out.append(render_table(["目标探测端口", "实际应答 IP / 节点", "判定", "说明"], h_rows, [16, 22, 16, 48]))

    findings_txt = render_findings(leak.get("findings", []))
    if findings_txt:
        out.append("\n" + findings_txt)
    return "\n".join(out)


def render_webrtc_section(rtc: dict) -> str:
    out = [render_section_header("4. WebRTC / STUN UDP 穿透与 IPv6 泄漏检测")]
    v_color = C.RED if (rtc["webrtc_udp_leak"] or rtc["ipv6_leak"]) else C.GREEN
    out.append(f"  检测结论 : {v_color}{C.BOLD}{rtc['verdict_label']}{C.RESET}")

    stun_rows = []
    for p in rtc.get("stun_probes", []):
        intel = p.get("intel") or {}
        if p["success"]:
            loc = intel.get("location", "-")
            isp = intel.get("display_isp", "-")
            mapped = f"{p['mapped_ip']}:{p['mapped_port']}"
            lat = f"{p['latency_ms']:.1f}ms"
        else:
            loc = "-"
            isp = p.get("error") or "超时"
            mapped = "(不可达)"
            lat = "-"
        stun_rows.append([p["provider_name"], f"IPv{p['ip_version']}", mapped, loc, isp, lat])

    out.append("\n  " + f"{C.BOLD}STUN UDP 公网 IP 映射探测 (WebRTC srflx 等效):{C.RESET}")
    out.append(render_table(["STUN 服务器", "协议", "映射公网 IP:端口", "归属地", "运营商", "延迟"], stun_rows, [22, 6, 28, 18, 28, 10], ["left", "center", "left", "left", "left", "right"]))

    lans = rtc.get("local_lan_ips", [])
    if lans:
        lan_str = ", ".join(f"{l['interface']}:{l['ip']}" for l in lans[:6])
        out.append(f"\n  {C.BOLD}本机网卡地址 (Host 候选):{C.RESET} {C.DIM}{lan_str}{C.RESET}")

    findings_txt = render_findings(rtc.get("findings", []))
    if findings_txt:
        out.append("\n" + findings_txt)
    return "\n".join(out)


def render_pollution_section(pol: dict) -> str:
    out = [render_section_header("5. DNS 污染 / 抢答投毒对比检测")]
    color = C.RED if pol["pollution_detected"] else C.GREEN
    out.append(f"  污染判定 : {color}{C.BOLD}{pol['summary']}{C.RESET}")

    if pol.get("rows"):
        srv_headers = [c["server_label"] for c in pol["rows"][0]["results"]]
        table_rows = []
        for row in pol["rows"]:
            base = row["baseline_ips"][0] if row["baseline_ips"] else "(无)"
            cells = [f"{row['domain']}", base]
            for c in row["results"]:
                st = c["status"]
                ans_first = c["answers"][0] if c["answers"] else "-"
                if st == "CLEAN":
                    cells.append(f"{C.GREEN}✔ 正常{C.RESET} ({ans_first})")
                elif st == "FAKE_IP":
                    cells.append(f"{C.CYAN}◆ FakeIP{C.RESET} ({ans_first})")
                elif st == "POISONED":
                    cells.append(f"{C.RED}✖ 投毒{C.RESET} ({ans_first})")
                else:
                    cells.append(f"{C.DIM}○ 超时{C.RESET}")
            table_rows.append(cells)

        headers = ["探测域名", "DoH 可信基准"] + srv_headers
        out.append(render_table(headers, table_rows, [18, 18] + [24] * len(srv_headers)))

    findings_txt = render_findings(pol.get("findings", []))
    if findings_txt:
        out.append("\n" + findings_txt)
    return "\n".join(out)


def render_benchmark_section(bench: dict) -> str:
    out = [render_section_header("6. 公共 & 加密 DNS (UDP / DoT / DoH) 多协议测速榜")]
    rows = []
    for e in bench.get("entries", []):
        if e["available"]:
            bar = render_latency_bar(e["avg_ms"])
            lat_str = f"{e['avg_ms']:.1f}ms"
            dnssec = f"{C.GREEN}支持{C.RESET}" if e["dnssec_ad"] else f"{C.DIM}未标记{C.RESET}"
            rate = f"{e['success_rate']:.0f}%"
        else:
            bar = f"{C.RED}✖ 不可用{C.RESET}"
            lat_str = "-"
            dnssec = "-"
            rate = "0%"
        rows.append([e["name"], e["protocol"], e["region"], lat_str, bar, rate, dnssec])

    out.append(render_table(["DNS 服务商", "协议", "区域", "平均延迟", "响应柱状图", "可用率", "DNSSEC"], rows, [22, 6, 6, 10, 20, 8, 8], ["left", "center", "center", "right", "left", "right", "center"]))
    return "\n".join(out)


def render_ai_section(ai: dict) -> str:
    out = [render_section_header("7. 一线 AI 服务连通性、分流出口与锁区检测")]
    out.append(
        f"  检测汇总 : 共 {ai.get('total_count', 0)} 项   "
        f"{C.GREEN}✔ 正常可用: {ai.get('available_count', 0)}{C.RESET}   "
        f"{C.YELLOW}▲ Web风控/CF盾: {ai.get('challenge_count', 0)}{C.RESET}   "
        f"{C.RED}✖ 锁区受限: {ai.get('region_blocked_count', 0)}{C.RESET}   "
        f"{C.DIM}○ 不可达: {ai.get('unreachable_count', 0)}{C.RESET}"
    )

    rows = []
    for s in ai.get("services", []):
        dns_tag = (
            f"{C.CYAN}Fake-IP{C.RESET}"
            if s["dns_status"] == "FAKE_IP"
            else (
                f"{C.RED}污染{C.RESET}"
                if s["dns_status"] == "POISONED"
                else (f"{C.DIM}无记录{C.RESET}" if s["dns_status"] == "NXDOMAIN" else "真实IP")
            )
        )
        loc = s.get("exit_location") or "-"
        if s.get("colo"):
            loc = f"{loc} [{s['colo']}]"
        lat = f"{s['latency_ms']:.0f}ms" if s.get("tls_ok") else "-"
        avail = s["availability"]
        if avail == "AVAILABLE":
            st_str = f"{C.GREEN}✔ {s['availability_label']}{C.RESET}"
        elif avail == "RISK_CHALLENGE":
            st_str = f"{C.YELLOW}▲ {s['availability_label']}{C.RESET}"
        elif avail == "REGION_BLOCKED":
            st_str = f"{C.RED}✖ {s['availability_label']}{C.RESET}"
        else:
            st_str = f"{C.RED}✖ {s['availability_label']}{C.RESET}"

        rows.append([
            f"{s['provider']} · {s['name']}",
            s["domain"],
            dns_tag,
            loc,
            lat,
            st_str,
            s.get("note", ""),
        ])

    out.append(
        render_table(
            ["AI 平台 / 服务", "域名", "DNS 模式", "出口地区 / POP", "延迟", "诊断状态", "说明"],
            rows,
            [24, 30, 10, 22, 8, 22, 34],
            ["left", "left", "center", "left", "right", "left", "left"],
        )
    )
    findings_txt = render_findings(ai.get("findings", []))
    if findings_txt:
        out.append("\n" + findings_txt)
    return "\n".join(out)


def render_proxy_audit_section(pa: dict) -> str:
    out = [render_section_header("8. 本机代理配置与规则求值只读审计 (Proxy Config Audit)")]
    if not pa.get("client_detected"):
        out.append(f"  检测状态 : {C.DIM}{pa.get('client_name', '未检测到支持的客户端')}{C.RESET}")
        findings_txt = render_findings(pa.get("findings", []))
        if findings_txt:
            out.append("\n" + findings_txt)
        return "\n".join(out)

    ver = pa.get("client_version") or pa.get("client_name")
    prof = pa.get("active_profile") or "-"
    enh = "On" if pa.get("enhanced_mode") else "Off"
    sysp = "On" if pa.get("system_proxy") else "Off"
    out.append(
        f"  代理客户端 : {C.CYAN}{C.BOLD}{ver}{C.RESET}   "
        f"活跃配置: {C.WHITE}{prof}{C.RESET}   "
        f"增强模式: {enh} · 系统代理: {sysp}   "
        f"配置评分: {C.BOLD}{pa.get('audit_score', 100)}/100{C.RESET}"
    )

    re_obj = pa.get("rule_explain")
    if re_obj and re_obj.get("success"):
        dns_flag = (
            f"{C.RED}✖ 触发本地 DNS ({re_obj.get('trigger_rule')}){C.RESET}"
            if re_obj.get("triggered_local_dns")
            else f"{C.GREEN}✔ 零本地 DNS 预解析{C.RESET}"
        )
        rows = [
            [
                re_obj.get("canary_domain", "-"),
                re_obj.get("matched_rule", "-"),
                re_obj.get("final_policy", "-"),
                f"{re_obj.get('duration_ms', 0):.1f}ms",
                dns_flag,
            ]
        ]
        out.append("\n  " + f"{C.BOLD}未知海外域名规则求值实测 (Dry-Run Rule Explain):{C.RESET}")
        out.append(
            render_table(
                ["探测金丝雀域名", "命中规则", "最终出站策略", "耗时", "本地 DNS 行为"],
                rows,
                [28, 24, 24, 10, 26],
                ["left", "left", "left", "right", "left"],
            )
        )

    findings_txt = render_findings(pa.get("findings", []))
    if findings_txt:
        out.append("\n" + findings_txt)
    return "\n".join(out)


def render_claude_guard_section(cg: dict) -> str:
    out = [render_section_header("9. Claude 全链路防风控分流一致性审计 (14 域名 + 34.8.0.0/16)")]
    verdict = cg.get("verdict", "WARNING")
    bg = C.BG_GREEN if verdict == "SAFE" else (C.BG_YELLOW if verdict == "WARNING" else C.BG_RED)
    mode_str = f"白盒规则直审 ({cg['whitebox_client']})" if cg.get("whitebox_client") else "黑盒 DNS + CF Trace 模式"
    base_str = cg.get("baseline_policy") or cg.get("baseline_exit_ip") or "-"
    out.append(
        f"  风控评级 : {bg} {cg.get('verdict_label', '-')} {C.RESET}   "
        f"一致性评分: {C.BOLD}{cg.get('score', 0)}/100{C.RESET}   "
        f"基准出口: {C.CYAN}{base_str}{C.RESET}"
    )
    out.append(
        f"  审计模式 : {C.DIM}{mode_str} · 一致: {cg.get('consistent_count', 0)}/{cg.get('total_count', 0)} · "
        f"直连泄漏: {cg.get('direct_leak_count', 0)} · 出口漂移: {cg.get('split_drift_count', 0)}{C.RESET}"
    )

    rows = []
    for t in cg.get("targets", []):
        st = t.get("status", "INFO")
        if st == "CONSISTENT":
            st_str = f"{C.GREEN}✔ {t['status_label']}{C.RESET}"
        elif st == "SPLIT_DRIFT":
            st_str = f"{C.YELLOW}▲ {t['status_label']}{C.RESET}"
        elif st in ("DIRECT_LEAK", "REGION_BLOCKED"):
            st_str = f"{C.RED}✖ {t['status_label']}{C.RESET}"
        else:
            st_str = f"{C.DIM}ℹ {t['status_label']}{C.RESET}"

        exit_col = t.get("final_policy") or (
            f"{t['cf_exit_ip']} ({t['cf_exit_cc']})" if t.get("cf_exit_ip") else t.get("dns_status", "-")
        )
        rows.append([
            t["target"],
            t["role"],
            exit_col,
            st_str,
            t.get("note", ""),
        ])

    out.append(
        render_table(
            ["域名 / IP 段", "关联用途", "实际命中出口 / DNS", "一致性判定", "风险说明"],
            rows,
            [30, 18, 28, 16, 38],
            ["left", "left", "left", "left", "left"],
        )
    )
    findings_txt = render_findings(cg.get("findings", []))
    if findings_txt:
        out.append("\n" + findings_txt)
    return "\n".join(out)


def render_dig_result(res: dict) -> str:
    out = [render_section_header(f"DNS 报文自定义探测 ({res['protocol']} -> {res['server']})")]
    out.append(f"  查询域名 : {C.BOLD}{res['domain']}{C.RESET}  |  记录类型: {res['qtype']}  |  状态码: {res['rcode']}  |  耗时: {res['latency_ms']}ms")
    flags = res.get("packet_flags") or {}
    if flags:
        flag_list = [k.upper() for k, v in flags.items() if v]
        out.append(f"  报文标志 : {', '.join(flag_list) if flag_list else '无'}  |  DNSSEC(AD): {'是' if res.get('dnssec_ad') else '否'}")
    if res.get("edns_ecs"):
        ecs = res["edns_ecs"]
        out.append(f"  EDNS ECS : {ecs.get('cidr')} (scope /{ecs.get('scope_prefix_len')})")

    intel_map: Dict[str, dict] = res.get("answer_intel") or {}
    if res.get("answers"):
        rows = []
        for ans in res["answers"]:
            info = intel_map.get(ans) or {}
            rows.append([
                ans,
                str(res.get("ttl") if res.get("ttl") is not None else "-"),
                info.get("location", "-"),
                info.get("display_isp", "-"),
            ])
        out.append(render_table(["应答记录 (RDATA)", "TTL", "地理位置", "运营商 / ASN"], rows, [34, 8, 22, 32], ["left", "right", "left", "left"]))
    else:
        out.append(f"  {C.YELLOW}未返回应答记录 ({res.get('error') or res['rcode']}){C.RESET}")
    return "\n".join(out)


def render_full_audit_report(audit: dict) -> str:
    parts = [render_banner()]
    score = audit["overall_score"]
    verdict = audit["overall_verdict"]
    bg = C.BG_GREEN if verdict == "SAFE" else (C.BG_YELLOW if verdict == "WARNING" else C.BG_RED)

    parts.append(
        f"\n  {C.BOLD}综合安全评分:{C.RESET} {C.WHITE}{C.BOLD}{score}/100{C.RESET}   "
        f"{bg} {audit['overall_verdict_label']} {C.RESET}   "
        f"{C.DIM}(检测耗时 {audit['elapsed_ms']:.0f}ms · {audit['timestamp']}){C.RESET}"
    )

    parts.append(render_env_section(audit["env"]))
    parts.append(render_split_section(audit["split"]))
    parts.append(render_leak_section(audit["leak"]))
    parts.append(render_webrtc_section(audit["webrtc"]))
    parts.append(render_pollution_section(audit["pollution"]))
    parts.append(render_benchmark_section(audit["benchmark"]))
    if audit.get("ai"):
        parts.append(render_ai_section(audit["ai"]))
    if audit.get("claude_guard"):
        parts.append(render_claude_guard_section(audit["claude_guard"]))
    if audit.get("proxy_audit") and audit["proxy_audit"].get("client_detected"):
        parts.append(render_proxy_audit_section(audit["proxy_audit"]))

    recs = audit.get("recommendations", [])
    if recs:
        parts.append(render_section_header("安全加固建议 (Actionable Recommendations)"))
        for i, rec in enumerate(recs, 1):
            parts.append(f"  {C.CYAN}{i}.{C.RESET} {rec}")
    parts.append("")
    return "\n".join(parts)
