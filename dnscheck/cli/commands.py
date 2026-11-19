"""
CLI Command Router for DNSGuard (`dnscheck`).
Supports: all, leak, env, split, webrtc, pollute, bench, dig, ui.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from dnscheck import __version__
from dnscheck.cli import renderer
from dnscheck.detectors import (
    run_ai_services_diagnostics,
    run_custom_dig,
    run_dns_benchmark,
    run_dns_leak_detection,
    run_full_audit,
    run_pollution_detection,
    run_split_route_diagnostics,
    run_system_env_diagnostics,
    run_webrtc_ipv6_diagnostics,
)


def _write_json_output(data: dict, output_path: Optional[str], print_stdout: bool) -> None:
    json_str = json.dumps(data, ensure_ascii=False, indent=2)
    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(json_str)
        if not print_stdout:
            print(f"✔ 检测报告已导出至: {output_path}")
    if print_stdout:
        print(json_str)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dnscheck",
        description="DNSGuard (dnscheck) — DNS 泄漏深度检测、污染诊断、分流对比、WebRTC 与加密 DNS 测速工具",
    )
    parser.add_argument("--version", action="version", version=f"DNSGuard v{__version__}")

    subparsers = parser.add_subparsers(dest="command", help="诊断子命令 (默认为 all)")

    def _add_json_flags(p: argparse.ArgumentParser) -> None:
        p.add_argument("--json", action="store_true", help="以 JSON 格式输出结果")
        p.add_argument("-o", "--output", metavar="FILE", help="将 JSON 检测报告保存至指定文件")

    def _add_oast_flags(p: argparse.ArgumentParser) -> None:
        p.add_argument(
            "--oast-server",
            default=None,
            help="自定义 Interactsh OAST 服务器域名 (默认自动竞速公网 oast.* 集群)",
        )
        p.add_argument(
            "--oast-token",
            default=None,
            help="可选: 自建或 PDCP Interactsh OAST 认证 Token",
        )

    # 1. all
    p_all = subparsers.add_parser("all", help="运行完整深度安全审计 (默认)")
    _add_oast_flags(p_all)
    _add_json_flags(p_all)

    # 2. leak
    p_leak = subparsers.add_parser("leak", help="DNS 泄漏深度检测 (Interactsh OAST 带外权威抓包 + 透明劫持审计)")
    p_leak.add_argument("--rounds", type=int, default=6, help="辅助探测轮次 (默认 6)")
    _add_oast_flags(p_leak)
    _add_json_flags(p_leak)

    # 3. env
    p_env = subparsers.add_parser("env", help="本机系统 DNS 环境、TUN 虚拟网卡、Fake-IP 与 ECS 诊断")
    _add_json_flags(p_env)

    # 4. split
    p_split = subparsers.add_parser("split", help="国内外分流与多出口 IP 对比")
    _add_json_flags(p_split)

    # 5. webrtc
    p_rtc = subparsers.add_parser("webrtc", help="WebRTC / STUN UDP 真实公网 IP 与 IPv6 泄漏检测")
    _add_json_flags(p_rtc)

    # 6. pollute
    p_pol = subparsers.add_parser("pollute", help="DNS 污染/投毒检测 (对比 DoH 基准与明文 UDP-53)")
    _add_json_flags(p_pol)

    # 7. bench
    p_bench = subparsers.add_parser("bench", help="UDP / DoT / DoH 多协议加密 DNS 测速对比")
    p_bench.add_argument("--rounds", type=int, default=2, help="每个服务器测试轮次 (默认 2)")
    _add_json_flags(p_bench)

    # 8. ai
    p_ai = subparsers.add_parser("ai", help="一线 AI 服务 (OpenAI / Claude / Gemini / Grok / DeepSeek 等) 连通性与锁区检测")
    _add_json_flags(p_ai)

    # 8. dig
    p_dig = subparsers.add_parser("dig", help="自定义 DNS 报文探测器 (支持 UDP/TCP/DoT/DoH 及 ECS)")
    p_dig.add_argument("domain", help="要查询的目标域名")
    p_dig.add_argument("-s", "--server", default="223.5.5.5", help="目标 DNS IP 或 DoH URL (默认 223.5.5.5)")
    p_dig.add_argument("-p", "--proto", choices=["udp", "tcp", "dot", "doh", "system"], default="udp", help="传输协议")
    p_dig.add_argument("-t", "--type", default="A", help="记录类型 (A, AAAA, HTTPS, SVCB, TXT, NS, SOA, CNAME, PTR)")
    p_dig.add_argument("--ecs", default=None, help="附带 EDNS Client Subnet CIDR (例如 114.114.114.0/24)")
    _add_json_flags(p_dig)

    # 9. ui
    p_ui = subparsers.add_parser("ui", help="启动桌面 / Web 可视化诊断控制台")
    p_ui.add_argument("--port", type=int, default=8765, help="本地 HTTP 服务端口 (默认 8765)")
    p_ui.add_argument("--no-browser", action="store_true", help="仅启动本地服务，不自动打开窗口或浏览器")
    p_ui.add_argument("--app", action="store_true", help="尝试使用独立桌面应用窗口模式打开 (Chrome/Edge --app)")

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    cmd = args.command or "all"

    if cmd == "ui":
        from dnscheck.web.server import start_web_ui
        start_web_ui(port=args.port, open_browser=not args.no_browser, desktop_app=args.app)
        return 0

    as_json = getattr(args, "json", False)
    out_file = getattr(args, "output", None)
    oast_srv = getattr(args, "oast_server", None)
    oast_tok = getattr(args, "oast_token", None)

    if cmd == "all":
        if not as_json:
            print("正在并发执行 6 项深度 DNS 安全、Interactsh OAST 泄漏与 AI 解锁诊断，请稍候...", file=sys.stderr)
        audit = run_full_audit(oast_server=oast_srv, oast_token=oast_tok)
        if as_json or out_file:
            _write_json_output(audit, out_file, as_json)
        if not as_json:
            print(renderer.render_full_audit_report(audit))
        return 0

    if cmd == "ai":
        if not as_json:
            print("正在并发检测一线 AI 平台 (OpenAI / Claude / Gemini / Grok / Cursor / DeepSeek 等) 连通性与锁区状态...", file=sys.stderr)
        split_rep = run_split_route_diagnostics()
        rep = run_ai_services_diagnostics(split_report=split_rep).to_dict()
        if as_json or out_file:
            _write_json_output(rep, out_file, as_json)
        if not as_json:
            print(renderer.render_banner())
            print(renderer.render_ai_section(rep))
        return 0

    if cmd == "env":
        rep = run_system_env_diagnostics().to_dict()
        if as_json or out_file:
            _write_json_output(rep, out_file, as_json)
        if not as_json:
            print(renderer.render_banner())
            print(renderer.render_env_section(rep))
        return 0

    if cmd == "split":
        rep = run_split_route_diagnostics().to_dict()
        if as_json or out_file:
            _write_json_output(rep, out_file, as_json)
        if not as_json:
            print(renderer.render_banner())
            print(renderer.render_split_section(rep))
        return 0

    if cmd == "leak":
        if not as_json:
            print("正在启动 Interactsh OAST 带外权威抓包与多通道泄漏归因探测...", file=sys.stderr)
        split_rep = run_split_route_diagnostics()
        rep = run_dns_leak_detection(
            split_report=split_rep,
            rounds=args.rounds,
            oast_server=oast_srv,
            oast_token=oast_tok,
        ).to_dict()
        if as_json or out_file:
            _write_json_output(rep, out_file, as_json)
        if not as_json:
            print(renderer.render_banner())
            print(renderer.render_leak_section(rep))
        return 0

    if cmd == "webrtc":
        split_rep = run_split_route_diagnostics()
        rep = run_webrtc_ipv6_diagnostics(split_report=split_rep).to_dict()
        if as_json or out_file:
            _write_json_output(rep, out_file, as_json)
        if not as_json:
            print(renderer.render_banner())
            print(renderer.render_webrtc_section(rep))
        return 0

    if cmd == "pollute":
        if not as_json:
            print("正在获取 DoH 可信基准并对比明文 UDP-53 污染状态...", file=sys.stderr)
        rep = run_pollution_detection().to_dict()
        if as_json or out_file:
            _write_json_output(rep, out_file, as_json)
        if not as_json:
            print(renderer.render_banner())
            print(renderer.render_pollution_section(rep))
        return 0

    if cmd == "bench":
        if not as_json:
            print("正在并发测试国内外主流 UDP / DoT / DoH DNS 服务器性能...", file=sys.stderr)
        rep = run_dns_benchmark(rounds=args.rounds).to_dict()
        if as_json or out_file:
            _write_json_output(rep, out_file, as_json)
        if not as_json:
            print(renderer.render_banner())
            print(renderer.render_benchmark_section(rep))
        return 0

    if cmd == "dig":
        rep = run_custom_dig(
            domain=args.domain,
            server=args.server,
            proto=args.proto,
            qtype_name=args.type,
            ecs=args.ecs,
        )
        if as_json or out_file:
            _write_json_output(rep, out_file, as_json)
        if not as_json:
            print(renderer.render_dig_result(rep))
        return 0

    parser.print_help()
    return 1
