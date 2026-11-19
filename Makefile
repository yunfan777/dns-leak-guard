PYTHON ?= python3

.PHONY: help check leak env split webrtc pollute bench ai ui app test clean

help:
	@echo "DNSGuard (dnscheck) 快捷命令:"
	@echo "  make check    - 运行全套 6 合 1 DNS 安全与 AI 解锁深度诊断 (CLI)"
	@echo "  make ui       - 启动本地 Web 可视化诊断控制台 (默认 127.0.0.1:8765)"
	@echo "  make app      - 以独立桌面应用窗口模式启动可视化面板"
	@echo "  make leak     - 仅运行 DNS 泄漏与透明劫持检测"
	@echo "  make env      - 仅运行本机系统 DNS / TUN / Fake-IP / ECS 诊断"
	@echo "  make split    - 仅运行国内外网络分流与多出口对比"
	@echo "  make ai       - 仅运行一线 AI 服务连通性与锁区检测 (OpenAI/Claude/Gemini等)"
	@echo "  make webrtc   - 仅运行 STUN / WebRTC UDP 穿透与 IPv6 泄漏检测"
	@echo "  make pollute  - 仅运行 DNS 污染/抢答投毒检测"
	@echo "  make bench    - 仅运行 UDP / DoT / DoH 多协议加密 DNS 测速"
	@echo "  make test     - 运行单元测试"

check:
	$(PYTHON) dnscheck.py all

leak:
	$(PYTHON) dnscheck.py leak

env:
	$(PYTHON) dnscheck.py env

split:
	$(PYTHON) dnscheck.py split

webrtc:
	$(PYTHON) dnscheck.py webrtc

pollute:
	$(PYTHON) dnscheck.py pollute

bench:
	$(PYTHON) dnscheck.py bench

ai:
	$(PYTHON) dnscheck.py ai

ui:
	$(PYTHON) dnscheck.py ui

app:
	$(PYTHON) dnscheck.py ui --app

test:
	$(PYTHON) -m unittest discover -s tests -v

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
