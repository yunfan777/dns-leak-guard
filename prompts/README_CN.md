# AI Prompt 与 Agent Skill 使用指南

[English](./README.md) | 简体中文

DNSGuard (`dnscheck`) 同时提供**模块化 Agent Skill**（适用于具备终端能力的 AI Agent）以及**开箱即用的独立 Prompt**（可复制到任意 AI 对话或 Agent 工具中直接使用）。

---

## 该选哪一种？

| 方案 | 文件路径 | 适用场景 |
| :--- | :--- | :--- |
| **Agent Skill** *(推荐)* | [`../.agents/skills/network-dns-audit/SKILL.md`](../.agents/skills/network-dns-audit/SKILL.md) | 适用于 **Antigravity、Claude Code、Codex、Cursor** 等支持 `.agents/skills/` 规范的 Agent。会自动按需路由 `dnscheck --json`、解读 OAST/规则审计结果，并生成对应代理客户端修复配置。 |
| **独立 Prompt（英文默认）** | [`./network-dns-audit.md`](./network-dns-audit.md) | 复制到任意 AI 助手（ChatGPT、Claude、Gemini 等），兼顾“带终端自动执行”与“纯对话引导排查”双模式。 |
| **独立 Prompt（简体中文）** | [`./network-dns-audit_zh.md`](./network-dns-audit_zh.md) | 简体中文版独立 Prompt，包含完整的中文诊断结构、防误判约束与客户端修复模板。 |

---

## Agent Skill 快速启用

### 方式一：在本仓库内直接使用（零配置）

在 Antigravity、Claude Code、Codex 或其他支持 `.agents/skills/` 的客户端中打开本仓库，`.agents/skills/network-dns-audit/SKILL.md` 会被自动发现。

直接用自然语言提问即可，例如：
- “帮我测一下当前代理环境有没有 DNS 泄漏。”
- “审计一下我的 Surge 规则，看看是哪条规则触发了本地 DNS 预解析。”
- “检查一下 Claude 14 个伴生域名的防风控分流一致性，并导出 Mihomo 规则。”
- “最近网络延迟抖动大、偶尔 TLS 卡住，帮我做一次完整的网络和 DNS 体检。”

### 方式二：安装到本机全局（在任意项目里都能随时调用）

1. 先以零依赖方式全局注册 `dnscheck` 命令：
   ```bash
   pip3 install --no-deps -e .
   ```
2. 将 Skill 软链接（或复制）到全局 skills 目录：
   ```bash
   # Antigravity 全局 skills 目录
   mkdir -p ~/.gemini/config/skills
   ln -s "$(pwd)/.agents/skills/network-dns-audit" ~/.gemini/config/skills/network-dns-audit
   ```
   *（若使用其他 Agent，可软链接到对应的全局 skills 目录，例如 `~/.agents/skills/` 或 `~/.claude/skills/`。）*

---

## 运行前友好提示

- **需要宿主机真实网络权限**：DNS 泄漏（Interactsh OAST）、STUN/WebRTC、分流与路由追踪必须运行在**宿主机真实网络栈**上，不能在断网沙箱中运行。如 Agent 弹窗请求联网执行权限，授权该诊断命令即可获得真实结果。
- **严格只读与隐私保护**：Skill 与 `dnscheck` 绝不会读取或输出代理密码、UUID、私钥或订阅链接；如计划将报告贴到公开 Issue，请注意先对住宅公网 IP 或 ECS 网段打码。
- **浏览器 WebRTC 同屏复核**：如需在浏览器侧同步核验 `RTCPeerConnection` ICE 候选，可启动仅绑定本机 `127.0.0.1` 的可视化控制台：
  ```bash
  dnscheck ui
  ```
