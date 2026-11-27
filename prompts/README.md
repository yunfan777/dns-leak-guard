# AI Prompts & Agent Skill Guide

English | [简体中文](./README_CN.md)

DNSGuard (`dnscheck`) ships with both a **modular Agent Skill** (for terminal-capable AI coding agents) and **copy-pasteable standalone Prompts** (for any AI chat or agent interface).

---

## Which One Should I Use?

| Option | Location | Best For |
| :--- | :--- | :--- |
| **Agent Skill** *(Recommended)* | [`../.agents/skills/network-dns-audit/SKILL.md`](../.agents/skills/network-dns-audit/SKILL.md) | **Antigravity, Claude Code, Codex, Cursor**, and other agents supporting `.agents/skills/`. Automatically routes intents, runs `dnscheck --json`, interprets OAST & rule audits, and generates client-specific fixes. |
| **Standalone Prompt (EN)** | [`./network-dns-audit.md`](./network-dns-audit.md) | Copy-paste into **any AI assistant** (ChatGPT, Claude, Gemini, local agents). Works both when the AI has shell access and when you paste terminal output manually. |
| **Standalone Prompt (ZH)** | [`./network-dns-audit_zh.md`](./network-dns-audit_zh.md) | Simplified Chinese version of the standalone prompt with idiomatic phrasing and Chinese remediation guidance. |

---

## Quick Setup for the Agent Skill

### Option A: Use Directly Inside This Repository (Zero Setup)

Open this repository in Antigravity, Claude Code, Codex, or another `.agents/skills/`-compatible client. The skill at `.agents/skills/network-dns-audit/SKILL.md` is discovered automatically.

Just ask naturally, for example:
- *"Check if I have any DNS leaks under my proxy."*
- *"Audit my Surge rules to see why overseas domains trigger local DNS lookups."*
- *"Check my Claude 14-domain anti-fraud split consistency and export Mihomo rules."*
- *"My connection feels sluggish and TLS occasionally hangs — run a network & DNS health check."*

### Option B: Install Globally for Use in Any Workspace

1. Install `dnscheck` globally (zero third-party dependencies):
   ```bash
   pip3 install --no-deps -e .
   ```
2. Symlink (or copy) the skill into your global skills directory:
   ```bash
   # Antigravity global skills directory
   mkdir -p ~/.gemini/config/skills
   ln -s "$(pwd)/.agents/skills/network-dns-audit" ~/.gemini/config/skills/network-dns-audit
   ```
   *(For other tools, symlink into their respective global skill folder, e.g., `~/.agents/skills/` or `~/.claude/skills/`.)*

---

## Friendly Tips Before Running

- **Real Host Network Required**: DNS leak (Interactsh OAST), STUN/WebRTC, split-routing, and traceroute probes must run on your **real host network**, not inside an offline sandbox. If your agent asks for network execution permission, allow the diagnostic command so results reflect your actual proxy/DNS stack.
- **Read-Only & Privacy-First**: Neither the skill nor `dnscheck` reads proxy passwords, UUIDs, WireGuard private keys, or subscription URLs. Before sharing raw output publicly, redact your residential IP or ECS subnet.
- **Browser WebRTC Verification**: For browser-native `RTCPeerConnection` ICE checks alongside OS socket probes, launch the local dashboard (`127.0.0.1` only):
  ```bash
  dnscheck ui
  ```
