---
name: network-dns-audit
description: >-
  Comprehensive network diagnostics and deep DNS leak auditing powered by DNSGuard
  (`dnscheck`) plus general OS network checks (latency, packet loss, routing, TLS,
  and local ports). Use when the user asks to check DNS leaks (Interactsh OAST,
  Fake-IP pre-resolution, Type 65 HTTPS bypass, transparent UDP-53 hijacking),
  audit Surge/Clash/Mihomo/Sing-box proxy rules, verify split-routing, WebRTC/STUN
  or IPv6 leaks, test AI service geo-unlock or Claude 14-domain anti-fraud
  consistency, detect DNS poisoning, benchmark DoH/DoT/UDP resolvers, or diagnose
  general network connectivity, latency, packet loss, traceroute, or TLS issues.
---

# Network & DNS Leak Audit Skill (`network-dns-audit`)

Perform structured, root-cause-oriented network diagnostics and DNS leak auditing
by combining **DNSGuard (`dnscheck`)** with complementary general OS network
checks and actionable, friendly remediation guidance.

> **Language Policy**: Default documentation is English; **always respond in the
> user's language** (e.g., English or Simplified Chinese / 简体中文). For Chinese
> remediation templates, see [remediation_zh.md](./references/remediation_zh.md).

---

## Pre-Flight Guardrails (Read Before Running Anything)

1. **Host Network Requirement (Friendly Sandbox Notice)**
   - DNS leak detection (Interactsh OAST), STUN/WebRTC probing, split-routing,
     AI geo-checks, and traceroute **must run against the user's real host
     network stack**.
   - If your terminal executes inside an offline or isolated sandbox, a command
     will fail or return empty probes. Clearly explain to the user *why* real
     host network access is required and ask permission to run outside the
     sandbox — **never silently fake results or conclude "no leak" from failed
     or empty probes**.
2. **Strict Privacy & Read-Only Safety**
   - **NEVER** read, print, log, or summarize proxy node credentials, passwords,
     UUIDs, WireGuard private keys, subscription URLs, or personal OAST/API
     tokens.
   - `dnscheck audit` is strictly read-only (`[General]` / `[Rule]` hygiene and
     `surge-cli rule explain` dry-runs only). Never modify the user's proxy
     configuration, `/etc/hosts`, or OS network settings unless the user
     explicitly asks you to apply a specific change.
   - Before suggesting the user paste raw output into a public GitHub issue,
     remind them to redact their residential public IP or ECS subnet.
3. **Avoid Unnecessary Full Scans**
   - `dnscheck all` runs all 9 modules concurrently and takes longer. Match the
     user's intent first using the routing table below, and offer deeper scans
     as a friendly next step.

---

## Step 1: Discover `dnscheck` & Available Tools

Run the zero-dependency helper script first to see whether `dnscheck` is ready
and which native network tools (`dig`, `curl`, `openssl`, `traceroute`, `mtr`,
`scutil`, `surge-cli`, etc.) exist on this machine:

```bash
python3 .agents/skills/network-dns-audit/scripts/run_dnscheck.py --check-env
```

*(If installed globally in `~/.gemini/config/skills/network-dns-audit/`, invoke
the script via its installed path, or run `dnscheck --version` directly.)*

- **If `dnscheck_available` is `true`**: Use `run_dnscheck.py <subcommand> --json`
  (or `dnscheck <subcommand> --json`) as the primary engine.
- **If `dnscheck_available` is `false`**: Inform the user cleanly how to enable
  it (`pip3 install --no-deps -e .` from the DNSGuard repo or set
  `DNSCHECK_HOME`), then proceed with native fallback checks from
  [general-network-and-fallback.md](./references/general-network-and-fallback.md)
  while clearly noting which blind spots (such as Fake-IP pre-resolution races
  and Type 65 bypasses) require `dnscheck` OAST.

---

## Step 2: Route the User's Request to the Right Modules

Select only the modules needed for the user's question:

| User Goal / Symptom | Primary Command(s) | Notes & Complementary Checks |
| :--- | :--- | :--- |
| **DNS leak check** (proxy / VPN / Fake-IP / ISP leak) | `env --json`, `leak --json`, `audit --json` | Add `--oast-server <host>` / `--oast-token <tok>` only if user provides one |
| **Find which proxy rule causes local DNS pre-resolution** | `audit --json` | Supports Surge (`surge-cli rule explain`) & local Clash/Mihomo hygiene |
| **Split-routing / egress IP / IPv6 bypass / WebRTC UDP leak** | `split --json`, `webrtc --json` | Also offer `dnscheck ui` if user wants live browser `RTCPeerConnection` ICE verification |
| **AI platform connectivity & region lock** (OpenAI, Claude, Gemini, Grok, Cursor, etc.) | `ai --json` | Checks DNS mode, exit region, geo-blocks, and Cloudflare challenges |
| **Claude anti-fraud consistency** (14 companion domains + `34.8.0.0/16`) | `claude --json` | Export ready-to-paste rules with `claude --export surge\|clash\|mihomo\|shadowrocket --policy "Claude"` |
| **DNS poisoning / hijacking or encrypted DNS speed** | `pollute --json`, `bench --json` | Compares plaintext UDP-53 against DoH baseline; benchmarks UDP/DoT/DoH + DNSSEC `AD` |
| **Custom DNS record / ECS / Type 65 query** | `dig <domain> -s <server> -p <udp\|tcp\|dot\|doh\|system> -t <A\|AAAA\|HTTPS\|TXT\|...> [--ecs CIDR] --json` | Ideal for verifying a specific domain after a fix |
| **Full security & network health check** | `all --json` (or `all --output report.json`) | Covers `env`, `audit`, `split`, `leak`, `webrtc`, `pollute`, `bench`, `ai`, `claude` |
| **General network troubleshooting** (slow network, packet loss, jitter, unreachable host, TLS error, port conflict) | Native OS commands in [general-network-and-fallback.md](./references/general-network-and-fallback.md) | Combine with `env --json` / `split --json` if a proxy/TUN is active |

---

## Step 3: Interpret Results Accurately (Anti-False-Positive Checklist)

When analyzing JSON output from `dnscheck`, verify these critical signals before
writing your diagnosis:

1. **Never Emit a False-Green on Zero OAST Callbacks**
   - Check `oast_enabled` and `oast_events_count` in the `leak` report.
   - If `oast_enabled` is `false` or `oast_events_count == 0`, OAST authoritative
     capture was degraded or blocked (e.g., firewall, proxy outage, or offline
     sandbox). State this clearly as **inconclusive / degraded** and suggest
     checking network access or trying `--oast-server oast.pro`.
2. **Pinpoint the Exact Leak Mechanism from `vector_probes` & Flags**
   - `concurrent_race_leak: true` → Same probe hit both domestic ISP DNS and
     overseas DNS (typically `GEOIP`/`IP-CIDR`/`RULE-SET,LAN` missing
     `,no-resolve`, or Clash/Mihomo `nameserver` + `fallback` racing).
   - `qtype65_leak: true` → DNS `Type 65 (HTTPS)` bypassed Fake-IP (common on
     macOS/iOS Safari & Chromium with Mihomo/Clash).
   - `direct_bypass_leak: true` → Proxied HTTP traffic (`proxy-sni`) is safe,
     but non-proxy-aware CLI / OS stub (`sys-v4` / `direct-sni`) leaks to local
     DNS (usually HTTP/SOCKS-only proxy without TUN / Enhanced Mode).
   - `ecs_leaked_subnets` non-empty on overseas resolvers → EDNS Client Subnet
     exposes a domestic IP prefix.
3. **Distinguish Proxy `dns-hijack` from ISP Transparent Hijacking**
   - In `hijack_probes`, check `proxy_hijacked` vs `hijacked`:
     - `proxy_hijacked: true` means the user's **own local proxy** intercepted
       UDP-53 (expected in TUN/Fake-IP setups — explain this reassuringly!).
     - `hijacked: true` and `proxy_hijacked: false` means **real ISP/router
       port-53 transparent hijacking** — recommend encrypted DoH/DoT.
4. **Cross-Check Proxy Rule Audit (`audit`) & Claude Guard (`claude`)**
   - If `rule_explain.triggered_local_dns` is `true`, highlight the exact
     `trigger_rule` and `dns_lookup_ms` overhead — that single line is usually
     the root cause of Fake-IP pre-resolution leaks.
   - In `claude`, call out every `DIRECT_LEAK`, `SPLIT_DRIFT`, or
     `REGION_BLOCKED` companion domain (e.g., `r.stripe.com`,
     `siftscience.com`, `api-iam.intercom.io`, `34.8.0.0/16`) and offer the
     `dnscheck claude --export ...` command.
5. **Cross-Check General Network Checks (When Run)**
   - Correlate ping packet loss/jitter, traceroute hop drops (remember intermediate
     routers may rate-limit ICMP — only loss persisting to the final hop is real
     packet loss), TLS handshake failures (SNI reset vs cert/clock issue), and
     local TUN/proxy port status.

---

## Step 4: Present a Friendly, Actionable Report

Consult [remediation.md](./references/remediation.md) (English) or
[remediation_zh.md](./references/remediation_zh.md) (Chinese) for exact
copy-paste configuration fixes, then format your response using this clear
structure:

1. **Verdict & Health Summary**: One-line plain-language verdict (e.g., `SAFE` /
   `WARNING` / `LEAK`), overall score (if available), active proxy/TUN mode, and
   whether OAST verification succeeded.
2. **Key Findings Table**: Concise breakdown by check dimension (Status,
   Observed Evidence, Impact).
3. **Root Cause (Plain Language)**: Explain *why* each issue happens in 1–3
   sentences so even non-networking experts understand it.
4. **Actionable Fixes (Copy-Paste Ready)**: Provide exact config snippets
   tailored to the detected client (Surge / Clash-Mihomo / Sing-box /
   Shadowrocket / OS / Browser).
5. **Friendly Next Steps**:
   - After editing proxy rules, suggest a fast targeted re-test (e.g.,
     `dnscheck leak` or `dnscheck audit` or `dnscheck claude`).
   - Mention `dnscheck ui` (binds locally to `127.0.0.1:8765`) when the user
     wants visual browser-side WebRTC `RTCPeerConnection` + `fetch` cross-checks.
   - Remind the user to mask personal public IPs before sharing reports online.
