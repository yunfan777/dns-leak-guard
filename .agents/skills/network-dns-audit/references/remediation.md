# Network & DNS Leak Remediation Playbook (English)

Use these verified, copy-paste-ready fixes when `dnscheck` or general network
diagnostics identify a specific root cause. Always tailor snippets to the
client actually detected on the user's machine.

---

## 1. Pre-Resolution / Concurrent Race Leak under Fake-IP

**Symptoms**:
- `concurrent_race_leak: true` in `dnscheck leak` (the same OAST probe hits both
  domestic ISP DNS and overseas DNS).
- `rule_explain.triggered_local_dns: true` in `dnscheck audit`.

**Why it happens**:
An IP-based rule (`RULE-SET,LAN`, `GEOIP,CN`, `IP-CIDR`) without `,no-resolve`
forces the proxy core to resolve unknown domains using local DNS *just to check
whether the IP is LAN or CN*, even when the domain ends up routed through a
remote proxy. On Clash/Mihomo, configuring both `nameserver` and `fallback` can
also trigger concurrent plaintext/domestic races.

### Surge Fix
1. Append `,no-resolve` to `RULE-SET,LAN,DIRECT`, every IP-bearing `RULE-SET`,
   `IP-CIDR`, `IP-CIDR6`, and `GEOIP,CN`.
2. Place domestic domain rule-sets **above** `GEOIP,CN` so domestic domains
   match by domain name without requiring local resolution of overseas domains.

```ini
[Rule]
# Keep LAN / IP rules non-resolving
RULE-SET,LAN,DIRECT,no-resolve

# Match known domestic domains by name first
DOMAIN-SUFFIX,cn,DIRECT
RULE-SET,https://example.com/ChinaDomain.list,DIRECT

# Final geoip fallback MUST include ,no-resolve
GEOIP,CN,DIRECT,no-resolve
FINAL,PROXY,dns-failed
```

### Clash / Mihomo Fix
1. Append `,no-resolve` to all `IP-CIDR`, `IP-CIDR6`, and `GEOIP` rules.
2. Clear `fallback: []` and use `respect-rules: true` with `nameserver-policy`.

```yaml
dns:
  enable: true
  enhanced-mode: fake-ip
  respect-rules: true
  default-nameserver:
    - 223.5.5.5
    - 119.29.29.29
  nameserver:
    - https://1.1.1.1/dns-query
    - https://8.8.8.8/dns-query
  proxy-server-nameserver:
    - https://223.5.5.5/dns-query
  nameserver-policy:
    "geosite:cn,private":
      - https://223.5.5.5/dns-query
      - https://doh.pub/dns-query
  fallback: []
```

### Sing-box Fix
Ensure DNS routing rules direct `geosite:cn` to a domestic DoH server and all
other domains to a remote/proxy DNS server (`strategy` / `fakeip`), avoiding
unnecessary IP-rule resolution before domain matching.

---

## 2. DNS Type 65 (`HTTPS` / `SVCB`) Record Bypassing Fake-IP

**Symptoms**: `qtype65_leak: true` or `qtype65` vector shows domestic ISP
resolver IPs while `sys-v4` returns Fake-IP.

**Why it happens**:
Modern macOS, iOS, Safari, and Chromium issue `Type 65 (HTTPS)` queries
alongside `A`/`AAAA`. Older or default Fake-IP handlers only synthesize `A`
records, letting `HTTPS` queries pass straight through to upstream/local DNS.

### Mihomo (v1.19.19+) Fix
Append `#disable-qtype-65=true` to upstream DNS servers (or enable
`fake-ip-filter` / disable HTTPS record pass-through):

```yaml
dns:
  nameserver:
    - https://223.5.5.5/dns-query#disable-qtype-65=true
```

### Surge Fix
Ensure `enhanced-mode` (VIF) is enabled and `hijack-dns = *:53` is active; avoid
leaving plaintext `system` in `dns-server`.

---

## 3. Plaintext ISP DNS & Transparent UDP-53 Hijacking

**Symptoms**:
- `transparent_hijack_detected: true` (`hijacked: true` and `proxy_hijacked: false`).
- `uses_plaintext_system_dns: true` in `dnscheck audit`.

**Why it happens**:
Your ISP or router intercepts outbound UDP port 53 packets and silently
redirects them to ISP resolvers (or poisons answers).

**Note**: If `proxy_hijacked: true`, that is your **own local proxy** taking
over UDP-53 (`hijack-dns`), which is normal and **not** an ISP hijack.

### Fix
- Remove `system` from `dns-server` and switch to **IP-based encrypted DoH/DoT**
  (using raw IP endpoints avoids bootstrap DNS circularity):
  - Domestic encrypted: `https://223.5.5.5/dns-query` or `https://1.12.12.12/dns-query`
  - Global encrypted: `https://1.1.1.1/dns-query` or `https://8.8.8.8/dns-query`
- In Surge `[General]`:
  ```ini
  [General]
  dns-server = 223.5.5.5, 119.29.29.29
  encrypted-dns-server = https://223.5.5.5/dns-query, https://doh.pub/dns-query
  hijack-dns = *:53
  ```

---

## 4. Proxy Channel Safe, But CLI / Direct OS Processes Leaking

**Symptoms**: `direct_bypass_leak: true` (`proxy-sni` is clean, `sys-v4` /
`direct-sni` hits domestic DNS).

**Why it happens**:
Only HTTP/SOCKS system proxy is active. Terminal tools (`curl`, `git`, `python`,
`dig`, background apps) ignore system HTTP proxy settings and resolve directly
via OS stub DNS.

### Fix
- **Surge**: Enable **Enhanced Mode (VIF)** (`enhanced-mode = true`).
- **Clash / Mihomo / Sing-box**: Enable **TUN mode** (`tun: { enable: true }`)
  with `enhanced-mode: fake-ip` and `auto-route: true`.

---

## 5. IPv6 Bypass Leak & WebRTC / STUN UDP Leak

### IPv6 Bypass (`ipv6_leak: true`)
**Why it happens**: Proxy only tunnels IPv4, so dual-stack hosts leak real
domestic IPv6 addresses directly to dual-stack websites.

**Fix**:
- Either enable full IPv6 proxying on both client and proxy node, **or** disable
  proxy IPv6 handling if your node does not support IPv6:
  - **Surge**: `ipv6 = false` and `ipv6-vif = disabled`
  - **Mihomo**: `ipv6: false`

### WebRTC / STUN UDP Leak (`webrtc_udp_leak: true`)
**Why it happens**: STUN Binding requests over UDP bypass TCP-only proxies or
browser `RTCPeerConnection` exposes local/public non-proxied ICE candidates.

**Fix**:
1. Enable **UDP relay (`udp: true`)** on your proxy node and client.
2. In browsers:
   - **Firefox**: `about:config` → set `media.peerconnection.ice.proxy_only_if_behind_proxy = true` (or `media.peerconnection.enabled = false` if WebRTC calls aren't needed).
   - **Chrome / Edge / Brave**: Set WebRTC IP handling policy to *Disable non-proxied UDP* (via policy or trusted WebRTC Control extension).
3. Verify visually in browser using `dnscheck ui`.

---

## 6. EDNS Client Subnet (ECS) Privacy Exposure

**Symptoms**: `ecs_leaked_subnets` shows a domestic prefix sent to an overseas
resolver.

**Fix**:
Switch overseas/proxy DNS upstreams to no-ECS privacy resolvers such as
Cloudflare (`https://1.1.1.1/dns-query`) or Quad9 (`https://9.9.9.9/dns-query`),
or disable ECS forwarding in your DNS forwarder.

---

## 7. AI Geo-Blocking & Claude Anti-Fraud Split Consistency

**Symptoms**:
- `ai` reports `CN/HK` exit or Cloudflare challenge on OpenAI/Claude/Gemini.
- `claude` reports `DIRECT_LEAK` or `SPLIT_DRIFT` on companion domains
  (`r.stripe.com`, `siftscience.com`, `api-iam.intercom.io`,
  `us5.datadoghq.com`, `us.sentry.io`, `fcmtoken.googleapis.com`,
  `34.8.0.0/16`).

**Fix**:
1. Route all 14 Claude companion domains + `34.8.0.0/16` to **one single fixed,
   clean residential/supported-region exit** (e.g., US / JP / SG / TW — never
   auto-load-balanced across countries).
2. Generate ready-to-paste rules automatically:
   ```bash
   dnscheck claude --export surge --policy "Claude"
   dnscheck claude --export mihomo --policy "Claude"
   dnscheck claude --export shadowrocket --policy "Claude"
   ```
3. Place the exported rules **above** generic Google, LAN, and `FINAL` rules,
   then re-run `dnscheck claude` to confirm 15/15 consistency.

---

## 8. General Network Troubleshooting Quick Fixes

- **High latency/jitter on first hop**: Check Wi-Fi band (switch 2.4 GHz → 5 GHz
  or Ethernet) and router QoS/bufferbloat.
- **TCP connects but TLS hangs**: Suspect MTU/MSS mismatch on TUN/WireGuard
  (try lowering TUN MTU to `1280`–`1400`) or SNI interference on a direct route.
- **Stale local DNS cache after fixing rules**:
  - macOS: `sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder`
  - Linux (`systemd-resolved`): `sudo resolvectl flush-caches`
  *(Only suggest these commands to the user; do not run `sudo` commands without
  explicit approval.)*
