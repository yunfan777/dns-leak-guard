# General Network Diagnostics & Native Fallback Reference

Use this reference in two situations:
1. **Complementing `dnscheck`**: When the user reports general connectivity
   issues (high latency, packet loss, routing hops, TLS/HTTPS errors, port
   binding conflicts, VPN/TUN interface problems).
2. **Native Fallback Mode**: When `dnscheck` is not installed and the user still
   wants a quick read-only diagnostic pass using built-in OS tools.

> All commands below are **strictly read-only**. Never read proxy credential
> files or subscription URLs.

---

## Part 1: Complementary General Network Diagnostics

Run only the checks relevant to the user's symptom.

### 1. Local Interfaces, Routes, DNS & System Proxy

**macOS:**
```bash
# Active network interfaces & IPv4/IPv6 addresses (highlight utun*/wg* TUN interfaces)
ifconfig | grep -E '^[a-z0-9]+:|inet |inet6 '

# Default IPv4 & IPv6 routes
netstat -rn | grep -E 'default|utun|198\.18'

# System DNS resolvers & scoped DNS
scutil --dns | head -n 60

# System HTTP/HTTPS/SOCKS proxy settings
scutil --proxy
```

**Linux:**
```bash
ip -br addr
ip route show; ip -6 route show
resolvectl status 2>/dev/null || cat /etc/resolv.conf
env | grep -iE '^(http|https|all|no)_proxy='
```

### 2. Latency, Jitter & Packet Loss

```bash
# Test local gateway or public targets (5 packets to stay fast)
ping -c 5 1.1.1.1
ping -c 5 223.5.5.5
```

- **Interpretation tips**:
  - `0% packet loss` + stable RTT → healthy L3 path.
  - High stddev/jitter (`> 30ms` on local Wi-Fi or `> 80ms` on WAN) → Wi-Fi
    interference, bufferbloat, or congested proxy node.
  - Note: Some proxies/TUN interfaces drop or synthesize ICMP echo; verify with
    TCP/HTTPS timing below before concluding the link is down.

### 3. Path & Hop Tracing (`traceroute` / `mtr`)

```bash
# macOS / Linux traceroute (numeric, max 20 hops, short wait)
traceroute -n -m 20 -w 2 1.1.1.1

# If mtr is installed (best for diagnosing where packet loss actually starts)
mtr -n -r -c 10 1.1.1.1
```

- **Interpretation tip**: A single intermediate hop showing `100%` loss or `* * *`
  while subsequent hops respond normally is just ICMP rate-limiting on that
  router — **not** real packet loss. Real packet loss starts at a hop and
  persists all the way to the destination.

### 4. TCP Port, TLS Handshake & HTTP Timing

```bash
# Breakdown of DNS, TCP connect, TLS handshake, TTFB, and total latency
curl -sS -o /dev/null --max-time 10 \
  -w "remote_ip=%{remote_ip} http=%{http_code} dns=%{time_namelookup}s tcp=%{time_connect}s tls=%{time_appconnect}s ttfb=%{time_starttransfer}s total=%{time_total}s\n" \
  https://www.cloudflare.com/cdn-cgi/trace

# Inspect TLS certificate chain, ALPN/TLS version, and SNI behavior
echo | openssl s_client -servername example.com -connect example.com:443 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates

# Quick TCP port reachability test (e.g., local proxy port 7890 / 6152)
nc -vz -w 3 127.0.0.1 7890
```

- **Interpretation tips**:
  - `dns` high (`> 0.3s`) → slow or stalling DNS resolver / missing `,no-resolve`.
  - `tcp` succeeds but `tls` hangs or resets → SNI/TLS interference, MTU/MSS
    blackhole, or broken proxy TLS relay.
  - `remote_ip=198.18.x.x` → Fake-IP mode is active (normal under TUN/VIF).

### 5. Local Listening Ports & Proxy Process Check

```bash
# macOS (read-only list of listening TCP ports)
lsof -nP -iTCP -sTCP:LISTEN

# Linux
ss -tulnp 2>/dev/null || netstat -tulnp
```

Useful for confirming whether a local proxy listener (e.g., `6152`, `7890`,
`1080`, `2080`) or local service is actually bound and listening on the expected
interface (`127.0.0.1` vs `0.0.0.0`).

---

## Part 2: Native Fallback DNS & Egress Checks (When `dnscheck` Is Unavailable)

If `dnscheck` cannot be found, you can still run these read-only checks to give
the user immediate value:

```bash
# 1. Check active recursive resolver identity & EDNS Client Subnet (ECS)
dig +short TXT whoami.ds.akahelp.net
dig +short TXT o-o.myaddr.l.google.com

# 2. Check transparent UDP-53 interception (compare plaintext 1.1.1.1 vs DoH)
dig @1.1.1.1 +short TXT whoami.ds.akahelp.net
dig @8.8.8.8 +short TXT o-o.myaddr.l.google.com

# 3. Check DNS Type 65 (HTTPS) record resolution behavior
dig +short HTTPS www.cloudflare.com

# 4. Compare IPv4 vs IPv6 egress & Cloudflare Anycast colo
curl -4 -sS --max-time 6 https://www.cloudflare.com/cdn-cgi/trace | grep -E '^(ip|loc|colo|warp)='
curl -6 -sS --max-time 6 https://www.cloudflare.com/cdn-cgi/trace | grep -E '^(ip|loc|colo|warp)='
```

### Important Blind-Spot Warning (Always Tell the User in Fallback Mode)

Native `dig` / `curl` commands **cannot** reliably detect:
- **Fake-IP pre-resolution / concurrent race leaks** (when a proxy queries your
  domestic ISP DNS in the background while returning a clean overseas exit).
- **Multi-vector attribution** isolating `sys-v4`, `sys-v6`, `Type 65 (HTTPS)`,
  `TXT`, `direct-sni`, and `proxy-sni` via out-of-band authoritative capture.
- **RFC 5389 STUN UDP real-IP leaks** and **Claude 14-domain consistency**.

Recommend installing `dnscheck` (zero third-party dependencies, Python 3.9+
only):
```bash
git clone https://github.com/yunfan777/dns-leak-guard.git
cd dns-leak-guard
pip3 install --no-deps -e .
dnscheck leak
```
