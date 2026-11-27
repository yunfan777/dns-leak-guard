# 网络与 DNS 泄漏修复速查手册（简体中文）

当 `dnscheck` 或常规网络诊断定位到具体根因后，参考以下实测有效的修复方案，并结合用户当前实际使用的代理客户端给出可直接复制的配置片段。

---

## 1. Fake-IP 下仍向国内 DNS 预解析 / 并发抢答泄漏

**典型信号**：
- `dnscheck leak` 中 `concurrent_race_leak: true`（同一 OAST 探针同时命中了国内运营商 DNS 与海外 DNS）。
- `dnscheck audit` 中 `rule_explain.triggered_local_dns: true`。

**原因解析**：
`RULE-SET,LAN`、`GEOIP,CN`、`IP-CIDR` 等 IP 类规则如果漏写了 `,no-resolve`，代理内核在匹配冷门海外域名时，会先在后台向本地/国内 DNS 发一次真实解析以判断 IP 归属，即便最终走了海外代理，域名访问记录也已经泄漏。在 Clash/Mihomo 中同时配置 `nameserver` 与 `fallback` 竞速也会触发同样问题。

### Surge 修复方案
1. 给 `RULE-SET,LAN,DIRECT`、所有含 IP 的 `RULE-SET`、`IP-CIDR`、`IP-CIDR6`、`GEOIP,CN` 补齐 `,no-resolve`。
2. 在 `GEOIP,CN` 上方前置国内域名规则集，让已知国内域名直接按域名命中，避免对冷门海外域名做本地预解析。

```ini
[Rule]
# 所有 LAN / IP 规则补齐 ,no-resolve
RULE-SET,LAN,DIRECT,no-resolve

# 先按域名匹配国内站点
DOMAIN-SUFFIX,cn,DIRECT
RULE-SET,https://example.com/ChinaDomain.list,DIRECT

# 兜底 GEOIP 必须加 ,no-resolve
GEOIP,CN,DIRECT,no-resolve
FINAL,PROXY,dns-failed
```

### Clash / Mihomo 修复方案
1. 所有 `IP-CIDR`、`IP-CIDR6`、`GEOIP` 规则末尾补齐 `,no-resolve`。
2. 清空 `fallback: []`，改用 `respect-rules: true` + `nameserver-policy` 按域名精准分流。

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

### Sing-box 修复方案
在 `dns.rules` 中将 `geosite:cn` 定向至国内 DoH，其余域名统一走远端代理 DNS 或 `fakeip`，避免在域名规则之前触发 IP 规则预解析。

---

## 2. DNS Type 65（`HTTPS` / `SVCB`）记录穿透 Fake-IP

**典型信号**：`qtype65_leak: true`，或 `qtype65` 通道命中国内运营商 DNS，而 `sys-v4` 正常返回 Fake-IP。

**原因解析**：
新版 macOS / iOS、Safari 和 Chromium 在查 `A`/`AAAA` 的同时会并发查 `Type 65 (HTTPS)` 记录。部分代理内核默认只对 `A`/`AAAA` 返回 Fake-IP，导致 `HTTPS` 查询绕过 Fake-IP 穿透到本地上游。

### Mihomo (v1.19.19+) 修复方案
在 DNS 上游地址后追加 `#disable-qtype-65=true`：

```yaml
dns:
  nameserver:
    - https://223.5.5.5/dns-query#disable-qtype-65=true
```

### Surge 修复方案
开启增强模式（VIF，`enhanced-mode = true`）并配置 `hijack-dns = *:53`，移除 `[General]` 中的明文 `system` DNS。

---

## 3. 运营商明文 DNS 与 UDP-53 透明劫持

**典型信号**：
- `transparent_hijack_detected: true`（`hijacked: true` 且 `proxy_hijacked: false`）。
- `dnscheck audit` 提示 `uses_plaintext_system_dns: true`。

**重要区分**：如果 `proxy_hijacked: true`，说明是**你自己的代理软件**通过 `hijack-dns` 接管了 53 端口，属于正常安全行为，**不是**运营商劫持。

### 修复方案
- 移除 `system` 运营商默认 DNS，全面改用**纯 IP 加密 DoH / DoT**（避免引导解析循环依赖）：
  - 国内加密：`https://223.5.5.5/dns-query` 或 `https://1.12.12.12/dns-query`
  - 海外加密：`https://1.1.1.1/dns-query` 或 `https://8.8.8.8/dns-query`
- Surge `[General]` 参考：
  ```ini
  [General]
  dns-server = 223.5.5.5, 119.29.29.29
  encrypted-dns-server = https://223.5.5.5/dns-query, https://doh.pub/dns-query
  hijack-dns = *:53
  ```

---

## 4. 代理通道安全，但终端 / 直连进程仍在泄漏

**典型信号**：`direct_bypass_leak: true`（`proxy-sni` 安全，但 `sys-v4` / `direct-sni` 落回国内 DNS）。

**原因解析**：
当前仅开启了系统 HTTP/SOCKS 代理。命令行工具（`curl`、`git`、`python`、`dig`）及大量桌面后台进程不会遵守系统 HTTP 代理，直接走系统 Stub DNS。

### 修复方案
- **Surge**：开启 **增强模式 (VIF)**（`enhanced-mode = true`）。
- **Clash / Mihomo / Sing-box**：开启 **TUN 虚拟网卡模式**（`tun: { enable: true }`）+ `Fake-IP`。

---

## 5. IPv6 旁路泄漏与 WebRTC / STUN UDP 泄漏

### IPv6 旁路泄漏（`ipv6_leak: true`）
**原因**：代理仅接管了 IPv4，双栈网站直接通过本机公网 IPv6 暴露国内真实地址。

**修复**：若代理节点未完整支持 IPv6，建议直接关闭客户端 IPv6：
- **Surge**：`ipv6 = false` 且 `ipv6-vif = disabled`
- **Mihomo**：`ipv6: false`

### WebRTC / STUN UDP 泄漏（`webrtc_udp_leak: true`）
**修复**：
1. 在代理节点与客户端中开启 **UDP 转发（`udp: true`）**。
2. 浏览器加固：
   - **Firefox**：在 `about:config` 将 `media.peerconnection.ice.proxy_only_if_behind_proxy` 设为 `true`。
   - **Chrome / Edge / Brave**：通过策略或可信扩展禁用非代理 WebRTC UDP。
3. 可运行 `dnscheck ui` 在本地浏览器同屏复核 `RTCPeerConnection` ICE 候选。

---

## 6. EDNS Client Subnet (ECS) 子网暴露

**典型信号**：`ecs_leaked_subnets` 在海外递归解析器上暴露了国内网段。

**修复**：将海外代理 DNS 切换为不透传 ECS 的隐私解析器，如 Cloudflare（`https://1.1.1.1/dns-query`）或 Quad9（`https://9.9.9.9/dns-query`）。

---

## 7. AI 服务锁区 & Claude 全链路 14 域名防风控一致性

**典型信号**：
- `ai` 检出 CN/HK 出口或触发 Cloudflare 风控盾。
- `claude` 检出伴生域名（如 `r.stripe.com`、`siftscience.com`、`api-iam.intercom.io`、`us5.datadoghq.com`、`us.sentry.io`、`fcmtoken.googleapis.com` 或 `34.8.0.0/16`）出现 `DIRECT_LEAK`（直连泄漏）或 `SPLIT_DRIFT`（出口节点漂移）。

**修复**：
1. 将全部 14 个 Claude 伴生域名 + `34.8.0.0/16` 绑定到**同一个固定、纯净的支持地区节点**（如美/日/新/台，切忌负载均衡跨区漂移）。
2. 一键导出可直接粘贴的规则：
   ```bash
   dnscheck claude --export surge --policy "Claude"
   dnscheck claude --export mihomo --policy "Claude"
   dnscheck claude --export shadowrocket --policy "Claude"
   ```
3. 将规则放到通用规则、Google 规则、`LAN` 规则及 `FINAL` **之前**，生效后重新运行 `dnscheck claude` 复测至 15/15 一致。

---

## 8. 常规网络问题快查

- **首跳延迟抖动大**：优先排查 Wi-Fi 频段干扰（建议 5GHz 或有线网）与路由器 bufferbloat。
- **TCP 通但 TLS 卡死/重置**：排查 TUN / WireGuard 的 MTU 问题（可尝试将 TUN MTU 调低至 `1280`–`1400`）或直连 SNI 干扰。
- **改完配置后仍有旧解析缓存**：
  - macOS：`sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder`
  - Linux：`sudo resolvectl flush-caches`
  *（仅作为建议提供给用户，未经明确同意不要主动执行 `sudo`。）*
