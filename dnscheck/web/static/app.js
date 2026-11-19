/* DNSGuard Frontend Controller & Browser-Side WebRTC / DNS Leak Probes */

let latestAuditReport = null;

function esc(str) {
  if (str === null || str === undefined) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function randomHex(len = 16) {
  const bytes = new Uint8Array(len / 2);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

// Tab switching
document.querySelectorAll(".tab-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab-btn").forEach((b) => b.classList.remove("active"));
    document.querySelectorAll(".tab-content").forEach((c) => c.classList.remove("active"));
    btn.classList.add("active");
    document.getElementById(btn.dataset.tab).classList.add("active");
  });
});

function setScanState(running, label) {
  const pill = document.getElementById("scan-status-pill");
  const btn = document.getElementById("btn-run-all");
  const btnText = document.getElementById("btn-run-text");
  if (running) {
    pill.className = "status-pill status-running";
    pill.textContent = label || "正在全量检测...";
    btn.classList.add("loading");
    btn.disabled = true;
    btnText.textContent = "诊断中...";
  } else {
    pill.className = "status-pill status-done";
    pill.textContent = label || "检测完成";
    btn.classList.remove("loading");
    btn.disabled = false;
    btnText.textContent = "重新全量诊断";
  }
}

function renderFindings(containerId, findings) {
  const el = document.getElementById(containerId);
  if (!el) return;
  if (!findings || findings.length === 0) {
    el.innerHTML = "";
    return;
  }
  el.innerHTML = findings
    .map((f) => {
      const cls =
        f.level === "ok"
          ? "finding-ok"
          : f.level === "warning"
          ? "finding-warning"
          : f.level === "danger"
          ? "finding-danger"
          : "";
      return `
        <div class="finding-item ${cls}">
          <div class="finding-title">${esc(f.title)}</div>
          ${f.detail ? `<div class="finding-detail">${esc(f.detail)}</div>` : ""}
        </div>`;
    })
    .join("");
}

function updateHeroScore(audit) {
  const score = audit.overall_score ?? 0;
  const fg = document.getElementById("score-ring-fg");
  const circumference = 314.16;
  const offset = circumference - (score / 100) * circumference;
  fg.style.strokeDashoffset = offset.toFixed(2);
  fg.style.stroke =
    score >= 85 ? "var(--green)" : score >= 60 ? "var(--yellow)" : "var(--red)";

  document.getElementById("overall-score-num").textContent = score;
  const badge = document.getElementById("overall-verdict-badge");
  badge.className = `verdict-badge verdict-${audit.overall_verdict}`;
  badge.textContent = audit.overall_verdict_label;

  document.getElementById("overall-verdict-desc").textContent =
    audit.leak?.findings?.[0]?.detail ||
    "已完成系统级 DNS 泄漏、分流路由、STUN 穿透与污染对比审计。";
  document.getElementById("scan-timing").textContent =
    `检测时间: ${audit.timestamp} · 总耗时: ${Math.round(audit.elapsed_ms)} ms`;

  // KPIs
  document.getElementById("kpi-dns-mode").textContent = audit.env?.dns_mode || "-";
  document.getElementById("kpi-dns-sub").textContent = audit.env?.ecs_supported
    ? `ECS 已启用 (${audit.env.ecs_subnet})`
    : "ECS 未暴露 / 已关闭";

  const leak = audit.leak || {};
  document.getElementById("kpi-resolvers").textContent = `${(leak.resolvers || []).length} 个上游节点`;
  document.getElementById("kpi-resolvers-sub").textContent =
    `国内: ${leak.cn_resolver_count || 0} · 海外: ${leak.overseas_resolver_count || 0}${
      leak.transparent_hijack_detected ? " · 存在53端口劫持!" : ""
    }`;

  const split = audit.split || {};
  document.getElementById("kpi-routing").textContent = split.routing_mode || "-";
  document.getElementById("kpi-routing-sub").textContent = `国内: ${
    split.cn_ip || "未通"
  } | 海外: ${split.global_ip || "未通"}`;

  const rtc = audit.webrtc || {};
  document.getElementById("kpi-webrtc").textContent = rtc.verdict_label || "-";
  document.getElementById("kpi-webrtc-sub").textContent = rtc.ipv6_ip
    ? `IPv6 出口: ${rtc.ipv6_ip}`
    : "未检测到公网 IPv6";

  // Recommendations
  const recPanel = document.getElementById("recommendations-panel");
  const recList = document.getElementById("recommendations-list");
  if (audit.recommendations && audit.recommendations.length > 0) {
    recPanel.classList.remove("hidden");
    recList.innerHTML = audit.recommendations.map((r) => `<li>${esc(r)}</li>`).join("");
  } else {
    recPanel.classList.add("hidden");
  }
}

function renderLeakPanel(leak) {
  const oastBadge = document.getElementById("oast-engine-badge");
  const vbody = document.getElementById("tbody-oast-vectors");
  if (oastBadge) {
    if (leak.oast_enabled) {
      oastBadge.className = "tag tag-green";
      oastBadge.textContent = `OAST 已连接: ${leak.oast_server} (${Math.round(leak.oast_register_ms || 0)} ms · 捕获 ${leak.oast_events_count || 0} 包)`;
    } else {
      oastBadge.className = "tag tag-yellow";
      oastBadge.textContent = "OAST 受限 · 已自动切换备援会话模式";
    }
  }
  if (vbody) {
    const vecs = leak.vector_probes || [];
    if (vecs.length === 0) {
      vbody.innerHTML = `<tr><td colspan="5" class="empty-cell">当前网络环境未返回 OAST 带外通道矩阵 (已使用右侧/下方多源汇总)</td></tr>`;
    } else {
      vbody.innerHTML = vecs
        .map((v) => {
          let badge = `<span class="tag tag-muted">${esc(v.status_label)}</span>`;
          if (v.status === "SAFE") badge = `<span class="tag tag-green">${esc(v.status_label)}</span>`;
          else if (v.status === "INTERCEPTED") badge = `<span class="tag tag-cyan">${esc(v.status_label)}</span>`;
          else if (v.status === "WARNING") badge = `<span class="tag tag-yellow">${esc(v.status_label)}</span>`;
          else if (v.status === "LEAK") badge = `<span class="tag tag-red">${esc(v.status_label)}</span>`;

          let capText = `<span class="muted">(零公网触发)</span>`;
          if (v.resolver_ips && v.resolver_ips.length > 0) {
            capText = v.resolver_ips.slice(0, 3).map((ip) => esc(ip)).join(", ");
            if (v.resolver_ips.length > 3) capText += ` (+${v.resolver_ips.length - 3})`;
          } else if (v.is_fake_ip && v.local_answers && v.local_answers.length > 0) {
            capText = `本地 Fake-IP (${esc(v.local_answers[0])})`;
          }
          return `
            <tr>
              <td><strong>${esc(v.vector_name)}</strong></td>
              <td><span class="tag tag-muted">${esc(v.qtype)}</span></td>
              <td class="mono">${capText}</td>
              <td>${badge}</td>
              <td class="muted">${esc(v.note)}</td>
            </tr>`;
        })
        .join("");
    }
  }

  const tbody = document.getElementById("tbody-sys-resolvers");
  const resolvers = leak.resolvers || [];
  if (resolvers.length === 0) {
    tbody.innerHTML = `<tr><td colspan="5" class="empty-cell">未捕获到公网递归 DNS 节点</td></tr>`;
  } else {
    tbody.innerHTML = resolvers
      .map((r) => {
        const intel = r.intel || {};
        const regionTag = intel.is_cn
          ? `<span class="tag tag-yellow">国内</span>`
          : intel.is_private
          ? `<span class="tag tag-cyan">本地</span>`
          : `<span class="tag tag-green">海外</span>`;
        return `
          <tr>
            <td class="mono">${esc(r.ip)}</td>
            <td>${regionTag}</td>
            <td>${esc(intel.location || "-")}</td>
            <td>${esc(intel.display_isp || "-")}</td>
            <td>${r.hits}</td>
          </tr>`;
      })
      .join("");
  }

  const hbody = document.getElementById("tbody-hijack");
  const hijacks = leak.hijack_probes || [];
  hbody.innerHTML = hijacks
    .map((h) => {
      const intel = h.intel || {};
      const statusTag = !h.success
        ? `<span class="tag tag-muted">超时/丢弃</span>`
        : h.proxy_hijacked
        ? `<span class="tag tag-cyan">本机代理接管</span>`
        : h.hijacked
        ? `<span class="tag tag-red">被透明劫持</span>`
        : `<span class="tag tag-green">正常直连/转发</span>`;
      const retIp = h.returned_resolver_ip || h.chaos_id || "-";
      return `
        <tr>
          <td class="mono">${esc(h.target_server)}</td>
          <td class="mono">${esc(retIp)}</td>
          <td>${esc(intel.display_isp || "-")}</td>
          <td>${statusTag}</td>
          <td>${esc(h.reason)}</td>
        </tr>`;
    })
    .join("");

  renderFindings("leak-findings", leak.findings);
}

function renderSplitPanel(split) {
  const grid = document.getElementById("split-cards-grid");
  const exits = split.exits || [];
  grid.innerHTML = exits
    .map((ex) => {
      const intel = ex.intel || {};
      const statusTag = ex.success
        ? `<span class="tag tag-green">${Math.round(ex.latency_ms)} ms</span>`
        : `<span class="tag tag-muted">不可达</span>`;
      const colo = ex.extra_meta?.colo ? ` · POP: ${ex.extra_meta.colo}` : "";
      return `
        <div class="exit-card">
          <div class="section-title-row">
            <span class="exit-card-title">${esc(ex.category_name)}</span>
            ${statusTag}
          </div>
          <div class="exit-card-ip">${esc(ex.ip || "-")}</div>
          <div class="exit-card-meta">
            ${ex.success ? `${esc(intel.location || "-")} ${esc(colo)}<br/><span class="muted">${esc(intel.display_isp || "-")}</span>` : `<span class="muted">${esc(ex.error || "未开启或超时")}</span>`}
          </div>
        </div>`;
    })
    .join("");
  renderFindings("split-findings", split.findings);
}

function renderWebRTCPanel(rtc) {
  const verdictEl = document.getElementById("sys-webrtc-verdict");
  verdictEl.textContent = rtc.verdict_label || "-";
  verdictEl.style.color =
    rtc.webrtc_udp_leak || rtc.ipv6_leak ? "var(--red)" : "var(--green)";

  const tbody = document.getElementById("tbody-sys-stun");
  const probes = rtc.stun_probes || [];
  tbody.innerHTML = probes
    .map((p) => {
      const intel = p.intel || {};
      return `
        <tr>
          <td>${esc(p.provider_name)} <span class="tag tag-muted">v${p.ip_version}</span></td>
          <td class="mono">${p.success ? `${esc(p.mapped_ip)}:${p.mapped_port}` : `<span class="muted">(超时)</span>`}</td>
          <td>${p.success ? `${esc(intel.location || "-")} · ${esc(intel.display_isp || "-")}` : `<span class="muted">${esc(p.error || "-")}</span>`}</td>
          <td>${p.success ? `${Math.round(p.latency_ms)} ms` : "-"}</td>
        </tr>`;
    })
    .join("");

  renderFindings("webrtc-findings", rtc.findings);
}

function renderPollutionPanel(pol) {
  const tbody = document.getElementById("tbody-pollution");
  const rows = pol.rows || [];
  if (rows.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" class="empty-cell">暂无数据</td></tr>`;
    return;
  }

  const thead = document.getElementById("thead-pollution");
  const srvHeaders = rows[0].results.map((r) => `<th>${esc(r.server_label)}</th>`).join("");
  thead.innerHTML = `<tr><th>探测域名</th><th>DoH 可信基准</th>${srvHeaders}</tr>`;

  tbody.innerHTML = rows
    .map((row) => {
      const baseIp = row.baseline_ips && row.baseline_ips.length ? row.baseline_ips[0] : "-";
      const cells = row.results
        .map((c) => {
          const ans = c.answers && c.answers.length ? c.answers[0] : "-";
          let badge = `<span class="tag tag-muted">超时</span>`;
          if (c.status === "CLEAN") badge = `<span class="tag tag-green">正常</span>`;
          else if (c.status === "FAKE_IP") badge = `<span class="tag tag-cyan">FakeIP</span>`;
          else if (c.status === "POISONED") badge = `<span class="tag tag-red">投毒</span>`;
          return `<td title="${esc(c.detail)}">${badge}<br/><span class="mono muted">${esc(ans)}</span></td>`;
        })
        .join("");
      return `
        <tr>
          <td><strong>${esc(row.domain)}</strong><br/><span class="muted" style="font-size:0.75rem">${esc(row.label)}</span></td>
          <td class="mono">${esc(baseIp)}</td>
          ${cells}
        </tr>`;
    })
    .join("");

  renderFindings("pollution-findings", pol.findings);
}

function renderBenchmarkPanel(bench) {
  const hl = document.getElementById("bench-highlights");
  const chips = [];
  if (bench.fastest_domestic) {
    chips.push(`<div class="highlight-chip">国内最快: <strong>${esc(bench.fastest_domestic.name)}</strong> (${bench.fastest_domestic.avg_ms} ms)</div>`);
  }
  if (bench.fastest_overseas) {
    chips.push(`<div class="highlight-chip">海外最快: <strong>${esc(bench.fastest_overseas.name)}</strong> (${bench.fastest_overseas.avg_ms} ms)</div>`);
  }
  if (bench.fastest_encrypted) {
    chips.push(`<div class="highlight-chip">加密 DNS 最快: <strong>${esc(bench.fastest_encrypted.name)}</strong> (${bench.fastest_encrypted.avg_ms} ms)</div>`);
  }
  hl.innerHTML = chips.join("");

  const tbody = document.getElementById("tbody-bench");
  const entries = bench.entries || [];
  const maxMs = Math.max(150, ...entries.filter((e) => e.available).map((e) => e.avg_ms));

  tbody.innerHTML = entries
    .map((e) => {
      if (!e.available) {
        return `
          <tr>
            <td>${esc(e.name)}</td>
            <td><span class="tag tag-muted">${esc(e.protocol)}</span></td>
            <td>${esc(e.region)}</td>
            <td>-</td>
            <td><span class="tag tag-red">不可达</span></td>
            <td>0%</td>
            <td>-</td>
          </tr>`;
      }
      const pct = Math.min(100, Math.max(5, (e.avg_ms / maxMs) * 100));
      const color = e.avg_ms < 50 ? "var(--green)" : e.avg_ms < 140 ? "var(--yellow)" : "var(--red)";
      const protoTag = e.protocol === "UDP" ? "tag-muted" : "tag-cyan";
      return `
        <tr>
          <td><strong>${esc(e.name)}</strong><br/><span class="mono muted" style="font-size:0.74rem">${esc(e.server)}</span></td>
          <td><span class="tag ${protoTag}">${esc(e.protocol)}</span></td>
          <td>${esc(e.region)}</td>
          <td class="mono"><strong>${e.avg_ms} ms</strong></td>
          <td>
            <div class="bar-track"><div class="bar-fill" style="width:${pct.toFixed(1)}%;background:${color}"></div></div>
          </td>
          <td>${e.success_rate}%</td>
          <td>${e.dnssec_ad ? `<span class="tag tag-green">AD 支持</span>` : `<span class="muted">未标记</span>`}</td>
        </tr>`;
    })
    .join("");
}

function renderEnvPanel(env, proxyAudit) {
  const box = document.getElementById("env-details-box");
  const dnsList = (env.configured_dns_details || [])
    .map((d) => `${d.ip} (${d.location || "-"} · ${d.display_isp || "-"})`)
    .join("<br/>");
  const tunList = (env.tun_interfaces || [])
    .map((t) => `${t.name}: ${(t.ipv4 || []).join(", ")} [${t.likely_client}]`)
    .join("<br/>");
  const fakeSamples = (env.fake_ip_samples || [])
    .map(
      (s) =>
        `<tr><td class="mono">${esc(s.domain)}</td><td class="mono">${esc(
          (s.answers || []).join(", ") || "(无)"
        )}</td><td>${
          s.is_fake_ip ? `<span class="tag tag-cyan">Fake-IP</span>` : `<span class="tag tag-muted">真实解析</span>`
        }</td></tr>`
    )
    .join("");

  const proxySummary =
    proxyAudit && proxyAudit.client_detected
      ? `<div class="env-kv"><span class="muted">客户端规则直审</span><span><strong style="color:var(--green)">${esc(
          proxyAudit.client_version || proxyAudit.client_name
        )}</strong> · 配置 ${esc(proxyAudit.active_profile || "-")} (${proxyAudit.audit_score}/100)</span></div>`
      : "";

  box.innerHTML = `
    <div class="env-kv-grid">
      <div class="env-kv"><span class="muted">操作系统</span><span>${esc(env.os_name)}</span></div>
      <div class="env-kv"><span class="muted">工作模式</span><strong style="color:var(--cyan)">${esc(env.dns_mode)}</strong></div>
      ${proxySummary}
      <div class="env-kv"><span class="muted">系统主 DNS</span><span class="mono" style="text-align:right">${dnsList || "未检测到"}</span></div>
      <div class="env-kv"><span class="muted">TUN 虚拟网卡</span><span class="mono" style="text-align:right">${tunList || "未检测到活跃 TUN 网卡"}</span></div>
      <div class="env-kv"><span class="muted">EDNS Client Subnet</span><span>${env.ecs_supported ? esc(env.ecs_subnet) : "未暴露"}</span></div>
    </div>
    <div class="table-wrap">
      <table>
        <thead><tr><th>Fake-IP 嗅探域名</th><th>返回 IP</th><th>模式</th></tr></thead>
        <tbody>${fakeSamples}</tbody>
      </table>
    </div>
  `;
  const combinedFindings = [
    ...(env.findings || []),
    ...(proxyAudit && proxyAudit.client_detected ? proxyAudit.findings || [] : []),
  ];
  renderFindings("env-findings", combinedFindings);
}

// Browser-Side DNS Leak Probe (Cross-verifies Browser HTTP DNS vs System CLI DNS)
async function runBrowserDnsProbe() {
  const tbody = document.getElementById("tbody-browser-resolvers");
  tbody.innerHTML = `<tr><td colspan="5" class="empty-cell">正在浏览器内发起多轮随机子域名探测...</td></tr>`;

  const discovered = new Map();
  const attempts = Array.from({ length: 4 }, (_, i) =>
    (async () => {
      const sub = randomHex(20);
      for (const scheme of ["https", "http"]) {
        try {
          const resp = await fetch(`${scheme}://${sub}.edns.ip-api.com/json`, { cache: "no-store" });
          if (resp.ok) {
            const data = await resp.json();
            const ip = data?.dns?.ip;
            if (ip) {
              discovered.set(ip, { ip, source: `Browser DNS #${i + 1}`, geoHint: data?.dns?.geo || "" });
              break;
            }
          }
        } catch (_) {}
      }
    })()
  );

  await Promise.all(attempts);

  if (discovered.size === 0) {
    tbody.innerHTML = `<tr><td colspan="5" class="empty-cell">浏览器侧探测请求被拦截或离线 (可对比左侧系统探针)</td></tr>`;
    return;
  }

  let intelMap = {};
  try {
    const res = await fetch("/api/enrich", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ips: Array.from(discovered.keys()) }),
    });
    const j = await res.json();
    intelMap = j.results || {};
  } catch (_) {}

  tbody.innerHTML = Array.from(discovered.values())
    .map((item) => {
      const intel = intelMap[item.ip] || {};
      const regionTag = intel.is_cn
        ? `<span class="tag tag-yellow">国内</span>`
        : intel.is_private
        ? `<span class="tag tag-cyan">本地</span>`
        : `<span class="tag tag-green">海外</span>`;
      return `
        <tr>
          <td class="mono">${esc(item.ip)}</td>
          <td>${regionTag}</td>
          <td>${esc(intel.location || item.geoHint || "-")}</td>
          <td>${esc(intel.display_isp || "-")}</td>
          <td>${esc(item.source)}</td>
        </tr>`;
    })
    .join("");
}

// Browser-Side Native RTCPeerConnection WebRTC Leak Probe
async function runBrowserWebRTC() {
  const tbody = document.getElementById("tbody-browser-webrtc");
  const verdict = document.getElementById("browser-webrtc-verdict");

  if (!window.RTCPeerConnection) {
    verdict.textContent = "当前浏览器不支持或已禁用 RTCPeerConnection";
    tbody.innerHTML = `<tr><td colspan="4" class="empty-cell">WebRTC API 不可用</td></tr>`;
    return;
  }

  verdict.textContent = "正在收集浏览器 ICE 候选地址...";
  verdict.style.color = "var(--cyan)";
  tbody.innerHTML = `<tr><td colspan="4" class="empty-cell">正在通过 STUN 服务器探测...</td></tr>`;

  const candidates = new Map();
  const stunUrls = [
    "stun:stun.l.google.com:19302",
    "stun:stun.cloudflare.com:3478",
    "stun:stun.qq.com:3478",
  ];

  await new Promise((resolve) => {
    let pc;
    try {
      pc = new RTCPeerConnection({
        iceServers: stunUrls.map((urls) => ({ urls })),
      });
      pc.createDataChannel("dnsguard-probe");
      const timer = setTimeout(() => {
        try { pc.close(); } catch (_) {}
        resolve();
      }, 3200);

      pc.onicecandidate = (evt) => {
        if (!evt.candidate) {
          clearTimeout(timer);
          try { pc.close(); } catch (_) {}
          resolve();
          return;
        }
        const candStr = evt.candidate.candidate || "";
        // Parse SDP candidate: candidate:<foundation> <component> <protocol> <priority> <ip> <port> typ <type>
        const parts = candStr.split(" ");
        if (parts.length >= 8) {
          const ip = parts[4];
          const typIdx = parts.indexOf("typ");
          const ctype = typIdx !== -1 ? parts[typIdx + 1] : "unknown";
          const key = `${ctype}:${ip}`;
          if (!candidates.has(key)) {
            candidates.set(key, { type: ctype, ip, proto: parts[2] || "udp" });
          }
        }
      };

      pc.createOffer()
        .then((offer) => pc.setLocalDescription(offer))
        .catch(() => {
          clearTimeout(timer);
          resolve();
        });
    } catch (_) {
      resolve();
    }
  });

  if (candidates.size === 0) {
    verdict.textContent = "未发现任何浏览器 WebRTC ICE 候选 (WebRTC 可能已被隐私扩展/策略禁用)";
    verdict.style.color = "var(--green)";
    tbody.innerHTML = `<tr><td colspan="4" class="empty-cell">无候选暴露</td></tr>`;
    return;
  }

  const publicIps = Array.from(candidates.values())
    .map((c) => c.ip)
    .filter((ip) => !ip.endsWith(".local"));

  let intelMap = {};
  if (publicIps.length > 0) {
    try {
      const res = await fetch("/api/enrich", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ips: publicIps }),
      });
      const j = await res.json();
      intelMap = j.results || {};
    } catch (_) {}
  }

  let hasSrflx = false;
  let hasCnSrflx = false;

  tbody.innerHTML = Array.from(candidates.values())
    .map((c) => {
      const isMdns = c.ip.endsWith(".local");
      const intel = intelMap[c.ip] || {};
      if (c.type === "srflx") {
        hasSrflx = true;
        if (intel.is_cn) hasCnSrflx = true;
      }
      const badge =
        c.type === "srflx"
          ? `<span class="tag tag-yellow">srflx (公网穿透)</span>`
          : `<span class="tag tag-muted">${esc(c.type)} (本地)</span>`;
      const desc = isMdns
        ? "mDNS 隐私掩码保护 (未暴露真实内网 IP)"
        : `${esc(intel.location || "-")} · ${esc(intel.display_isp || "-")}`;
      return `
        <tr>
          <td>${badge}</td>
          <td class="mono">${esc(c.ip)}</td>
          <td>${desc}</td>
          <td class="mono muted">${esc(c.proto.toUpperCase())}</td>
        </tr>`;
    })
    .join("");

  if (hasCnSrflx) {
    verdict.textContent = "注意: 浏览器 WebRTC STUN 捕获到国内公网 IP (若开启海外代理则存在 WebRTC 泄漏)";
    verdict.style.color = "var(--red)";
  } else if (hasSrflx) {
    verdict.textContent = "浏览器 WebRTC 捕获到海外 STUN 出口 IP (未见国内宽带 IP 暴露)";
    verdict.style.color = "var(--green)";
  } else {
    verdict.textContent = "浏览器 WebRTC 仅暴露本地/mDNS 候选地址 (公网 IP 未暴露)";
    verdict.style.color = "var(--green)";
  }
}

function renderAIPanel(ai) {
  if (!ai) return;
  const chipsEl = document.getElementById("ai-summary-chips");
  if (chipsEl) {
    chipsEl.innerHTML = `
      <div class="highlight-chip">检测总数: <strong>${ai.total_count ?? 0}</strong></div>
      <div class="highlight-chip">正常可用: <strong style="color:var(--green)">${ai.available_count ?? 0}</strong></div>
      <div class="highlight-chip">CF盾/风控: <strong style="color:var(--yellow)">${ai.challenge_count ?? 0}</strong></div>
      <div class="highlight-chip">地区锁区: <strong style="color:var(--red)">${ai.region_blocked_count ?? 0}</strong></div>
      <div class="highlight-chip">不可达: <strong class="muted">${ai.unreachable_count ?? 0}</strong></div>
    `;
  }

  const tbody = document.getElementById("tbody-ai-services");
  const services = ai.services || [];
  if (services.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" class="empty-cell">暂无 AI 服务检测数据</td></tr>`;
  } else {
    tbody.innerHTML = services
      .map((s) => {
        const dnsTag =
          s.dns_status === "FAKE_IP"
            ? `<span class="tag tag-cyan">Fake-IP</span>`
            : s.dns_status === "POISONED"
            ? `<span class="tag tag-red">污染</span>`
            : s.dns_status === "NXDOMAIN"
            ? `<span class="tag tag-muted">无记录</span>`
            : `<span class="tag tag-muted">真实IP</span>`;

        const loc = s.colo ? `${s.exit_location || "-"} [${s.colo}]` : s.exit_location || "-";
        const lat = s.tls_ok ? `${Math.round(s.latency_ms)} ms` : "-";
        let statusBadge = `<span class="tag tag-red">${esc(s.availability_label)}</span>`;
        if (s.availability === "AVAILABLE") {
          statusBadge = `<span class="tag tag-green">${esc(s.availability_label)}</span>`;
        } else if (s.availability === "RISK_CHALLENGE") {
          statusBadge = `<span class="tag tag-yellow">${esc(s.availability_label)}</span>`;
        }

        return `
          <tr>
            <td><strong>${esc(s.provider)}</strong> · ${esc(s.name)}</td>
            <td class="mono">${esc(s.domain)}</td>
            <td>${dnsTag}</td>
            <td>${esc(loc)}</td>
            <td class="mono">${esc(lat)}</td>
            <td>${statusBadge}</td>
            <td class="muted">${esc(s.note)}</td>
          </tr>`;
      })
      .join("");
  }
  renderFindings("ai-findings", ai.findings);
}

async function runAllDiagnostics() {
  setScanState(true, "并发执行 6 项深度安全与 AI 解锁审计...");
  try {
    // Launch backend 6-in-1 audit + browser-side probes concurrently
    const [audit] = await Promise.all([
      fetch("/api/run/all").then((r) => r.json()),
      runBrowserDnsProbe(),
      runBrowserWebRTC(),
    ]);

    latestAuditReport = audit;
    document.getElementById("btn-export-json").disabled = false;

    updateHeroScore(audit);
    renderLeakPanel(audit.leak);
    renderSplitPanel(audit.split);
    renderAIPanel(audit.ai);
    renderWebRTCPanel(audit.webrtc);
    renderPollutionPanel(audit.pollution);
    renderBenchmarkPanel(audit.benchmark);
    renderEnvPanel(audit.env, audit.proxy_audit);
    setScanState(false, "全量审计完成");
  } catch (err) {
    console.error(err);
    setScanState(false, "扫描出现异常");
  }
}

async function runSingleModule(mod) {
  setScanState(true, `正在运行 ${mod} 模块...`);
  try {
    const res = await fetch(`/api/run/${mod}`);
    const data = await res.json();
    if (mod === "leak") renderLeakPanel(data);
    else if (mod === "split") renderSplitPanel(data);
    else if (mod === "ai") renderAIPanel(data);
    else if (mod === "webrtc") renderWebRTCPanel(data);
    else if (mod === "pollute") renderPollutionPanel(data);
    else if (mod === "bench") renderBenchmarkPanel(data);
    else if (mod === "env") renderEnvPanel(data);
    setScanState(false, `${mod} 更新完成`);
  } catch (err) {
    console.error(err);
    setScanState(false, "模块请求失败");
  }
}

document.getElementById("btn-run-all").addEventListener("click", runAllDiagnostics);

document.getElementById("btn-export-json").addEventListener("click", () => {
  if (!latestAuditReport) return;
  const blob = new Blob([JSON.stringify(latestAuditReport, null, 2)], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `dnscheck-report-${Date.now()}.json`;
  a.click();
});

// Custom DNS Dig Inspector Form
document.getElementById("dig-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const box = document.getElementById("dig-result-box");
  box.innerHTML = `<div class="muted">正在构造 DNS 报文并等待响应...</div>`;

  const payload = {
    domain: document.getElementById("dig-domain").value,
    qtype: document.getElementById("dig-qtype").value,
    proto: document.getElementById("dig-proto").value,
    server: document.getElementById("dig-server").value,
    ecs: document.getElementById("dig-ecs").value,
  };

  try {
    const resp = await fetch("/api/dig", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const res = await resp.json();
    if (res.error && !res.rcode) {
      box.innerHTML = `<div class="tag tag-red">错误: ${esc(res.error)}</div>`;
      return;
    }

    const flags = res.packet_flags
      ? Object.entries(res.packet_flags)
          .filter(([, v]) => v)
          .map(([k]) => k.toUpperCase())
          .join(", ")
      : "-";
    const intelMap = res.answer_intel || {};
    const answersHtml = (res.answers || []).length
      ? res.answers
          .map((ans) => {
            const info = intelMap[ans] || {};
            return `
              <tr>
                <td class="mono">${esc(ans)}</td>
                <td>${res.ttl ?? "-"}</td>
                <td>${esc(info.location || "-")}</td>
                <td>${esc(info.display_isp || "-")}</td>
              </tr>`;
          })
          .join("")
      : `<tr><td colspan="4" class="empty-cell">无应答记录 (${esc(res.error || res.rcode)})</td></tr>`;

    box.innerHTML = `
      <div class="section-title-row">
        <span class="tag ${res.success ? "tag-green" : "tag-red"}">${esc(res.rcode)}</span>
        <span class="mono muted">${esc(res.protocol)} · ${res.latency_ms} ms · Flags: ${esc(flags)}</span>
      </div>
      ${
        res.edns_ecs
          ? `<div class="small-desc muted">EDNS ECS Echo: <span class="mono">${esc(res.edns_ecs.cidr)}</span> (Scope /${res.edns_ecs.scope_prefix_len})</div>`
          : ""
      }
      <div class="table-wrap">
        <table>
          <thead><tr><th>RDATA</th><th>TTL</th><th>归属地</th><th>运营商 / ASN</th></tr></thead>
          <tbody>${answersHtml}</tbody>
        </table>
      </div>`;
  } catch (err) {
    box.innerHTML = `<div class="tag tag-red">请求异常: ${esc(err)}</div>`;
  }
});

// Auto-run full audit once page loads
window.addEventListener("DOMContentLoaded", () => {
  runAllDiagnostics();
});
