var B = location.origin, ri = null, currentRange = "24h";

function gt() { return sessionStorage.getItem("t"); }
function st(t) { sessionStorage.setItem("t", t); }
function ct() { sessionStorage.removeItem("t"); }

async function login() {
  var inp = document.getElementById("token-input");
  var err = document.getElementById("login-error");
  var tok = inp.value.trim();
  if (!tok) { err.textContent = "Token required"; return; }
  try {
    var res = await fetch(B + "/api/stats?chart_range=" + currentRange, { headers: { Authorization: "Bearer " + tok } });
    if (res.status === 401) { err.textContent = "Invalid token"; return; }
    if (!res.ok) { err.textContent = "Error " + res.status; return; }
    st(tok); inp.value = ""; err.textContent = "";
    show(); render(await res.json());
  } catch(e) { err.textContent = "Network error"; }
}

document.getElementById("token-input").addEventListener("keydown", function(e) { if (e.key === "Enter") login(); });
document.getElementById("login-btn").addEventListener("click", login);
document.getElementById("logout-btn").addEventListener("click", logout);

function logout() {
  ct(); stopR();
  document.getElementById("login").classList.remove("hidden");
  document.getElementById("dashboard").classList.remove("active");
}

function show() {
  document.getElementById("login").classList.add("hidden");
  document.getElementById("dashboard").classList.add("active");
  startR();
}

function startR() { stopR(); if (document.getElementById("auto-refresh").checked) ri = setInterval(load, 10000); }
function stopR() { if (ri) { clearInterval(ri); ri = null; } }
document.getElementById("auto-refresh").addEventListener("change", function() {
  if (this.checked) startR(); else stopR();
});

async function load() {
  var tok = gt(); if (!tok) return;
  try {
    var res = await fetch(B + "/api/stats?chart_range=" + currentRange, { headers: { Authorization: "Bearer " + tok } });
    if (res.status === 401) { logout(); return; }
    if (!res.ok) return;
    render(await res.json());
  } catch(e) {}
}

// --- Range selector ---
var rangeLabels = { "24h": "Last 24 hours", "7d": "Last 7 days", "14d": "Last 14 days", "30d": "Last 30 days", "90d": "Last 90 days", "all": "All time" };

document.getElementById("chart-range-pills").addEventListener("click", function(e) {
  var btn = e.target.closest(".chart-range-pill");
  if (!btn || btn.classList.contains("active")) return;
  document.querySelectorAll(".chart-range-pill").forEach(function(p) { p.classList.remove("active"); });
  btn.classList.add("active");
  currentRange = btn.dataset.range;
  document.getElementById("chart-range-label").textContent = rangeLabels[currentRange] || currentRange;
  load();
});

function fmt$(v) { return "$" + Number(v || 0).toFixed(4); }
function fmtN(v) { return Number(v || 0).toLocaleString(); }
function fmtPct(v) { return (Number(v || 0) * 100).toFixed(1) + "%"; }
function fmtTime(iso) {
  if (!iso) return "--";
  var normalized = iso.replace(" ", "T");
  if (!/[Z+\-]\d*$/.test(normalized)) normalized += "Z";
  var d = new Date(normalized);
  if (isNaN(d)) return iso;
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}
function esc(s) { var d = document.createElement("div"); d.textContent = s || ""; return d.innerHTML; }

function fmtChartLabel(raw, mode) {
  if (mode === "hourly") {
    var parts = raw.split(" ");
    return parts[1] ? parts[1] : raw;
  }
  // daily: "2026-03-28" -> "Mar 28"
  var d = new Date(raw + "T00:00:00Z");
  if (isNaN(d)) return raw;
  var months = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"];
  return months[d.getUTCMonth()] + " " + d.getUTCDate();
}

function fmtTooltipLabel(raw, mode) {
  if (mode === "hourly") {
    var parts = raw.split(" ");
    var datePart = parts[0] || "";
    var timePart = parts[1] || "";
    var d = new Date(datePart + "T" + timePart + ":00Z");
    if (isNaN(d)) return raw;
    var months = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"];
    return months[d.getUTCMonth()] + " " + d.getUTCDate() + ", " + timePart;
  }
  var d2 = new Date(raw + "T00:00:00Z");
  if (isNaN(d2)) return raw;
  var days = ["Sun","Mon","Tue","Wed","Thu","Fri","Sat"];
  var months2 = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"];
  return days[d2.getUTCDay()] + ", " + months2[d2.getUTCMonth()] + " " + d2.getUTCDate();
}

// --- SVG ---
function sparkline(el, data, color) {
  if (!data || !data.length) { el.innerHTML = ""; return; }
  var w = 80, h = 28, max = Math.max.apply(null, data.concat([0.001]));
  var pts = data.map(function(v, i) {
    return [(i / Math.max(data.length - 1, 1)) * w, h - (v / max) * (h - 2) - 1];
  });
  var d = pts.map(function(p, i) { return (i ? "L" : "M") + p[0].toFixed(1) + "," + p[1].toFixed(1); }).join("");
  el.innerHTML = '<svg viewBox="0 0 ' + w + ' ' + h + '" preserveAspectRatio="none">' +
    '<path d="' + d + '" fill="none" stroke="' + color + '" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>';
}

function lineChart(el, rawLabels, vals, mode) {
  if (!vals || !vals.length) { el.innerHTML = '<div class="empty-state">No data</div>'; return; }

  var n = vals.length;
  var max = Math.max.apply(null, vals.concat([1]));

  // Nice Y-axis ticks
  var gridLines = 4;
  var rawStep = max / gridLines;
  var mag = Math.pow(10, Math.floor(Math.log10(rawStep || 1)));
  var niceStep = Math.ceil(rawStep / mag) * mag;
  if (niceStep === 0) niceStep = 1;
  var niceMax = niceStep * gridLines;

  // Use actual container dimensions so viewBox matches pixels 1:1 — no stretching
  var w = el.clientWidth || 700;
  var h = el.clientHeight || 180;
  var pad = { top: 12, right: 12, bottom: 32, left: 44 };
  var cw = w - pad.left - pad.right;
  var ch = h - pad.top - pad.bottom;

  var svg = '<defs>';
  svg += '<linearGradient id="areaGrad" x1="0" y1="0" x2="0" y2="1">';
  svg += '<stop offset="0%" stop-color="#ededed" stop-opacity="0.12"/>';
  svg += '<stop offset="100%" stop-color="#ededed" stop-opacity="0"/>';
  svg += '</linearGradient>';
  svg += '</defs>';

  // Grid lines + Y labels
  for (var g = 0; g <= gridLines; g++) {
    var gy = pad.top + (ch / gridLines) * g;
    var yVal = Math.round(niceMax - (niceMax / gridLines) * g);
    svg += '<line x1="' + pad.left + '" y1="' + gy.toFixed(1) + '" x2="' + (w - pad.right) + '" y2="' + gy.toFixed(1) + '" stroke="#1a1a1a" stroke-width="1"/>';
    svg += '<text x="' + (pad.left - 8) + '" y="' + (gy + 3.5).toFixed(1) + '" fill="#444" font-size="10" font-family="Inter,sans-serif" text-anchor="end">' + yVal + '</text>';
  }

  // Compute points
  var pts = [];
  for (var i = 0; i < n; i++) {
    var px = pad.left + (n === 1 ? cw / 2 : (i / (n - 1)) * cw);
    var py = pad.top + ch - (vals[i] / niceMax) * ch;
    pts.push([px, py]);
  }

  // Area fill
  var areaPath = "M" + pts[0][0].toFixed(1) + "," + pts[0][1].toFixed(1);
  for (var i = 1; i < pts.length; i++) {
    areaPath += "L" + pts[i][0].toFixed(1) + "," + pts[i][1].toFixed(1);
  }
  areaPath += "L" + pts[pts.length - 1][0].toFixed(1) + "," + (pad.top + ch) + "L" + pts[0][0].toFixed(1) + "," + (pad.top + ch) + "Z";
  svg += '<path d="' + areaPath + '" fill="url(#areaGrad)"/>';

  // Line
  var linePath = pts.map(function(p, i) { return (i ? "L" : "M") + p[0].toFixed(1) + "," + p[1].toFixed(1); }).join("");
  svg += '<path d="' + linePath + '" fill="none" stroke="#ededed" stroke-width="1.5" stroke-linejoin="round" stroke-linecap="round"/>';

  // Points + invisible hit areas
  var dotR = n > 60 ? 0 : n > 30 ? 2 : 3;
  for (var i = 0; i < n; i++) {
    // Wide invisible hit column for each point
    var colW = cw / n;
    var colX = pad.left + (n === 1 ? 0 : (i / (n - 1)) * cw - colW / 2);
    svg += '<rect x="' + colX.toFixed(1) + '" y="' + pad.top + '" width="' + colW.toFixed(1) + '" height="' + ch + '" fill="transparent" data-idx="' + i + '" class="chart-hit"/>';
    if (dotR > 0) {
      svg += '<circle cx="' + pts[i][0].toFixed(1) + '" cy="' + pts[i][1].toFixed(1) + '" r="' + dotR + '" fill="#0a0a0a" stroke="#ededed" stroke-width="1.5" class="chart-dot" data-idx="' + i + '"/>';
    }
  }

  // X-axis labels
  var maxLabels = Math.min(n, mode === "hourly" ? 8 : 10);
  var step = Math.max(1, Math.ceil(n / maxLabels));
  for (var j = 0; j < n; j += step) {
    var label = fmtChartLabel(rawLabels[j], mode);
    svg += '<text x="' + pts[j][0].toFixed(1) + '" y="' + (h - 6) + '" fill="#555" font-size="10" font-family="Inter,sans-serif" text-anchor="middle">' + esc(label) + '</text>';
  }

  el.innerHTML = '<svg viewBox="0 0 ' + w + ' ' + h + '" width="' + w + '" height="' + h + '">' + svg + '</svg>';

  // Tooltip
  var tooltip = document.getElementById("chart-tooltip");
  var tooltipLabel = document.getElementById("tooltip-label");
  var tooltipValue = document.getElementById("tooltip-value");
  var svgEl = el.querySelector("svg");

  svgEl.addEventListener("mousemove", function(e) {
    var hit = e.target.closest("[data-idx]");
    if (!hit) { tooltip.classList.remove("visible"); return; }
    var idx = parseInt(hit.dataset.idx);
    tooltipLabel.textContent = fmtTooltipLabel(rawLabels[idx], mode);
    tooltipValue.textContent = fmtN(vals[idx]) + " request" + (vals[idx] !== 1 ? "s" : "");
    tooltip.classList.add("visible");
    var rect = el.parentElement.getBoundingClientRect();
    var ex = e.clientX - rect.left;
    var ey = e.clientY - rect.top;
    tooltip.style.left = Math.min(ex + 12, rect.width - 160) + "px";
    tooltip.style.top = (ey - 48) + "px";
  });

  svgEl.addEventListener("mouseleave", function() {
    tooltip.classList.remove("visible");
  });
}

function breakdown(el, items) {
  if (!items || !items.length) { el.innerHTML = '<div class="empty-state">No revenue data</div>'; return; }
  var colors = ["#ededed", "#999", "#666", "#555", "#444", "#333"];
  el.innerHTML = items.slice(0, 8).map(function(item, i) {
    return '<div class="breakdown-item">' +
      '<div class="breakdown-dot" style="background:' + colors[i % colors.length] + '"></div>' +
      '<div class="breakdown-name">' + esc(item.api_name) + '</div>' +
      '<div class="breakdown-val">' + fmt$(item.total_usd) + '</div></div>';
  }).join("");
}

function render(data) {
  var upd = function(id, v) { document.getElementById(id).textContent = v; };
  var range = data.chart_range || "7d";
  var rangeLabel = range === "24h" ? "24h" : range === "all" ? "all" : range;

  upd("rev-7d", fmt$(data.revenue_7d));
  upd("rev-30d", fmt$(data.revenue_30d));
  upd("active-apis", data.apis ? data.apis.length : 0);
  upd("total-requests", fmtN(data.total_requests));
  upd("requests-range-label", "Requests (" + rangeLabel + ")");

  // Update API table headers to reflect range
  var reqHeader = document.getElementById("api-req-header");
  var errHeader = document.getElementById("api-err-header");
  if (reqHeader) reqHeader.textContent = "Requests (" + rangeLabel + ")";
  if (errHeader) errHeader.textContent = "Errors (" + rangeLabel + ")";

  if (data.wallet) {
    document.getElementById("wallet").textContent = data.wallet.substring(0, 6) + "..." + data.wallet.slice(-4);
    document.getElementById("wallet").title = data.wallet;
  }
  document.getElementById("last-updated").textContent = new Date().toLocaleTimeString();

  if (data.charts) {
    sparkline(document.getElementById("spark-rev"), (data.charts.daily_revenue_7d || []).map(function(d) { return d.total_usd; }), "#3ddc84");
    sparkline(document.getElementById("spark-rev-30"), (data.charts.daily_revenue_30d || []).map(function(d) { return d.total_usd; }), "#3ddc84");
    sparkline(document.getElementById("spark-req"), (data.charts.daily_requests_7d || []).map(function(d) { return d.total; }), "#ededed");

    var rd = data.charts.range_data;
    if (rd) {
      lineChart(document.getElementById("chart-hourly"), rd.labels, rd.values, rd.mode);
    }
  }

  breakdown(document.getElementById("api-breakdown"), data.revenue_by_api);

  var ab = document.getElementById("apis-table");
  if (!data.apis || !data.apis.length) {
    ab.innerHTML = '<tr><td colspan="9" class="empty-state">No APIs</td></tr>';
  } else {
    // Sort by total requests descending
    var sorted = data.apis.slice().sort(function(a, b) { return (b.total_requests || 0) - (a.total_requests || 0); });
    ab.innerHTML = sorted.map(function(a) {
      var er = a.error_rate_range || a.error_rate_7d;
      var errColor = er && er.rate > 0.05 ? ' class="mono red"' : ' class="mono dim"';
      var created = a.created_at ? new Date(a.created_at.replace(" ", "T") + (a.created_at.includes("Z") ? "" : "Z")).toLocaleDateString() : "--";
      var avg = a.avg_latency_ms != null ? a.avg_latency_ms.toFixed(0) : "--";
      var p95 = a.p95_latency_ms != null ? a.p95_latency_ms.toFixed(0) : "--";
      return '<tr class="api-row" data-api="' + esc(a.name) + '" style="cursor:pointer">' +
        '<td class="primary">' + esc(a.name) + '</td>' +
        '<td class="mono dim">' + created + '</td>' +
        '<td class="mono">' + fmtN(a.requests_range) + '</td>' +
        '<td class="mono">' + fmtN(a.total_requests) + '</td>' +
        '<td' + errColor + '>' + fmtPct(er ? er.rate : 0) + '</td>' +
        '<td class="mono dim">' + avg + '</td>' +
        '<td class="mono dim">' + p95 + '</td>' +
        '<td class="mono dim">' + fmtN(a.unique_callers) + '</td>' +
        '<td class="mono green">' + fmt$(a.total_revenue_usd) + '</td></tr>';
    }).join("");

    // Click handler for API rows
    ab.querySelectorAll(".api-row").forEach(function(row) {
      row.addEventListener("click", function() { loadApiDetail(row.dataset.api); });
    });
  }

  var rb = document.getElementById("requests-table");
  if (!data.recent_requests || !data.recent_requests.length) {
    rb.innerHTML = '<tr><td colspan="6" class="empty-state">No events</td></tr>';
  } else {
    rb.innerHTML = data.recent_requests.slice(0, 15).map(function(r) {
      var sc = r.status_code;
      var scClass = sc >= 500 ? "mono red" : sc >= 400 ? "mono" : "mono green";
      return '<tr>' +
        '<td class="mono dim">' + fmtTime(r.created_at) + '</td>' +
        '<td class="primary">' + esc(r.api_name) + '</td>' +
        '<td class="mono dim">' + esc(r.method) + ' ' + esc(r.endpoint) + '</td>' +
        '<td class="' + scClass + '">' + (Number.isFinite(sc) ? sc : "--") + '</td>' +
        '<td class="mono dim">' + (Number.isFinite(r.response_time_ms) ? r.response_time_ms.toFixed(0) + "ms" : "--") + '</td>' +
        '<td>' + (r.paid ? '<span class="badge badge-paid">paid</span>' : '<span class="badge badge-free">free</span>') + '</td></tr>';
    }).join("");
  }

  var sn = data.signup_notifications || { counts: [], recent: [] };
  var summaryEl = document.getElementById("signup-summary");
  if (summaryEl) {
    if (sn.counts && sn.counts.length) {
      var total = sn.counts.reduce(function(s, x) { return s + (x.count || 0); }, 0);
      // textContent escapes automatically — don't double-encode via esc().
      var per = sn.counts.map(function(x) { return x.source + " " + fmtN(x.count); }).join(" · ");
      summaryEl.textContent = fmtN(total) + " total — " + per;
    } else {
      summaryEl.textContent = "0 total";
    }
  }
  var sb = document.getElementById("signup-table");
  if (sb) {
    if (!sn.recent || !sn.recent.length) {
      sb.innerHTML = '<tr><td colspan="4" class="empty-state">No signups yet</td></tr>';
    } else {
      sb.innerHTML = sn.recent.slice(0, 20).map(function(r) {
        return '<tr>' +
          '<td class="mono dim">' + fmtTime(r.created_at) + '</td>' +
          '<td class="primary">' + esc(r.source) + '</td>' +
          '<td class="mono dim">' + esc(r.interest || "") + '</td>' +
          '<td class="mono">' + esc(r.email) + '</td></tr>';
      }).join("");
    }
  }
}

// --- API Detail Modal ---
function closeApiModal() {
  var overlay = document.getElementById("api-modal-overlay");
  if (overlay) overlay.remove();
}

async function loadApiDetail(name) {
  var tok = gt(); if (!tok) return;

  // Remove existing modal
  closeApiModal();

  // Create modal overlay
  var overlay = document.createElement("div");
  overlay.id = "api-modal-overlay";
  overlay.style.cssText = "position:fixed;inset:0;z-index:200;background:rgba(0,0,0,0.7);display:flex;align-items:center;justify-content:center;padding:24px";
  overlay.addEventListener("click", function(e) { if (e.target === overlay) closeApiModal(); });

  var modal = document.createElement("div");
  modal.style.cssText = "background:#141414;border:1px solid #222;border-radius:8px;width:100%;max-width:900px;max-height:85vh;overflow-y:auto;padding:24px";
  modal.id = "api-detail-panel";
  modal.innerHTML = '<div class="panel-header">Loading ' + esc(name) + '...</div>';

  overlay.appendChild(modal);
  document.body.appendChild(overlay);

  // Close on Escape
  var escHandler = function(e) { if (e.key === "Escape") { closeApiModal(); document.removeEventListener("keydown", escHandler); } };
  document.addEventListener("keydown", escHandler);

  try {
    var res = await fetch(B + "/api/api-detail?name=" + encodeURIComponent(name) + "&range=" + currentRange, {
      headers: { Authorization: "Bearer " + tok }
    });
    if (!res.ok) { modal.innerHTML = '<div class="panel-header">Error loading details (' + res.status + ')</div>'; return; }
    var d = await res.json();
    renderApiDetail(d, modal);
  } catch(e) {
    modal.innerHTML = '<div class="panel-header">Error: ' + esc(e.message) + '</div>';
  }
}

function renderApiDetail(d, panel) {
  var html = '<div class="panel-header">' + esc(d.name) + ' — Detail (' + esc(d.range) + ')' +
    '<span style="float:right;cursor:pointer;font-size:12px;opacity:0.5" onclick="closeApiModal()">&#x2715; close</span></div>';

  // Status breakdown
  if (d.status_breakdown && d.status_breakdown.length) {
    html += '<div style="margin:12px 0"><strong>Status Codes</strong></div>';
    html += '<div style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:12px">';
    d.status_breakdown.forEach(function(s) {
      var color = s.status_code >= 500 ? "#ff4444" : s.status_code >= 400 ? "#ff8800" : "#3ddc84";
      html += '<div style="background:rgba(255,255,255,0.05);padding:6px 12px;border-radius:4px;border-left:3px solid ' + color + '">' +
        '<span class="mono" style="color:' + color + '">' + s.status_code + '</span>' +
        '<span class="mono dim" style="margin-left:8px">' + fmtN(s.count) + '</span></div>';
    });
    html += '</div>';
  }

  // Error log
  if (d.errors && d.errors.length) {
    html += '<div style="margin:12px 0"><strong>Errors (' + d.errors.length + ')</strong></div>';
    html += '<table><thead><tr><th>Time</th><th>Method</th><th>Endpoint</th><th>Status</th><th>Latency</th><th>Client IP</th></tr></thead><tbody>';
    d.errors.forEach(function(e) {
      var sc = e.status_code;
      var scClass = sc >= 500 ? "mono red" : "mono";
      html += '<tr>' +
        '<td class="mono dim">' + fmtTime(e.created_at) + '</td>' +
        '<td class="mono dim">' + esc(e.method) + '</td>' +
        '<td class="mono">' + esc(e.endpoint) + '</td>' +
        '<td class="' + scClass + '">' + sc + '</td>' +
        '<td class="mono dim">' + (e.response_time_ms != null ? e.response_time_ms.toFixed(0) + 'ms' : '--') + '</td>' +
        '<td class="mono dim">' + esc(e.client_ip || '--') + '</td></tr>';
    });
    html += '</tbody></table>';
  } else {
    html += '<div style="margin:12px 0;opacity:0.5">No errors in this period</div>';
  }

  // Recent requests
  if (d.recent_requests && d.recent_requests.length) {
    html += '<div style="margin:16px 0 8px"><strong>Recent Requests (last ' + Math.min(d.recent_requests.length, 50) + ')</strong></div>';
    html += '<table><thead><tr><th>Time</th><th>Method</th><th>Endpoint</th><th>Status</th><th>Latency</th><th>Paid</th></tr></thead><tbody>';
    d.recent_requests.slice(0, 50).forEach(function(r) {
      var sc = r.status_code;
      var scClass = sc >= 500 ? "mono red" : sc >= 400 ? "mono" : "mono green";
      html += '<tr>' +
        '<td class="mono dim">' + fmtTime(r.created_at) + '</td>' +
        '<td class="mono dim">' + esc(r.method) + '</td>' +
        '<td class="mono">' + esc(r.endpoint) + '</td>' +
        '<td class="' + scClass + '">' + sc + '</td>' +
        '<td class="mono dim">' + (r.response_time_ms != null ? r.response_time_ms.toFixed(0) + 'ms' : '--') + '</td>' +
        '<td>' + (r.paid ? '<span class="badge badge-paid">paid</span>' : '<span class="badge badge-free">free</span>') + '</td></tr>';
    });
    html += '</tbody></table>';
  }

  panel.innerHTML = html;
}

if (gt()) { show(); load(); }

// --- Tabs ---
document.querySelectorAll(".tab").forEach(function(tab) {
  tab.addEventListener("click", function() {
    document.querySelectorAll(".tab").forEach(function(t) { t.classList.remove("active"); });
    document.querySelectorAll(".tab-content").forEach(function(t) { t.classList.remove("active"); });
    tab.classList.add("active");
    document.getElementById("tab-" + tab.dataset.tab).classList.add("active");
    if (tab.dataset.tab === "caps") loadCaps();
  });
});

// --- Audit Log ---
var auditOffset = 0, auditLimit = 50;

function fmtWallet(w) {
  if (!w) return '<span class="dim">--</span>';
  return '<span title="' + esc(w) + '">' + esc(w.substring(0, 6) + "..." + w.slice(-4)) + '</span>';
}
function fmtTx(h) {
  if (!h) return '<span class="dim">--</span>';
  return '<a href="https://basescan.org/tx/' + esc(h) + '" target="_blank" style="color:#52a8ff">' + esc(h.substring(0, 8) + "...") + '</a>';
}

async function loadAudit(reset) {
  var tok = gt(); if (!tok) return;
  if (reset) auditOffset = 0;
  var wallet = document.getElementById("audit-wallet").value.trim();
  var api = document.getElementById("audit-api").value;
  var params = "limit=" + auditLimit + "&offset=" + auditOffset;
  if (wallet) params += "&wallet=" + encodeURIComponent(wallet);
  if (api) params += "&api=" + encodeURIComponent(api);
  try {
    var res = await fetch(B + "/api/audit-log?" + params, { headers: { Authorization: "Bearer " + tok } });
    if (!res.ok) return;
    var data = await res.json();
    renderAudit(data);
  } catch(e) {}
}

function renderAudit(data) {
  var tb = document.getElementById("audit-table");
  if (!data.rows || !data.rows.length) {
    tb.innerHTML = '<tr><td colspan="7" class="empty-state">No records found</td></tr>';
    document.getElementById("audit-pagination").style.display = "none";
    return;
  }
  tb.innerHTML = data.rows.map(function(r) {
    var sc = r.status_code;
    var scClass = sc >= 500 ? "mono red" : sc >= 400 ? "mono" : "mono green";
    return '<tr>' +
      '<td class="mono dim">' + fmtTime(r.created_at) + '</td>' +
      '<td class="mono">' + fmtWallet(r.payer_wallet) + '</td>' +
      '<td class="primary">' + esc(r.api_name) + '</td>' +
      '<td class="mono dim">' + esc(r.method) + ' ' + esc(r.endpoint) + '</td>' +
      '<td class="' + scClass + '">' + (Number.isFinite(sc) ? sc : esc(String(sc))) + '</td>' +
      '<td class="mono">' + (r.amount_usd > 0 ? '<span class="green">' + fmt$(r.amount_usd) + '</span>' : '<span class="dim">free</span>') + '</td>' +
      '<td class="mono">' + fmtTx(r.tx_hash) + '</td></tr>';
  }).join("");

  var pg = document.getElementById("audit-pagination");
  pg.style.display = "flex";
  document.getElementById("audit-info").textContent = "Showing " + (auditOffset + 1) + "-" + Math.min(auditOffset + auditLimit, data.total) + " of " + data.total;
  document.getElementById("audit-prev").disabled = auditOffset === 0;
  document.getElementById("audit-next").disabled = !data.has_more;
}

document.getElementById("audit-search").addEventListener("click", function() { loadAudit(true); });
document.getElementById("audit-prev").addEventListener("click", function() { auditOffset = Math.max(0, auditOffset - auditLimit); loadAudit(); });
document.getElementById("audit-next").addEventListener("click", function() { auditOffset += auditLimit; loadAudit(); });

// Populate API dropdown from stats data
function populateApiFilter(apis) {
  var sel = document.getElementById("audit-api");
  if (sel.options.length > 1) return;
  (apis || []).forEach(function(a) {
    var opt = document.createElement("option");
    opt.value = a.name;
    opt.textContent = a.name;
    sel.appendChild(opt);
  });
}

// Hook into render to populate the API filter
var origRender = render;
render = function(data) {
  origRender(data);
  populateApiFilter(data.apis);
};

// --- Spend Caps ---
async function loadCaps() {
  var tok = gt(); if (!tok) return;
  try {
    var res1 = await fetch(B + "/api/spend-caps", { headers: { Authorization: "Bearer " + tok } });
    var res2 = await fetch(B + "/api/wallets", { headers: { Authorization: "Bearer " + tok } });
    if (res1.ok) renderCaps(await res1.json());
    if (res2.ok) renderWallets(await res2.json());
  } catch(e) {}
}

function renderCaps(data) {
  var tb = document.getElementById("caps-table");
  if (!data.caps || !data.caps.length) {
    tb.innerHTML = '<tr><td colspan="6" class="empty-state">No spend caps configured</td></tr>';
    return;
  }
  tb.innerHTML = data.caps.map(function(c) {
    return '<tr>' +
      '<td class="mono">' + fmtWallet(c.wallet) + '</td>' +
      '<td>' + esc(c.label || "--") + '</td>' +
      '<td class="mono">' + (c.daily_limit_usd !== null ? fmt$(c.daily_limit_usd) : '<span class="dim">unlimited</span>') + '</td>' +
      '<td class="mono">' + (c.monthly_limit_usd !== null ? fmt$(c.monthly_limit_usd) : '<span class="dim">unlimited</span>') + '</td>' +
      '<td class="mono dim">' + fmtTime(c.updated_at) + '</td>' +
      '<td><button class="btn-danger btn-delete-cap" data-wallet="' + esc(c.wallet) + '">Remove</button></td></tr>';
  }).join("");
  tb.querySelectorAll(".btn-delete-cap").forEach(function(btn) {
    btn.addEventListener("click", function() { deleteCap(btn.dataset.wallet); });
  });
}

function renderWallets(data) {
  var tb = document.getElementById("wallets-table");
  if (!data.wallets || !data.wallets.length) {
    tb.innerHTML = '<tr><td colspan="7" class="empty-state">No wallet activity recorded</td></tr>';
    return;
  }
  tb.innerHTML = data.wallets.map(function(w) {
    var capBadge = w.cap ? '<span class="badge badge-ok">capped</span>' : '<span class="badge badge-free">uncapped</span>';
    return '<tr>' +
      '<td class="mono">' + fmtWallet(w.wallet) + '</td>' +
      '<td class="mono green">' + fmt$(w.spend_7d) + '</td>' +
      '<td class="mono green">' + fmt$(w.spend_30d) + '</td>' +
      '<td class="mono">' + fmt$(w.total_spent) + '</td>' +
      '<td class="mono">' + fmtN(w.request_count) + '</td>' +
      '<td class="mono dim">' + fmtTime(w.last_seen) + '</td>' +
      '<td>' + capBadge + '</td></tr>';
  }).join("");
}

document.getElementById("cap-save").addEventListener("click", async function() {
  var tok = gt(); if (!tok) return;
  var msg = document.getElementById("cap-msg");
  var wallet = document.getElementById("cap-wallet").value.trim();
  var label = document.getElementById("cap-label").value.trim() || null;
  var daily = document.getElementById("cap-daily").value;
  var monthly = document.getElementById("cap-monthly").value;

  if (!wallet || !/^0x[0-9a-fA-F]{40}$/.test(wallet)) {
    msg.className = "cap-msg err";
    msg.textContent = "Enter a valid 0x wallet address (42 chars)";
    return;
  }

  var body = {
    wallet: wallet,
    label: label,
    daily_limit_usd: daily ? parseFloat(daily) : null,
    monthly_limit_usd: monthly ? parseFloat(monthly) : null
  };

  try {
    var res = await fetch(B + "/api/spend-caps", {
      method: "PUT",
      headers: { Authorization: "Bearer " + tok, "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });
    var data = await res.json();
    if (res.ok) {
      msg.className = "cap-msg ok";
      msg.textContent = "Spend cap saved for " + wallet.substring(0, 8) + "...";
      document.getElementById("cap-wallet").value = "";
      document.getElementById("cap-label").value = "";
      document.getElementById("cap-daily").value = "";
      document.getElementById("cap-monthly").value = "";
      loadCaps();
    } else {
      msg.className = "cap-msg err";
      msg.textContent = data.error || "Failed to save";
    }
  } catch(e) {
    msg.className = "cap-msg err";
    msg.textContent = "Network error";
  }
});

async function deleteCap(wallet) {
  var tok = gt(); if (!tok) return;
  if (!confirm("Remove spend cap for " + wallet.substring(0, 10) + "...?")) return;
  try {
    var res = await fetch(B + "/api/spend-caps/" + encodeURIComponent(wallet), {
      method: "DELETE",
      headers: { Authorization: "Bearer " + tok }
    });
    var data = await res.json();
    if (data.ok) loadCaps();
  } catch(e) {}
}
