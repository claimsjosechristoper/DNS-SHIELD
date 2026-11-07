/**
 * DNS Security Gateway Dashboard Frontend Logic.
 * Real-time WebSocket telemetry, deterministic ALLOW/BLOCK visual states,
 * and authenticated policy administration.
 */

const API_BASE = window.location.origin;
let apiKey = localStorage.getItem("dns_gateway_admin_key") || "";

// Navigation State
let currentTab = "tab-overview";
let logsOffset = 0;
const logsLimit = 50;
let debounceTimer = null;

// Chart Instances & Telemetry Aggregation State
let chartTraffic = null;
let chartDecisions = null;
const WINDOW_SECONDS = 60;
// One-second timestamp buckets: epochSecond -> { allowed: number, blocked: number }
const secondBuckets = new Map();

// Connection State: "CONNECTING", "CONNECTED", "RECONNECTING", "DISCONNECTED"
let wsConnectionState = "DISCONNECTED";
let lastReceivedEventTime = null;
let reconnectTimer = null;
let chartTicker = null;

// WebSocket Reference
let ws = null;

// Initialize on DOM Load
document.addEventListener("DOMContentLoaded", () => {
    updateAuthIndicator();
    initCharts();
    loadDashboardStats();
    connectWebSocket();

    // Start 1-second rolling chart ticker (renders at most once per second)
    if (!chartTicker) {
        chartTicker = setInterval(renderTrafficChart, 1000);
    }

    // Auto-refresh stats every 4 seconds
    setInterval(loadDashboardStats, 4000);
});

// Authentication Handling
function getAuthHeaders() {
    const headers = { "Content-Type": "application/json" };
    if (apiKey) {
        headers["X-API-Key"] = apiKey;
    }
    return headers;
}

function updateAuthIndicator() {
    const el = document.getElementById("auth-status-indicator");
    if (apiKey) {
        el.textContent = "🔑 Key Active";
        el.style.color = "var(--decision-allow)";
    } else {
        el.textContent = "🔑 Set API Key";
        el.style.color = "var(--text-muted)";
    }
}

function openKeyModal() {
    document.getElementById("input-api-key").value = apiKey;
    document.getElementById("modal-api-key").style.display = "flex";
}

async function saveApiKey(e) {
    e.preventDefault();
    const val = document.getElementById("input-api-key").value.trim();
    if (!val) {
        return;
    }

    try {
        const resp = await fetch(`${API_BASE}/api/auth/login`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ api_key: val })
        });
        const result = await resp.json();
        if (!resp.ok) {
            throw new Error(result.detail || "Invalid administrative API key.");
        }

        apiKey = val;
        localStorage.setItem("dns_gateway_admin_key", apiKey);
        updateAuthIndicator();
        closeModals();
        alert("Administrative API Key authorized.");
        refreshActiveTabData();
    } catch (error) {
        apiKey = "";
        localStorage.removeItem("dns_gateway_admin_key");
        updateAuthIndicator();
        alert(`Authorization failed: ${error.message}`);
    }
}

// Tab Switching
function switchTab(tabId) {
    currentTab = tabId;
    document.querySelectorAll(".tab-content").forEach(el => el.style.display = "none");
    document.querySelectorAll(".tab-btn").forEach(btn => btn.classList.remove("active"));

    const target = document.getElementById(tabId);
    if (target) target.style.display = "block";

    const activeBtn = Array.from(document.querySelectorAll(".tab-btn")).find(btn =>
        btn.getAttribute("onclick") && btn.getAttribute("onclick").includes(tabId)
    );
    if (activeBtn) activeBtn.classList.add("active");

    refreshActiveTabData();
}

function refreshActiveTabData() {
    if (currentTab === "tab-overview") loadDashboardStats();
    else if (currentTab === "tab-logs") loadLogs();
    else if (currentTab === "tab-rules") loadCustomRules();
    else if (currentTab === "tab-allowlist") loadAllowlist();
    else if (currentTab === "tab-blocklists") loadBlocklists();
    else if (currentTab === "tab-upstreams") loadUpstreams();
    else if (currentTab === "tab-settings") loadSettingsAndRecordTypes();
    else if (currentTab === "tab-audit") loadAuditLogs();
}

// Chart Initializations
class LocalChart {
    constructor(canvas, config) {
        this.canvas = canvas;
        this.type = config.type;
        this.data = config.data;
        this.resizeObserver = new ResizeObserver(() => this.update());
        this.resizeObserver.observe(canvas.parentElement || canvas);
        this.update();
    }

    update() {
        const rect = (this.canvas.parentElement || this.canvas).getBoundingClientRect();
        const width = Math.max(1, Math.floor(rect.width));
        const height = Math.max(1, Math.floor(rect.height));
        const ratio = window.devicePixelRatio || 1;
        this.canvas.width = width * ratio;
        this.canvas.height = height * ratio;
        const ctx = this.canvas.getContext("2d");
        ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
        ctx.clearRect(0, 0, width, height);
        if (this.type === "doughnut") {
            this.drawDoughnut(ctx, width, height);
        } else {
            this.drawLine(ctx, width, height);
        }
    }

    drawLine(ctx, width, height) {
        const left = 42;
        const right = 12;
        const top = 12;
        const bottom = 28;
        const plotWidth = Math.max(1, width - left - right);
        const plotHeight = Math.max(1, height - top - bottom);
        const datasets = this.data.datasets || [];
        const values = datasets.flatMap(dataset =>
            dataset.data.filter(value => typeof value === "number" && Number.isFinite(value))
        );
        const maxValue = Math.max(1, ...values);

        ctx.font = "10px Inter, sans-serif";
        ctx.strokeStyle = "rgba(51, 65, 85, 0.25)";
        ctx.fillStyle = "#64748b";
        ctx.lineWidth = 1;
        for (let i = 0; i <= 4; i += 1) {
            const y = top + (plotHeight * i / 4);
            ctx.beginPath();
            ctx.moveTo(left, y);
            ctx.lineTo(width - right, y);
            ctx.stroke();
            ctx.fillText(String(Math.round(maxValue * (4 - i) / 4)), 4, y + 3);
        }

        datasets.forEach(dataset => {
            const points = dataset.data;
            if (!points.length) return;
            ctx.strokeStyle = dataset.borderColor || "#3b82f6";
            ctx.lineWidth = 2;
            ctx.beginPath();
            let started = false;
            points.forEach((value, index) => {
                if (typeof value !== "number" || !Number.isFinite(value)) {
                    started = false;
                    return;
                }
                const x = left + (plotWidth * index / Math.max(1, points.length - 1));
                const y = top + plotHeight - (value / maxValue * plotHeight);
                if (!started) {
                    ctx.moveTo(x, y);
                    started = true;
                } else {
                    ctx.lineTo(x, y);
                }
            });
            ctx.stroke();
        });
    }

    drawDoughnut(ctx, width, height) {
        const values = this.data.datasets[0].data.map(value => Number(value) || 0);
        const total = values.reduce((sum, value) => sum + value, 0);
        const radius = Math.max(20, Math.min(width, height) * 0.34);
        const centerX = width / 2;
        const centerY = height / 2;
        const colors = this.data.datasets[0].backgroundColor;
        let angle = -Math.PI / 2;

        if (total > 0) {
            values.forEach((value, index) => {
                const nextAngle = angle + (value / total) * Math.PI * 2;
                ctx.beginPath();
                ctx.arc(centerX, centerY, radius, angle, nextAngle);
                ctx.strokeStyle = colors[index];
                ctx.lineWidth = radius * 0.35;
                ctx.stroke();
                angle = nextAngle;
            });
        } else {
            ctx.beginPath();
            ctx.arc(centerX, centerY, radius, 0, Math.PI * 2);
            ctx.strokeStyle = "#cbd5e1";
            ctx.lineWidth = radius * 0.35;
            ctx.stroke();
        }

        ctx.font = "600 12px Inter, sans-serif";
        ctx.fillStyle = "#64748b";
        ctx.textAlign = "center";
        ctx.fillText(total.toLocaleString(), centerX, centerY + 4);
        ctx.textAlign = "start";
    }
}

function initCharts() {
    const ctxTraffic = document.getElementById("chart-traffic");
    if (ctxTraffic && !chartTraffic) {
        chartTraffic = new LocalChart(ctxTraffic, {
            type: "line",
            data: {
                labels: [],
                datasets: [
                    {
                        label: "ALLOWED",
                        data: [],
                        borderColor: "#10b981",
                        backgroundColor: "rgba(16, 185, 129, 0.15)",
                        fill: true,
                        tension: 0.25,
                        borderWidth: 2,
                        pointRadius: 1,
                        spanGaps: false
                    },
                    {
                        label: "BLOCKED",
                        data: [],
                        borderColor: "#ef4444",
                        backgroundColor: "rgba(239, 68, 68, 0.15)",
                        fill: true,
                        tension: 0.25,
                        borderWidth: 2,
                        pointRadius: 1,
                        spanGaps: false
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: false,
                plugins: {
                    legend: {
                        position: "top",
                        labels: { color: "#94a3b8", boxWidth: 12, font: { size: 11 } }
                    },
                    tooltip: {
                        mode: "index",
                        intersect: false
                    }
                },
                scales: {
                    x: {
                        ticks: {
                            color: "#64748b",
                            maxTicksLimit: 10,
                            font: { size: 10 }
                        },
                        grid: { color: "rgba(51,65,85,0.2)" }
                    },
                    y: {
                        beginAtZero: true,
                        ticks: {
                            color: "#64748b",
                            precision: 0,
                            font: { size: 10 }
                        },
                        grid: { color: "rgba(51,65,85,0.2)" },
                        title: {
                            display: true,
                            text: "Queries per second",
                            color: "#94a3b8",
                            font: { size: 11, weight: "bold" }
                        }
                    }
                }
            }
        });
    }

    const ctxDecisions = document.getElementById("chart-decisions");
    if (ctxDecisions && !chartDecisions) {
        chartDecisions = new LocalChart(ctxDecisions, {
            type: "doughnut",
            data: {
                labels: ["ALLOWED", "BLOCKED"],
                datasets: [{
                    data: [0, 0],
                    backgroundColor: ["#10b981", "#ef4444"],
                    borderColor: "#070a13",
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { position: "bottom", labels: { color: "#94a3b8" } }
                },
                cutout: "70%"
            }
        });
    }
}

// Render rolling 60-second window aggregated in 1-second buckets
function renderTrafficChart() {
    if (!chartTraffic) return;

    const nowSec = Math.floor(Date.now() / 1000);
    const labels = [];
    const allowedData = [];
    const blockedData = [];

    // Prune buckets older than window + 10s
    const pruneThreshold = nowSec - WINDOW_SECONDS - 10;
    for (const [secKey] of secondBuckets) {
        if (secKey < pruneThreshold) {
            secondBuckets.delete(secKey);
        }
    }

    const isConnected = (wsConnectionState === "CONNECTED");

    for (let i = WINDOW_SECONDS - 1; i >= 0; i--) {
        const targetSec = nowSec - i;
        const d = new Date(targetSec * 1000);
        const timeLabel = d.toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
        labels.push(timeLabel);

        if (secondBuckets.has(targetSec)) {
            const b = secondBuckets.get(targetSec);
            allowedData.push(b.allowed);
            blockedData.push(b.blocked);
        } else {
            // Connected with zero traffic -> 0
            // Disconnected / telemetry unavailable -> null (creates gap, no fake zero)
            if (isConnected) {
                allowedData.push(0);
                blockedData.push(0);
            } else {
                allowedData.push(null);
                blockedData.push(null);
            }
        }
    }

    chartTraffic.data.labels = labels;
    chartTraffic.data.datasets[0].data = allowedData;
    chartTraffic.data.datasets[1].data = blockedData;
    chartTraffic.update("none");
}

// Dashboard Overview Data
async function loadDashboardStats() {
    try {
        const resp = await fetch(`${API_BASE}/api/status`);
        if (!resp.ok) return;
        const data = await resp.json();

        document.getElementById("stat-total-queries").textContent = data.total_requests.toLocaleString();
        document.getElementById("stat-allowed-queries").textContent = data.allowed_requests.toLocaleString();
        document.getElementById("stat-blocked-queries").textContent = data.blocked_requests.toLocaleString();
        document.getElementById("stat-blocklist-entries").textContent = data.total_blocklist_rules.toLocaleString();
        document.getElementById("stat-resolver-health").textContent = data.resolver_health;

        // Fetch deep statistics
        const statsResp = await fetch(`${API_BASE}/api/dns/statistics`);
        if (statsResp.ok) {
            const stats = await statsResp.json();
            updateTopBlockedTable(stats.top_blocked_domains || []);
            updateDecisionsChart(stats.allowed_queries, stats.blocked_queries);
        }
    } catch (e) {
        console.error("Failed to load dashboard stats:", e);
    }
}

function updateTopBlockedTable(domains) {
    const tbody = document.getElementById("top-blocked-table-body");
    if (!tbody) return;
    if (domains.length === 0) {
        tbody.innerHTML = `<tr><td colspan="3" style="text-align:center; color: var(--text-muted);">No blocked requests recorded yet</td></tr>`;
        return;
    }

    tbody.innerHTML = domains.map(d => `
        <tr>
            <td style="font-family: var(--font-mono); color: #fca5a5; font-weight:600;">${escapeHtml(d.domain)}</td>
            <td style="font-family: var(--font-mono); font-weight:700;">${d.count}</td>
            <td><span class="badge-type">${escapeHtml(d.decision_type || d.matched_rule || 'POLICY')}</span></td>
        </tr>
    `).join("");
}

function updateDecisionsChart(allowed, blocked) {
    if (chartDecisions) {
        chartDecisions.data.datasets[0].data = [allowed || 0, blocked || 0];
        chartDecisions.update("none");
    }
}

// Connection State Management & UI Updates
function setConnectionState(state) {
    wsConnectionState = state;
    updateConnectionStatusUI();
}

function updateConnectionStatusUI() {
    const wsStatusText = document.getElementById("ws-status-text");
    const wsPulseDot = document.getElementById("ws-pulse-dot");
    const gatewayStatusText = document.getElementById("gateway-status-text");
    const systemStatus = document.getElementById("system-status");

    let statusLabel = "";
    let isOnline = false;

    switch (wsConnectionState) {
        case "CONNECTING":
            statusLabel = "Connecting...";
            if (wsPulseDot) wsPulseDot.className = "pulse-dot pulse-amber";
            break;
        case "CONNECTED":
            isOnline = true;
            if (lastReceivedEventTime) {
                const timeStr = lastReceivedEventTime.toLocaleTimeString([], { hour12: false });
                statusLabel = `Connected — Last event: ${timeStr}`;
            } else {
                statusLabel = "Connected — waiting for DNS traffic";
            }
            if (wsPulseDot) wsPulseDot.className = "pulse-dot";
            break;
        case "RECONNECTING":
            statusLabel = "Reconnecting...";
            if (wsPulseDot) wsPulseDot.className = "pulse-dot pulse-amber";
            break;
        case "DISCONNECTED":
        default:
            statusLabel = "Disconnected";
            if (wsPulseDot) wsPulseDot.className = "pulse-dot pulse-red";
            break;
    }

    if (wsStatusText) {
        wsStatusText.textContent = statusLabel;
    }

    if (gatewayStatusText) {
        gatewayStatusText.textContent = isOnline ? "GATEWAY ONLINE" : "OFFLINE / RECONNECTING";
    }
    if (systemStatus) {
        if (isOnline) {
            systemStatus.classList.remove("status-offline");
        } else {
            systemStatus.classList.add("status-offline");
        }
    }
}

// Real-Time WebSocket Connection Lifecycle
function connectWebSocket() {
    if (reconnectTimer) {
        clearTimeout(reconnectTimer);
        reconnectTimer = null;
    }

    if (ws) {
        try {
            ws.onopen = null;
            ws.onmessage = null;
            ws.onclose = null;
            ws.onerror = null;
            ws.close();
        } catch (e) {}
        ws = null;
    }

    setConnectionState("CONNECTING");

    const wsProto = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = `${wsProto}//${window.location.host}/ws/live`;

    try {
        ws = new WebSocket(wsUrl);
    } catch (err) {
        console.error("Failed to construct WebSocket:", err);
        scheduleReconnect();
        return;
    }

    ws.onopen = () => {
        setConnectionState("CONNECTED");
    };

    ws.onmessage = (event) => {
        try {
            const payload = JSON.parse(event.data);
            if (payload.type === "DNS_EVENT" && payload.data) {
                handleLiveDNSEvent(payload.data);
            }
        } catch (e) {
            console.error("WS message parse error:", e);
        }
    };

    ws.onclose = () => {
        setConnectionState("DISCONNECTED");
        scheduleReconnect();
    };

    ws.onerror = (e) => {
        console.warn("WS error encountered:", e);
    };
}

function scheduleReconnect() {
    if (reconnectTimer) return;
    setConnectionState("RECONNECTING");
    reconnectTimer = setTimeout(() => {
        reconnectTimer = null;
        connectWebSocket();
    }, 2500);
}

function handleLiveDNSEvent(event) {
    if (!event || typeof event !== "object") {
        console.warn("Dropped malformed live DNS event:", event);
        return;
    }

    const rawDecision = (event.decision || "").toUpperCase();
    let isAllow = false;
    let isBlock = false;

    if (rawDecision === "ALLOW" || rawDecision === "ALLOWED") {
        isAllow = true;
    } else if (rawDecision === "BLOCK" || rawDecision === "BLOCKED" || rawDecision === "REFUSED") {
        isBlock = true;
    } else {
        console.warn(`Unknown DNS decision type '${event.decision}', recorded in blocked series`, event);
        isBlock = true;
    }

    // 1. Record event in 1-second aggregation bucket
    let sec = null;
    if (typeof event.timestamp === "number" && !isNaN(event.timestamp) && event.timestamp > 0) {
        sec = Math.floor(event.timestamp);
    } else {
        sec = Math.floor(Date.now() / 1000);
    }

    if (!secondBuckets.has(sec)) {
        secondBuckets.set(sec, { allowed: 0, blocked: 0 });
    }
    const bucket = secondBuckets.get(sec);
    if (isAllow) {
        bucket.allowed += 1;
    } else {
        bucket.blocked += 1;
    }

    lastReceivedEventTime = new Date();
    updateConnectionStatusUI();

    // 2. Add to live streaming table on Overview
    const streamTbody = document.getElementById("live-stream-table-body");
    if (streamTbody) {
        const timeStr = new Date(sec * 1000).toLocaleTimeString([], { hour12: false });
        const badgeClass = isAllow ? "badge-allow" : "badge-block";
        const displayDecision = isAllow ? "ALLOW" : "BLOCK";

        const row = document.createElement("tr");
        row.innerHTML = `
            <td style="font-family: var(--font-mono); font-size: 0.75rem; color: var(--text-dim);">${timeStr}</td>
            <td style="font-family: var(--font-mono); font-size: 0.8rem;">${escapeHtml(event.client_ip || "127.0.0.1")}</td>
            <td style="font-family: var(--font-mono); font-weight:600; color: ${isAllow ? '#a7f3d0' : '#fca5a5'};">${escapeHtml(event.domain || "-")}</td>
            <td><span class="badge-decision ${badgeClass}">${displayDecision}</span></td>
            <td style="font-size: 0.78rem; color: var(--text-muted);">${escapeHtml(event.reason || event.matched_rule || "-")}</td>
        `;

        streamTbody.insertBefore(row, streamTbody.firstChild);
        if (streamTbody.children.length > 30) {
            streamTbody.removeChild(streamTbody.lastChild);
        }
    }
}

// Tab 2: DNS Query Logs Deep Explorer
async function loadLogs() {
    const decision = document.getElementById("filter-decision").value;
    const type = document.getElementById("filter-type").value;
    const search = document.getElementById("filter-search").value.trim();
    const client = document.getElementById("filter-client").value.trim();
    const qtype = document.getElementById("filter-qtype").value.trim();

    let url = `${API_BASE}/api/dns/logs?limit=${logsLimit}&offset=${logsOffset}`;
    if (decision) url += `&decision=${encodeURIComponent(decision)}`;
    if (type) url += `&decision_type=${encodeURIComponent(type)}`;
    if (search) url += `&search=${encodeURIComponent(search)}`;
    if (client) url += `&client_ip=${encodeURIComponent(client)}`;
    if (qtype) url += `&qtype=${encodeURIComponent(qtype)}`;

    try {
        const resp = await fetch(url);
        const data = await resp.json();
        renderLogsTable(data.logs || []);
        document.getElementById("logs-pagination-info").textContent =
            `Showing ${data.logs.length} of ${data.total} recorded logs`;

        document.getElementById("btn-prev-page").disabled = logsOffset === 0;
        document.getElementById("btn-next-page").disabled = logsOffset + logsLimit >= data.total;
    } catch (e) {
        console.error("Failed to load logs:", e);
    }
}

function renderLogsTable(logs) {
    const tbody = document.getElementById("logs-table-body");
    if (!tbody) return;
    if (logs.length === 0) {
        tbody.innerHTML = `<tr><td colspan="10" style="text-align:center; color: var(--text-muted);">No DNS query records matched filter criteria</td></tr>`;
        return;
    }

    tbody.innerHTML = logs.map(l => {
        const dateStr = new Date(l.timestamp * 1000).toLocaleString();
        const isAllow = l.decision === "ALLOW";
        const badge = isAllow ? `<span class="badge-decision badge-allow">ALLOW</span>` : `<span class="badge-decision badge-block">BLOCK</span>`;
        const logJson = JSON.stringify(l).replace(/'/g, "&#39;");

        return `
            <tr>
                <td style="font-family: var(--font-mono); font-size: 0.75rem;">${dateStr}</td>
                <td style="font-family: var(--font-mono);">${escapeHtml(l.client_ip)}</td>
                <td style="font-family: var(--font-mono); font-weight:600; color: ${isAllow ? '#6ee7b7' : '#f87171'};">${escapeHtml(l.domain)}</td>
                <td style="font-family: var(--font-mono);"><span class="badge-type">${escapeHtml(l.qtype)}</span></td>
                <td>${badge}</td>
                <td style="font-size: 0.78rem;">${escapeHtml(l.matched_rule || '-')}</td>
                <td style="font-size: 0.78rem; color: var(--text-muted);">${escapeHtml(l.reason || '-')}</td>
                <td style="font-family: var(--font-mono); font-size: 0.75rem;">${escapeHtml(l.rcode)}</td>
                <td style="font-family: var(--font-mono); font-size: 0.75rem;">${l.response_time_ms}ms (${escapeHtml(l.upstream_server || '-')})</td>
                <td>
                    <button class="btn btn-sm" onclick='inspectLog(${logJson})'>Inspect</button>
                </td>
            </tr>
        `;
    }).join("");
}

function debounceLogs() {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => {
        logsOffset = 0;
        loadLogs();
    }, 300);
}

function prevLogsPage() {
    if (logsOffset >= logsLimit) {
        logsOffset -= logsLimit;
        loadLogs();
    }
}

function nextLogsPage() {
    logsOffset += logsLimit;
    loadLogs();
}

function inspectLog(logObj) {
    document.getElementById("log-inspect-json").textContent = JSON.stringify(logObj, null, 2);
    document.getElementById("modal-log-inspect").style.display = "flex";
}

function exportLogsCSV() {
    window.open(`${API_BASE}/api/dns/logs?limit=1000&offset=0`, "_blank");
}

// Tab 3: Custom Blocking Rules
async function loadCustomRules() {
    try {
        const resp = await fetch(`${API_BASE}/api/rules/custom`, { headers: getAuthHeaders() });
        if (resp.status === 401) {
            promptAuth();
            return;
        }
        const rules = await resp.json();
        const tbody = document.getElementById("custom-rules-table-body");
        if (rules.length === 0) {
            tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; color: var(--text-muted);">No custom rules defined yet</td></tr>`;
            return;
        }

        tbody.innerHTML = rules.map(r => `
            <tr>
                <td style="font-family: var(--font-mono); font-weight:600; color: #fca5a5;">${escapeHtml(r.domain)}</td>
                <td><span class="badge-type">${r.rule_type === 'exact' ? 'Exact Match' : 'Domain & Subdomains (*)'}</span></td>
                <td>${r.enabled ? '<span class="badge-decision badge-block">ACTIVE BLOCK</span>' : '<span class="badge-type">DISABLED</span>'}</td>
                <td style="color: var(--text-muted);">${escapeHtml(r.reason || '-')}</td>
                <td style="font-size: 0.75rem;">${new Date(r.created_at * 1000).toLocaleDateString()}</td>
                <td style="display: flex; gap: 0.4rem;">
                    <button class="btn btn-sm" onclick="toggleCustomRule(${r.id})">${r.enabled ? 'Disable' : 'Enable'}</button>
                    <button class="btn btn-sm btn-danger" onclick="deleteCustomRule(${r.id})">Delete</button>
                </td>
            </tr>
        `).join("");
    } catch (e) {
        console.error("Failed to load custom rules:", e);
    }
}

function openAddRuleModal() {
    document.getElementById("modal-add-rule").style.display = "flex";
}

async function submitAddRule(e) {
    e.preventDefault();
    const domain = document.getElementById("new-rule-domain").value.trim();
    const rule_type = document.getElementById("new-rule-type").value;
    const reason = document.getElementById("new-rule-reason").value.trim();

    try {
        const resp = await fetch(`${API_BASE}/api/rules/custom`, {
            method: "POST",
            headers: getAuthHeaders(),
            body: JSON.stringify({ domain, rule_type, reason })
        });
        if (!resp.ok) {
            const err = await resp.json();
            alert(`Failed to add rule: ${err.detail || "Server error"}`);
            return;
        }
        closeModals();
        loadCustomRules();
    } catch (e) {
        alert(`Error: ${e.message}`);
    }
}

async function toggleCustomRule(id) {
    await fetch(`${API_BASE}/api/rules/custom/${id}/toggle`, { method: "PUT", headers: getAuthHeaders() });
    loadCustomRules();
}

async function deleteCustomRule(id) {
    if (!confirm("Delete this custom blocking rule?")) return;
    await fetch(`${API_BASE}/api/rules/custom/${id}`, { method: "DELETE", headers: getAuthHeaders() });
    loadCustomRules();
}

// Tab 4: Allowlist Entries
async function loadAllowlist() {
    try {
        const resp = await fetch(`${API_BASE}/api/rules/allowlist`, { headers: getAuthHeaders() });
        if (resp.status === 401) {
            promptAuth();
            return;
        }
        const rules = await resp.json();
        const tbody = document.getElementById("allowlist-table-body");
        if (rules.length === 0) {
            tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; color: var(--text-muted);">No allowlist exemptions configured</td></tr>`;
            return;
        }

        tbody.innerHTML = rules.map(r => `
            <tr>
                <td style="font-family: var(--font-mono); font-weight:600; color: #a7f3d0;">${escapeHtml(r.domain)}</td>
                <td><span class="badge-type">${r.rule_type === 'exact' ? 'Exact Match' : 'Domain & Subdomains (*)'}</span></td>
                <td>${r.enabled ? '<span class="badge-decision badge-allow">ACTIVE EXEMPTION</span>' : '<span class="badge-type">DISABLED</span>'}</td>
                <td style="color: var(--text-muted);">${escapeHtml(r.reason || '-')}</td>
                <td style="font-size: 0.75rem;">${new Date(r.created_at * 1000).toLocaleDateString()}</td>
                <td style="display: flex; gap: 0.4rem;">
                    <button class="btn btn-sm" onclick="toggleAllowlist(${r.id})">${r.enabled ? 'Disable' : 'Enable'}</button>
                    <button class="btn btn-sm btn-danger" onclick="deleteAllowlist(${r.id})">Delete</button>
                </td>
            </tr>
        `).join("");
    } catch (e) {
        console.error("Failed to load allowlist:", e);
    }
}

function openAddAllowlistModal() {
    document.getElementById("modal-add-allowlist").style.display = "flex";
}

async function submitAddAllowlist(e) {
    e.preventDefault();
    const domain = document.getElementById("new-allow-domain").value.trim();
    const rule_type = document.getElementById("new-allow-type").value;
    const reason = document.getElementById("new-allow-reason").value.trim();

    try {
        const resp = await fetch(`${API_BASE}/api/rules/allowlist`, {
            method: "POST",
            headers: getAuthHeaders(),
            body: JSON.stringify({ domain, rule_type, reason })
        });
        if (!resp.ok) {
            const err = await resp.json();
            alert(`Failed: ${err.detail || "Server error"}`);
            return;
        }
        closeModals();
        loadAllowlist();
    } catch (e) {
        alert(`Error: ${e.message}`);
    }
}

async function toggleAllowlist(id) {
    await fetch(`${API_BASE}/api/rules/allowlist/${id}/toggle`, { method: "PUT", headers: getAuthHeaders() });
    loadAllowlist();
}

async function deleteAllowlist(id) {
    if (!confirm("Remove this allowlist entry?")) return;
    await fetch(`${API_BASE}/api/rules/allowlist/${id}`, { method: "DELETE", headers: getAuthHeaders() });
    loadAllowlist();
}

// Tab 5: Threat Blocklists
async function loadBlocklists() {
    try {
        const resp = await fetch(`${API_BASE}/api/blocklists`, { headers: getAuthHeaders() });
        if (resp.status === 401) {
            promptAuth();
            return;
        }
        const lists = await resp.json();
        const tbody = document.getElementById("blocklists-table-body");

        tbody.innerHTML = lists.map(b => {
            const isOk = b.last_status === "OK";
            const statusBadge = isOk
                ? `<span class="badge-decision badge-allow">OK</span>`
                : `<span class="badge-decision badge-block" title="${escapeHtml(b.last_error || '')}">FAIL (RETAINED)</span>`;

            return `
                <tr>
                    <td style="font-weight:700;">${escapeHtml(b.name)}</td>
                    <td><span class="badge-type">${escapeHtml(b.category.toUpperCase())}</span></td>
                    <td style="font-family: var(--font-mono); font-size: 0.75rem; color: var(--text-dim);">${escapeHtml(b.url_or_path)}</td>
                    <td style="font-family: var(--font-mono); font-weight:700;">${b.entry_count.toLocaleString()}</td>
                    <td>${statusBadge}</td>
                    <td style="font-size: 0.75rem;">${b.last_updated ? new Date(b.last_updated * 1000).toLocaleString() : 'Never'}</td>
                    <td style="display: flex; gap: 0.4rem;">
                        <button class="btn btn-sm btn-cyan" onclick="syncBlocklist(${b.id})">Sync Now</button>
                        <button class="btn btn-sm btn-danger" onclick="deleteBlocklist(${b.id})">Remove</button>
                    </td>
                </tr>
            `;
        }).join("");
    } catch (e) {
        console.error("Failed to load blocklists:", e);
    }
}

async function syncBlocklist(id) {
    try {
        const resp = await fetch(`${API_BASE}/api/blocklists/${id}/sync`, { method: "POST", headers: getAuthHeaders() });
        const res = await resp.json();
        alert(res.message || res.detail || "Sync completed");
        loadBlocklists();
        loadDashboardStats();
    } catch (e) {
        alert(`Sync error: ${e.message}`);
    }
}

async function syncAllBlocklists() {
    try {
        const resp = await fetch(`${API_BASE}/api/blocklists/sync-all`, { method: "POST", headers: getAuthHeaders() });
        const res = await resp.json();
        alert("All feeds synced successfully.");
        loadBlocklists();
        loadDashboardStats();
    } catch (e) {
        alert(`Sync error: ${e.message}`);
    }
}

function openAddBlocklistModal() {
    document.getElementById("modal-add-blocklist").style.display = "flex";
}

async function submitAddBlocklist(e) {
    e.preventDefault();
    const name = document.getElementById("new-feed-name").value.trim();
    const category = document.getElementById("new-feed-category").value;
    const url_or_path = document.getElementById("new-feed-path").value.trim();

    try {
        const resp = await fetch(`${API_BASE}/api/blocklists`, {
            method: "POST",
            headers: getAuthHeaders(),
            body: JSON.stringify({ name, category, url_or_path })
        });
        if (!resp.ok) {
            const err = await resp.json();
            alert(`Failed: ${err.detail}`);
            return;
        }
        closeModals();
        loadBlocklists();
        loadDashboardStats();
    } catch (e) {
        alert(`Error: ${e.message}`);
    }
}

async function deleteBlocklist(id) {
    if (!confirm("Delete this blocklist source?")) return;
    await fetch(`${API_BASE}/api/blocklists/${id}`, { method: "DELETE", headers: getAuthHeaders() });
    loadBlocklists();
    loadDashboardStats();
}

// Tab 6: Upstream Resolvers
async function loadUpstreams() {
    try {
        const resp = await fetch(`${API_BASE}/api/upstreams`, { headers: getAuthHeaders() });
        if (resp.status === 401) {
            promptAuth();
            return;
        }
        const upstreams = await resp.json();
        const tbody = document.getElementById("upstreams-table-body");

        tbody.innerHTML = upstreams.map(u => {
            const isHealthy = u.health_status === "HEALTHY";
            const badge = isHealthy
                ? `<span class="badge-decision badge-allow">HEALTHY</span>`
                : `<span class="badge-decision badge-block">DEGRADED</span>`;

            return `
                <tr>
                    <td style="font-family: var(--font-mono); font-weight:700;">${escapeHtml(u.address)}</td>
                    <td style="font-family: var(--font-mono);">${u.port}</td>
                    <td><span class="badge-type">${escapeHtml(u.protocol)}</span></td>
                    <td style="font-family: var(--font-mono);">${u.priority}</td>
                    <td>${badge}</td>
                    <td style="font-family: var(--font-mono);">${u.last_latency_ms ? u.last_latency_ms + 'ms' : '-'}</td>
                    <td style="display: flex; gap: 0.4rem;">
                        <button class="btn btn-sm btn-cyan" onclick="probeUpstream('${u.address}', ${u.port}, '${u.protocol}')">Test Probe</button>
                        <button class="btn btn-sm btn-danger" onclick="deleteUpstream(${u.id})">Delete</button>
                    </td>
                </tr>
            `;
        }).join("");
    } catch (e) {
        console.error("Failed to load upstreams:", e);
    }
}

async function probeUpstream(addr, port, proto) {
    try {
        const resp = await fetch(`${API_BASE}/api/upstreams/test`, {
            method: "POST",
            headers: getAuthHeaders(),
            body: JSON.stringify({ address: addr, port: port, protocol: proto })
        });
        const res = await resp.json();
        if (res.success) {
            alert(`Upstream ${addr}:${port} responded in ${res.latency_ms}ms (RCODE: ${res.rcode})`);
        } else {
            alert(`Probe failed: ${res.error}`);
        }
        loadUpstreams();
    } catch (e) {
        alert(`Probe error: ${e.message}`);
    }
}

function openAddUpstreamModal() {
    document.getElementById("modal-add-upstream").style.display = "flex";
}

async function submitAddUpstream(e) {
    e.preventDefault();
    const address = document.getElementById("new-upstream-addr").value.trim();
    const port = parseInt(document.getElementById("new-upstream-port").value, 10);
    const protocol = document.getElementById("new-upstream-proto").value;
    const priority = parseInt(document.getElementById("new-upstream-prio").value, 10);

    try {
        const resp = await fetch(`${API_BASE}/api/upstreams`, {
            method: "POST",
            headers: getAuthHeaders(),
            body: JSON.stringify({ address, port, protocol, priority })
        });
        if (!resp.ok) {
            const err = await resp.json();
            alert(`Failed: ${err.detail}`);
            return;
        }
        closeModals();
        loadUpstreams();
    } catch (e) {
        alert(`Error: ${e.message}`);
    }
}

async function deleteUpstream(id) {
    if (!confirm("Delete this upstream resolver?")) return;
    await fetch(`${API_BASE}/api/upstreams/${id}`, { method: "DELETE", headers: getAuthHeaders() });
    loadUpstreams();
}

// Tab 7: Settings & Record Types
async function loadSettingsAndRecordTypes() {
    // Record types
    try {
        const resp = await fetch(`${API_BASE}/api/rules/record-types`, { headers: getAuthHeaders() });
        if (resp.status === 401) {
            promptAuth();
            return;
        }
        const types = await resp.json();
        const tbody = document.getElementById("record-types-table-body");
        tbody.innerHTML = types.map(t => `
            <tr>
                <td style="font-family: var(--font-mono); font-weight:700; color: #fca5a5;">${escapeHtml(t.qtype)}</td>
                <td style="color: var(--text-muted); font-size: 0.8rem;">${escapeHtml(t.reason || '-')}</td>
                <td>
                    <button class="btn btn-sm btn-danger" onclick="deleteRecordType(${t.id})">Unblock</button>
                </td>
            </tr>
        `).join("");
    } catch (e) {
        console.error("Failed to load record types:", e);
    }

    // Settings
    try {
        const setResp = await fetch(`${API_BASE}/api/settings`, { headers: getAuthHeaders() });
        if (setResp.ok) {
            const settings = await setResp.json();
            if (settings.blocked_response_rcode) {
                document.getElementById("setting-blocked-rcode").value = settings.blocked_response_rcode;
            }
            if (settings.allowed_networks) {
                document.getElementById("setting-allowed-networks").value = settings.allowed_networks;
            }
            if (settings.log_retention_days) {
                document.getElementById("setting-retention-days").value = settings.log_retention_days;
            }
        }
    } catch (e) {
        console.error("Failed to load settings:", e);
    }
}

function openAddRecordTypeModal() {
    document.getElementById("modal-add-record-type").style.display = "flex";
}

async function submitAddRecordType(e) {
    e.preventDefault();
    const qtype = document.getElementById("new-record-type").value.trim().toUpperCase();
    const reason = document.getElementById("new-record-reason").value.trim();

    try {
        const resp = await fetch(`${API_BASE}/api/rules/record-types`, {
            method: "POST",
            headers: getAuthHeaders(),
            body: JSON.stringify({ qtype, reason })
        });
        if (!resp.ok) {
            const err = await resp.json();
            alert(`Failed: ${err.detail}`);
            return;
        }
        closeModals();
        loadSettingsAndRecordTypes();
    } catch (e) {
        alert(`Error: ${e.message}`);
    }
}

async function deleteRecordType(id) {
    await fetch(`${API_BASE}/api/rules/record-types/${id}`, { method: "DELETE", headers: getAuthHeaders() });
    loadSettingsAndRecordTypes();
}

async function saveGatewaySettings(e) {
    e.preventDefault();
    const blocked_response_rcode = document.getElementById("setting-blocked-rcode").value;
    const allowed_networks = document.getElementById("setting-allowed-networks").value.trim();
    const log_retention_days = parseInt(document.getElementById("setting-retention-days").value, 10);

    try {
        const resp = await fetch(`${API_BASE}/api/settings`, {
            method: "PUT",
            headers: getAuthHeaders(),
            body: JSON.stringify({ blocked_response_rcode, allowed_networks, log_retention_days })
        });
        if (!resp.ok) {
            const err = await resp.json();
            alert(`Failed: ${err.detail}`);
            return;
        }
        alert("Gateway settings saved and applied dynamically.");
    } catch (e) {
        alert(`Error: ${e.message}`);
    }
}

async function triggerLogPrune() {
    if (!confirm("Prune old query logs based on retention threshold?")) return;
    try {
        const resp = await fetch(`${API_BASE}/api/dns/logs/prune`, {
            method: "POST",
            headers: getAuthHeaders(),
            body: JSON.stringify({})
        });
        const res = await resp.json();
        alert(`Prune complete: deleted ${res.deleted_rows} older logs.`);
        loadDashboardStats();
    } catch (e) {
        alert(`Prune error: ${e.message}`);
    }
}

// Tab 8: Audit Trail
async function loadAuditLogs() {
    try {
        const resp = await fetch(`${API_BASE}/api/audit`, { headers: getAuthHeaders() });
        if (resp.status === 401) {
            promptAuth();
            return;
        }
        const logs = await resp.json();
        const tbody = document.getElementById("audit-table-body");
        if (logs.length === 0) {
            tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; color: var(--text-muted);">No audit events recorded</td></tr>`;
            return;
        }

        tbody.innerHTML = logs.map(a => `
            <tr>
                <td style="font-family: var(--font-mono); font-size: 0.75rem;">${new Date(a.timestamp * 1000).toLocaleString()}</td>
                <td style="font-weight:700; color: var(--accent-cyan);">${escapeHtml(a.username)}</td>
                <td style="font-family: var(--font-mono); font-weight:600;"><span class="badge-type">${escapeHtml(a.action)}</span></td>
                <td>${escapeHtml(a.target_type)} ${a.target_id ? '#' + escapeHtml(a.target_id) : ''}</td>
                <td style="font-family: var(--font-mono); font-size: 0.75rem; color: var(--text-muted);">${escapeHtml(JSON.stringify(a.details))}</td>
            </tr>
        `).join("");
    } catch (e) {
        console.error("Failed to load audit logs:", e);
    }
}

// Helper Utilities
function closeModals() {
    document.querySelectorAll(".modal-overlay").forEach(m => m.style.display = "none");
}

function promptAuth() {
    openKeyModal();
}

function escapeHtml(str) {
    if (typeof str !== "string") return str || "";
    return str
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}
