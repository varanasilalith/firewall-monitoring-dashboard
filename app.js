const API_BASE = "https://firewall-monitoring-dashboard.onrender.com";
const $ = (id) => document.getElementById(id);
from fastapi.middleware.cors import CORSMiddleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://YOUR-USERNAME.github.io"
    ],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)
let activityChart = null;
let outcomeChart = null;
let refreshTimer = null;
let toastTimer = null;

function safe(value) {
  return String(value ?? "").replace(/[&<>"']/g, (ch) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[ch]));
}
function number(value) { return new Intl.NumberFormat().format(value || 0); }
function formatTime(value) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? safe(value) : date.toLocaleString(undefined, {
    month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit",
    hour12: false, timeZone: "UTC"
  });
}
function showToast(message, isError = false) {
  const toast = $("toast");
  toast.textContent = message;
  toast.classList.toggle("error", isError);
  toast.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.remove("show"), 3000);
}
async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options
  });
  if (!response.ok) {
    let detail = `Request failed (${response.status})`;
    try { const body = await response.json(); detail = body.detail || detail; } catch {}
    throw new Error(detail);
  }
  return response.json();
}
function drawActivity(timeline) {
  const labels = timeline.map(item => {
    const date = new Date(item.time);
    return Number.isNaN(date.getTime()) ? item.time : date.toLocaleTimeString([], {hour: "2-digit", minute: "2-digit", timeZone: "UTC"});
  });
  const values = timeline.map(item => item.count);
  const data = {
    labels, datasets: [{
      label: "Events", data: values, borderColor: "#51d9ef",
      backgroundColor: (context) => {
        const chart = context.chart;
        const {ctx, chartArea} = chart;
        if (!chartArea) return "rgba(81,217,239,.12)";
        const gradient = ctx.createLinearGradient(0, chartArea.top, 0, chartArea.bottom);
        gradient.addColorStop(0, "rgba(81,217,239,.25)");
        gradient.addColorStop(1, "rgba(81,217,239,0)");
        return gradient;
      },
      fill: true, tension: .35, pointRadius: 3, pointHoverRadius: 5,
      pointBackgroundColor: "#51d9ef", borderWidth: 2
    }]
  };
  const options = {
    responsive: true, maintainAspectRatio: false,
    plugins: {legend: {display: false}, tooltip: {backgroundColor: "#0a1321", borderColor: "#2a3b50", borderWidth: 1, titleColor: "#dce8f8", bodyColor: "#9eacc0"}},
    scales: {
      x: {grid: {display: false}, ticks: {color: "#71839c", maxTicksLimit: 7, font: {size: 9}}, border: {display: false}},
      y: {beginAtZero: true, ticks: {precision: 0, color: "#71839c", font: {size: 9}}, grid: {color: "rgba(119,143,174,.12)"}, border: {display: false}}
    }
  };
  if (activityChart) { activityChart.data = data; activityChart.update(); }
  else activityChart = new Chart($("activity-chart"), {type: "line", data, options});
}
function drawOutcomes(allowed, blocked) {
  const data = {
    labels: ["Allowed", "Blocked"],
    datasets: [{data: [allowed, blocked], backgroundColor: ["#4dd6a1", "#ff687d"], borderColor: "#101a2a", borderWidth: 4, hoverOffset: 5}]
  };
  const options = {
    responsive: true, maintainAspectRatio: false, cutout: "72%",
    plugins: {legend: {display: false}, tooltip: {backgroundColor: "#0a1321", borderColor: "#2a3b50", borderWidth: 1}}
  };
  if (outcomeChart) { outcomeChart.data = data; outcomeChart.update(); }
  else outcomeChart = new Chart($("outcome-chart"), {type: "doughnut", data, options});
}
async function loadStats() {
  const stats = await api("/api/stats");
  $("metric-total").textContent = number(stats.total_events);
  $("metric-blocked").textContent = number(stats.blocked);
  $("metric-allowed").textContent = number(stats.allowed);
  $("metric-sources").textContent = number(stats.unique_sources);
  $("block-rate").textContent = `${stats.block_rate}%`;
  $("legend-allowed").textContent = number(stats.allowed);
  $("legend-blocked").textContent = number(stats.blocked);
  drawActivity(stats.timeline || []);
  drawOutcomes(stats.allowed, stats.blocked);
}
async function loadAlerts() {
  const result = await api("/api/alerts?limit=100");
  $("alert-count").textContent = `${result.count} alert${result.count === 1 ? "" : "s"}`;
  $("nav-alert-count").textContent = result.count;
  const body = $("alerts-body");
  if (!result.items.length) {
    body.innerHTML = '<tr><td colspan="5" class="empty">No alerts currently match the demo rules.</td></tr>';
    return;
  }
  body.innerHTML = result.items.slice(0, 30).map(alert => `
    <tr>
      <td><span class="severity ${safe(alert.severity.toLowerCase())}">${safe(alert.severity)}</span></td>
      <td>${safe(alert.title)}</td>
      <td class="ip">${safe(alert.src_ip)}</td>
      <td class="mono">${safe(formatTime(alert.timestamp))}</td>
      <td>${safe(alert.description)}</td>
    </tr>`).join("");
}
async function loadEvents() {
  const params = new URLSearchParams({limit: "500"});
  const search = $("search-input").value.trim();
  const action = $("action-filter").value;
  const protocol = $("protocol-filter").value;
  if (search) params.set("search", search);
  if (action) params.set("action", action);
  if (protocol) params.set("protocol", protocol);
  const result = await api(`/api/events?${params.toString()}`);
  $("events-count").textContent = `${result.count} record${result.count === 1 ? "" : "s"}`;
  const body = $("events-body");
  if (!result.items.length) {
    body.innerHTML = '<tr><td colspan="7" class="empty">No events match these filters.</td></tr>';
    return;
  }
  body.innerHTML = result.items.map(event => `
    <tr>
      <td class="mono">${safe(formatTime(event.timestamp))}</td>
      <td class="ip">${safe(event.src_ip)}:${safe(event.src_port)}</td>
      <td class="ip">${safe(event.dst_ip)}:${safe(event.dst_port)}</td>
      <td>${safe(event.protocol)}</td>
      <td class="mono">${number(event.bytes)}</td>
      <td><span class="action-pill ${event.action === "BLOCK" ? "block" : "allow"}">${event.action === "BLOCK" ? "⊘" : "✓"} ${safe(event.action)}</span></td>
      <td>${safe(event.note)}</td>
    </tr>`).join("");
}
async function refreshAll(showMessage = false) {
  try {
    await Promise.all([loadStats(), loadAlerts(), loadEvents()]);
    $("last-updated").textContent = new Date().toLocaleTimeString([], {hour: "2-digit", minute: "2-digit", second: "2-digit"});
    if (showMessage) showToast("Dashboard refreshed");
  } catch (error) {
    showToast(`Could not load dashboard: ${error.message}`, true);
  }
}
let searchDebounce;
$("search-input").addEventListener("input", () => {
  clearTimeout(searchDebounce);
  searchDebounce = setTimeout(() => loadEvents().catch(err => showToast(err.message, true)), 250);
});
$("action-filter").addEventListener("change", () => loadEvents().catch(err => showToast(err.message, true)));
$("protocol-filter").addEventListener("change", () => loadEvents().catch(err => showToast(err.message, true)));
$("refresh-btn").addEventListener("click", () => refreshAll(true));
$("export-btn").addEventListener("click", () => { window.location.href = "/api/export.csv"; });
refreshAll();
refreshTimer = setInterval(() => refreshAll(), 15000);
window.addEventListener("beforeunload", () => clearInterval(refreshTimer));
async function api(path, options = {}) {
  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {})
    }
  });

  if (!response.ok) {
    let detail = `Request failed (${response.status})`;
    try {
      const body = await response.json();
      detail = body.detail || detail;
    } catch {}
    throw new Error(detail);
  }

  return response.json();
}
