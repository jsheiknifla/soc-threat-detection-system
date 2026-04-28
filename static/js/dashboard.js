'use strict';

// ── Clock ──────────────────────────────────────────────────────────────────────
const clockEl = document.getElementById('clock');
function tick() { clockEl.textContent = new Date().toLocaleTimeString(); }
setInterval(tick, 1000); tick();

// ── Chart defaults (dark) ──────────────────────────────────────────────────────
Chart.defaults.color = '#8b949e';
Chart.defaults.borderColor = '#30363d';
Chart.defaults.font.family = "'Segoe UI', system-ui, sans-serif";

// ── Timeline Chart ─────────────────────────────────────────────────────────────
const tlChart = new Chart(document.getElementById('timelineChart'), {
  type: 'bar',
  data: {
    labels: [],
    datasets: [
      { label: 'Info',    data: [], backgroundColor: '#1f4068', borderColor: '#58a6ff', borderWidth: 1, borderRadius: 3 },
      { label: 'Warning', data: [], backgroundColor: '#3a2800', borderColor: '#d29922', borderWidth: 1, borderRadius: 3 },
      { label: 'Error',   data: [], backgroundColor: '#3a1010', borderColor: '#f85149', borderWidth: 1, borderRadius: 3 }
    ]
  },
  options: {
    responsive: true,
    plugins: { legend: { position: 'top', labels: { boxWidth: 12, padding: 10 } } },
    scales: {
      x: { stacked: true, grid: { display: false }, ticks: { maxRotation: 45 } },
      y: { stacked: true, beginAtZero: true, ticks: { stepSize: 1 } }
    }
  }
});

// ── Alert Type Doughnut ────────────────────────────────────────────────────────
const atChart = new Chart(document.getElementById('alertTypeChart'), {
  type: 'doughnut',
  data: {
    labels: [],
    datasets: [{
      data: [],
      backgroundColor: ['#f85149','#f0883e','#d29922','#3fb950','#58a6ff','#bc8cff','#39d0d8','#ff7b72'],
      borderColor: '#161b22',
      borderWidth: 2
    }]
  },
  options: {
    responsive: true,
    cutout: '62%',
    plugins: { legend: { position: 'bottom', labels: { padding: 10, boxWidth: 12, font: { size: 11 } } } }
  }
});

// ── Source Bar Chart ───────────────────────────────────────────────────────────
const srcChart = new Chart(document.getElementById('sourceChart'), {
  type: 'bar',
  data: {
    labels: [],
    datasets: [{
      label: 'Events',
      data: [],
      backgroundColor: ['#1f4068','#1a3a1a','#2a1800','#2a1010','#1e1030'],
      borderColor:      ['#58a6ff','#3fb950','#f0883e','#f85149','#bc8cff'],
      borderWidth: 1,
      borderRadius: 4
    }]
  },
  options: {
    indexAxis: 'y',
    responsive: true,
    plugins: { legend: { display: false } },
    scales: {
      x: { beginAtZero: true },
      y: { grid: { display: false }, ticks: { font: { size: 10 } } }
    }
  }
});

// ── Modal ──────────────────────────────────────────────────────────────────────
function openModal(html) {
  document.getElementById('modal-content').innerHTML = html;
  document.getElementById('modal-overlay').classList.remove('hidden');
}
function closeModal() {
  document.getElementById('modal-overlay').classList.add('hidden');
}
document.addEventListener('keydown', e => { if (e.key === 'Escape') closeModal(); });

function field(label, value) {
  return `<div class="modal-field"><label>${label}</label><span>${value || '—'}</span></div>`;
}
function badge(cls, text) {
  return `<span class="badge badge-${cls.toLowerCase()}">${text}</span>`;
}

// ── Log detail modal ───────────────────────────────────────────────────────────
async function showLog(id) {
  const d = await fetch(`/api/logs/${id}`).then(r => r.json());
  openModal(`
    <div class="modal-title">📋 Log Entry #${d.id}</div>
    <div class="modal-grid">
      ${field('Timestamp', d.timestamp)}
      ${field('Log Name', d.log_name)}
      ${field('Event ID', `<code>${d.event_id}</code>`)}
      ${field('Level', badge(d.level, d.level))}
      ${field('Provider', d.provider)}
      ${field('Source', d.source)}
    </div>
    <div class="modal-message">
      <label>Full Message</label>
      <pre>${d.message || 'No message available.'}</pre>
    </div>
  `);
}

// ── Alert detail modal ─────────────────────────────────────────────────────────
async function showAlert(id) {
  const d = await fetch(`/api/alerts/${id}`).then(r => r.json());
  openModal(`
    <div class="modal-title">🚨 Alert #${d.id}</div>
    <div class="modal-grid">
      ${field('Timestamp', d.timestamp)}
      ${field('Event ID', `<code>${d.event_id}</code>`)}
      ${field('Alert Type', d.alert_type)}
      ${field('Severity', badge(d.severity, d.severity))}
      ${field('Source', d.source)}
    </div>
    <div class="modal-message">
      <label>Description</label>
      <pre>${d.description || 'No description.'}</pre>
    </div>
  `);
}

// ── Blocked detail modal ───────────────────────────────────────────────────────
async function showBlocked(id) {
  const d = await fetch(`/api/blocked/${id}`).then(r => r.json());
  openModal(`
    <div class="modal-title">🚫 Blocked Source #${d.id}</div>
    <div class="modal-grid">
      ${field('Source', d.source)}
      ${field('Blocked At', d.blocked_at)}
      ${field('Reason', badge('blocked', d.reason))}
    </div>
    <div class="modal-message">
      <label>Action Taken</label>
      <pre>Source "${d.source}" was automatically flagged and blocked by SIEM ThreatWatch.\nReason: ${d.reason}\nTime: ${d.blocked_at}</pre>
    </div>
  `);
}

// ── Render helpers ─────────────────────────────────────────────────────────────
function levelBadge(l) {
  const map = { Information:'information', Warning:'warning', Error:'error', Critical:'critical', '':'information' };
  const cls = map[l] || 'information';
  return `<span class="badge badge-${cls}">${l || 'Info'}</span>`;
}
function sevBadge(s) {
  return `<span class="badge badge-${s.toLowerCase()}">${s}</span>`;
}
function trunc(s, n=60) { return s && s.length > n ? s.slice(0,n)+'…' : (s||''); }

// ── Fetch & render ─────────────────────────────────────────────────────────────
async function fetchStats() {
  const d = await fetch('/api/stats').then(r => r.json());
  document.getElementById('s-total').textContent    = d.total;
  document.getElementById('s-info').textContent     = d.info;
  document.getElementById('s-errors').textContent   = d.errors;
  document.getElementById('s-alerts').textContent   = d.alerts;
  document.getElementById('s-critical').textContent = d.critical;
  document.getElementById('s-blocked').textContent  = d.blocked;
}

async function fetchLogs() {
  const rows = await fetch('/api/logs').then(r => r.json());
  document.getElementById('logs-body').innerHTML = rows.map(r => `
    <tr onclick="showLog(${r.id})">
      <td>${r.timestamp}</td>
      <td><code>${r.log_name}</code></td>
      <td><code>${r.event_id}</code></td>
      <td>${levelBadge(r.level)}</td>
      <td>${trunc(r.provider, 35)}</td>
      <td>${trunc(r.message, 60)}</td>
    </tr>`).join('');
}

async function fetchAlerts() {
  const rows = await fetch('/api/alerts').then(r => r.json());
  document.getElementById('alerts-body').innerHTML = rows.map(r => `
    <tr onclick="showAlert(${r.id})">
      <td>${r.timestamp}</td>
      <td>${trunc(r.source, 30)}</td>
      <td>${r.alert_type}</td>
      <td>${trunc(r.description, 55)}</td>
      <td>${sevBadge(r.severity)}</td>
      <td><code>${r.event_id}</code></td>
    </tr>`).join('');
}

async function fetchBlocked() {
  const rows = await fetch('/api/blocked').then(r => r.json());
  document.getElementById('blocked-body').innerHTML = rows.map(r => `
    <tr onclick="showBlocked(${r.id})">
      <td>${r.source}</td>
      <td>${r.blocked_at}</td>
      <td><span class="badge badge-blocked">${r.reason}</span></td>
    </tr>`).join('');
}

async function fetchTimeline() {
  const d = await fetch('/api/chart/timeline').then(r => r.json());
  tlChart.data.labels = d.labels;
  tlChart.data.datasets[0].data = d.info;
  tlChart.data.datasets[1].data = d.warning;
  tlChart.data.datasets[2].data = d.error;
  tlChart.update('none');
}

async function fetchAlertTypes() {
  const d = await fetch('/api/chart/alerts_by_type').then(r => r.json());
  atChart.data.labels = d.labels;
  atChart.data.datasets[0].data = d.counts;
  atChart.update('none');
}

async function fetchSources() {
  const d = await fetch('/api/chart/logs_by_source').then(r => r.json());
  // shorten long log names
  srcChart.data.labels = d.labels.map(l => l.length > 30 ? l.slice(0,30)+'…' : l);
  srcChart.data.datasets[0].data = d.counts;
  srcChart.update('none');
}

async function refreshAll() {
  await Promise.all([
    fetchStats(), fetchLogs(), fetchAlerts(),
    fetchBlocked(), fetchTimeline(), fetchAlertTypes(), fetchSources()
  ]);
}

refreshAll();
setInterval(refreshAll, 8000);
