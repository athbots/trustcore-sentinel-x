/**
 * TrustCore Sentinel X — Dashboard Logic
 * Connects to FastAPI backend, drives all UI updates.
 */

const API = '';  // same origin — FastAPI serves this file

// ── State ─────────────────────────────────────────────────────────────────
let eventCount = 0;
let lastRiskScore = 0;

// ── Helpers ────────────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);

function now() {
  return new Date().toLocaleTimeString('en-US', { hour12: false });
}

function colorForLevel(level) {
  return { SAFE: '#30d158', LOW: '#00f5ff', MEDIUM: '#f5a623', HIGH: '#ff2d55', CRITICAL: '#ff2d55' }[level] || '#8891b4';
}
function classForLevel(level) {
  return (level || 'safe').toLowerCase();
}

// ── Gauge ──────────────────────────────────────────────────────────────────
function setGauge(score, level) {
  const ARC_LEN = 251.2;   // full half-circle length (π × 80)
  const fill = $('gaugeFill');
  const needle = $('gaugeNeedle');
  const scoreEl = $('gaugeScore');
  const badge = $('threatBadge');

  // Arc fill (0→score%)
  const offset = ARC_LEN - (ARC_LEN * Math.min(score, 100) / 100);
  fill.style.strokeDashoffset = offset;

  // Needle rotation: -90° (score=0) → +90° (score=100)
  const deg = -90 + (score / 100) * 180;
  needle.style.transform = `rotate(${deg}deg)`;

  // Score text
  scoreEl.textContent = score;

  // Color
  const col = colorForLevel(level);
  fill.style.stroke = `url(#gaugeGrad)`;   // keep gradient
  needle.style.stroke = col;

  // Badge
  badge.textContent = level;
  badge.className = `threat-badge badge-${classForLevel(level)}`;
}

// ── Score Bars ─────────────────────────────────────────────────────────────
function setBar(id, pct, color) {
  const bar = $(id);
  bar.style.width = `${Math.min(pct, 100)}%`;
  bar.style.background = color;
}

function setChip(id, text) {
  const chip = $(id);
  chip.textContent = text;
  chip.className = `verdict-chip chip-${(text || '').toLowerCase().replace(/ /g, '_')}`;
}

// ── Response Panel ─────────────────────────────────────────────────────────
const RESPONSE_META = {
  LOG:     { icon: '📋', color: 'log',     label: '✅ ACTION: LOG' },
  ALERT:   { icon: '🔔', color: 'alert',   label: '🔔 ACTION: ALERT' },
  BLOCK:   { icon: '🚫', color: 'block',   label: '🚫 ACTION: BLOCK' },
  ISOLATE: { icon: '☢️', color: 'isolate', label: '☢️ ACTION: ISOLATE' },
};

function updateResponsePanel(record) {
  const meta = RESPONSE_META[record.action] || { icon: '⚡', color: 'log', label: record.action };
  const panel = $('responsePanel');
  panel.className = `response-active response-${meta.color}`;
  $('responseIcon').textContent = meta.icon;
  $('responseAction').textContent = meta.label;
  $('responseDetail').textContent = record.outcome || record.description;
}

// ── Event Feed ─────────────────────────────────────────────────────────────
function addEventToFeed(result, eventType) {
  const level = result.risk?.threat_level || 'SAFE';
  const score = result.risk?.risk_score ?? 0;
  const text = result.phishing?.verdict || '—';
  const col = colorForLevel(level);

  eventCount++;
  $('feedCount').textContent = `${eventCount} event${eventCount !== 1 ? 's' : ''}`;

  const el = document.createElement('div');
  el.className = `event-item ${classForLevel(level)}`;
  el.innerHTML = `
    <div class="event-meta">
      <span class="event-type" style="color:${col}">${eventType || 'EVENT'}</span>
      <span class="event-text">${
        (document.getElementById('inputText').value || '—').substring(0, 60)
      }</span>
      <span class="event-time">${now()}</span>
    </div>
    <span class="event-score" style="color:${col}">${score}</span>
  `;
  el.style.cursor = 'pointer';
  el.addEventListener('click', () => showModal(result));

  const feed = $('eventFeed');
  feed.insertBefore(el, feed.firstChild);
  // cap at 50
  while (feed.children.length > 50) feed.removeChild(feed.lastChild);
}

// ── Actions Log ────────────────────────────────────────────────────────────
function addActionToLog(record) {
  const meta = RESPONSE_META[record.action] || { icon: '⚡' };
  const el = document.createElement('div');
  el.className = 'action-item';
  el.innerHTML = `
    <div class="action-row">
      <span class="action-icon">${meta.icon}</span>
      <span class="action-name">${record.action}</span>
      <span class="action-score-chip">${record.risk_score}/100</span>
    </div>
    <div class="action-detail">${record.outcome || record.description}</div>
    <div class="action-time">${record.source_ip || '—'} → ${record.target || '—'} · ${now()}</div>
  `;
  const log = $('actionsLog');
  log.insertBefore(el, log.firstChild);
  while (log.children.length > 50) log.removeChild(log.lastChild);
}

// ── Signals ────────────────────────────────────────────────────────────────
function showSignals(signals) {
  const box = $('signalsBox');
  const list = $('signalsList');
  if (!signals || signals.length === 0) { box.style.display = 'none'; return; }
  box.style.display = 'block';
  list.innerHTML = signals.map(s => `<span class="signal-tag">▸ ${s}</span>`).join('');
}

// ── Modal ───────────────────────────────────────────────────────────────────
function showModal(data) {
  $('jsonContent').textContent = JSON.stringify(data, null, 2);
  $('jsonModal').classList.add('open');
  $('jsonModal').style.display = 'flex';
}
function closeModal(e) {
  if (e.target === $('jsonModal')) {
    $('jsonModal').style.display = 'none';
    $('jsonModal').classList.remove('open');
  }
}

// ── Core: Send to /analyze ──────────────────────────────────────────────────
async function callAnalyze(payload) {
  const res = await fetch(`${API}/analyze`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

// ── UI Action: Analyze ──────────────────────────────────────────────────────
async function runAnalysis() {
  const btn = $('btnAnalyze');
  btn.disabled = true;
  btn.textContent = 'Analyzing…';

  try {
    const text = $('inputText').value.trim();
    const rawF = $('inputFeatures').value;
    const features = rawF.split(',').map(v => parseFloat(v.trim())).filter(n => !isNaN(n));
    const sourceIp = $('inputIP').value.trim() || undefined;

    const payload = { text, features, source_ip: sourceIp };
    const result = await callAnalyze(payload);

    updateUI(result, payload.text ? 'MANUAL' : 'UNKNOWN');
  } catch(err) {
    console.error(err);
    alert('Analysis failed: ' + err.message);
  } finally {
    btn.disabled = false;
    btn.innerHTML = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg> Analyze Threat`;
  }
}

// ── UI Action: Simulate Attack ─────────────────────────────────────────────
async function simulateAttack() {
  const btn = $('btnSimulate');
  btn.disabled = true;
  btn.textContent = 'Generating…';

  try {
    // 1. Get a simulated attack event
    const eventRes = await fetch(`${API}/simulate_attack`);
    const attackEvent = await eventRes.json();

    // 2. Populate UI inputs for visibility
    $('inputText').value = attackEvent.text || '';
    $('inputFeatures').value = (attackEvent.features || []).join(', ');
    $('inputIP').value = attackEvent.source_ip || '';

    // 3. Analyze it
    const result = await callAnalyze(attackEvent);

    updateUI(result, attackEvent.event_type);
  } catch(err) {
    console.error(err);
    alert('Simulation failed: ' + err.message);
  } finally {
    btn.disabled = false;
    btn.innerHTML = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg> Simulate Attack`;
  }
}

// ── Update all UI panels ────────────────────────────────────────────────────
function updateUI(result, eventType) {
  const risk  = result.risk  || {};
  const phish = result.phishing || {};
  const anom  = result.anomaly  || {};
  const resp  = result.response || {};

  // Gauge
  setGauge(risk.risk_score ?? 0, risk.threat_level ?? 'SAFE');

  // Breakdown bars
  const comp = risk.component_scores || {};
  setBar('barPhishing', comp.phishing ?? 0, '#ff2d55');
  setBar('barAnomaly',  comp.anomaly  ?? 0, '#f5a623');
  setBar('barContext',  comp.context  ?? 0, '#a259ff');
  $('valPhishing').textContent = `${(comp.phishing ?? 0).toFixed(0)}`;
  $('valAnomaly').textContent  = `${(comp.anomaly  ?? 0).toFixed(0)}`;
  $('valContext').textContent  = `${(comp.context  ?? 0).toFixed(0)}`;

  setChip('chipPhishing', phish.verdict || '—');
  setChip('chipAnomaly',  anom.verdict  || '—');

  // Signals
  showSignals(phish.signals || []);

  // Response Panel
  if (resp.action) updateResponsePanel(resp);

  // Feed + Log
  addEventToFeed(result, eventType);
  if (resp.action) addActionToLog(resp);
}

// ── Status Polling ─────────────────────────────────────────────────────────
async function pollStatus() {
  try {
    const res = await fetch(`${API}/system_status`);
    if (!res.ok) throw new Error('offline');
    const data = await res.json();

    // Uptime
    $('uptimeDisplay').textContent = data.uptime_human || '—';

    // System dot
    const dot = $('systemStatusDot');
    const lbl = $('systemStatusLabel');
    dot.className = 'status-dot online';
    lbl.textContent = 'OPERATIONAL';

    // Populate actions log from history on first load
    if (data.recent_actions && data.recent_actions.length && $('actionsLog').children.length === 0) {
      data.recent_actions.slice().reverse().forEach(a => addActionToLog(a));
    }
  } catch {
    const dot = $('systemStatusDot');
    const lbl = $('systemStatusLabel');
    dot.className = 'status-dot error';
    lbl.textContent = 'OFFLINE';
  }
}

// ── Init ───────────────────────────────────────────────────────────────────
setGauge(0, 'SAFE');
pollStatus();
setInterval(pollStatus, 5000);
