/**
 * TrustCore Sentinel X — Dashboard v2
 * Real-time updates via WebSocket (/ws/feed) with HTTP fallback polling.
 */

const API = '';
const API_KEY = 'trustcore-super-secret-key-2026';
const WS_URL = `ws://${location.host}/ws/feed`;

// ── State ──────────────────────────────────────────────────────────────────
let eventCount = 0;
let ws = null;
let wsConnected = false;
let reconnectTimer = null;

// ── Helpers ────────────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);
const now = () => new Date().toLocaleTimeString('en-US', { hour12: false });

function colorForLevel(level) {
  return { SAFE:'#30d158', LOW:'#00f5ff', MEDIUM:'#f5a623', HIGH:'#ff2d55', CRITICAL:'#ff2d55' }[level] || '#8891b4';
}
function classForLevel(level) { return (level||'safe').toLowerCase(); }

// ── WebSocket ──────────────────────────────────────────────────────────────
function connectWS() {
  if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) return;

  ws = new WebSocket(WS_URL);

  ws.onopen = () => {
    wsConnected = true;
    clearTimeout(reconnectTimer);
    setStatus('online', 'LIVE');
    console.log('[WS] Connected');
    // heartbeat
    setInterval(() => { if (ws.readyState === WebSocket.OPEN) ws.send('ping'); }, 20000);
  };

  ws.onmessage = (evt) => {
    try {
      const data = JSON.parse(evt.data);
      if (data === 'pong') return;
      updateUI(data, data.response?.event_type || 'LIVE');
    } catch(e) { console.error('[WS] parse error', e); }
  };

  ws.onerror = () => { wsConnected = false; };

  ws.onclose = () => {
    wsConnected = false;
    setStatus('error', 'RECONNECTING…');
    reconnectTimer = setTimeout(connectWS, 3000);
  };
}

// ── Status ─────────────────────────────────────────────────────────────────
function setStatus(cls, label) {
  const dot = $('systemStatusDot');
  const lbl = $('systemStatusLabel');
  dot.className = `status-dot ${cls}`;
  lbl.textContent = label;
}

// ── Gauge ──────────────────────────────────────────────────────────────────
function setGauge(score, level, confidence) {
  const ARC = 251.2;
  $('gaugeFill').style.strokeDashoffset = ARC - (ARC * Math.min(score, 100) / 100);
  $('gaugeNeedle').style.transform = `rotate(${-90 + (score/100)*180}deg)`;
  $('gaugeScore').textContent = score;

  const col = colorForLevel(level);
  $('gaugeNeedle').style.stroke = col;
  $('threatBadge').textContent = level;
  $('threatBadge').className = `threat-badge badge-${classForLevel(level)}`;

  // Confidence display
  const confEl = $('confidenceDisplay');
  if (confEl && confidence != null) {
    confEl.textContent = `${Math.round(confidence * 100)}% confidence`;
    confEl.style.opacity = '1';
  }
}

// ── Bars ───────────────────────────────────────────────────────────────────
function setBar(id, pct, color) {
  const b = $(id);
  b.style.width = `${Math.min(pct, 100)}%`;
  b.style.background = color;
}
function setChip(id, text) {
  const c = $(id);
  c.textContent = text;
  c.className = `verdict-chip chip-${(text||'').toLowerCase().replace(/ /g,'_')}`;
}

// ── Response Panel ─────────────────────────────────────────────────────────
const RESP_META = {
  LOG:     { icon:'📋', color:'log',     label:'✅ ACTION: LOG' },
  ALERT:   { icon:'🔔', color:'alert',   label:'🔔 ACTION: ALERT' },
  BLOCK:   { icon:'🚫', color:'block',   label:'🚫 ACTION: BLOCK' },
  ISOLATE: { icon:'☢️', color:'isolate', label:'☢️ ACTION: ISOLATE' },
};

function updateResponsePanel(rec) {
  const m = RESP_META[rec.action] || { icon:'⚡', color:'log', label: rec.action };
  const p = $('responsePanel');
  p.className = `response-active response-${m.color}`;
  $('responseIcon').textContent = m.icon;
  $('responseAction').textContent = m.label;
  $('responseDetail').textContent = rec.outcome || rec.description || '';
}

// ── Explanation Panel ──────────────────────────────────────────────────────
function updateExplanation(expl) {
  const box = $('explanationBox');
  if (!expl || !expl.summary) { box.style.display = 'none'; return; }
  box.style.display = 'block';
  $('explanationSummary').textContent = expl.summary;
  $('explanationNarrative').textContent = expl.narrative || '';
  $('explanationRec').textContent = expl.recommendation || '';
}

// ── Event Feed ─────────────────────────────────────────────────────────────
function addToFeed(result, eventType) {
  const level = result.risk?.threat_level || 'SAFE';
  const score = result.risk?.risk_score ?? 0;
  const col = colorForLevel(level);

  eventCount++;
  $('feedCount').textContent = `${eventCount} event${eventCount !== 1 ? 's' : ''}`;

  const el = document.createElement('div');
  el.className = `event-item ${classForLevel(level)}`;
  el.innerHTML = `
    <div class="event-meta">
      <span class="event-type" style="color:${col}">${eventType || 'EVENT'}</span>
      <span class="event-text">${(result.explanation?.summary || result.phishing?.verdict || '—').substring(0,70)}</span>
      <span class="event-time">${now()}</span>
    </div>
    <span class="event-score" style="color:${col}">${score}</span>
  `;
  el.style.cursor = 'pointer';
  el.addEventListener('click', () => showModal(result));

  const feed = $('eventFeed');
  feed.insertBefore(el, feed.firstChild);
  while (feed.children.length > 10) feed.removeChild(feed.lastChild);
}

// ── Actions Log ────────────────────────────────────────────────────────────
function addToLog(rec) {
  const m = RESP_META[rec.action] || { icon:'⚡' };
  const el = document.createElement('div');
  el.className = 'action-item';
  el.innerHTML = `
    <div class="action-row">
      <span class="action-icon">${m.icon}</span>
      <span class="action-name">${rec.action}</span>
      <span class="action-score-chip">${rec.risk_score}/100</span>
    </div>
    <div class="action-detail">${rec.outcome || rec.description || ''}</div>
    <div class="action-time">${rec.source_ip||'—'} → ${rec.target||'—'} · ${now()}</div>
  `;
  const log = $('actionsLog');
  log.insertBefore(el, log.firstChild);
  while (log.children.length > 20) log.removeChild(log.lastChild);
}

// ── Signals ────────────────────────────────────────────────────────────────
function showSignals(signals) {
  const box = $('signalsBox'), list = $('signalsList');
  if (!signals?.length) { box.style.display='none'; return; }
  box.style.display='block';
  list.innerHTML = signals.map(s=>`<span class="signal-tag">▸ ${s}</span>`).join('');
}

// ── Modal ──────────────────────────────────────────────────────────────────
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

// ── Master UI update (called from WS or manual analyze) ───────────────────
function updateUI(result, eventType) {
  const risk  = result.risk  || {};
  const phish = result.phishing || {};
  const anom  = result.anomaly  || {};
  const resp  = result.response || {};
  const expl  = result.explanation || {};
  const comp  = risk.component_scores || {};
  const intel = result.intelligence || {};

  setGauge(risk.risk_score ?? 0, risk.threat_level ?? 'SAFE', risk.confidence);

  // System status indicator
  const sysStatus = result.system_status || 'SECURE';
  const statusEl = $('systemMode');
  if (statusEl) {
    statusEl.textContent = sysStatus;
    statusEl.className = `system-mode mode-${sysStatus === 'UNDER ATTACK' ? 'attack' : 'secure'}`;
  }

  // Score bars
  setBar('barPhishing', comp.phishing ?? 0, '#ff2d55');
  setBar('barAnomaly',  comp.network_anomaly ?? comp.anomaly ?? 0, '#f5a623');
  setBar('barContext',  comp.context ?? 0, '#a259ff');
  $('valPhishing').textContent = `${Math.round(comp.phishing ?? 0)}`;
  $('valAnomaly').textContent  = `${Math.round(comp.network_anomaly ?? comp.anomaly ?? 0)}`;
  $('valContext').textContent  = `${Math.round(comp.context ?? 0)}`;

  // Threat intel + behavior bars (if elements exist)
  if ($('barThreatIntel')) setBar('barThreatIntel', comp.threat_intel ?? 0, '#ff6b6b');
  if ($('barBehavior'))    setBar('barBehavior',    comp.behavior ?? 0, '#00f5ff');
  if ($('valThreatIntel')) $('valThreatIntel').textContent = `${Math.round(comp.threat_intel ?? 0)}`;
  if ($('valBehavior'))    $('valBehavior').textContent    = `${Math.round(comp.behavior ?? 0)}`;

  setChip('chipPhishing', phish.verdict || '—');
  setChip('chipAnomaly',  anom.verdict  || '—');

  showSignals(phish.signals || []);

  if (resp.action) { updateResponsePanel(resp); addToLog(resp); }

  // Enhanced explanation with intelligence
  const enhancedExpl = Object.assign({}, expl);
  if (risk.reason) enhancedExpl.summary = risk.reason;
  if (intel.correlation?.matched) {
    enhancedExpl.narrative = `⚡ Attack Chain: ${intel.correlation.chain_name}\n${intel.correlation.description}\nConfidence: ${Math.round(intel.correlation.confidence * 100)}%`;
  }
  updateExplanation(enhancedExpl);
  addToFeed(result, eventType);
}

// ── Manual Analyze ─────────────────────────────────────────────────────────
async function runAnalysis() {
  const btn = $('btnAnalyze');
  btn.disabled = true; btn.textContent = 'Analyzing…';
  try {
    const text     = $('inputText').value.trim();
    const features = $('inputFeatures').value.split(',').map(v=>parseFloat(v.trim())).filter(n=>!isNaN(n));
    const sourceIp = $('inputIP').value.trim() || undefined;

    const res = await fetch(`${API}/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text, features, source_ip: sourceIp }),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    updateUI(await res.json(), 'MANUAL');
  } catch(err) {
    alert('Analysis failed: ' + err.message);
  } finally {
    btn.disabled = false;
    btn.innerHTML = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg> Analyze Threat`;
  }
}

// ── Simulate Attack ────────────────────────────────────────────────────────
async function simulateAttack() {
  const btn = $('btnSimulate');
  btn.disabled = true; btn.textContent = 'Generating…';
  try {
    const ev = await (await fetch(`${API}/simulate_attack`, { headers: { 'X-API-Key': API_KEY } })).json();
    $('inputText').value = ev.text || '';
    $('inputFeatures').value = (ev.features || []).join(', ');
    $('inputIP').value = ev.source_ip || '';

    const res = await fetch(`${API}/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-API-Key': API_KEY },
      body: JSON.stringify(ev),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    updateUI(await res.json(), ev.event_type);
  } catch(err) {
    alert('Simulation failed: ' + err.message);
  } finally {
    btn.disabled = false;
    btn.innerHTML = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg> Simulate Attack`;
  }
}

// ── HTTP Status Polling (uptime + offline fallback) ────────────────────────
async function pollStatus() {
  try {
    const data = await (await fetch(`${API}/system_status`)).json();
    $('uptimeDisplay').textContent = data.uptime_human || '—';
    if (!wsConnected) setStatus('online', 'HTTP POLL');

    // Backfill actions log if empty
    if (data.recent_actions?.length && $('actionsLog').children.length === 0) {
      data.recent_actions.slice().reverse().forEach(a => addToLog(a));
    }
  } catch {
    if (!wsConnected) setStatus('error', 'OFFLINE');
  }
}

// ── Init ───────────────────────────────────────────────────────────────────
setGauge(0, 'SAFE');
$('explanationBox').style.display = 'none';
connectWS();
pollStatus();
setInterval(pollStatus, 10000);
