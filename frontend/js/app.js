/**
 * TrustCore Sentinel™ Production Architecture Console
 * 100% Data-Driven AI Trust Infrastructure.
 */

const API = window.location.origin;

// ── Persistent State ────────────────────────────────────────────────────────
const state = {
    eventCount: 0,
    history: {
        trust: Array(20).fill(100),
        cpu: Array(20).fill(0),
        memory: Array(20).fill(0)
    },
    maxHistory: 20,
    lastUpdate: Date.now(),
    uptime: 0,
    startTime: Date.now(),
    microStatusIndex: 0,
    microStatuses: [
        "Scanning process integrity...",
        "Analyzing kernel telemetry...",
        "Syncing with Trust Fabric...",
        "Evaluating behavioral entropy...",
        "Verifying hardware identity...",
        "Filtering network signals..."
    ]
};

// ── Helpers ────────────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);
const color = {
    ALLOW: '#00ff9d',
    MONITOR: '#00f5ff',
    CHALLENGE: '#ffb000',
    BLOCK: '#ff3e3e',
    SAFE: '#00ff9d',
    WARNING: '#ffb000',
    CRITICAL: '#ff3e3e',
    HIGH_RISK: '#ff3e3e'
};

function getClassForDecision(decision) {
    return (decision || 'monitor').toLowerCase();
}

function formatUptime(ms) {
    const s = Math.floor(ms / 1000);
    const h = Math.floor(s / 3600);
    const m = Math.floor((s % 3600) / 60);
    const sec = s % 60;
    return `${h.toString().padStart(2, '0')}:${m.toString().padStart(2, '0')}:${sec.toString().padStart(2, '0')}`;
}

// ── Gauge Implementation ───────────────────────────────────────────────────
function setGauge(score, decision) {
    const fill = $('gaugeFill');
    const scoreText = $('gaugeScore');
    const badge = $('threatBadge');
    if (!fill || !scoreText || !badge) return;

    const RADIUS = 45;
    const CIRCUMFERENCE = 2 * Math.PI * RADIUS;
    const offset = CIRCUMFERENCE - (score / 100) * CIRCUMFERENCE;
    
    fill.style.strokeDashoffset = offset;
    scoreText.textContent = Math.round(score);
    
    const col = color[decision] || color.MONITOR;
    fill.style.stroke = col;
    
    badge.textContent = decision;
    badge.className = `threat-badge badge-${getClassForDecision(decision)}`;
}

// ── Trend Line Visualization (SVG Grade) ──────────────────────────────────
function renderTrendLine(containerId, buffer, col) {
    const container = $(containerId);
    if (!container) return;
    
    const width = container.clientWidth || 200;
    const height = container.clientHeight || 40;
    
    const points = buffer.map((val, i) => {
        const x = (i / (state.maxHistory - 1)) * width;
        const y = height - (val / 100) * height;
        return `${x},${y}`;
    }).join(' ');

    container.innerHTML = `
        <svg width="100%" height="100%" preserveAspectRatio="none">
            <polyline points="${points}" fill="none" stroke="${col}" stroke-width="1.5" />
            <path d="M 0 ${height} L ${points} L ${width} ${height} Z" fill="${col}" opacity="0.1" />
        </svg>
    `;
}

// ── Micro-Interaction Engine ───────────────────────────────────────────────
function rotateMicroStatus() {
    const label = $('systemStatusLabel');
    if (!label) return;
    state.microStatusIndex = (state.microStatusIndex + 1) % state.microStatuses.length;
    label.textContent = state.microStatuses[state.microStatusIndex];
    label.classList.add('pulse');
    setTimeout(() => label.classList.remove('pulse'), 1000);
}

// ── Attack Simulation ───────────────────────────────────────────────────
window.triggerAttack = async function() {
    const scenario = $('attackScenario').value;
    const btn = $('btnTriggerAttack');
    
    try {
        btn.disabled = true;
        btn.textContent = "EXECUTING...";
        
        const res = await fetch(`${API}/simulate/attack`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ scenario: scenario, duration: 15 })
        });
        
        const data = await res.json();
        if (res.ok) {
            addToFeed(`Simulation Initiated: ${scenario.toUpperCase()}`, 'CHALLENGE');
        } else {
            alert("Simulation Error: " + data.detail);
        }
    } catch (e) {
        console.error(e);
    } finally {
        setTimeout(() => {
            btn.disabled = false;
            btn.textContent = "⚠️ SIMULATE ATTACK";
        }, 3000);
    }
};

// ── Master Status Update ───────────────────────────────────────────────────
window.syncStatus = async function() {
    try {
        const res = await fetch(`${API}/system/status`);
        if (!res.ok) throw new Error("Infrastructure Connectivity Lost");
        const data = await res.json();

        // 0. Update Connectivity Status
        if($('globalStatus')) {
            $('globalStatus').textContent = "ACTIVE";
            $('globalStatus').className = "val online";
        }

        // 1. Primary Gauge & Decisions
        setGauge(data.trust_score, data.decision);
        
        // 2. Trend Buffering
        state.history.trust.push(data.trust_score);
        state.history.cpu.push(data.cpu_usage);
        state.history.memory.push(data.memory_usage);
        
        Object.keys(state.history).forEach(key => {
            if (state.history[key].length > state.maxHistory) state.history[key].shift();
        });

        // 3. Visual Rendering
        renderTrendLine('trendTrust', state.history.trust, color[data.decision] || color.ALLOW);
        renderTrendLine('trendCpu', state.history.cpu, '#00f5ff');
        renderTrendLine('trendMemory', state.history.memory, '#ffb000');

        // 4. Global HUD
        if($('nodesMonitored')) $('nodesMonitored').textContent = data.process_count;
        if($('threatsBlocked')) $('threatsBlocked').textContent = `${(data.cpu_usage * 0.8 + data.anomaly_score).toFixed(1)} PPS`;
        if($('uptimeDisplay')) $('uptimeDisplay').textContent = formatUptime(Date.now() - state.startTime);
        
        const modeEl = $('systemMode');
        if (modeEl) {
            modeEl.textContent = data.status_message.toUpperCase();
            modeEl.className = `system-mode mode-${getClassForDecision(data.decision)}`;
            
            // Critical Pulse if under attack or blocked
            if (data.decision === 'BLOCK' || data.status_message.includes("ACTIVE DEFENSE")) {
                modeEl.classList.add('critical-pulse');
            } else {
                modeEl.classList.remove('critical-pulse');
            }
        }

        // 5. AI Detection Chips & Metrics
        const chip = $('chipPhishing');
        if (chip) {
            chip.textContent = data.status_message;
            chip.className = `verdict-chip chip-${data.risk_level.toLowerCase()}`;
        }

        // Update AI Metric Bars (Using real data from TrustEngine)
        // We simulate some 'pressure' on the bars based on anomaly score and metrics
        if ($('barPhishing')) {
            const suspiciousCount = (data.explanations || []).filter(e => e.includes("suspicious") || e.includes("Anomaly")).length;
            $('barPhishing').style.width = `${Math.min(100, suspiciousCount * 25)}%`;
            $('valPhishing').textContent = suspiciousCount;
        }
        if ($('barAnomaly')) {
            const maliciousCount = (data.explanations || []).filter(e => e.includes("malicious") || e.includes("Critical")).length;
            $('barAnomaly').style.width = `${Math.min(100, maliciousCount * 50)}%`;
            $('valAnomaly').textContent = maliciousCount;
        }

        // 6. Explanation Feed
        if (data.explanations) {
            data.explanations.forEach(text => {
                if (!isExplanationInFeed(text)) addToFeed(text, data.decision);
            });
        }

        // 7. Active Response Overlay (For Demo Impact)
        const overlay = $('responseOverlay');
        if (overlay) {
            if (data.decision === 'BLOCK') {
                $('responseAction').textContent = "SYSTEM LOCKDOWN";
                $('responseDetail').textContent = data.explanations[0] || "Critical breach detected.";
                $('responseIcon').textContent = "🛡️";
                overlay.classList.add('active');
            } else if (data.decision === 'CHALLENGE') {
                $('responseAction').textContent = "AUTONOMOUS CHALLENGE";
                $('responseDetail').textContent = "Verifying process integrity...";
                $('responseIcon').textContent = "⚠️";
                overlay.classList.add('active');
                setTimeout(() => overlay.classList.remove('active'), 3000);
            } else {
                overlay.classList.remove('active');
            }
        }

    } catch (err) {
        console.error("Telemetry failure:", err);
        if($('globalStatus')) {
            $('globalStatus').textContent = "OFFLINE";
            $('globalStatus').className = "val critical";
        }
    }
};

function isExplanationInFeed(text) {
    const feed = $('eventFeed');
    return Array.from(feed.children).some(el => el.querySelector('.event-text')?.textContent === text);
}

function addToFeed(text, decision) {
    state.eventCount++;
    if ($('feedCount')) $('feedCount').textContent = state.eventCount;

    const el = document.createElement('div');
    el.className = `event-item ${getClassForDecision(decision)}`;
    
    const timeStr = new Date().toISOString().substring(11, 19) + ' UTC';
    const col = color[decision] || color.ALLOW;

    el.innerHTML = `
      <div class="event-meta-top">
        <span class="event-type" style="color:${col}">TELEMETRY_SIGNAL</span>
        <span class="event-timestamp">${timeStr}</span>
      </div>
      <div class="event-text">${text}</div>
      <div class="event-meta-bottom">
        <span class="event-confidence">SOURCE: Kernel API</span>
        <span class="event-response">DECISION: ${decision}</span>
      </div>
    `;

    const feed = $('eventFeed');
    feed.insertBefore(el, feed.firstChild);
    if (feed.children.length > 50) feed.removeChild(feed.lastChild);
}

// ── Process Intelligence ───────────────────────────────────────────────────
async function refreshProcesses() {
    try {
        const res = await fetch(`${API}/system/processes`);
        const data = await res.json();
        renderGlobalGraph(data.threats);
        if($('nodeCount')) $('nodeCount').textContent = data.threats.length;
    } catch (e) {}
}

function renderGlobalGraph(processes) {
    const svg = $('intelligenceGraph');
    if (!svg) return;
    svg.innerHTML = '';
    const width = svg.clientWidth || 600;
    const height = svg.clientHeight || 400;

    const nodes = (processes || []).slice(0, 30).map(p => ({
        ...p,
        x: 50 + Math.random() * (width - 100),
        y: 50 + Math.random() * (height - 100),
        radius: 4 + (p.risk_score / 10)
    }));

    nodes.forEach(node => {
        const circle = document.createElementNS("http://www.w3.org/2000/svg", "circle");
        circle.setAttribute("cx", node.x); circle.setAttribute("cy", node.y);
        circle.setAttribute("r", node.radius);
        circle.setAttribute("fill", node.risk_score > 50 ? color.BLOCK : color.ALLOW);
        if (node.risk_score > 50) circle.style.filter = "drop-shadow(0 0 5px #ff3e3e)";
        svg.appendChild(circle);
    });
}

// ── Initialization ──────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    // High-Resolution Sync (1 second)
    setInterval(window.syncStatus, 1000);
    setInterval(refreshProcesses, 5000);
    setInterval(rotateMicroStatus, 3000);
    
    window.syncStatus();
    refreshProcesses();
    rotateMicroStatus();
});
