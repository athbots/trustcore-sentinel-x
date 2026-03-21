"""
TrustCore Sentinel X — Process Anomaly Detector

Rule-based detector for suspicious process behavior.
Analyzes process events from the ProcessCollector and produces
an anomaly score + signals.

Detection categories:
    - LOLBin execution
    - Suspicious command-line patterns
    - Unusual parent→child process spawning
    - High CPU usage (crypto-miner heuristic)
"""
from sentinel.utils.logger import get_logger

logger = get_logger("detector.process_anomaly")


def analyze_process(event: dict) -> dict:
    """
    Analyze a process event for anomalous behavior.

    The ProcessCollector already performs initial signal detection.
    This detector enriches with scoring and verdict.

    Args:
        event: process event dict from ProcessCollector

    Returns dict with:
        score (float): 0.0–1.0 anomaly score
        verdict (str): NORMAL | SUSPICIOUS | MALICIOUS
        signals (list): human-readable signal descriptions
        explanation (str): narrative of what was detected
    """
    _event_type = event.get("event_type", "UNKNOWN")  # kept for future scoring
    signals = event.get("signals", [])
    risk_hint = event.get("risk_hint", 0.1)

    # ── Score Calculation ────────────────────────────────────────────────────
    score = risk_hint

    # Boost score based on signal count and severity
    for signal in signals:
        if "suspicious_spawn" in signal:
            score += 0.3   # Office → shell = very bad
        elif "lolbin:" in signal:
            score += 0.15  # LOLBin alone is moderate risk
        elif "cmd_pattern:" in signal:
            score += 0.2   # Matching known attack pattern
        elif "brute_force" in signal:
            score += 0.35  # Brute-force is high risk
        elif "sustained_high_cpu" in signal:
            score += 0.2   # Possible crypto miner
        elif "possible_cryptominer" in signal:
            score += 0.15

    score = min(score, 1.0)

    # ── Verdict ──────────────────────────────────────────────────────────────
    if score >= 0.65:
        verdict = "MALICIOUS"
    elif score >= 0.35:
        verdict = "SUSPICIOUS"
    else:
        verdict = "NORMAL"

    # ── Human-readable signals ───────────────────────────────────────────────
    readable_signals = []
    for s in signals:
        if s.startswith("lolbin:"):
            binary = s.split(":")[1]
            readable_signals.append(f"Living-off-the-Land Binary detected: {binary}")
        elif s.startswith("cmd_pattern:"):
            pattern = s.split(":")[1]
            readable_signals.append(f"Suspicious command pattern: {pattern}")
        elif s.startswith("suspicious_spawn:"):
            chain = s.split(":")[1]
            readable_signals.append(f"Suspicious process chain: {chain}")
        elif "brute_force" in s:
            readable_signals.append("Brute-force login attempt detected")
        elif "sustained_high_cpu" in s:
            readable_signals.append(f"Sustained high CPU usage ({event.get('cpu_percent', '?')}%)")
        elif "possible_cryptominer" in s:
            readable_signals.append("Behavior consistent with cryptocurrency mining")
        else:
            readable_signals.append(s)

    # ── Explanation ──────────────────────────────────────────────────────────
    name = event.get("name", "unknown")
    pid = event.get("pid", "?")

    if verdict == "MALICIOUS":
        explanation = (
            f"🔴 MALICIOUS: Process '{name}' (PID {pid}) exhibits high-risk behavior. "
            f"Detected: {', '.join(readable_signals[:3])}."
        )
    elif verdict == "SUSPICIOUS":
        explanation = (
            f"🟡 SUSPICIOUS: Process '{name}' (PID {pid}) shows concerning activity. "
            f"Detected: {', '.join(readable_signals[:3])}."
        )
    else:
        explanation = f"🟢 NORMAL: Process '{name}' (PID {pid}) — no anomalies detected."

    return {
        "score": round(score, 4),
        "verdict": verdict,
        "signals": readable_signals,
        "explanation": explanation,
        "process_name": name,
        "pid": pid,
    }
