"""Quick smoke test for all v2 modules."""
import sys
sys.path.insert(0, ".")

print("=" * 50)
print("  Final Upgrade Smoke Test")
print("=" * 50)

from sentinel.intelligence.entity_tracker import track, get_multiplier
p = track("203.0.113.66", "ip", 85, "BLOCK", "PHISHING")
p = track("203.0.113.66", "ip", 90, "ISOLATE", "BRUTE_FORCE")
p = track("203.0.113.66", "ip", 92, "ISOLATE", "DATA_EXFIL")
assert p.is_repeat_offender
print(f"[1] Entity tracker: mult={p.risk_multiplier} OK")

from sentinel.intelligence.correlation import record_event, correlate
record_event("test-ip", "BRUTE_FORCE_DETECTED")
record_event("test-ip", "SUSPICIOUS_PROCESS")
record_event("test-ip", "DATA_EXFIL")
c = correlate("test-ip")
assert c["matched"]
print(f"[2] Correlation: {c['chain_name']} OK")

from sentinel.intelligence.threat_intel import analyze
ti = analyze({"source_ip": "203.0.113.66", "text": "evil-phishing.com"})
assert ti["score"] >= 0.5
print(f"[3] Threat intel: score={ti['score']} OK")

from sentinel.intelligence.behavior import analyze_behavior
b = analyze_behavior("test", {"event_type": "TEST"})
print(f"[4] Behavior: score={b['score']} OK")

from sentinel.core.risk_scorer import compute_risk
r = compute_risk(0.9, 0.7, 0.5, {"source_ip": "203.0.113.66"},
                 threat_intel_score=0.6, behavior_score=0.3,
                 entity_multiplier=1.3, correlation_boost=30,
                 correlation_info={"matched": True, "chain_name": "Test"})
assert r["confidence"] > 0
assert r["risk_score"] > 70
print(f"[5] Risk v2: score={r['risk_score']} conf={r['confidence']} level={r['threat_level']} OK")

from sentinel.core.settings import load
load()
from sentinel.core.auth import init_api_key
key = init_api_key()
assert len(key) > 20
print(f"[6] Auth: key={key[:8]}... OK")

print("\n" + "=" * 50)
print("  ALL TESTS PASSED")
print("=" * 50)
