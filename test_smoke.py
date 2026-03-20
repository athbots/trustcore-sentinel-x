"""Smoke test for industry-grade upgrade modules."""
import sys
sys.path.insert(0, ".")

print("=" * 50)
print("  Industry-Grade Upgrade — Smoke Test")
print("=" * 50)

# 1. Structured logger
from sentinel.utils.logger import get_logger, audit, export_logs
logger = get_logger("test")
logger.info("Smoke test started")
audit("TEST", "smoke test audit entry")
print("[1] Logger + audit ✓")

# 2. Settings
from sentinel.core.settings import load, get, get_all, update
cfg = load()
assert cfg["safe_mode"] == True
assert cfg["risk_critical"] == 85
print(f"[2] Settings loaded ({len(cfg)} keys) ✓")

# 3. Response engine (safe mode)
from sentinel.core.response_engine import execute_response, get_status, set_safe_mode, SAFE_MODE
assert SAFE_MODE == True
r = execute_response("HIGH", 78, "BLOCK", "Test block", {"source_ip": "203.0.113.45"})
assert "[SIMULATED]" in r["outcome"]
assert r["mode"] == "SIMULATED"
print(f"[3] Response engine (safe mode): {r['outcome'][:40]}… ✓")

# 4. Unblock
from sentinel.core.response_engine import unblock_ip
r2 = unblock_ip("203.0.113.45")
print(f"[4] Unblock: {r2} ✓")

# 5. Watchdog
from sentinel.utils.watchdog import CollectorWatchdog, CircuitBreaker
wd = CollectorWatchdog()
assert wd.health() == {}
cb = CircuitBreaker(threshold=3)
assert cb.state == "CLOSED"
for _ in range(3):
    cb.record_failure()
assert cb.state == "OPEN"
assert not cb.allow()
print("[5] Watchdog + circuit breaker ✓")

# 6. Admin route import
from sentinel.routes.admin import router as admin_router
assert len(admin_router.routes) > 0
print(f"[6] Admin routes: {len(admin_router.routes)} endpoints ✓")

# 7. Full pipeline + detectors check
from sentinel.detectors.phishing import analyze_phishing
r = analyze_phishing("Verify your PayPal account immediately")
assert r["verdict"] in ("PHISHING", "SUSPICIOUS")
print(f"[7] Phishing detector: {r['verdict']} ✓")

from sentinel.core.risk_scorer import compute_risk
r = compute_risk(0.9, 0.7, 0.5, {"source_ip": "203.0.113.45", "event_type": "PHISHING"})
assert r["risk_score"] > 50
print(f"[8] Risk scorer: {r['risk_score']}/100 {r['threat_level']} ✓")

print("\n" + "=" * 50)
print("  ALL TESTS PASSED ✅")
print("=" * 50)
