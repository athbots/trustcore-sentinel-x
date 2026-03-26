import threading
import time
import os
import shutil
import tempfile
import uuid
from typing import Dict, Any, List, Optional
try:
    from backend.infra.logger import get_logger
except ImportError:
    from infra.logger import get_logger

logger = get_logger("attack_simulator")

class AttackSimulator:
    """
    A safe, controlled, and repeatable attack simulation module.
    Triggers real telemetry changes (CPU, RAM, Processes) without causing damage.
    """
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(AttackSimulator, cls).__new__(cls)
                cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self.active_scenario: Optional[str] = None
        self.start_time: float = 0
        self.duration: int = 10
        self.stop_event = threading.Event()
        self.threads: List[threading.Thread] = []
        self.memory_blocks: List[Any] = []
        self.temp_dir: Optional[str] = None
        self.simulated_signals: Dict[str, Any] = {}
        self._initialized = True

    def start_scenario(self, scenario: str, duration: int = 10) -> Dict[str, Any]:
        with self._lock:
            if self.active_scenario:
                return {"error": f"Scenario '{self.active_scenario}' is already running."}
            
            self.active_scenario = scenario
            self.duration = duration
            self.start_time = time.time()
            self.stop_event.clear()
            self.simulated_signals = {}
            
            logger.info(f"Starting attack simulation: {scenario} for {duration}s")
            
            if scenario == "cpu_spike":
                self._run_cpu_spike()
            elif scenario == "memory_pressure":
                self._run_memory_pressure()
            elif scenario == "process_burst":
                self._run_process_burst()
            elif scenario == "file_churn":
                self._run_file_churn()
            elif scenario == "mixed_attack":
                self._run_mixed_attack()
            else:
                self.active_scenario = None
                return {"error": f"Unknown scenario: {scenario}"}
            
            # Start a watchdog thread for auto-cleanup
            threading.Thread(target=self._watchdog, daemon=True).start()
            
            return {
                "scenario": scenario,
                "status": "started",
                "duration_seconds": duration,
                "expected_effect": self._get_expected_effect(scenario)
            }

    def get_status(self) -> Dict[str, Any]:
        elapsed = time.time() - self.start_time if self.active_scenario else 0
        remaining = max(0, self.duration - elapsed) if self.active_scenario else 0
        
        return {
            "active_scenario": self.active_scenario,
            "elapsed_seconds": round(elapsed, 1),
            "remaining_seconds": round(remaining, 1),
            "is_running": self.active_scenario is not None,
            "simulated_signals": self.simulated_signals
        }

    def stop_all(self):
        with self._lock:
            if not self.active_scenario:
                return
            logger.info(f"Stopping simulation: {self.active_scenario}")
            self.stop_event.set()
            
            # Cleanup
            self.memory_blocks = []
            if self.temp_dir and os.path.exists(self.temp_dir):
                try:
                    shutil.rmtree(self.temp_dir)
                except Exception as e:
                    logger.error(f"Failed to cleanup temp dir: {e}")
            self.temp_dir = None
            
            self.active_scenario = None
            self.simulated_signals = {}
            logger.info("Simulation cleaned up and restored to baseline.")

    def _watchdog(self):
        time.sleep(self.duration)
        self.stop_all()

    def _get_expected_effect(self, scenario: str) -> str:
        effects = {
            "cpu_spike": "Elevated CPU usage and trust score degradation.",
            "memory_pressure": "Significant memory allocation and system strain.",
            "process_burst": "Sudden surge in active processes and behavioral alerts.",
            "file_churn": "High-frequency file I/O operations in sandbox.",
            "mixed_attack": "Correlated multi-vector telemetry anomaly."
        }
        return effects.get(scenario, "Undefined effect.")

    # ── Simulation Scenarios ────────────────────────────────────────────────

    def _run_cpu_spike(self):
        def cpu_worker():
            while not self.stop_event.is_set():
                # Bounded work
                _ = sum(i * i for i in range(1000))
                time.sleep(0.01)
        
        # Max 4 threads to be safe but visible
        num_threads = min(os.cpu_count() or 2, 4)
        for _ in range(num_threads):
            t = threading.Thread(target=cpu_worker, daemon=True)
            t.start()
            self.threads.append(t)
        
        self.simulated_signals["cpu_anomaly"] = True

    def _run_memory_pressure(self):
        # Safely allocate ~100MB of overhead
        try:
            for _ in range(10):
                if self.stop_event.is_set(): break
                self.memory_blocks.append(" " * (10 * 1024 * 1024)) # 10MB chunks
                time.sleep(0.1)
        except MemoryError:
            logger.warning("Memory pressure reached system limit early.")
        
        self.simulated_signals["memory_anomaly"] = True

    def _run_process_burst(self):
        # We don't actually need to spawn 100 processes (dangerous).
        # We inject 'simulated' process metadata that the Heuristics Engine will see.
        self.simulated_signals["process_burst"] = 50 
        self.simulated_signals["suspicious_activity"] = "Rapid process creation detected"

    def _run_file_churn(self):
        self.temp_dir = tempfile.mkdtemp(prefix="trustcore_sim_")
        def file_worker():
            while not self.stop_event.is_set():
                fname = os.path.join(self.temp_dir, f"{uuid.uuid4()}.tmp")
                with open(fname, "w") as f:
                    f.write("SIMULATED DATA")
                time.sleep(0.05)
                if os.path.exists(fname):
                    os.remove(fname)
                time.sleep(0.05)
        
        t = threading.Thread(target=file_worker, daemon=True)
        t.start()
        self.threads.append(t)
        self.simulated_signals["file_anomaly"] = True

    def _run_mixed_attack(self):
        self._run_cpu_spike()
        self._run_process_burst()
        self.simulated_signals["correlated_attack"] = True
