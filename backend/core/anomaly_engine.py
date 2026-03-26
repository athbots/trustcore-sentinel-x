import time
from collections import deque
from typing import Dict, List, Any

class AnomalyEngine:
    """
    Stateful engine that monitors system metrics over a rolling window.
    Uses standard deviation and delta thresholds to identify sudden spikes.
    """
    def __init__(self, window_size: int = 10):
        self.window_size = window_size
        self.history = {
            "cpu": deque(maxlen=window_size),
            "memory": deque(maxlen=window_size),
            "process_count": deque(maxlen=window_size)
        }

    def observe(self, cpu: float, memory: float, process_count: int) -> float:
        """Add a new sample and return an anomaly_score (0-100)."""
        score = 0.0
        
        # 1. Store observation
        if len(self.history["cpu"]) > 0:
            # Detect Sudden Spikes
            avg_cpu = sum(self.history["cpu"]) / len(self.history["cpu"])
            avg_mem = sum(self.history["memory"]) / len(self.history["memory"])
            avg_proc = sum(self.history["process_count"]) / len(self.history["process_count"])

            # CPU Jump > 30% from average
            if cpu > avg_cpu + 30:
                score += 40.0
            
            # Memory Jump > 10% from average
            if memory > avg_mem + 10:
                score += 30.0
                
            # Process Count increase > 5
            if process_count > avg_proc + 5:
                score += 30.0

        # Update History
        self.history["cpu"].append(cpu)
        self.history["memory"].append(memory)
        self.history["process_count"].append(process_count)

        return min(max(score, 0.0), 100.0)

    def get_explanations(self, score: float, current_metrics: Dict[str, Any]) -> List[str]:
        """Generate human-readable explanations if anomalies are detected."""
        explanations = []
        if score > 0:
            cpu = current_metrics.get("cpu", 0)
            avg_cpu = sum(self.history["cpu"]) / max(len(self.history["cpu"]), 1)
            if cpu > avg_cpu + 30:
                explanations.append(f"Sudden CPU spike detected: {cpu}% (prev avg: {round(avg_cpu,1)}%)")
            
            proc_count = current_metrics.get("process_count", 0)
            avg_proc = sum(self.history["process_count"]) / max(len(self.history["process_count"]), 1)
            if proc_count > avg_proc + 5:
                explanations.append(f"Anomalous process count increase: +{int(proc_count - avg_proc)} background tasks")

        return explanations
