import random
from typing import List, Dict, Any

class TrustEngine:
    """
    Calculates the global system trust score based on OS telemetry and security signals.
    Enforces the standardized 4-tier decision model: 
    ALLOW (>80), MONITOR (60-80), CHALLENGE (40-60), BLOCK (<40).
    """
    
    def __init__(self):
        self.base_score = 100.0

    def calculate_score(self, 
                        malicious_files: int, 
                        suspicious_processes: int, 
                        os_metrics: Dict[str, float] = None,
                        anomaly_score: float = 0.0,
                        simulation_status: Dict[str, Any] = None) -> Dict[str, Any]:
        explanations = []
        deductions = 0.0
        
        # 1. Threat Penalties (Direct signal from scanners)
        if malicious_files > 0:
            deduc = malicious_files * 20.0
            deductions += deduc
            explanations.append(f"Critical: {malicious_files} malicious files detected (-{deduc})")
            
        if suspicious_processes > 0:
            deduc = suspicious_processes * 12.0
            deductions += deduc
            explanations.append(f"Warning: {suspicious_processes} suspicious processes active (-{deduc})")
            
        # 2. Anomaly Penalty (ML Signal)
        if anomaly_score > 0.4: # Only deduct if significantly anomalous
            deduc = (anomaly_score * 40.0)
            deductions += deduc
            explanations.append(f"ML Anomaly detected (Score: {anomaly_score:.2f}, Deduction: -{deduc:.1f})")

        # 3. OS Telemetry Penalties (Real-time hardware stress)
        status_message = "System Healthy"
        if os_metrics:
            cpu = os_metrics.get("cpu_percent", 0.0)
            mem = os_metrics.get("memory_percent", 0.0)
            
            # Sub-threshold deductions for realism (micro-fluctuations)
            if cpu > 15.0:
                deduc = (cpu * 0.05)
                deductions += deduc
                
            if cpu > 85.0:
                status_message = "Critical CPU Load"
                explanations.append(f"Hardware Stress: CPU at {cpu}%")
            elif cpu > 60.0:
                status_message = "Elevated Resource Usage"
                explanations.append(f"High CPU utilization: {cpu}%")
                
            if mem > 90.0:
                status_message = "Memory Exhaustion"
                deductions += 15.0
                explanations.append(f"Critical Memory: {mem}%")
                
        # 4. Simulation Overrides (For Demonstrable Proof)
        if simulation_status and simulation_status.get("is_running"):
            scenario = simulation_status.get("active_scenario")
            
            if scenario == "cpu_spike":
                deductions += 35.0
                explanations.append("Scenario: CPU Spike (Simulated)")
            elif scenario == "memory_pressure":
                deductions += 30.0
                explanations.append("Scenario: Memory Pressure (Simulated)")
            elif scenario == "process_burst":
                deductions += 45.0
                explanations.append("Scenario: Process Burst (Simulated)")
            elif scenario == "file_churn":
                deductions += 25.0
                explanations.append("Scenario: File Churn (Simulated)")
            elif scenario == "mixed_attack":
                deductions += 65.0
                explanations.append("Scenario: Multi-Vector Breach (Simulated)")
                
            status_message = f"ACTIVE DEFENSE: {str(scenario).upper().replace('_', ' ')}"
                
        # Real-time jitter for heartbeat visual
        final_score = self.base_score - deductions
        final_score += (random.random() * 0.6) - 0.3 
        
        final_score = max(0.0, min(100.0, final_score))
        
        if not explanations:
            explanations.append("System integrity verified. No threats detected.")
            
        # Standardized 4-Tier Mapping
        if final_score > 80:
            decision = "ALLOW"
            status = "SECURE"
        elif final_score >= 60:
            decision = "MONITOR"
            status = "WARNING"
            status_message = "Heuristic Alert"
        elif final_score >= 40:
            decision = "CHALLENGE"
            status = "HIGH_RISK"
            status_message = "Autonomous Challenge"
        else:
            decision = "BLOCK"
            status = "CRITICAL"
            status_message = "System Lockdown"
            
        return {
            "trust_score": round(final_score, 1),
            "status": status,
            "status_message": status_message,
            "decision": decision,
            "explanations": explanations,
            "metrics": {
                "malicious_files": malicious_files,
                "suspicious_processes": suspicious_processes,
                "anomaly_score": anomaly_score
            }
        }
