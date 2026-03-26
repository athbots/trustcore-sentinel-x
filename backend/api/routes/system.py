from fastapi import APIRouter, HTTPException, Query
from core.scanner import SystemScanner
from core.heuristics import HeuristicsEngine
from core.process_monitor import ProcessMonitor
from core.quarantine import QuarantineManager
from core.trust_engine import TrustEngine
from core.anomaly_engine import AnomalyEngine
from core.attack_simulator import AttackSimulator
from schemas.system import SystemStatusResponse, SystemMetrics, ProcessThreat, ProcessStatusResponse, OsMetrics, FullSystemStatus
from api.utils import get_safe_response, standardize_response
from typing import List, Dict, Any, Optional
import os

router = APIRouter()

# Initialize cores
heuristics = HeuristicsEngine()
proc_monitor = ProcessMonitor()
quarantine_mgr = QuarantineManager()
trust_engine = TrustEngine()
anomaly_engine = AnomalyEngine()
simulator = AttackSimulator()

@router.get("/status")
async def get_system_status():
    """Consolidated production-ready status endpoint."""
    try:
        os_metrics = proc_monitor.get_system_metrics()
        procs = proc_monitor.get_running_processes()
        
        cpu = os_metrics.get("cpu_percent", 0.0)
        mem = os_metrics.get("memory_percent", 0.0)
        proc_count = len(procs)
        
        # Observe for anomalies
        anomaly_score = anomaly_engine.observe(cpu, mem, proc_count)
        
        suspicious_procs = len([p for p in procs if p['risk_score'] >= 50])
        
        # Get simulation status
        sim_status = simulator.get_status()
        
        score_data = trust_engine.calculate_score(0, suspicious_procs, os_metrics, anomaly_score, sim_status)
        
        # Merge explanations from trust engine and anomaly engine
        all_explanations = score_data.get('explanations', [])
        anomaly_explanations = anomaly_engine.get_explanations(anomaly_score, {"cpu": cpu, "process_count": proc_count})
        all_explanations.extend(anomaly_explanations)

        # Standardized 7-field structure
        return standardize_response({
            "trust_score": float(score_data['trust_score']),
            "risk_level": str(score_data['status']),
            "status": str(score_data['status_message']),
            "decision": str(score_data['decision']),
            "cpu": float(cpu),
            "memory": float(mem),
            "process_count": int(proc_count)
        })
    except Exception as e:
        return get_safe_response("/system/status", e)

@router.get("/processes")
async def get_processes():
    """Return filtered real-time process risk data and base OS metrics."""
    try:
        os_metrics = proc_monitor.get_system_metrics()
        all_procs = proc_monitor.get_running_processes()
        
        suspicious = [p for p in all_procs if p['risk_score'] >= 50]
        
        # Reuse anomaly engine for consistency
        cpu = os_metrics.get("cpu_percent", 0.0)
        mem = os_metrics.get("memory_percent", 0.0)
        anomaly_score = anomaly_engine.observe(cpu, mem, len(all_procs))
        
        score_data = trust_engine.calculate_score(0, len(suspicious), os_metrics, anomaly_score)
        
        # We return the standardized response as requested
        return standardize_response({
            "trust_score": float(score_data['trust_score']),
            "risk_level": str(score_data['status']),
            "status": str(score_data['status_message']),
            "decision": str(score_data['decision']),
            "cpu": float(cpu),
            "memory": float(mem),
            "process_count": int(len(all_procs))
        })
    except Exception as e:
        return get_safe_response("/system/processes", e)
