from fastapi import APIRouter, HTTPException, Query
from core.scanner import SystemScanner
from core.heuristics import HeuristicsEngine
from core.process_monitor import ProcessMonitor
from core.quarantine import QuarantineManager
from core.trust_engine import TrustEngine
from core.anomaly_engine import AnomalyEngine
from core.attack_simulator import AttackSimulator
from schemas.system import SystemStatusResponse, SystemMetrics, ProcessThreat, ProcessStatusResponse, OsMetrics, FullSystemStatus
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

@router.get("/status", response_model=FullSystemStatus)
async def get_system_status():
    """Consolidated production-ready status endpoint."""
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

    return FullSystemStatus(
        trust_score=score_data['trust_score'],
        risk_level=score_data['status'],
        status_message=score_data['status_message'],
        decision=score_data['decision'],
        cpu_usage=cpu,
        memory_usage=mem,
        process_count=proc_count,
        anomaly_score=anomaly_score,
        explanations=all_explanations
    )

@router.get("/processes", response_model=ProcessStatusResponse)
async def get_processes():
    """Return filtered real-time process risk data and base OS metrics."""
    os_metrics = proc_monitor.get_system_metrics()
    all_procs = proc_monitor.get_running_processes()
    
    suspicious = [p for p in all_procs if p['risk_score'] >= 50]
    
    # Reuse anomaly engine for consistency
    cpu = os_metrics.get("cpu_percent", 0.0)
    mem = os_metrics.get("memory_percent", 0.0)
    anomaly_score = anomaly_engine.observe(cpu, mem, len(all_procs))
    
    score_data = trust_engine.calculate_score(0, len(suspicious), os_metrics, anomaly_score)
    
    process_nodes = []
    for p in all_procs:
        process_nodes.append(ProcessThreat(
            path=p['name'],
            risk_score=p['risk_score'],
            reasons=p['reasons'],
            threat_level=p['threat_level'],
            decision="MONITOR",
            confidence=0.99,
            explanation=f"PID: {p['pid']} | CPU: {p['cpu']}% | RAM: {p['ram']}%"
        ))

    return ProcessStatusResponse(
        trust_score=score_data['trust_score'],
        risk_level=score_data['status'],
        decision=score_data['decision'],
        confidence=0.92,
        explanation=score_data['explanations'][0] if score_data['explanations'] else "Monitoring active.",
        explanations=score_data['explanations'],
        metrics=SystemMetrics(
            malicious_files=0,
            suspicious_processes=len(suspicious),
            high_risk_events=0
        ),
        os_metrics=OsMetrics(**os_metrics),
        threats=process_nodes
    )
