import psutil
import os
import time
from typing import List, Dict, Any

class ProcessMonitor:
    """
    Monitors running processes and identifies anomalies or high-resource usage.
    """
    
    WHITELIST = {
        'explorer.exe', 'svchost.exe', 'taskhostw.exe', 'wininit.exe', 
        'services.exe', 'lsass.exe', 'csrss.exe', 'winlogon.exe', 
        'System', 'Registry', 'smss.exe', 'python.exe', 'pythonw.exe', 'uvicorn.exe',
        'code.exe', 'msedge.exe', 'chrome.exe', 'brave.exe', 'System Idle Process',
        'conhost.exe', 'RuntimeBroker.exe', 'SearchHost.exe', 'ShellExperienceHost.exe',
        'StartMenuExperienceHost.exe', 'Taskmgr.exe', 'WindowsInternal.ComposableShell.Experiences.TextInput.InputApp.exe'
    }

    def __init__(self):
        # Initialize CPU tracking to avoid 0.0 on first call
        psutil.cpu_percent(interval=None)
        self.last_capture_time = time.time()

    def get_system_metrics(self) -> Dict[str, float]:
        """Fetch high-level OS metrics (CPU, Memory, Disk, Net)."""
        metrics = {
            "cpu_percent": 0.0,
            "memory_percent": 0.0,
            "disk_percent": 0.0,
            "network_connections": 0
        }
        try:
            # interval=None returns percentage since last call (efficient for polling)
            cpu = psutil.cpu_percent(interval=None)
            # Clamp: ensure [0, 100]
            metrics["cpu_percent"] = max(0.0, min(float(cpu or 0.0), 100.0))
            
            mem = psutil.virtual_memory()
            # Clamp: ensure [0, 100]
            metrics["memory_percent"] = max(0.0, min(float(mem.percent or 0.0), 100.0))
            
            try:
                disk_usage = psutil.disk_usage(os.path.splitdrive(os.getcwd())[0] + "\\").percent
                metrics["disk_percent"] = max(0.0, min(float(disk_usage or 0.0), 100.0))
            except Exception:
                metrics["disk_percent"] = 0.0
                
            try:
                # Optimized connection count
                conns = psutil.net_connections(kind='inet')
                metrics["network_connections"] = max(0, len(conns))
            except (psutil.AccessDenied, Exception):
                metrics["network_connections"] = 0
                
        except Exception:
            # Critical telemetry failure - safe fallback already in 'metrics'
            pass 
        return metrics

    def get_running_processes(self) -> List[Dict[str, Any]]:
        """List all processes with risk metadata."""
        processes = []
        try:
            # We only fetch vital info to stay fast
            for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent']):
                try:
                    pinfo = proc.info
                    name = pinfo.get('name') or "unknown"
                    
                    risk_score = 0
                    reasons = []
                    
                    # 1. Unknown Process check
                    if name not in self.WHITELIST:
                        risk_score += 20
                        reasons.append("Unknown process signature")
                    
                    # 2. Resource Anomaly
                    cpu_p = pinfo.get('cpu_percent') or 0.0
                    mem_p = pinfo.get('memory_percent') or 0.0
                    
                    if cpu_p > 40.0:
                        risk_score += 35
                        reasons.append(f"Excessive CPU: {cpu_p}%")
                    if mem_p > 15.0:
                        risk_score += 15
                        reasons.append(f"High memory: {mem_p:.1f}%")
                    
                    risk_score = min(risk_score, 100)

                    # Clamp individual process metrics
                    cpu_p = max(0.0, min(float(cpu_p), 100.0))
                    mem_p = max(0.0, min(float(mem_p), 100.0))

                    processes.append({
                        "pid": pinfo.get('pid', 0),
                        "name": name,
                        "user": pinfo.get('username') or "N/A",
                        "cpu": round(cpu_p, 1),
                        "ram": round(mem_p, 1),
                        "risk_score": risk_score,
                        "reasons": reasons,
                        "threat_level": "HIGH" if risk_score >= 50 else ("MEDIUM" if risk_score >= 25 else "SAFE")
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
        except Exception:
            return []
                
        # Sort by impact
        processes.sort(key=lambda x: x['risk_score'], reverse=True)
        return processes[:30] # Top 30 for UI performance
