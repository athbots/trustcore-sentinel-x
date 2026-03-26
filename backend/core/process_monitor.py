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
            metrics["cpu_percent"] = psutil.cpu_percent(interval=None)
            mem = psutil.virtual_memory()
            metrics["memory_percent"] = mem.percent
            
            try:
                metrics["disk_percent"] = psutil.disk_usage(os.path.splitdrive(os.getcwd())[0] + "\\").percent
            except Exception:
                metrics["disk_percent"] = 0.0
                
            try:
                # Optimized connection count
                metrics["network_connections"] = len(psutil.net_connections(kind='inet'))
            except (psutil.AccessDenied, Exception):
                metrics["network_connections"] = 0
                
        except Exception:
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

                    processes.append({
                        "pid": pinfo['pid'],
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
