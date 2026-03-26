import os
import shutil
import json
import time
from typing import Dict, Any

class QuarantineManager:
    """
    Safely isolates malicious files and keeps a secure log.
    """
    
    def __init__(self, quarantine_dir: str = "C:/TrustCore_Quarantine"):
        self.quarantine_dir = quarantine_dir
        self.log_path = os.path.join(self.quarantine_dir, "quarantine_log.json")
        self._ensure_dir()

    def _ensure_dir(self):
        if not os.path.exists(self.quarantine_dir):
            try:
                os.makedirs(self.quarantine_dir)
            except Exception as e:
                # Fallback to local project dir if C:/ is protected
                self.quarantine_dir = os.path.abspath("./quarantine_storage")
                if not os.path.exists(self.quarantine_dir):
                    os.makedirs(self.quarantine_dir)
                self.log_path = os.path.join(self.quarantine_dir, "quarantine_log.json")

    def quarantine_file(self, file_path: str, reason: str) -> Dict[str, Any]:
        """Move file to quarantine and log the action."""
        if not os.path.exists(file_path):
            return {"status": "error", "message": "File not found"}

        file_name = os.path.basename(file_path)
        timestamp = int(time.time())
        quarantined_name = f"{timestamp}_{file_name}.tcq"
        destination = os.path.join(self.quarantine_dir, quarantined_name)

        try:
            shutil.move(file_path, destination)
            
            log_entry = {
                "original_path": file_path,
                "quarantine_path": destination,
                "timestamp": time.ctime(timestamp),
                "reason": reason
            }
            
            self._update_log(log_entry)
            
            return {
                "status": "success",
                "message": f"File {file_name} moved to vault.",
                "details": log_entry
            }
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def _update_log(self, entry: Dict[str, Any]):
        log_data = []
        if os.path.exists(self.log_path):
            try:
                with open(self.log_path, "r") as f:
                    log_data = json.load(f)
            except:
                log_data = []
        
        log_data.append(entry)
        
        with open(self.log_path, "w") as f:
            json.dump(log_data, f, indent=4)
