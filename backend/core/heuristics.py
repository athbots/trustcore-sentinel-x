import math
import os
from typing import Dict, Any, List

class HeuristicsEngine:
    """
    Analyzes files for suspicious patterns, high entropy, and known bad hashes.
    """
    
    # Small local bad hash list as requested
    KNOWN_BAD_HASHES = {
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", # Empty file hash (example)
        "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8", # 'password' hash (example)
    }
    
    SUSPICIOUS_EXTENSIONS = {'.scr', '.vbs', '.ps1', '.bat', '.exe'}

    def calculate_entropy(self, file_path: str) -> float:
        """
        Calculate Shannon entropy of a file. 
        High entropy (> 7.5) often indicates compression or encryption (common in malware/packers).
        """
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            if not data:
                return 0.0
            
            entropy = 0
            for i in range(256):
                p_i = data.count(i) / len(data)
                if p_i > 0:
                    entropy += -p_i * math.log2(p_i)
            return entropy
        except (PermissionError, FileNotFoundError):
            return 0.0

    def analyze_file(self, file_metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Grade a file based on its metadata and content."""
        risk_score = 0
        reasons = []
        
        # 1. Extension Check
        if file_metadata.get('extension') in self.SUSPICIOUS_EXTENSIONS:
            risk_score += 20
            reasons.append(f"Suspicious extension: {file_metadata['extension']}")
            
        # 2. Known Bad Hash
        if file_metadata.get('hash') in self.KNOWN_BAD_HASHES:
            risk_score += 100
            reasons.append("Matched known malicious signature (Bad Hash)")
            
        # 3. High Entropy (Possible Packer/Encryption)
        entropy = self.calculate_entropy(file_metadata['path'])
        if entropy > 7.2:
            risk_score += 40
            reasons.append(f"High entropy detected ({entropy:.2f}): Likely packed or encrypted executable")
            
        # 4. Hidden Executable
        if file_metadata.get('is_hidden') and file_metadata.get('extension') in self.SUSPICIOUS_EXTENSIONS:
            risk_score += 30
            reasons.append("Hidden executable file detected")

        # Clamp score
        risk_score = min(risk_score, 100)
        
        return {
            "path": file_metadata['path'],
            "risk_score": risk_score,
            "reasons": reasons,
            "entropy": round(entropy, 2),
            "threat_level": "CRITICAL" if risk_score >= 85 else ("HIGH" if risk_score >= 65 else ("MEDIUM" if risk_score >= 35 else "SAFE"))
        }
