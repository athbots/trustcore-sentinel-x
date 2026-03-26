import os
import hashlib
import time
from typing import List, Dict, Any

class SystemScanner:
    """
    Recursively scans directories to detect suspicious files and collect metadata.
    Optimized for production with depth limits and path sanitization.
    """
    
    SUSPICIOUS_EXTENSIONS = {'.exe', '.bat', '.ps1', '.dll', '.scr', '.vbs', '.js', '.py'}
    
    def __init__(self, root_path: str, max_depth: int = 3):
        self.root_path = os.path.abspath(root_path)
        self.max_depth = max_depth
        
    def get_file_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of a file."""
        sha256_hash = hashlib.sha256()
        try:
            # Check file size first - skip files > 50MB for performance
            if os.path.getsize(file_path) > 52428800:
                return "SKIPPED_LARGE_FILE"

            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(65536), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except (PermissionError, FileNotFoundError, OSError):
            return "ACCESS_DENIED"

    def is_hidden(self, file_path: str) -> bool:
        """Check if a file is hidden."""
        name = os.path.basename(file_path)
        if name.startswith('.'):
            return True
        try:
            import ctypes
            attrs = ctypes.windll.kernel32.GetFileAttributesW(file_path)
            return attrs & 0x02 if attrs != -1 else False
        except:
            return False

    def scan(self) -> List[Dict[str, Any]]:
        """Perform the optimized recursive scan."""
        results = []
        now = time.time()
        one_day_ago = now - (24 * 3600)
        
        root_depth = self.root_path.count(os.sep)

        for root, dirs, files in os.walk(self.root_path):
            current_depth = root.count(os.sep) - root_depth
            if current_depth >= self.max_depth:
                del dirs[:] # Stop recursion deeper than max_depth
                continue

            for file in files:
                file_path = os.path.join(root, file)
                try:
                    stat = os.stat(file_path)
                    ext = os.path.splitext(file)[1].lower()
                    
                    is_suspicious_ext = ext in self.SUSPICIOUS_EXTENSIONS
                    is_hidden_file = self.is_hidden(file_path)
                    is_recent = stat.st_mtime > one_day_ago
                    
                    if is_suspicious_ext or is_hidden_file or is_recent:
                        results.append({
                            "path": file_path,
                            "name": file,
                            "size": stat.st_size,
                            "last_modified": time.ctime(stat.st_mtime),
                            "extension": ext,
                            "is_hidden": is_hidden_file,
                            "is_recent": is_recent,
                            "hash": self.get_file_hash(file_path)
                        })
                except (PermissionError, OSError):
                    continue
                    
        return results
