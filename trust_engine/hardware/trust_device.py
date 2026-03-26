import hashlib
import logging
from typing import Dict, Any

log = logging.getLogger("trust_engine.hardware")

class HardwareTrust:
    def __init__(self):
        # Simulated Hardware Root of Trust Keys
        self.known_hw_keys = {
            "dev_corp_mac": "HW_SECRET_KEY_A",
            "device-123": "HW_SECRET_KEY_B"
        }

    def verify_device_signature(self, device_id: str, challenge: str, signature: str) -> bool:
        """
        Verifies a device's cryptographic signature using a simulated hardware root of trust.
        Mismatch results in an immediate BLOCK decision.
        """
        if device_id not in self.known_hw_keys:
            log.warning(f"Device ID {device_id} not found in hardware trust registry.")
            return False

        secret = self.known_hw_keys[device_id]
        expected_sig = hashlib.sha256(f"{challenge}:{secret}".encode()).hexdigest()
        
        if signature == expected_sig:
            log.info(f"Hardware signature for device {device_id} verified successfully.")
            return True
            
        log.warning(f"Hardware signature mismatch for device {device_id}. Expected: {expected_sig}, Received: {signature}")
        return False

    def validate_device_id(self, device_id: str, metadata: Dict[str, Any]) -> bool:
        """
        Check if hardware metadata (e.g. CPU serial, BIOS ID) matches the device identifier.
        """
        # Simulated check: In prod this would interface with TPM or OS-level hardware APIs
        if "hw_serial" in metadata and device_id.startswith("dev_"):
            return True
        return False
