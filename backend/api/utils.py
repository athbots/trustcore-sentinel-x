from typing import Dict, Any
from infra.logger import get_logger

logger = get_logger("api_utils")

SAFE_FALLBACK = {
    "trust_score": 50.0,
    "risk_level": "UNKNOWN",
    "decision": "MONITOR",
    "cpu": 0.0,
    "memory": 0.0,
    "process_count": 0,
    "status": "ERROR RECOVERED"
}

def get_safe_response(error_context: str, error: Exception = None) -> Dict[str, Any]:
    """Returns a standardized fallback JSON and logs the error."""
    if error:
        logger.error(f"FALLBACK TRIGGERED [{error_context}]: {str(error)}")
    else:
        logger.warning(f"FALLBACK TRIGGERED [{error_context}]")
    
    return SAFE_FALLBACK.copy()

def standardize_response(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Ensures the response dictionary contains all mandatory fields 
    with standardized names.
    """
    standard = SAFE_FALLBACK.copy()
    
    # Map possible internal names to standardized names
    mappings = {
        "trust_score": ["trust_score", "score"],
        "risk_level": ["risk_level", "status", "threat_level"],
        "decision": ["decision"],
        "cpu": ["cpu", "cpu_usage", "cpu_percent"],
        "memory": ["memory", "memory_usage", "memory_percent", "ram"],
        "process_count": ["process_count", "proc_count"],
        "status": ["status_message", "status"]
    }
    
    for key, aliases in mappings.items():
        for alias in aliases:
            if alias in data and data[alias] is not None:
                standard[key] = data[alias]
                break
                
    return standard
