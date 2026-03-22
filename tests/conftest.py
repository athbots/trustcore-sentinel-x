import sys
import os

# Ensure pytest can correctly resolve the TrustCore internal modules (infra.*, services.*, etc)
# This overrides the default module search to mimic FastAPI uvicorn execution paths.
backend_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend"))
if backend_path not in sys.path:
    sys.path.insert(0, backend_path)
