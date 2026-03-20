"""
TrustCore Sentinel X — Custom Exceptions & Error Handlers
==========================================================
Centralizes all application-specific error types and
FastAPI exception handler registration.
"""

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse


# ── Domain Exceptions ──────────────────────────────────────────────────────

class SentinelBaseError(Exception):
    """Base class for all TrustCore Sentinel X errors."""
    status_code: int = 500
    error_code:  str = "INTERNAL_ERROR"

    def __init__(self, message: str):
        self.message = message
        super().__init__(message)

    def to_dict(self) -> dict:
        return {
            "error": self.error_code,
            "message": self.message,
            "status": self.status_code,
        }


class InvalidFeatureVectorError(SentinelBaseError):
    """Raised when the feature vector contains non-numeric or out-of-range values."""
    status_code = 422
    error_code  = "INVALID_FEATURES"


class ModelNotReadyError(SentinelBaseError):
    """Raised when an AI model has not been initialized before inference."""
    status_code = 503
    error_code  = "MODEL_NOT_READY"


class AnalysisPipelineError(SentinelBaseError):
    """Raised when the analysis pipeline fails unexpectedly."""
    status_code = 500
    error_code  = "ANALYSIS_PIPELINE_FAILURE"


# ── FastAPI Exception Handlers ──────────────────────────────────────────────

def register_exception_handlers(app: FastAPI) -> None:
    """
    Register custom exception handlers on the FastAPI application.
    Call this in main.py after creating the app instance.
    """

    @app.exception_handler(SentinelBaseError)
    async def sentinel_error_handler(
        request: Request, exc: SentinelBaseError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content=exc.to_dict(),
        )

    @app.exception_handler(ValueError)
    async def value_error_handler(
        request: Request, exc: ValueError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content={
                "error":   "VALIDATION_ERROR",
                "message": str(exc),
                "status":  422,
            },
        )
