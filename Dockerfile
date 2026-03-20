# ── TrustCore Sentinel X — Dockerfile ────────────────────────────────────────
# Multi-stage build: keeps the final image lean (~200MB vs ~800MB)

# ── Stage 1: Builder ──────────────────────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /app

# Install build deps only in the builder stage
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy and install Python deps into a virtual env
COPY requirements.txt .
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt


# ── Stage 2: Runtime ──────────────────────────────────────────────────────────
FROM python:3.11-slim AS runtime

LABEL maintainer="TrustCore AI <team@trustcoreai.io>"
LABEL org.opencontainers.image.title="TrustCore Sentinel X"
LABEL org.opencontainers.image.description="AI-powered autonomous cyber defense system"
LABEL org.opencontainers.image.licenses="MIT"

WORKDIR /app

# Copy virtual env from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy application source
COPY backend/   ./backend/
COPY frontend/  ./frontend/

# Create log directory
RUN mkdir -p /app/logs

# Non-root user for security
RUN addgroup --system sentinel && adduser --system --ingroup sentinel sentinel
USER sentinel

# Expose application port
EXPOSE 8000

# Health check — hits system_status every 30s
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/system_status')" || exit 1

# Start the server
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
