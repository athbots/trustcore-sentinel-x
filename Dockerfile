# ── TrustCore Sentinel X — Dockerfile ────────────────────────────────────────
# Multi-stage build: lean final image running the sentinel package

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

# Copy ALL application source packages
COPY sentinel/   ./sentinel/
COPY backend/    ./backend/
COPY frontend/   ./frontend/
COPY models/     ./models/
COPY engine/     ./engine/
COPY data/       ./data/

# Create writable directories (logs, app config)
RUN mkdir -p /app/logs /tmp/sentinel-data

# Set env so sentinel config writes to a writable location (not /root)
ENV SENTINEL_DATA_DIR=/tmp/sentinel-data

# Non-root user for security
RUN addgroup --system sentinel && adduser --system --ingroup sentinel sentinel
USER sentinel

# Expose application port
EXPOSE 8000

# Health check — lightweight /health endpoint
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=5 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

# Start the server — binds to all interfaces on port 8000
CMD ["uvicorn", "sentinel.app:app", "--host", "0.0.0.0", "--port", "8000"]
