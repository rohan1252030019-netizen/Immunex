# ─────────────────────────────────────────────────────────────────────────────
# IMMUNEX Layer 5 — Production Dockerfile
# CPU-only, air-gapped compatible, enterprise-safe
# ─────────────────────────────────────────────────────────────────────────────

FROM python:3.11-slim-bookworm

# Metadata
LABEL org.opencontainers.image.title="IMMUNEX Autonomous SOC"
LABEL org.opencontainers.image.version="5.0.0-LAYER5"
LABEL org.opencontainers.image.description="Self-Evolving Autonomous Cyber-Defense System with Zero-Trust SOC Operations"

# ── System dependencies (minimal, no GPU) ─────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libgomp1 \
        curl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# ── Python environment ────────────────────────────────────────────────────────
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# ── Install Python deps (CPU-only torch) ─────────────────────────────────────
COPY requirements.txt .

# Install CPU-only PyTorch first (avoids pulling CUDA weights)
RUN pip install --no-cache-dir \
    torch --index-url https://download.pytorch.org/whl/cpu

# Install remaining dependencies
RUN pip install --no-cache-dir -r requirements.txt

# ── Copy application source ───────────────────────────────────────────────────
COPY . .

# ── Create data directories ───────────────────────────────────────────────────
RUN mkdir -p \
    data/logs \
    data/models \
    data/baseline_vectors \
    data/memory \
    data/drift \
    data/retrain_archive \
    data/mutations \
    data/reports

# ── Non-root user for security ────────────────────────────────────────────────
RUN useradd -m -u 1001 immunex && chown -R immunex:immunex /app
USER immunex

# ── Health check ──────────────────────────────────────────────────────────────
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# ── Ports ─────────────────────────────────────────────────────────────────────
EXPOSE 8080

# ── Default: run pipeline + API ───────────────────────────────────────────────
CMD ["python", "main.py", "--api"]
