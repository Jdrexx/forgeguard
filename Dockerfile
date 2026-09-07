# ForgeGuard — Multi-stage Dockerfile
#
# Build stage: install dependencies and compile
# Runtime stage: Python alpine with non-root user
#
# All base images pinned to digest for immutability and supply-chain security.
# Base: python:3.14-alpine (musl) — reduces the grype OS-package surface from
# ~277 matches (10 critical / 63 high on slim-bookworm) to ~9 (0 critical /
# 0 high after apk upgrade). apk upgrade pulls the latest alpine point
# releases so image-embedded CVEs (e.g. libuuid) are cleared at build time.

# ── Stage 1: Build ─────────────────────────────────────────────────────
FROM python:3.14-alpine@sha256:c6ead215bfd31f1e433d968853b7a769989117115b728874824e6c0a27cb96fc AS builder

WORKDIR /build

# Install build dependencies (musl-dev for any sdist builds)
RUN apk add --no-cache gcc musl-dev

# Copy dependency manifest and install
COPY requirements.txt .
RUN pip install --no-cache-dir --user --upgrade pip && \
    pip install --no-cache-dir --user -r requirements.txt

# Copy application code
COPY security/ security/
COPY app/ app/
COPY policy/ policy/

# ── Stage 2: Runtime ───────────────────────────────────────────────────
FROM python:3.14-alpine@sha256:c6ead215bfd31f1e433d968853b7a769989117115b728874824e6c0a27cb96fc AS runtime

# Pull latest alpine point releases (clears image-snapshot CVEs like libuuid)
RUN apk upgrade --no-cache

# Create non-root user
RUN addgroup -g 10001 forgeguard && \
    adduser -D -u 10001 -G forgeguard -s /sbin/nologin -h /home/forgeguard forgeguard

# Copy installed packages from builder
COPY --from=builder /root/.local /home/forgeguard/.local

# Copy application
COPY --from=builder /build/security /app/security
COPY --from=builder /build/app /app/app
COPY --from=builder /build/policy /app/policy

WORKDIR /app

ENV PATH="/home/forgeguard/.local/bin:${PATH}" \
    PYTHONPATH="/app" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEMO_MODE=0

# Switch to non-root user
USER forgeguard

# No shell access — /sbin/nologin
# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/livez')" \
    || exit 1

# FastAPI with uvicorn
EXPOSE 8000
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
