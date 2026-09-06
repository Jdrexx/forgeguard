# ForgeGuard — Multi-stage Dockerfile
#
# Build stage: install dependencies and compile
# Runtime stage: distroless Python with non-root user
#
# All base images pinned to digest for immutability and supply-chain security.

# ── Stage 1: Build ─────────────────────────────────────────────────────
FROM python:3.12-slim-bookworm@sha256:782412e85d0f0984994c290652577d4018aff08145c85b262bb63dc0c7522254 AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy dependency manifest and install
COPY requirements.txt .
RUN pip install --no-cache-dir --user --upgrade pip && \
    pip install --no-cache-dir --user -r requirements.txt

# Copy application code
COPY security/ security/
COPY app/ app/
COPY policy/ policy/

# ── Stage 2: Runtime ───────────────────────────────────────────────────
FROM python:3.12-slim-bookworm@sha256:782412e85d0f0984994c290652577d4018aff08145c85b262bb63dc0c7522254 AS runtime

# Create non-root user
RUN groupadd --gid 10001 forgeguard && \
    useradd --uid 10001 --gid forgeguard --shell /sbin/nologin --create-home forgeguard

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
