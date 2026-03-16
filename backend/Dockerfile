# ── CloudGuard Backend — Dockerfile ───────────────────────────────────────────
# Cloud Computing: containerised microservice with health checks.

FROM python:3.11-slim

WORKDIR /app

# Install dependencies first (layer caching — only reinstalls on requirements change)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY . .

# Create directories for persistent key and model artefacts (mounted as volumes)
RUN mkdir -p keys model

EXPOSE 5001

# Health check — Nginx / load balancer uses this to verify container readiness
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5001/api/health')"

CMD ["python", "app.py"]
