# AgentShield Governance Control Plane Dockerfile
FROM python:3.11-slim AS base

# Install security updates and curl for container health check
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Create non-root user and group
RUN groupadd -g 10001 agentshield && \
    useradd -u 10001 -g agentshield -s /bin/bash -m agentshield

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY . .

# Set permissions for data directory and runtime
RUN mkdir -p /app/data && chown -R agentshield:agentshield /app

USER agentshield

# Default environment configuration
ENV PYTHONUNBUFFERED=1 \
    DATABASE_PATH=/app/data/state.db \
    PORT=8000

EXPOSE 8000

# Built-in Docker healthcheck on /healthz
HEALTHCHECK --interval=15s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/healthz || exit 1

# Start the AgentShield ASGI application
CMD ["uvicorn", "api.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
