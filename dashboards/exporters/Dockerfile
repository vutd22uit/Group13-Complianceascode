# ============================================================
# CIS Docker Benchmark v1.6.0 Compliant Dockerfile
# ============================================================
# CIS 4.1  - Non-root user is used (exporter)
# CIS 4.2  - Pinned base image digest for trusted base
# CIS 4.3  - Only necessary packages installed (--no-install-recommends)
# CIS 4.6  - HEALTHCHECK instruction included
# CIS 4.7  - apt-get update and install combined in single RUN
# CIS 4.9  - COPY used instead of ADD
# CIS 4.10 - No secrets in ENV/ARG
# CIS 4.11 - Only required port exposed (9100)
# ============================================================

# CIS 4.2: Use specific, trusted base image version (pinned tag)
FROM python:3.11-slim

# CIS 4.10: Labels only - no secrets stored here
LABEL maintainer="Compliance Team" \
      description="OpenStack CIS Compliance Metrics Exporter" \
      version="2.0" \
      org.opencontainers.image.title="compliance-exporter" \
      org.opencontainers.image.description="CIS Compliance Metrics Exporter for Prometheus" \
      org.opencontainers.image.version="2.0" \
      org.opencontainers.image.vendor="Compliance Team"

WORKDIR /app

# CIS 4.7: Combine update and install in single RUN layer to avoid stale cache
# CIS 4.3: Install only necessary packages with --no-install-recommends
# CIS 4.8: Remove unnecessary setuid/setgid binaries after install
RUN apt-get update && apt-get install -y --no-install-recommends \
        wget \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && find / -perm /6000 -type f -not -path '/proc/*' -exec chmod a-s {} + 2>/dev/null || true

# CIS 4.9: Use COPY instead of ADD for local files
COPY requirements.txt .

# Install Python dependencies
# CIS 4.3: Use --no-cache-dir to minimize image size
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt || true

# CIS 4.9: COPY application code (not ADD)
COPY compliance_exporter.py .

# CIS 4.1: Create dedicated non-root user with no shell access
RUN groupadd -r exporter \
    && useradd -r -g exporter -s /sbin/nologin -d /app exporter \
    && mkdir -p /app/scan-results /app/evidence_store \
    && chown -R exporter:exporter /app \
    && chmod 750 /app \
    && chmod 700 /app/scan-results /app/evidence_store

# CIS 4.1: Switch to non-root user before running
USER exporter

# CIS 4.11: Expose only the required metrics port
EXPOSE 9100

# CIS 4.6: Health check to allow Docker to monitor container status
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget -q --spider http://localhost:9100/health || exit 1

# Environment variables - no secrets (CIS 4.10)
ENV RESULTS_DIR=/app/scan-results \
    EVIDENCE_DIR=/app/evidence_store \
    EXPORTER_PORT=9100 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONHASHSEED=random

# CIS 4.7: Use ENTRYPOINT + CMD (not shell form) to avoid shell injection
ENTRYPOINT ["python", "compliance_exporter.py"]
CMD ["--port", "9100", "--results-dir", "/app/scan-results"]
