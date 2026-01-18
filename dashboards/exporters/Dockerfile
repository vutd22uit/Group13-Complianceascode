FROM python:3.11-slim

LABEL maintainer="Compliance Team"
LABEL description="OpenStack CIS Compliance Metrics Exporter"
LABEL version="2.0"

WORKDIR /app

# Install wget for health checks
RUN apt-get update && apt-get install -y --no-install-recommends wget && \
    rm -rf /var/lib/apt/lists/*

# Copy and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt || true

# Copy exporter code
COPY compliance_exporter.py .

# Create non-root user for security
RUN useradd -r -s /bin/false exporter && \
    mkdir -p /app/scan-results /app/evidence_store && \
    chown -R exporter:exporter /app

# Switch to non-root user
USER exporter

# Expose metrics port
EXPOSE 9100

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget -q --spider http://localhost:9100/health || exit 1

# Environment variables
ENV RESULTS_DIR=/app/scan-results
ENV EVIDENCE_DIR=/app/evidence_store
ENV EXPORTER_PORT=9100
ENV PYTHONUNBUFFERED=1

# Run exporter
ENTRYPOINT ["python", "compliance_exporter.py"]
CMD ["--port", "9100", "--results-dir", "/app/scan-results"]
