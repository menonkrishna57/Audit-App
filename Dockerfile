# ==============================================================================
# Dockerfile for Audit-App
# Multi-stage / lightweight Python 3.11 container with Streamlit & Audit CLI
# ==============================================================================

FROM python:3.11-slim AS base

# Set environment flags
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    STREAMLIT_SERVER_PORT=8501 \
    STREAMLIT_SERVER_ADDRESS=0.0.0.0 \
    STREAMLIT_SERVER_HEADLESS=true \
    STREAMLIT_BROWSER_GATHER_USAGE_STATS=false

# Install minimal OS dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Create non-root application user
RUN groupadd -g 1000 appgroup && \
    useradd -u 1000 -g appgroup -m -s /bin/bash appuser

WORKDIR /app

# Copy dependency definition and install
COPY requirements.txt /app/
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY --chown=appuser:appgroup . /app/

# Create reports directory with appropriate permissions
RUN mkdir -p /app/reports && chown -R appuser:appgroup /app/reports

# Switch to non-root user
USER appuser

# Expose Streamlit dashboard port
EXPOSE 8501

# Container healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl --fail http://localhost:8501/_stcore/health || exit 1

# Default command launches the Streamlit web dashboard
CMD ["streamlit", "run", "app.py"]
