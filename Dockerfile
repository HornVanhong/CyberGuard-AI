# Multi-stage secure build for CyberGuard AI
FROM python:3.12-slim AS builder

WORKDIR /build

# Install build dependencies for C-extensions (yara, etc.)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libtool \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# Final runtime image
FROM python:3.12-slim

# Install runtime utilities (exiftool, libmagic)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libimage-exiftool-perl \
    libmagic1 \
    && rm -rf /var/lib/apt/lists/*

# Create dedicated non-privileged user and group
RUN groupadd -g 10001 cyberguard && \
    useradd -u 10001 -g cyberguard -s /usr/sbin/nologin -d /app cyberguard

WORKDIR /app

# Copy installed python wheels from builder
COPY --from=builder /install /usr/local

# Copy application source code and rules
COPY --chown=cyberguard:cyberguard app/ /app/app/
COPY --chown=cyberguard:cyberguard rules/ /app/rules/
COPY --chown=cyberguard:cyberguard data/ /app/data/
COPY --chown=cyberguard:cyberguard temp_uploads/ /app/temp_uploads/

# Ensure safe permissions and ownership
RUN chown -R cyberguard:cyberguard /app && \
    chmod -R 755 /app && \
    chmod 775 /app/data /app/temp_uploads

# Run as non-root user
USER cyberguard:cyberguard

# Environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "from app.config import settings; print('CyberGuard config ok')" || exit 1

ENTRYPOINT ["python", "-m", "app.bot"]
