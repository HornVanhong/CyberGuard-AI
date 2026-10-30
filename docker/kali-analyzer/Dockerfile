# ==============================================================================
# CyberGuard AI — Dedicated Kali Linux Malware Analysis Container
# Base Image: Official Kali Linux Rolling (kalilinux/kali-rolling)
# ==============================================================================

FROM kalilinux/kali-rolling:latest

LABEL maintainer="CyberGuard AI Team"
LABEL description="Dedicated Kali Linux Container for Safe Malware Analysis & Reverse Engineering"
LABEL version="2.0.0"

ENV DEBIAN_FRONTEND=noninteractive \
    LC_ALL=C.UTF-8 \
    LANG=C.UTF-8 \
    PATH="/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin:/opt/venv/bin"

# 1. Configure reliable Fast CDN mirror & install baseline utilities
RUN sed -i 's|http://http.kali.org/kali/|http://kali.download/kali/|g' /etc/apt/sources.list.d/kali.sources && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        wget \
        gnupg \
        unzip \
        tar \
        git \
        jq \
        procps \
        build-essential \
        default-jre-headless && \
    rm -rf /var/lib/apt/lists/*

# 2. Install official Kali malware scanning and static analysis packages
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        clamav \
        clamav-freshclam \
        yara \
        libyara-dev \
        file \
        binutils \
        binwalk \
        libimage-exiftool-perl \
        bsdextrautils \
        xxd \
        detect-it-easy \
        radare2 \
        strace \
        ltrace \
        python3 \
        python3-pip \
        python3-venv \
        python3-dev \
        python3-yara \
        python3-requests \
        python3-magic && \
    rm -rf /var/lib/apt/lists/*

# 3. Install Linux Malware Detect (LMD / maldet) from official source
RUN curl -sSL https://www.rfxn.com/downloads/maldetect-current.tar.gz -o /tmp/maldet.tar.gz && \
    mkdir -p /tmp/maldet && \
    tar -xzf /tmp/maldet.tar.gz -C /tmp/maldet --strip-components=1 && \
    cd /tmp/maldet && \
    ./install.sh && \
    rm -rf /tmp/maldet /tmp/maldet.tar.gz && \
    ln -sf /usr/local/maldetect/maldet /usr/local/bin/maldet

# 4. Install Mandiant capa (official Linux standalone binary) & official rules
COPY tools/capa*.zip /tmp/
RUN if [ -f /tmp/capa.zip ]; then \
        unzip -q /tmp/capa.zip -d /usr/local/bin/ && \
        chmod 755 /usr/local/bin/capa && \
        rm -f /tmp/capa.zip; \
    else \
        curl -sSL https://github.com/mandiant/capa/releases/download/v10.0.0/capa-v10.0.0-linux.zip -o /tmp/capa.zip && \
        unzip -q /tmp/capa.zip -d /usr/local/bin/ && \
        chmod 755 /usr/local/bin/capa && \
        rm -f /tmp/capa.zip; \
    fi && \
    mkdir -p /opt/rules/capa-rules && \
    if [ -f /tmp/capa-rules.zip ]; then \
        unzip -q /tmp/capa-rules.zip -d /tmp/capa-rules-tmp && \
        mv /tmp/capa-rules-tmp/capa-rules-*/* /opt/rules/capa-rules/ && \
        rm -rf /tmp/capa-rules*; \
    else \
        curl -sSL https://github.com/mandiant/capa-rules/archive/refs/tags/v10.0.0.zip -o /tmp/capa-rules.zip && \
        unzip -q /tmp/capa-rules.zip -d /tmp/capa-rules-tmp && \
        mv /tmp/capa-rules-tmp/capa-rules-*/* /opt/rules/capa-rules/ && \
        rm -rf /tmp/capa-rules*; \
    fi

# 5. Create isolated Python virtual environment for security libraries
RUN python3 -m venv --system-site-packages /opt/venv && \
    /opt/venv/bin/pip install --no-cache-dir --retries 5 --timeout 60 \
        puremagic \
        oletools

# 6. Install Ghidra SRE Headless (optional build arg, default: true)
ARG INSTALL_GHIDRA=true
COPY tools/ghidra.zip* /tmp/
RUN if [ "$INSTALL_GHIDRA" = "true" ] && [ -f /tmp/ghidra.zip ]; then \
        echo "Installing Ghidra from local archive..." && \
        mkdir -p /opt && \
        unzip -q /tmp/ghidra.zip -d /opt && \
        mv /opt/ghidra_* /opt/ghidra && \
        rm -f /tmp/ghidra.zip && \
        chmod -R 755 /opt/ghidra && \
        ln -sf /opt/ghidra/support/analyzeHeadless /usr/local/bin/analyzeHeadless; \
    else \
        echo "Skipping Ghidra archive unpack"; \
    fi

# 7. Initialize default YARA rules directory
COPY rules/ /opt/rules/yara/

# 8. Create unprivileged analysis user & set strict directory permissions
RUN groupadd -g 10002 analyzer && \
    useradd -u 10002 -g analyzer -s /bin/bash -m -d /home/analyzer analyzer && \
    mkdir -p /samples /reports /logs /tmp/analysis && \
    chown -R analyzer:analyzer /home/analyzer /reports /logs /tmp/analysis /opt/rules && \
    chmod 770 /reports /logs /tmp/analysis && \
    chmod 755 /opt/rules && \
    chmod 555 /samples

# 9. Copy scanner CLI engine, entrypoint, and verification scripts
COPY docker/kali-analyzer/kali_scanner.py /usr/local/bin/kali_scanner.py
COPY scripts/check_tools.sh /usr/local/bin/check_tools.sh
COPY docker/kali-analyzer/entrypoint.sh /usr/local/bin/entrypoint.sh

RUN chmod 755 /usr/local/bin/kali_scanner.py \
              /usr/local/bin/check_tools.sh \
              /usr/local/bin/entrypoint.sh && \
    ln -sf /usr/local/bin/kali_scanner.py /usr/local/bin/kali-scan

# 10. Switch to non-root user
USER analyzer:analyzer
WORKDIR /home/analyzer

ENV HOME=/home/analyzer \
    TMPDIR=/tmp \
    JAVA_TOOL_OPTIONS="-Duser.home=/tmp/analysis"

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["python3", "/usr/local/bin/kali_scanner.py", "--help"]
