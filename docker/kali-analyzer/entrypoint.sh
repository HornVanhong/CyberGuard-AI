#!/usr/bin/env bash
# Entrypoint for CyberGuard AI Kali Malware Analysis Container

set -e

# Ensure analysis workspace permissions if writable
mkdir -p /tmp/analysis 2>/dev/null || true
mkdir -p /reports 2>/dev/null || true
mkdir -p /logs 2>/dev/null || true
chmod 770 /tmp/analysis 2>/dev/null || true
chmod 770 /reports 2>/dev/null || true
chmod 770 /logs 2>/dev/null || true

# If arguments passed, execute them
if [ "$#" -gt 0 ]; then
    exec "$@"
fi

# Default mode: Keep container listening or run check_tools
echo "🛡️ CyberGuard AI Kali Malware Analysis Container Ready"
echo "Usage: docker run --rm -v /path/to/sample:/samples/sample.bin:ro cyberguard-kali-analyzer /samples/sample.bin"
exec tail -f /dev/null
