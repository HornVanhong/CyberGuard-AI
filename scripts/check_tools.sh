#!/usr/bin/env bash
# ==============================================================================
# CyberGuard AI — Kali Malware Analysis Environment Tool Verification Script
# ==============================================================================
# Verifies installation, versions, and readiness of all security tools.
# Safe to execute repeatedly without modifying system state.
# ==============================================================================

set -o pipefail

# ANSI Color Codes
GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[1;33m"
CYAN="\033[0;36m"
BOLD="\033[1m"
RESET="\033[0m"

TOTAL_CHECKS=0
PASSED_CHECKS=0
WARNINGS=0
ERRORS=0

log_header() {
    echo -e "\n${BOLD}${CYAN}=== $1 ===${RESET}"
}

check_tool() {
    local name="$1"
    local bin="$2"
    local ver_cmd="$3"
    local is_optional="${4:-false}"

    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    echo -n "  Checking $name ($bin)... "

    if command -v "$bin" >/dev/null 2>&1; then
        local version=""
        if [ -n "$ver_cmd" ]; then
            version=$(eval "$ver_cmd" 2>/dev/null | head -n 1 | tr -d '\r\n')
        fi
        if [ -n "$version" ]; then
            echo -e "${GREEN}✓ Ready${RESET} (${CYAN}${version}${RESET})"
        else
            echo -e "${GREEN}✓ Ready${RESET}"
        fi
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
        return 0
    else
        if [ "$is_optional" = "true" ]; then
            echo -e "${YELLOW}○ Optional (Not installed)${RESET}"
            WARNINGS=$((WARNINGS + 1))
        else
            echo -e "${RED}✗ Missing${RESET}"
            ERRORS=$((ERRORS + 1))
        fi
        return 1
    fi
}

echo -e "${BOLD}=================================================================="
echo -e "       CyberGuard AI — Kali Security Tools Verification"
echo -e "==================================================================${RESET}"
echo -e "Host / Container: $(uname -s) $(uname -r) ($(uname -m))"
echo -e "Operating System: $(grep -oP 'PRETTY_NAME="\K[^"]+' /etc/os-release 2>/dev/null || cat /etc/os-release 2>/dev/null | head -n1 || echo 'Unknown')"
echo -e "Execution Time:   $(date -u '+%Y-%m-%d %H:%M:%S UTC')"

# ------------------------------------------------------------------------------
# 1. Malware Scanning Engines
# ------------------------------------------------------------------------------
log_header "1. Malware Scanning Engines"

check_tool "ClamAV Scanner" "clamscan" "clamscan --version | cut -d'/' -f1"
check_tool "ClamAV Freshclam" "freshclam" "freshclam --version | cut -d'/' -f1"
check_tool "YARA Pattern Scanner" "yara" "yara --version"
check_tool "Linux Malware Detect" "maldet" "maldet --help | grep -i 'linux malware detect' | head -n1" "true"

# Check ClamAV Virus Signatures
echo -n "  Checking ClamAV Signature Database... "
CLAMAV_DIR="/var/lib/clamav"
if [ -d "$CLAMAV_DIR" ] && [ -n "$(ls -A "$CLAMAV_DIR" 2>/dev/null)" ]; then
    SIG_COUNT=$(ls -1 "$CLAMAV_DIR"/*.cld "$CLAMAV_DIR"/*.cvd 2>/dev/null | wc -l)
    if [ "$SIG_COUNT" -gt 0 ]; then
        echo -e "${GREEN}✓ Initialized${RESET} ($SIG_COUNT database files present)"
    else
        echo -e "${YELLOW}○ Directory exists but no .cvd/.cld files yet${RESET}"
    fi
else
    echo -e "${YELLOW}○ Database empty (run freshclam to update)${RESET}"
fi

# ------------------------------------------------------------------------------
# 2. Static Analysis & File Inspection
# ------------------------------------------------------------------------------
log_header "2. Static Analysis & File Inspection"

check_tool "file utility" "file" "file --version | head -n1"
check_tool "strings utility" "strings" "strings --version | head -n1"
check_tool "binwalk" "binwalk" "binwalk --help | head -n2 | tail -n1"
check_tool "ExifTool" "exiftool" "exiftool -ver"
check_tool "hexdump" "hexdump" "hexdump -v --version 2>&1 | head -n1"
check_tool "xxd" "xxd" "xxd -v 2>&1 | head -n1"
check_tool "Detect It Easy (diec)" "diec" "diec --version 2>&1 | head -n1"
check_tool "Mandiant capa" "capa" "capa --version 2>&1 | head -n1"

# Check capa rules
echo -n "  Checking Mandiant capa rules... "
if [ -d "/opt/rules/capa-rules" ] && [ -n "$(ls -A "/opt/rules/capa-rules" 2>/dev/null)" ]; then
    RULE_COUNT=$(find /opt/rules/capa-rules -name "*.yml" -o -name "*.yaml" | wc -l)
    echo -e "${GREEN}✓ Ready${RESET} ($RULE_COUNT rule files in /opt/rules/capa-rules)"
else
    echo -e "${YELLOW}○ Not found in /opt/rules/capa-rules${RESET}"
fi

# ------------------------------------------------------------------------------
# 3. Reverse Engineering & Binary Inspection
# ------------------------------------------------------------------------------
log_header "3. Reverse Engineering & Binary Inspection"

check_tool "Radare2" "r2" "r2 -v | head -n1"
check_tool "rabin2" "rabin2" "rabin2 -v | head -n1"
check_tool "Ghidra Headless (SRE)" "analyzeHeadless" "analyzeHeadless -h 2>&1 | head -n1" "true"

# ------------------------------------------------------------------------------
# 4. System Tracing & Forensics
# ------------------------------------------------------------------------------
log_header "4. System Tracing & Forensics"

check_tool "strace" "strace" "strace -V | head -n1"
check_tool "ltrace" "ltrace" "ltrace -V 2>&1 | head -n1"

# ------------------------------------------------------------------------------
# 5. Supporting Tools & Python Runtime
# ------------------------------------------------------------------------------
log_header "5. Supporting Tools & Python Runtime"

check_tool "Python 3" "python3" "python3 --version"
check_tool "pip package manager" "pip3" "pip3 --version | cut -d' ' -f1,2"
check_tool "binutils" "objdump" "objdump --version | head -n1"

# Check Python security packages
echo -n "  Checking Python yara-python module... "
if python3 -c "import yara; print(yara.__version__)" 2>/dev/null; then
    echo -e "${GREEN}✓ Installed${RESET} (yara-python $(python3 -c "import yara; print(yara.__file__)" 2>/dev/null))"
else
    echo -e "${YELLOW}○ Not found in system python (may be inside /opt/venv)${RESET}"
fi

# Check /opt/venv if present
if [ -d "/opt/venv" ]; then
    echo -n "  Checking Container /opt/venv Python Environment... "
    if /opt/venv/bin/python3 -c "import yara, puremagic; print('OK')" 2>/dev/null; then
        echo -e "${GREEN}✓ Operational${RESET} (isolated analyzer venv)"
    else
        echo -e "${YELLOW}○ Virtual environment present${RESET}"
    fi
fi

# ------------------------------------------------------------------------------
# Verification Summary
# ------------------------------------------------------------------------------
echo -e "\n${BOLD}=================================================================="
echo -e "                     Verification Summary"
echo -e "==================================================================${RESET}"
echo -e "  Total Checks:    ${BOLD}$TOTAL_CHECKS${RESET}"
echo -e "  Passed:          ${GREEN}${BOLD}$PASSED_CHECKS${RESET}"
echo -e "  Warnings:        ${YELLOW}${BOLD}$WARNINGS${RESET}"
echo -e "  Missing/Errors:  ${RED}${BOLD}$ERRORS${RESET}"

if [ "$ERRORS" -eq 0 ]; then
    echo -e "\n${GREEN}${BOLD}✓ ALL REQUIRED SECURITY TOOLS ARE INSTALLED AND OPERATIONAL!${RESET}\n"
    exit 0
else
    echo -e "\n${RED}${BOLD}✗ SOME CRITICAL TOOLS ARE MISSING. REVIEW OUTPUT ABOVE.${RESET}\n"
    exit 1
fi
