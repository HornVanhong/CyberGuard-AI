# CyberGuard AI — YARA Detection Rules

## Overview
This directory contains modular YARA rules curated for detecting malicious files, weaponized documents, webshells, and dangerous payload scripts.

## Rules Inventory
- `malicious_scripts.yar`: Signatures for PHP webshells, PowerShell obfuscation, and reverse shells.
- `suspicious_pe.yar`: Signatures for suspicious PE executable characteristics, packer headers, and ransomware artifacts.
- `suspicious_office.yar`: Signatures for weaponized Office documents, embedded executables, and auto-executing macros.
- `test_fixtures.yar`: Synthetic, harmless signatures designed for automated pipeline testing.

## Licensing & Attribution
- Custom rules created for the CyberGuard AI project.
- Community patterns adapted under Apache 2.0 / BSD 3-Clause licenses.
- Attribution to Florian Roth (Neo23x0 / signature-base) and the YARA-Rules project where patterns are derived from community research.

## Guidelines
- Avoid treating single generic strings as definitive proof of malware.
- All rules must include `meta` tags with `description`, `severity`, `author`, and `reference`.
- Never submit confidential internal signatures to public feeds without sanitation.
