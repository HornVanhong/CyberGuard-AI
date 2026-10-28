"""CyberGuard AI - Internationalization Module.

Provides English (en) and Khmer (km) translations for Telegram bot messages,
scan status descriptions, risk levels, and security recommendations.
"""

from __future__ import annotations

from typing import Dict, Any

MESSAGES: Dict[str, Dict[str, str]] = {
    "en": {
        # Commands
        "start_title": "🛡️ *CyberGuard AI — Malware Scanner Bot*",
        "start_intro": (
            "Welcome! I am CyberGuard AI, an advanced security bot designed to inspect "
            "files for malware, viruses, suspicious scripts, and dangerous payloads *before* "
            "you open them."
        ),
        "start_capabilities": (
            "✨ *Core Capabilities:*\n"
            "• ClamAV Antivirus signature scanning\n"
            "• YARA pattern & malware heuristics matching\n"
            "• Script inspection (PowerShell, JS, Python, Shell, PHP)\n"
            "• Document analysis (PDF streams, Office VBA macros, embedded objects)\n"
            "• Archive safety analysis (Zip bomb & path traversal detection)\n"
            "• Optional VirusTotal Threat Intelligence\n"
            "• Optional AI-powered risk explanations"
        ),
        "start_limits": (
            "📏 *Limits & Formats:*\n"
            "• Max file size: {max_size_mb} MB\n"
            "• Supported formats: `.exe`, `.dll`, `.pdf`, `.docx`, `.xlsx`, `.zip`, `.tar`, `.py`, `.js`, `.ps1`, `.sh`, `.php`, etc."
        ),
        "start_privacy_notice": (
            "🔒 *Privacy Guarantee:*\n"
            "Files are analyzed in an isolated sandbox and immediately deleted upon scan completion. "
            "Original file contents are *never* permanently stored or shared without your explicit consent."
        ),
        "start_prompt": "📤 *Send or forward any file or document to begin scanning.*",
        
        # Help
        "help_title": "📚 *CyberGuard AI — Help & Guide*",
        "help_how_to": (
            "📌 *How to scan a file:*\n"
            "1. Simply upload or forward any file/document to this chat.\n"
            "2. Wait for the automated pipeline to analyze it.\n"
            "3. Receive a comprehensive security report."
        ),
        "help_commands": (
            "⌨️ *Available Commands:*\n"
            "• /scan — Prompt file upload\n"
            "• /status — Check scanning engine health & signatures\n"
            "• /history — View your recent scan records\n"
            "• /privacy — Review data retention & privacy policies\n"
            "• /cleardata — Delete your scan history records\n"
            "• /lang — Switch language (English / ខ្មែរ)\n"
            "• /help — Show this help message"
        ),
        "help_verdicts": (
            "🚦 *Risk Levels Explained:*\n"
            "🔴 *CRITICAL / HIGH* — Known malware or active threat patterns detected.\n"
            "🟡 *MEDIUM / LOW* — Suspicious indicators (e.g. embedded scripts, macros, obfuscation).\n"
            "🟢 *LOW (NO KNOWN THREAT)* — No known threats detected by enabled engines.\n"
            "⚪ *INCONCLUSIVE* — Analysis could not be fully completed."
        ),
        "help_disclaimer": "⚠️ *Disclaimer:* No automated scanner guarantees 100% safety. Exercise zero-trust caution.",

        # Status
        "status_title": "⚙️ *CyberGuard AI — Engine Health Status*",
        "status_clamav": "• ClamAV Antivirus: {clamav_status} ({clamav_version})",
        "status_yara": "• YARA Rules Engine: {yara_status} ({yara_rules_count} rules loaded)",
        "status_vt": "• VirusTotal Threat Intel: {vt_status}",
        "status_ai": "• AI Security Explanations: {ai_status} ({ai_model})",
        "status_db": "• Audit Database: {db_status}",

        # Privacy
        "privacy_title": "🔐 *CyberGuard AI — Privacy & Security Policy*",
        "privacy_content": (
            "1. *Zero File Retention:* Uploaded files are downloaded into an isolated temporary "
            "directory and deleted immediately after the scan finishes.\n\n"
            "2. *Audit Records:* We record only your Telegram User ID, sanitized filename, file size, "
            "SHA-256 hash, and scan verdict. You can erase your history at any time with `/cleardata`.\n\n"
            "3. *External Services:* By default, files are analyzed locally. External threat lookups "
            "(VirusTotal) only query the cryptographic SHA-256 hash. Files are *never* uploaded to "
            "third parties without explicit consent.\n\n"
            "4. *AI Analysis:* Only structured, sanitized scanner metadata is sent to the AI explanation "
            "engine; raw file contents and personal credentials are never transmitted."
        ),

        # Progress Messages
        "progress_starting": "🔄 Initializing secure scan environment...",
        "progress_downloading": "📥 Downloading file ({size_mb} MB)...",
        "progress_hashing": "🔐 Calculating SHA-256 hash & validating file signature...",
        "progress_scanning": "🔍 Scanning with ClamAV and YARA rules...",
        "progress_deep_analysis": "🔬 Performing format-specific static analysis...",
        "progress_vt": "🌐 Querying Threat Intelligence databases...",
        "progress_correlating": "⚖️ Correlating findings and evaluating risk score...",
        "progress_complete": "✅ Analysis complete. Generating security report...",

        # Rate Limiting & Auth
        "rate_limited": "⏳ Rate limit exceeded. Please wait {wait_seconds} seconds before submitting another file.",
        "file_too_large": "❌ File is too large! Maximum allowed size is {max_mb} MB (received {actual_mb} MB).",
        "unauthorized": "⛔ You are not authorized to use this bot.",
        "scan_failed": "⚠️ Scan could not be completed: {error}",

        # Report Strings
        "report_header": "🛡️ *CYBERGUARD AI — SECURITY REPORT*",
        "report_file": "📄 *File:* `{filename}`",
        "report_size": "📦 *Size:* {size_str}",
        "report_type": "🗂 *Actual Type:* {file_type}",
        "report_hash": "🔐 *SHA-256:*\n`{sha256}`",
        "report_divider": "━━━━━━━━━━━━━━━━━━",
        "report_results_title": "🔍 *SCAN RESULTS*",
        "report_clamav": "ClamAV: {result}",
        "report_yara": "YARA: {result}",
        "report_static": "Format Analysis: {result}",
        "report_vt": "VirusTotal: {result}",
        "report_verdict": "🚦 *VERDICT:* {verdict}",
        "report_risk": "⚠️ *Risk Level:* {risk_level}",
        "report_score": "📊 *Threat Score:* {score}/100",
        "report_findings_title": "📝 *Findings:*",
        "report_recommendations_title": "💡 *Recommendations:*",
        "report_confidence": "Confidence: {confidence}",
        "report_scan_id": "Scan ID: `{scan_id}`",
        "report_disclaimer": "⚠️ *Note:* No detection does not guarantee that a file is safe.",

        # Button Labels
        "btn_ai_explain": "🤖 Explain with AI",
        "btn_vt_lookup": "🌐 VirusTotal Lookup",
        "btn_delete_history": "🗑️ Clear My History",
        "history_empty": "📭 You have no scan history records.",
        "history_title": "📜 *Your Recent Scan History:*",
        "history_cleared": "✅ Your scan history records have been completely erased.",
    },
    "km": {
        # Khmer Translations
        "start_title": "🛡️ *CyberGuard AI — បូតត្រួតពិនិត្យមេរោគ*",
        "start_intro": (
            "សូមស្វាគមន៍! ខ្ញុំជា CyberGuard AI ដែលជាបូតសុវត្ថិភាពស្វ័យប្រវត្ត "
            "សម្រាប់ត្រួតពិនិត្យឯកសារស្វែងរកមេរោគ (Malware, Virus, Scripts) និងឯកសារគ្រោះថ្នាក់ "
            "មុនពេលអ្នកបើកវា។"
        ),
        "start_capabilities": (
            "✨ *សមត្ថភាពចម្បង:*\n"
            "• ស្កេនមេរោគតាម ClamAV Antivirus\n"
            "• ផ្គូផ្គងលក្ខណៈគ្រោះថ្នាក់តាម YARA Rules\n"
            "• វិភាគស្គ្រីប (PowerShell, JS, Python, Shell, PHP)\n"
            "• វិភាគឯកសារ PDF និង Microsoft Office (VBA Macros)\n"
            "• ត្រួតពិនិត្យឯកសារបង្រួម Archive (Zip bomb & Path traversal)\n"
            "• ស្រាវជ្រាវប្រភព VirusTotal Threat Intelligence\n"
            "• ពន្យល់លទ្ធផលសុវត្ថិភាពដោយ AI"
        ),
        "start_limits": (
            "📏 *ទំហំ និងប្រភេទឯកសារ:*\n"
            "• ទំហំអតិបរមា: {max_size_mb} MB\n"
            "• ប្រភេទគាំទ្រ: `.exe`, `.dll`, `.pdf`, `.docx`, `.xlsx`, `.zip`, `.tar`, `.py`, `.js`, `.ps1`, `.sh`, `.php` ។ល។"
        ),
        "start_privacy_notice": (
            "🔒 *ការធានាឯកជនភាព:*\n"
            "ឯកសារត្រូវបានវិភាគក្នុងប្រព័ន្ធសុវត្ថិភាពដាច់ដោយឡែក ហើយត្រូវបានលុបចោលភ្លាមៗបន្ទាប់ពីស្កេនចប់។ "
            "ឯកសារដើមរបស់អ្នកមិនត្រូវបានរក្សាទុកជាអចិន្ត្រៃយ៍ឡើយ។"
        ),
        "start_prompt": "📤 *សូមផ្ញើឯកសារណាមួយដើម្បីចាប់ផ្តើមការស្កេន។*",

        "help_title": "📚 *CyberGuard AI — សេចក្តីណែនាំ*",
        "help_how_to": (
            "📌 *របៀបស្កេនឯកសារ:*\n"
            "1. ផ្ញើ ឬបញ្ជូនបន្ត (Forward) ឯកសារណាមួយមកកាន់ទីនេះ។\n"
            "2. រង់ចាំប្រព័ន្ធស្វ័យប្រវត្តធ្វើការវិភាគ។\n"
            "3. ទទួលរបាយការណ៍សុវត្ថិភាពលម្អិត។"
        ),
        "help_commands": (
            "⌨️ *ពាក្យបញ្ជាដែលមាន:*\n"
            "• /scan — ចាប់ផ្តើមស្កេនឯកសារ\n"
            "• /status — ពិនិត្យស្ថានភាពម៉ាស៊ីនស្កេន\n"
            "• /history — មើលប្រវត្តិស្កេនរបស់អ្នក\n"
            "• /privacy — អានគោលការណ៍ឯកជនភាព\n"
            "• /cleardata — លុបប្រវត្តិស្កេនរបស់អ្នកចោល\n"
            "• /lang — ផ្លាស់ប្តូរភាសា\n"
            "• /help — បង្ហាញជំនួយ"
        ),
        "help_verdicts": (
            "🚦 *កម្រិតហានិភ័យ:*\n"
            "🔴 *CRITICAL / HIGH* — រកឃើញមេរោគ ឬកូដគ្រោះថ្នាក់ជាក់លាក់។\n"
            "🟡 *MEDIUM / LOW* — សង្ស័យ (មានបង្កប់ Scripts, Macros, កូដបិទបាំង)។\n"
            "🟢 *LOW (NO KNOWN THREAT)* — មិនមានរកឃើញការគំរាមកំហែងដែលស្គាល់។\n"
            "⚪ *INCONCLUSIVE* — មិនអាចបញ្ចប់ការវិភាគបានពេញលេញ។"
        ),
        "help_disclaimer": "⚠️ *ការបញ្ជាក់:* គ្មានម៉ាស៊ីនស្កេនណាធានាសុវត្ថិភាព 100% នោះទេ។ សូមប្រុងប្រយ័ត្នជានិច្ច។",

        "status_title": "⚙️ *CyberGuard AI — ស្ថានភាពម៉ាស៊ីនវិភាគ*",
        "status_clamav": "• ClamAV Antivirus: {clamav_status} ({clamav_version})",
        "status_yara": "• YARA Rules Engine: {yara_status} (មាន {yara_rules_count} rules)",
        "status_vt": "• VirusTotal Threat Intel: {vt_status}",
        "status_ai": "• AI Security Explanations: {ai_status} ({ai_model})",
        "status_db": "• Audit Database: {db_status}",

        "privacy_title": "🔐 *CyberGuard AI — គោលការណ៍ឯកជនភាព និងសុវត្ថិភាព*",
        "privacy_content": (
            "1. *មិនរក្សាទុកឯកសារ:* ឯកសារត្រូវបានទាញយកទៅកាន់ថតបណ្តោះអាសន្ន ហើយលុបចេញភ្លាមៗក្រោយពេលស្កេនចប់។\n\n"
            "2. *កំណត់ត្រាសវនកម្ម:* យើងកត់ត្រាតែ Telegram User ID, ឈ្មោះឯកសារ, ទំហំ, SHA-256 hash និងលទ្ធផលប៉ុណ្ណោះ។ អ្នកអាចលុបវាចោលដោយប្រើ `/cleardata`។\n\n"
            "3. *សេវាកម្មខាងក្រៅ:* តាមលំនាំដើម ការស្កេនធ្វើឡើងនៅក្នុងម៉ាស៊ីនមូលដ្ឋាន។ VirusTotal ស្វែងរកតែតាមលេខកូដសម្ងាត់ SHA-256 ប៉ុណ្ណោះ មិនបញ្ជូនឯកសារដើមឡើយ។\n\n"
            "4. *ការវិភាគ AI:* មានតែទិន្នន័យសង្ខេបគ្មានគ្រោះថ្នាក់ប៉ុណ្ណោះដែលត្រូវបានបញ្ជូនទៅ AI ពន្យល់។"
        ),

        "progress_starting": "🔄 កំពុងរៀបចំបរិស្ថានសុវត្ថិភាព...",
        "progress_downloading": "📥 កំពុងទាញយកឯកសារ ({size_mb} MB)...",
        "progress_hashing": "🔐 កំពុងគណនា SHA-256 និងផ្ទៀងផ្ទាត់ប្រភេទឯកសារ...",
        "progress_scanning": "🔍 កំពុងស្កេនជាមួយ ClamAV និង YARA rules...",
        "progress_deep_analysis": "🔬 កំពុងវិភាគរចនាសម្ព័ន្ធឯកសារ...",
        "progress_vt": "🌐 កំពុងស្វែងរកក្នុងប្រព័ន្ធ Threat Intelligence...",
        "progress_correlating": "⚖️ កំពុងវាយតម្លៃកម្រិតហានិភ័យ...",
        "progress_complete": "✅ ការវិភាគបានបញ្ចប់។ កំពុងបង្កើតរបាយការណ៍...",

        "rate_limited": "⏳ អ្នកបានផ្ញើញឹកញាប់ពេក។ សូមរង់ចាំ {wait_seconds} វិនាទីសិន។",
        "file_too_large": "❌ ឯកសារធំពេក! ទំហំអតិបរមាគឺ {max_mb} MB (ឯកសាររបស់អ្នកមាន {actual_mb} MB)។",
        "unauthorized": "⛔ អ្នកមិនមានសិទ្ធិប្រើប្រាស់បូតនេះទេ។",
        "scan_failed": "⚠️ ការស្កេនមិនអាចបញ្ចប់បានទេ: {error}",

        "report_header": "🛡️ *CYBERGUARD AI — របាយការណ៍សុវត្ថិភាព*",
        "report_file": "📄 *ឯកសារ:* `{filename}`",
        "report_size": "📦 *ទំហំ:* {size_str}",
        "report_type": "🗂 *ប្រភេទពិត:* {file_type}",
        "report_hash": "🔐 *SHA-256:*\n`{sha256}`",
        "report_divider": "━━━━━━━━━━━━━━━━━━",
        "report_results_title": "🔍 *លទ្ធផលនៃការស្កេន*",
        "report_clamav": "ClamAV: {result}",
        "report_yara": "YARA: {result}",
        "report_static": "ការវិភាគរចនាសម្ព័ន្ធ: {result}",
        "report_vt": "VirusTotal: {result}",
        "report_verdict": "🚦 *សេចក្តីសន្និដ្ឋាន:* {verdict}",
        "report_risk": "⚠️ *កម្រិតហានិភ័យ:* {risk_level}",
        "report_score": "📊 *ពិន្ទុគ្រោះថ្នាក់:* {score}/100",
        "report_findings_title": "📝 *ចំណុចកត់សម្គាល់:*",
        "report_recommendations_title": "💡 *អនុសាសន៍:*",
        "report_confidence": "ទំនុកចិត្ត: {confidence}",
        "report_scan_id": "លេខសម្គាល់ស្កេន: `{scan_id}`",
        "report_disclaimer": "⚠️ *ចំណាំ:* មិនមានការរកឃើញ មិនមែនមានន័យថាឯកសារនេះមានសុវត្ថិភាព 100% នោះទេ។",

        "btn_ai_explain": "🤖 ពន្យល់ដោយ AI",
        "btn_vt_lookup": "🌐 ពិនិត្យលើ VirusTotal",
        "btn_delete_history": "🗑️ លុបប្រវត្តិរបស់ខ្ញុំ",
        "history_empty": "📭 អ្នកមិនមានប្រវត្តិស្កេនឯកសារនៅឡើយទេ។",
        "history_title": "📜 *ប្រវត្តិស្កេនថ្មីៗរបស់អ្នក:*",
        "history_cleared": "✅ ប្រវត្តិស្កេនរបស់អ្នកត្រូវបានលុបចេញទាំងស្រុង។",
    },
}

# User language preferences storage (in-memory with user_id -> lang)
_USER_LANG: Dict[int, str] = {}


def set_user_lang(user_id: int, lang: str) -> None:
    """Sets language preference for a Telegram user ('en' or 'km')."""
    if lang in MESSAGES:
        _USER_LANG[user_id] = lang


def get_user_lang(user_id: int, default: str = "en") -> str:
    """Retrieves language preference for a user."""
    return _USER_LANG.get(user_id, default)


def t(key: str, user_id: int | None = None, lang: str | None = None, **kwargs: Any) -> str:
    """Translates a message key according to the target language and formats placeholders."""
    if lang is None:
        lang = get_user_lang(user_id) if user_id is not None else "en"
    
    lang_dict = MESSAGES.get(lang, MESSAGES["en"])
    template = lang_dict.get(key, MESSAGES["en"].get(key, f"[{key}]"))
    
    if kwargs:
        try:
            return template.format(**kwargs)
        except Exception:
            return template
    return template
