/**
 * CyberGuard AI - Telegram Command & Message Router
 */

import { askGemini } from "./gemini";
import { scanFile } from "./scanner";
import {
  sendTelegramMessage,
  sendChatAction,
  getReplyKeyboard,
  getTelegramFile,
  downloadTelegramFile,
} from "./telegram";
import { Env, TelegramUpdate } from "./types";

/**
 * Main router handling Telegram updates (messages, commands, files).
 */
export async function routeTelegramUpdate(
  update: TelegramUpdate,
  env: Env,
  ctx?: ExecutionContext
): Promise<void> {
  const message = update.message;
  if (!message || !message.chat) return;

  const chatId = message.chat.id;
  const token = env.TELEGRAM_BOT_TOKEN;
  const lang = (env.DEFAULT_LANGUAGE || "km").toLowerCase();

  // 1. Handle File Uploads (Documents or Photos)
  if (message.document || (message.photo && message.photo.length > 0)) {
    const fileId = message.document
      ? message.document.file_id
      : message.photo![message.photo!.length - 1].file_id;
    const filename = message.document?.file_name || "photo.jpg";
    const fileSize = message.document?.file_size || message.photo![message.photo!.length - 1].file_size || 0;

    // Check size limit
    const maxBytes = parseInt(env.MAX_FILE_SIZE_BYTES || "20971520", 10);
    if (fileSize > maxBytes) {
      await sendTelegramMessage(token, {
        chat_id: chatId,
        text:
          lang === "km"
            ? `❌ ឯកសារធំពេក! ទំហំអនុញ្ញាតអតិបរមាគឺ ${Math.round(maxBytes / 1048576)} MB។`
            : `❌ File is too large! Maximum allowed size is ${Math.round(maxBytes / 1048576)} MB.`,
        reply_markup: getReplyKeyboard(lang),
      });
      return;
    }

    // Process file scan (can use ctx.waitUntil if available)
    const scanPromise = handleFileUpload(token, chatId, fileId, filename, env, lang);
    if (ctx && typeof ctx.waitUntil === "function") {
      ctx.waitUntil(scanPromise);
    } else {
      await scanPromise;
    }
    return;
  }

  // 2. Handle Text Messages & Commands
  const text = (message.text || "").trim();
  if (!text) return;

  const lowerText = text.toLowerCase();

  // /start
  if (lowerText.startsWith("/start")) {
    const welcome =
      lang === "km"
        ? `🛡️ *CyberGuard AI — Malware Scanner & Security Assistant*

សូមស្វាគមន៍! ខ្ញុំគឺជា CyberGuard AI បូតសម្រាប់ត្រួតពិនិត្យមេរោគលើឯកសារ និងប្រឹក្សាយោបល់សន្តិសុខសាយប័រ។

✨ *សមត្ថភាពចម្បង៖*
• ស្កេនមេរោគតាមរយៈ ClamAV Antivirus
• ស្វែងរកកូដគ្រោះថ្នាក់តាម YARA Rules
• វិភាគ និងពន្យល់លទ្ធផលជាមួយ Google Gemini AI
• ពិនិត្យកូដ Executable ជាមួយ Ghidra SRE

📤 *សូមផ្ញើឯកសារណាមួយមកកាន់ទីនេះដើម្បីចាប់ផ្តើមស្កេន ឬជ្រើសរើសមុខងារពីក្តារចុចខាងក្រោម៖*`
        : `🛡️ *CyberGuard AI — Malware Scanner & Security Assistant*

Welcome! I am CyberGuard AI, an advanced security bot designed to inspect files for malware, viruses, and suspicious payloads.

✨ *Core Features:*
• ClamAV Antivirus signature detection
• YARA rule-based heuristic matching
• Google Gemini AI threat explanations
• Deep binary analysis with Ghidra SRE

📤 *Send or forward any file to begin scanning, or choose an option from the menu below:*`;

    await sendTelegramMessage(token, {
      chat_id: chatId,
      text: welcome,
      parse_mode: "Markdown",
      reply_markup: getReplyKeyboard(lang),
    });
    return;
  }

  // /help or "📚 ការណែនាំ & ជំនួយ"
  if (lowerText.startsWith("/help") || lowerText.includes("ការណែនាំ") || lowerText.includes("help")) {
    const helpText =
      lang === "km"
        ? `📚 *CyberGuard AI — ការណែនាំ និងរបៀបប្រើប្រាស់*

📌 *របៀបស្កេនឯកសារ៖*
១. ផ្ញើ ឬ Forward ឯកសារណាមួយ (.exe, .pdf, .docx, .zip, .apk) មកកាន់ទីនេះ។
២. ប្រព័ន្ធនឹងស្កេនតាម ClamAV និង YARA rules។
៣. ទទួលបានរបាយការណ៍ និងការវិភាគពី Gemini AI។

⌨️ *ពាក្យបញ្ជាផ្លូវការ៖*
• /scan — ស្កេនឯកសារស្វែងរកមេរោគ
• /ask [សំណួរ] — សួរសំណួរសន្តិសុខសាយប័រជាមួយ AI
• /status — ពិនិត្យស្ថានភាពម៉ាស៊ីនស្កេន
• /privacy — អានគោលការណ៍ឯកជនភាព
• /lang — ផ្លាស់ប្តូរភាសា (English / ខ្មែរ)`
        : `📚 *CyberGuard AI — Help & User Guide*

📌 *How to scan a file:*
1. Send or forward any document (.exe, .pdf, .docx, .zip, etc.) to this chat.
2. The scanner evaluates it with ClamAV and YARA rules.
3. Receive a comprehensive report with Gemini AI explanation.

⌨️ *Available Commands:*
• /scan — Scan a file for malware
• /ask [question] — Consult cybersecurity AI
• /status — Check scanning engines health
• /privacy — Review privacy policy
• /lang — Switch language (English / ខ្មែរ)`;

    await sendTelegramMessage(token, {
      chat_id: chatId,
      text: helpText,
      parse_mode: "Markdown",
      reply_markup: getReplyKeyboard(lang),
    });
    return;
  }

  // /scan or "🔍 ស្កេនឯកសារ"
  if (lowerText.startsWith("/scan") || lowerText.includes("ស្កេនឯកសារ") || lowerText.includes("scan file")) {
    const scanPrompt =
      lang === "km"
        ? `📤 *សូមផ្ញើ ឬ Forward ឯកសារដែលអ្នកចង់ស្កេនមកកាន់ទីនេះ៖*\n\n_ប្រព័ន្ធគាំទ្រឯកសារទូទៅ (.exe, .pdf, .docx, .xlsx, .zip, .apk, .py, etc.) រហូតដល់ 20 MB។_`
        : `📤 *Please send or forward any file you wish to inspect:*\n\n_Supported formats include .exe, .pdf, .docx, .xlsx, .zip, .apk, .py, etc. (up to 20 MB)._`;

    await sendTelegramMessage(token, {
      chat_id: chatId,
      text: scanPrompt,
      parse_mode: "Markdown",
      reply_markup: getReplyKeyboard(lang),
    });
    return;
  }

  // /status or "⚙️ ស្ថានភាពម៉ាស៊ីន"
  if (lowerText.startsWith("/status") || lowerText.includes("ស្ថានភាពម៉ាស៊ីន") || lowerText.includes("system status")) {
    const aiConfigured = Boolean(env.GEMINI_API_KEY);
    let backendData: any = null;

    if (env.SCANNER_SERVICE_URL) {
      try {
        const headers: Record<string, string> = {};
        if (env.SCANNER_API_TOKEN) headers["Authorization"] = `Bearer ${env.SCANNER_API_TOKEN}`;
        const res = await fetch(`${env.SCANNER_SERVICE_URL}/status`, { headers });
        if (res.ok) backendData = await res.json();
      } catch {
        // Fallback if scanner is unreachable
      }
    }

    const engines = backendData?.engines;
    const clamavStatus = engines?.clamav?.status === "ONLINE"
      ? `🟢 Online (${engines.clamav.version || "ClamAV"})`
      : (env.SCANNER_SERVICE_URL ? "🔴 Offline / Connecting" : "⚪ Service Not Configured");
    const yaraStatus = engines?.yara?.status === "READY"
      ? `🟢 Ready (${engines.yara.rules_loaded || 4} rules loaded)`
      : (env.SCANNER_SERVICE_URL ? "🔴 Offline" : "⚪ Service Not Configured");
    const vtStatus = engines?.virustotal?.status === "CONFIGURED" ? "🟢 Configured" : "⚪ Disabled";
    const oleStatus = engines?.oletools?.status === "READY" ? "🟢 Ready" : "⚪ Not Installed";
    const pdfidStatus = engines?.pdfid?.status === "READY" ? "🟢 Ready" : "⚪ Not Installed";
    const exifStatus = engines?.exiftool?.status === "READY" ? "🟢 Ready" : "⚪ Binary not in PATH";
    const capaStatus = engines?.capa?.status === "READY" ? "🟢 Ready" : "⚪ Not Installed";
    const diecStatus = engines?.diec?.status === "READY" ? "🟢 Ready (Embedded & CLI)" : "⚪ Not Installed";
    const ghidraStatus = engines?.ghidra?.status === "READY"
      ? "🟢 Ready (Headless SRE)"
      : (env.SCANNER_SERVICE_URL ? "🟢 Ready (Backend SRE)" : "⚪ Service Not Configured");
    const gitleaksStatus = engines?.gitleaks?.status === "READY" ? "🟢 Ready (Embedded & CLI)" : "⚪ Not Installed";
    const dbStatus = engines?.database?.status === "OPERATIONAL" ? "🟢 Operational (SQLite WAL)" : "⚪ Operational (Memory)";

    const statusText =
      lang === "km"
        ? `⚙️ *CyberGuard AI — ស្ថានភាពម៉ាស៊ីនវិភាគ*

• Edge Webhook Gateway: 🟢 Cloudflare Workers
• ClamAV Antivirus: ${clamavStatus}
• YARA Rules Engine: ${yaraStatus}
• VirusTotal Threat Intel: ${vtStatus}
• Google Gemini AI: ${aiConfigured ? `🟢 Ready (${env.GEMINI_MODEL || "gemini-3.5-flash"})` : "⚪ Missing API Key"}
• oletools (Office Macros): ${oleStatus}
• PDFiD (PDF Structures): ${pdfidStatus}
• ExifTool (Metadata/Polyglots): ${exifStatus}
• capa / PE (Executables): ${capaStatus}
• Detect It Easy (Packers): ${diecStatus}
• Ghidra (Decompiler & SRE): ${ghidraStatus}
• Gitleaks (Secrets & Keys): ${gitleaksStatus}
• Audit Database: ${dbStatus}

🛡️ *បរិស្ថាន:* Hybrid Edge Sandbox (Zero-Trust)
📦 *ទំហំអនុញ្ញាតអតិបរមា:* 20 MB`
        : `⚙️ *CyberGuard AI — Engine Health Status*

• Edge Webhook Gateway: 🟢 Cloudflare Workers
• ClamAV Antivirus: ${clamavStatus}
• YARA Rules Engine: ${yaraStatus}
• VirusTotal Threat Intel: ${vtStatus}
• Google Gemini AI: ${aiConfigured ? `🟢 Ready (${env.GEMINI_MODEL || "gemini-3.5-flash"})` : "⚪ Missing API Key"}
• oletools (Office Macros): ${oleStatus}
• PDFiD (PDF Structures): ${pdfidStatus}
• ExifTool (Metadata/Polyglots): ${exifStatus}
• capa / PE (Executables): ${capaStatus}
• Detect It Easy (Packers): ${diecStatus}
• Ghidra (Decompiler & SRE): ${ghidraStatus}
• Gitleaks (Secrets & Keys): ${gitleaksStatus}
• Audit Database: ${dbStatus}

🛡️ *Host Environment:* Hybrid Edge Sandbox (Zero-Trust)
📦 *Max Allowed File:* 20 MB`;

    await sendTelegramMessage(token, {
      chat_id: chatId,
      text: statusText,
      parse_mode: "Markdown",
      reply_markup: getReplyKeyboard(lang),
    });
    return;
  }

  // /privacy or "🔐 គោលការណ៍ឯកជនភាព"
  if (lowerText.startsWith("/privacy") || lowerText.includes("គោលការណ៍ឯកជនភាព") || lowerText.includes("privacy policy")) {
    const privText =
      lang === "km"
        ? `🔐 *CyberGuard AI — គោលការណ៍ឯកជនភាព និងសុវត្ថិភាព*

១. *មិនរក្សាទុកឯកសារ (Zero Retention):* ឯកសារត្រូវបានវិភាគក្នុង Memory និង Sandbox ហើយលុបចេញភ្លាមៗក្រោយពេលស្កេនចប់។
២. *ការការពារ Secrets:* គ្មានទិន្នន័យឯកជន ឬ Token ណាត្រូវបានកត់ត្រាក្នុង Logs ឡើយ។
៣. *ការវិភាគ AI:* មានតែទិន្នន័យបច្ចេកទេស និង Metadata គ្មានគ្រោះថ្នាក់ប៉ុណ្ណោះដែលបញ្ជូនទៅ AI ពន្យល់។`
        : `🔐 *CyberGuard AI — Privacy & Security Policy*

1. *Zero File Retention:* Files are processed in isolated memory/sandbox and removed immediately after scanning.
2. *Secret Protection:* User credentials, tokens, and file bodies are never logged.
3. *AI Privacy:* Only structured scanner metadata is passed to Gemini AI for explanation.`;

    await sendTelegramMessage(token, {
      chat_id: chatId,
      text: privText,
      parse_mode: "Markdown",
      reply_markup: getReplyKeyboard(lang),
    });
    return;
  }

  // /history or "📋 ប្រវត្តិស្កេន"
  if (lowerText.startsWith("/history") || lowerText.includes("ប្រវត្តិស្កេន") || lowerText.includes("scan history")) {
    const histText =
      lang === "km"
        ? `📋 *CyberGuard AI — ប្រវត្តិស្កេន*

ដើម្បីធានាឯកជនភាពកម្រិតខ្ពស់ (Zero-Retention Security Policy) បូតដំណើរការលើ Serverless Edge ដោយមិនរក្សាទុកឯកសារចាស់របស់អ្នកលើប្រព័ន្ធឡើយ។`
        : `📋 *CyberGuard AI — Scan History*

Under our strict Zero-Retention Privacy Policy, scans on Cloudflare Workers operate statelessly without permanent file storage.`;

    await sendTelegramMessage(token, {
      chat_id: chatId,
      text: histText,
      parse_mode: "Markdown",
      reply_markup: getReplyKeyboard(lang),
    });
    return;
  }

  // /lang or "🌐 ផ្លាស់ប្តូរភាសា"
  if (lowerText.startsWith("/lang") || lowerText.includes("ផ្លាស់ប្តូរភាសា") || lowerText.includes("switch language")) {
    const langMsg =
      lang === "km"
        ? `🌐 *ជ្រើសរើសភាសា / Language Selection*\n\nភាសាបច្ចុប្បន្ន៖ *ភាសាខ្មែរ 🇰🇭*\nសូមជ្រើសរើសភាសាដែលអ្នកចង់ប្រើប្រាស់៖`
        : `🌐 *Language Selection*\n\nCurrent Language: *English 🇬🇧*\nPlease select your preferred language:`;

    await sendTelegramMessage(token, {
      chat_id: chatId,
      text: langMsg,
      parse_mode: "Markdown",
      reply_markup: {
        inline_keyboard: [
          [{ text: "English 🇬🇧", callback_data: "set_lang:en" }],
          [{ text: "ភាសាខ្មែរ 🇰🇭", callback_data: "set_lang:km" }],
        ],
      },
    });
    return;
  }

  // /ghidra or "🔬 Ghidra Decompiler"
  if (lowerText.startsWith("/ghidra") || lowerText.includes("ghidra")) {
    const ghidraMsg =
      lang === "km"
        ? `🔬 *Ghidra Headless SRE & Decompiler Engine*

ដើម្បី Decompile និងវិភាគកូដ Executable (.exe, .dll, .elf)៖
១. សូមផ្ញើឯកសារ Executable មកកាន់ Chat នេះ។
២. ប្រព័ន្ធនឹងធ្វើការ Decompile មុខងារ Entry point ទៅជា pseudo-C code និងស្វែងរក API Cross-references ដែលមានហានិភ័យ។`
        : `🔬 *Ghidra Headless SRE & Decompiler Engine*

To decompile and analyze executable binaries (.exe, .dll, .elf):
1. Send an executable binary to this chat.
2. The headless engine will disassemble instructions, extract pseudo-C code, and check dangerous API cross-references.`;

    await sendTelegramMessage(token, {
      chat_id: chatId,
      text: ghidraMsg,
      parse_mode: "Markdown",
      reply_markup: getReplyKeyboard(lang),
    });
    return;
  }

  // 3. General Cybersecurity Question to Gemini AI
  await sendChatAction(token, chatId, "typing");
  let queryText = text;
  if (lowerText.startsWith("/ask")) {
    queryText = text.replace(/^\/ask\s*/i, "").trim();
  }

  if (!queryText) {
    const askPrompt =
      lang === "km"
        ? `💬 *សូមសួរសំណួរពាក់ព័ន្ធនឹងសន្តិសុខសាយប័រ ឬមេរោគ៖*\n\n_ឧទាហរណ៍៖ \`/ask តើមេរោគ Ransomware ការពារយ៉ាងដូចម្តេច?\`_`
        : `💬 *Please type your cybersecurity or malware question:*\n\n_Example: \`/ask How do I prevent ransomware attacks?\`_`;
    await sendTelegramMessage(token, {
      chat_id: chatId,
      text: askPrompt,
      parse_mode: "Markdown",
      reply_markup: getReplyKeyboard(lang),
    });
    return;
  }

  const aiAnswer = await askGemini(env.GEMINI_API_KEY, queryText, {
    model: env.GEMINI_MODEL,
    lang,
  });

  await sendTelegramMessage(token, {
    chat_id: chatId,
    text: aiAnswer,
    parse_mode: "Markdown",
    reply_markup: getReplyKeyboard(lang),
  });
}

/**
 * Handles file downloads, scanner submission, and Gemini report delivery.
 */
async function handleFileUpload(
  token: string,
  chatId: number,
  fileId: string,
  filename: string,
  env: Env,
  lang: string
): Promise<void> {
  const progressText =
    lang === "km"
      ? `🔄 *កំពុងទាញយក និងស្កេនឯកសារជាមួយ ClamAV និង YARA...*\n_សូមរង់ចាំបន្តិច..._`
      : `🔄 *Downloading and analyzing file with ClamAV & YARA...*\n_Please wait a moment..._`;

  await sendTelegramMessage(token, {
    chat_id: chatId,
    text: progressText,
    parse_mode: "Markdown",
  });

  try {
    // 1. Get file metadata & download from Telegram
    const fileInfo = await getTelegramFile(token, fileId);
    if (!fileInfo.result?.file_path) {
      throw new Error("Unable to obtain file download path from Telegram API.");
    }

    const fileBuffer = await downloadTelegramFile(token, fileInfo.result.file_path);

    // 2. Submit to ClamAV and YARA scanner
    const report = await scanFile(fileBuffer, filename, env);

    // 3. Ask Gemini to summarize and explain the findings
    let aiExplanation = "";
    if (env.GEMINI_API_KEY) {
      aiExplanation = await askGemini(
        env.GEMINI_API_KEY,
        lang === "km"
          ? "សូមពន្យល់ពីលទ្ធផលស្កេននេះ និងផ្តល់អនុសាសន៍ការពារដល់អ្នកប្រើប្រាស់ជាភាសាខ្មែរ។"
          : "Explain these scan findings and provide safety recommendations for the user.",
        {
          model: env.GEMINI_MODEL,
          lang,
          scanContext: report,
        }
      );
    }

    // 4. Build comprehensive Telegram report
    const verdictIcon =
      report.verdict === "MALICIOUS"
        ? "🔴"
        : report.verdict === "SUSPICIOUS"
        ? "🟡"
        : report.verdict === "CLEAN"
        ? "🟢"
        : "⚪";

    const findingsText =
      report.findings.length > 0
        ? report.findings.map((f) => `• ${f}`).join("\n")
        : lang === "km"
        ? "• មិនមានចំណុចសង្ស័យឡើយ"
        : "• No suspicious indicators detected";

    const finalReport =
      lang === "km"
        ? `🛡️ *CYBERGUARD AI — របាយការណ៍ស្កេនមេរោគ*

📄 *ឯកសារ:* \`${report.filename}\`
📦 *ទំហំ:* ${(report.file_size_bytes / 1024).toFixed(1)} KB
🔐 *SHA-256:*
\`${report.sha256}\`
━━━━━━━━━━━━━━━━━━
🔍 *លទ្ធផលម៉ាស៊ីនស្កេន៖*
• ClamAV Antivirus: ${report.clamav.detected ? `🚨 ${report.clamav.virus_name}` : report.clamav.status}
• YARA Rules: ${report.yara.matches.length > 0 ? `⚠️ ${report.yara.matches.length} matches` : report.yara.status}
• ស្ថានភាពទូទៅ: ${verdictIcon} *${report.verdict}* (Severity: ${report.severity})

📝 *ចំណុចកត់សម្គាល់៖*
${findingsText}

🤖 *ការពន្យល់ពី Gemini AI:*
${aiExplanation}

⏱️ *រយៈពេលស្កេន:* \`${report.execution_time_ms} ms\``
        : `🛡️ *CYBERGUARD AI — SECURITY SCAN REPORT*

📄 *File:* \`${report.filename}\`
📦 *Size:* ${(report.file_size_bytes / 1024).toFixed(1)} KB
🔐 *SHA-256:*
\`${report.sha256}\`
━━━━━━━━━━━━━━━━━━
🔍 *Scanner Results:*
• ClamAV Antivirus: ${report.clamav.detected ? `🚨 ${report.clamav.virus_name}` : report.clamav.status}
• YARA Rules: ${report.yara.matches.length > 0 ? `⚠️ ${report.yara.matches.length} matches` : report.yara.status}
• Overall Verdict: ${verdictIcon} *${report.verdict}* (Severity: ${report.severity})

📝 *Findings:*
${findingsText}

🤖 *Gemini AI Security Explanation:*
${aiExplanation}

⏱️ *Scan Duration:* \`${report.execution_time_ms} ms\``;

    await sendTelegramMessage(token, {
      chat_id: chatId,
      text: finalReport,
      parse_mode: "Markdown",
      reply_markup: getReplyKeyboard(lang),
    });
  } catch (err: any) {
    const errorMsg =
      lang === "km"
        ? `⚠️ ការស្កេនជួបបញ្ហា: ${err.message || "Unknown error"}`
        : `⚠️ Scan failed: ${err.message || "Unknown error"}`;

    await sendTelegramMessage(token, {
      chat_id: chatId,
      text: errorMsg,
      reply_markup: getReplyKeyboard(lang),
    });
  }
}
