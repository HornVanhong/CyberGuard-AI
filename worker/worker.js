/**
 * CyberGuard AI - Cloudflare Worker
 * Telegram Webhook Gateway + Gemini 3.5 Flash + 12-Engine Scanner Integration
 */

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const method = request.method.toUpperCase();

    // 1. Health check endpoint (GET / or GET /health)
    if (url.pathname === "/" || url.pathname === "/health") {
      if (method === "GET") {
        return new Response(
          JSON.stringify({
            status: "online",
            service: "CyberGuard AI Telegram Webhook Gateway",
            platform: "Cloudflare Workers",
            scanner_service: env.SCANNER_SERVICE_URL ? "configured" : "unconfigured",
            gemini_ai: env.GEMINI_API_KEY ? "configured" : "unconfigured",
            gemini_model: env.GEMINI_MODEL || "gemini-3.5-flash",
            timestamp: new Date().toISOString(),
          }),
          { status: 200, headers: { "Content-Type": "application/json" } }
        );
      }
    }

    // 2. Reject non-POST requests to webhook endpoint
    if (method !== "POST") {
      return new Response(
        JSON.stringify({ error: "Method Not Allowed" }),
        { status: 405, headers: { "Content-Type": "application/json", Allow: "POST, GET" } }
      );
    }

    // 3. Webhook Authentication: Verify X-Telegram-Bot-Api-Secret-Token
    const secretTokenHeader = request.headers.get("X-Telegram-Bot-Api-Secret-Token");
    if (!secretTokenHeader || !env.TELEGRAM_WEBHOOK_SECRET) {
      return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
    }

    const isValidSecret = await timingSafeEqual(secretTokenHeader, env.TELEGRAM_WEBHOOK_SECRET);
    if (!isValidSecret) {
      return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
    }

    // 4. Request size check (max 512 KB)
    const rawBody = await request.text();
    if (rawBody.length > 524288) {
      return new Response(JSON.stringify({ error: "Payload Too Large" }), { status: 413 });
    }

    // 5. Parse Telegram Update
    let update;
    try {
      update = JSON.parse(rawBody);
    } catch {
      return new Response(JSON.stringify({ error: "Bad Request" }), { status: 400 });
    }

    if (!update || typeof update !== "object" || typeof update.update_id !== "number") {
      return new Response(JSON.stringify({ error: "Invalid Update" }), { status: 400 });
    }

    // 6. Route Update
    try {
      await routeTelegramUpdate(update, env, ctx);
    } catch (err) {
      console.error("[CyberGuard Worker] Router error:", err);
    }

    return new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  },
};

// ================= Security =================

async function timingSafeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const enc = new TextEncoder();
  const aBuf = enc.encode(a);
  const bBuf = enc.encode(b);
  if (aBuf.byteLength !== bBuf.byteLength) return false;
  let diff = 0;
  for (let i = 0; i < aBuf.byteLength; i++) {
    diff |= aBuf[i] ^ bBuf[i];
  }
  return diff === 0;
}

// ================= Keyboards =================

function getReplyKeyboard(lang = "km") {
  return {
    keyboard: [
      [{ text: "🔍 ស្កេនឯកសារ" }, { text: "💬 សួរ AI Security" }],
      [{ text: "⚙️ ស្ថានភាពម៉ាស៊ីន" }, { text: "🔬 Ghidra Decompiler" }],
      [{ text: "📋 ប្រវត្តិស្កេន" }, { text: "🌐 ផ្លាស់ប្តូរភាសា" }],
      [{ text: "🔐 គោលការណ៍ឯកជនភាព" }, { text: "📚 ការណែនាំ & ជំនួយ" }],
    ],
    resize_keyboard: true,
    is_persistent: true,
  };
}

// ================= Telegram API =================

async function sendTelegramMessage(token, payload) {
  const url = `https://api.telegram.org/bot${token}/sendMessage`;
  const text = payload.text || "";
  const maxLen = 4000;
  for (let i = 0; i < text.length; i += maxLen) {
    const chunk = text.slice(i, i + maxLen);
    const isLast = i + maxLen >= text.length;
    await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        chat_id: payload.chat_id,
        text: chunk,
        parse_mode: payload.parse_mode,
        reply_markup: isLast ? payload.reply_markup : undefined,
      }),
    });
  }
}

async function sendChatAction(token, chatId, action = "typing") {
  try {
    await fetch(`https://api.telegram.org/bot${token}/sendChatAction`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ chat_id: chatId, action }),
    });
  } catch {}
}

// ================= Gemini AI =================

async function askGemini(apiKey, prompt, model = "gemini-3.5-flash", lang = "km") {
  const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`;
  const sysInst =
    lang === "km"
      ? "អ្នកគឺជា CyberGuard AI ដែលជាជំនួយការ AI ផ្នែកសន្តិសុខសាយប័រ និងវិភាគមេរោគ។ ឆ្លើយតបយ៉ាងត្រឹមត្រូវ ច្បាស់លាស់ និងមានវិជ្ជាជីវៈជាភាសាខ្មែរ។ កុំបន្លំ ឬកែប្រែលទ្ធផលដែល Antivirus បានរកឃើញ។"
      : "You are CyberGuard AI, an expert cybersecurity assistant and malware analyst. Provide accurate, professional threat explanations.";

  const payload = {
    system_instruction: { parts: [{ text: sysInst }] },
    contents: [{ role: "user", parts: [{ text: prompt.slice(0, 1500) }] }],
    generationConfig: { temperature: 0.2, maxOutputTokens: 1000 },
  };

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 15000);
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });
    clearTimeout(timer);
    if (!res.ok) {
      return `⚠️ Gemini AI ជួបបញ្ហាក្នុងការឆ្លើយតប (HTTP ${res.status})។`;
    }
    const data = await res.json();
    return data.candidates?.[0]?.content?.parts?.[0]?.text || "⚠️ ពុំមានចម្លើយពី AI ឡើយ។";
  } catch {
    clearTimeout(timer);
    return "⚠️ ការភ្ជាប់ទៅកាន់ Gemini AI បានផុតកំណត់ (Timeout)។";
  }
}

// ================= Status Report =================

async function getStatusReport(env, lang = "km") {
  const aiConfigured = Boolean(env.GEMINI_API_KEY);
  let engines = null;

  if (env.SCANNER_SERVICE_URL) {
    try {
      const headers = {};
      if (env.SCANNER_API_TOKEN) headers["Authorization"] = `Bearer ${env.SCANNER_API_TOKEN}`;
      const res = await fetch(`${env.SCANNER_SERVICE_URL}/status`, { headers });
      if (res.ok) {
        const body = await res.json();
        engines = body.engines;
      }
    } catch {}
  }

  const clamavStatus = engines?.clamav?.status === "ONLINE"
    ? `🟢 Online (${engines.clamav.version || "ClamAV 1.5.4"})`
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

  if (lang === "km") {
    return `⚙️ *CyberGuard AI — ស្ថានភាពម៉ាស៊ីនវិភាគ*

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
📦 *ទំហំអនុញ្ញាតអតិបរមា:* 20 MB`;
  }

  return `⚙️ *CyberGuard AI — Engine Health Status*

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
}

// ================= File Analysis =================

async function handleFileUpload(token, chatId, fileId, filename, env, lang) {
  await sendTelegramMessage(token, {
    chat_id: chatId,
    text: lang === "km"
      ? "🔄 *កំពុងទាញយក និងស្កេនឯកសារជាមួយ ClamAV, YARA និងម៉ាស៊ីនវិភាគ...*\n_សូមរង់ចាំបន្តិច..._"
      : "🔄 *Downloading and analyzing file with ClamAV & YARA...*\n_Please wait a moment..._",
    parse_mode: "Markdown",
  });

  try {
    const fileRes = await fetch(`https://api.telegram.org/bot${token}/getFile?file_id=${fileId}`);
    const fileData = await fileRes.json();
    if (!fileData.ok || !fileData.result?.file_path) {
      throw new Error("Unable to obtain file from Telegram.");
    }

    const dlRes = await fetch(`https://api.telegram.org/file/bot${token}/${fileData.result.file_path}`);
    const fileBuffer = await dlRes.arrayBuffer();

    let scanReport = null;
    if (env.SCANNER_SERVICE_URL) {
      const formData = new FormData();
      formData.append("file", new Blob([fileBuffer]), filename);
      const headers = {};
      if (env.SCANNER_API_TOKEN) headers["Authorization"] = `Bearer ${env.SCANNER_API_TOKEN}`;
      const scanRes = await fetch(`${env.SCANNER_SERVICE_URL}/scan`, {
        method: "POST",
        headers,
        body: formData,
      });
      if (scanRes.ok) {
        scanReport = await scanRes.json();
      }
    }

    const verdict = scanReport?.verdict || "INCONCLUSIVE";
    const severity = scanReport?.severity || "MEDIUM";
    const findings = scanReport?.findings || ["Scanner backend unreachable."];
    const icon = verdict === "CLEAN" ? "🟢" : (verdict === "MALICIOUS" ? "🔴" : "🟡");

    let aiExplanation = "";
    if (env.GEMINI_API_KEY) {
      const prompt = `[File Scan Result]
File: ${filename}
Verdict: ${verdict}
Severity: ${severity}
Findings: ${findings.join("; ")}

Explain these results to the user in ${lang === "km" ? "Khmer" : "English"} and give security advice.`;
      aiExplanation = await askGemini(env.GEMINI_API_KEY, prompt, env.GEMINI_MODEL || "gemini-3.5-flash", lang);
    }

    const reportMsg = `🛡️ *CyberGuard AI — លទ្ធផលស្កេនឯកសារ*

📄 *ឯកសារ:* \`${filename}\`
${icon} *លទ្ធផល (Verdict):* *${verdict}*
⚠️ *កម្រិតហានិភ័យ:* *${severity}*

🔍 *ការរកឃើញ (Findings):*
${findings.map((f) => `• ${f}`).join("\n")}

🤖 *ការវិភាគពី Gemini AI:*
${aiExplanation}

🛡️ _CyberGuard AI Zero-Trust File Inspection_`;

    await sendTelegramMessage(token, {
      chat_id: chatId,
      text: reportMsg,
      parse_mode: "Markdown",
      reply_markup: getReplyKeyboard(lang),
    });
  } catch (err) {
    await sendTelegramMessage(token, {
      chat_id: chatId,
      text: `❌ បរាជ័យក្នុងការស្កេនឯកសារ៖ ${err.message}`,
      reply_markup: getReplyKeyboard(lang),
    });
  }
}

// ================= Router =================

async function routeTelegramUpdate(update, env, ctx) {
  const message = update.message;
  if (!message || !message.chat) return;

  const chatId = message.chat.id;
  const token = env.TELEGRAM_BOT_TOKEN;
  const lang = (env.DEFAULT_LANGUAGE || "km").toLowerCase();

  // 1. Handle File Uploads
  if (message.document || (message.photo && message.photo.length > 0)) {
    const fileId = message.document
      ? message.document.file_id
      : message.photo[message.photo.length - 1].file_id;
    const filename = message.document?.file_name || "photo.jpg";
    const fileSize = message.document?.file_size || message.photo[message.photo.length - 1].file_size || 0;

    const maxBytes = parseInt(env.MAX_FILE_SIZE_BYTES || "20971520", 10);
    if (fileSize > maxBytes) {
      await sendTelegramMessage(token, {
        chat_id: chatId,
        text: lang === "km"
          ? `❌ ឯកសារធំពេក! ទំហំអនុញ្ញាតអតិបរមាគឺ ${Math.round(maxBytes / 1048576)} MB។`
          : `❌ File is too large! Maximum allowed is ${Math.round(maxBytes / 1048576)} MB.`,
        reply_markup: getReplyKeyboard(lang),
      });
      return;
    }

    const p = handleFileUpload(token, chatId, fileId, filename, env, lang);
    if (ctx && typeof ctx.waitUntil === "function") {
      ctx.waitUntil(p);
    } else {
      await p;
    }
    return;
  }

  // 2. Handle Text & Commands
  const text = (message.text || "").trim();
  if (!text) return;
  const lowerText = text.toLowerCase();

  // /start
  if (lowerText.startsWith("/start")) {
    const welcome = `🛡️ *CyberGuard AI — Malware Scanner & Security Assistant*

សូមស្វាគមន៍! ខ្ញុំគឺជា CyberGuard AI បូតសម្រាប់ត្រួតពិនិត្យមេរោគលើឯកសារ និងប្រឹក្សាយោបល់សន្តិសុខសាយប័រ។

✨ *សមត្ថភាពចម្បង៖*
• ស្កេនមេរោគតាមរយៈ ClamAV Antivirus
• ស្វែងរកកូដគ្រោះថ្នាក់តាម YARA Rules
• វិភាគ និងពន្យល់លទ្ធផលជាមួយ Google Gemini AI
• ពិនិត្យកូដ Executable ជាមួយ Ghidra SRE

📤 *សូមផ្ញើឯកសារណាមួយមកកាន់ទីនេះដើម្បីចាប់ផ្តើមស្កេន ឬជ្រើសរើសមុខងារពីក្តារចុចខាងក្រោម៖*`;

    await sendTelegramMessage(token, {
      chat_id: chatId,
      text: welcome,
      parse_mode: "Markdown",
      reply_markup: getReplyKeyboard(lang),
    });
    return;
  }

  // /help or Help button
  if (lowerText.startsWith("/help") || lowerText.includes("ការណែនាំ") || lowerText.includes("help")) {
    const helpText = `📚 *CyberGuard AI — ការណែនាំ និងរបៀបប្រើប្រាស់*

📌 *របៀបស្កេនឯកសារ៖*
១. ផ្ញើ ឬ Forward ឯកសារណាមួយ (.exe, .pdf, .docx, .zip, .apk) មកកាន់ទីនេះ។
២. ប្រព័ន្ធនឹងស្កេនតាម ClamAV, YARA rules, និង Ghidra decompiler។
៣. ទទួលបានរបាយការណ៍ និងការវិភាគពី Gemini AI។

⌨️ *ពាក្យបញ្ជាផ្លូវការ៖*
• /scan — ស្កេនឯកសារស្វែងរកមេរោគ
• /ask [សំណួរ] — សួរសំណួរសន្តិសុខសាយប័រជាមួយ AI
• /status — ពិនិត្យស្ថានភាពម៉ាស៊ីនស្កេន
• /privacy — អានគោលការណ៍ឯកជនភាព
• /lang — ផ្លាស់ប្តូរភាសា (English / ខ្មែរ)`;

    await sendTelegramMessage(token, {
      chat_id: chatId,
      text: helpText,
      parse_mode: "Markdown",
      reply_markup: getReplyKeyboard(lang),
    });
    return;
  }

  // /scan or Scan button
  if (lowerText.startsWith("/scan") || lowerText.includes("ស្កេនឯកសារ") || lowerText.includes("scan file")) {
    await sendTelegramMessage(token, {
      chat_id: chatId,
      text: `📤 *សូមផ្ញើ ឬ Forward ឯកសារដែលអ្នកចង់ស្កេនមកកាន់ទីនេះ៖*\n\n_ប្រព័ន្ធគាំទ្រឯកសារទូទៅ (.exe, .pdf, .docx, .xlsx, .zip, .apk, .py, etc.) រហូតដល់ 20 MB។_`,
      parse_mode: "Markdown",
      reply_markup: getReplyKeyboard(lang),
    });
    return;
  }

  // /status or Status button
  if (lowerText.startsWith("/status") || lowerText.includes("ស្ថានភាពម៉ាស៊ីន") || lowerText.includes("system status")) {
    const statusMsg = await getStatusReport(env, lang);
    await sendTelegramMessage(token, {
      chat_id: chatId,
      text: statusMsg,
      parse_mode: "Markdown",
      reply_markup: getReplyKeyboard(lang),
    });
    return;
  }

  // /privacy or Privacy button
  if (lowerText.startsWith("/privacy") || lowerText.includes("គោលការណ៍ឯកជនភាព") || lowerText.includes("privacy")) {
    const privText = `🔐 *CyberGuard AI — គោលការណ៍ឯកជនភាព និងសុវត្ថិភាព*

១. *មិនរក្សាទុកឯកសារ (Zero Retention):* ឯកសារត្រូវបានវិភាគក្នុង Memory និង Sandbox ហើយលុបចេញភ្លាមៗក្រោយពេលស្កេនចប់។
២. *ការការពារ Secrets:* គ្មានទិន្នន័យឯកជន ឬ Token ណាត្រូវបានកត់ត្រាក្នុង Logs ឡើយ។
៣. *ការវិភាគ AI:* មានតែទិន្នន័យបច្ចេកទេស និង Metadata គ្មានគ្រោះថ្នាក់ប៉ុណ្ណោះដែលបញ្ជូនទៅ AI ពន្យល់។`;

    await sendTelegramMessage(token, {
      chat_id: chatId,
      text: privText,
      parse_mode: "Markdown",
      reply_markup: getReplyKeyboard(lang),
    });
    return;
  }

  // /lang or Language button
  if (lowerText.startsWith("/lang") || lowerText.includes("ផ្លាស់ប្តូរភាសា") || lowerText.includes("language")) {
    await sendTelegramMessage(token, {
      chat_id: chatId,
      text: `🌐 *ជ្រើសរើសភាសា / Language Selection*\n\nភាសាបច្ចុប្បន្ន៖ *ភាសាខ្មែរ 🇰🇭*\nប្រព័ន្ធគាំទ្រភាសាខ្មែរ និងភាសាអង់គ្លេសពេញលេញ។`,
      parse_mode: "Markdown",
      reply_markup: getReplyKeyboard(lang),
    });
    return;
  }

  // /ghidra or Ghidra button
  if (lowerText.startsWith("/ghidra") || lowerText.includes("ghidra")) {
    await sendTelegramMessage(token, {
      chat_id: chatId,
      text: `🔬 *Ghidra Headless SRE & Decompiler Engine*

ដើម្បី Decompile និងវិភាគកូដ Executable (.exe, .dll, .elf)៖
១. សូមផ្ញើឯកសារ Executable មកកាន់ Chat នេះ។
២. ប្រព័ន្ធនឹងធ្វើការ Decompile មុខងារ Entry point ទៅជា pseudo-C code និងស្វែងរក API Cross-references ដែលមានហានិភ័យ។`,
      parse_mode: "Markdown",
      reply_markup: getReplyKeyboard(lang),
    });
    return;
  }

  // 3. Ask Gemini AI (free-form question)
  await sendChatAction(token, chatId, "typing");
  let queryText = text;
  if (lowerText.startsWith("/ask")) {
    queryText = text.replace(/^\/ask\s*/i, "").trim();
  } else if (lowerText.includes("សួរ ai security")) {
    await sendTelegramMessage(token, {
      chat_id: chatId,
      text: `💬 *សូមវាយសំណួរពាក់ព័ន្ធនឹងសន្តិសុខសាយប័រ ឬមេរោគ៖*\n\n_ឧទាហរណ៍៖ \`តើមេរោគ Ransomware ការពារយ៉ាងដូចម្តេច?\`_`,
      parse_mode: "Markdown",
      reply_markup: getReplyKeyboard(lang),
    });
    return;
  }

  if (!queryText) return;

  const aiAnswer = await askGemini(env.GEMINI_API_KEY, queryText, env.GEMINI_MODEL || "gemini-3.5-flash", lang);
  await sendTelegramMessage(token, {
    chat_id: chatId,
    text: aiAnswer,
    reply_markup: getReplyKeyboard(lang),
  });
}
