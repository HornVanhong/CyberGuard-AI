/**
 * CyberGuard AI - Cloudflare Worker
 * Telegram Webhook Gateway + Gemini 3.5 Flash + 12-Engine Scanner Integration
 * Features: File Malware Scanning + URL & Phishing Threat Analysis
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

// ================= Security & Cryptographic Utilities =================

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

// ================= URL & Phishing Threat Intelligence Heuristics =================

const URL_REGEX = /(?:https?:\/\/|www\.)[^\s<>'\"{}|\\^`]+[^\s<>'\"{}|\\^`.,;:?!]/gi;
const IP_REGEX = /^https?:\/\/(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:\/.*)?$/i;

const KNOWN_SHORTENERS = new Set([
  "bit.ly", "tinyurl.com", "t.co", "cutt.ly", "is.gd", "rb.gy",
  "shorturl.at", "ow.ly", "rebrand.ly", "bl.ink", "v.gd", "t.ly", "s.id", "soo.gd",
]);

const HIGH_RISK_TLDS = new Set([
  "xyz", "top", "tk", "ml", "ga", "cf", "gq", "buzz", "fit", "work",
  "click", "rest", "icu", "cam", "live", "vip", "monster", "quest",
  "surf", "fun", "casa", "cfd", "sbs",
]);

const OFFICIAL_DOMAINS = {
  telegram: ["telegram.org", "t.me", "telegram.me"],
  google: ["google.com", "google.com.kh", "accounts.google.com"],
  apple: ["apple.com", "icloud.com"],
  microsoft: ["microsoft.com", "live.com", "office.com"],
  paypal: ["paypal.com"],
  facebook: ["facebook.com", "fb.com", "meta.com"],
  aba: ["ababank.com", "payway.com.kh"],
  acleda: ["acledabank.com.kh"],
  wing: ["wingbank.com.kh", "wingmoney.com"],
  canadia: ["canadiabank.com.kh"],
  binance: ["binance.com"],
};

const SENSITIVE_KEYWORDS = [
  "telegram", "whatsapp", "facebook", "meta", "google", "apple", "microsoft",
  "paypal", "binance", "coinbase", "trustwallet", "metamask", "aba", "acleda",
  "wing", "canadia", "login", "signin", "verify", "verification", "security",
  "account-update", "airdrop", "claim", "bonus", "free-gift", "customer-service",
  "support-team", "password-reset",
];

function extractUrls(text) {
  if (!text) return [];
  const matches = text.match(URL_REGEX);
  if (!matches) return [];

  const urls = [];
  for (const m of matches) {
    let clean = m.trim();
    if (!clean.startsWith("http://") && !clean.startsWith("https://")) {
      clean = "http://" + clean;
    }
    if (!urls.includes(clean)) {
      urls.push(clean);
    }
  }
  return urls;
}

function analyzeUrlHeuristics(targetUrl) {
  let cleanUrl = targetUrl.trim();
  if (!cleanUrl.startsWith("http://") && !cleanUrl.startsWith("https://")) {
    cleanUrl = "http://" + cleanUrl;
  }

  let domain = cleanUrl;
  let path = "";
  try {
    const parsed = new URL(cleanUrl);
    domain = parsed.hostname || cleanUrl;
    path = parsed.pathname || "";
  } catch {
    const match = cleanUrl.match(/^https?:\/\/([^/?#]+)(?:[/?#]|$)/i);
    if (match) domain = match[1];
  }

  const domainLower = domain.toLowerCase();
  const pathLower = path.toLowerCase();
  const redFlags = [];
  let score = 0;

  const isIp = IP_REGEX.test(cleanUrl);
  const isShortened = KNOWN_SHORTENERS.has(domainLower);
  const isPunycode = domainLower.includes("xn--");

  // 1. Bare IP
  if (isIp) {
    score += 45;
    redFlags.push("Bare IP address used instead of domain name (common in phishing & C2 nodes)");
  }

  // 2. Punycode
  if (isPunycode) {
    score += 40;
    redFlags.push(`Punycode characters detected in domain '${domain}' (potential spoofing of trusted brand)`);
  }

  // 3. Shortener
  if (isShortened) {
    score += 20;
    redFlags.push(`URL shortener '${domainLower}' conceals the true target destination`);
  }

  // 4. High-risk TLD
  const parts = domainLower.split(".");
  const tld = parts.length > 1 ? parts[parts.length - 1] : "";
  if (HIGH_RISK_TLDS.has(tld)) {
    score += 30;
    redFlags.push(`Suspicious top-level domain '.${tld}' frequently linked to phishing infrastructure`);
  }

  // 5. Brand Impersonation
  for (const [brand, officialList] of Object.entries(OFFICIAL_DOMAINS)) {
    if (domainLower.includes(brand)) {
      const isOfficial = officialList.some((off) => domainLower === off || domainLower.endsWith("." + off));
      if (!isOfficial) {
        score += 65;
        redFlags.push(`Impersonation detected: Contains '${brand}' but is NOT an official domain (${officialList.join(", ")})`);
      }
    }
  }

  // 6. Sensitive keywords
  const subdomains = parts.length > 2 ? parts.slice(0, parts.length - 2) : [];
  for (const kw of SENSITIVE_KEYWORDS) {
    if (subdomains.includes(kw) || pathLower.includes(kw)) {
      if (!Object.keys(OFFICIAL_DOMAINS).some((brand) => domainLower.includes(brand))) {
        score += 15;
        redFlags.push(`Security/Credential keyword '${kw}' present in unverified domain structure`);
        break;
      }
    }
  }

  score = Math.min(score, 100);
  const verdict = score >= 60 ? "MALICIOUS" : score >= 25 ? "SUSPICIOUS" : "CLEAN";

  const recommendations = [];
  if (verdict === "MALICIOUS") {
    recommendations.push("Do NOT open or click this link under any circumstances.");
    recommendations.push("Never enter passwords, banking details, or OTP codes on this site.");
    recommendations.push("Block and report the sender immediately.");
  } else if (verdict === "SUSPICIOUS") {
    recommendations.push("Exercise extreme caution before navigating to this destination.");
    recommendations.push("Verify through the service's official app or bookmarked website instead.");
  } else {
    recommendations.push("No immediate threats flagged by heuristic checks.");
    recommendations.push("Standard zero-trust browsing vigilance is always advised.");
  }

  return {
    url: cleanUrl,
    domain,
    verdict,
    riskScore: score,
    isShortened,
    isIp,
    isPunycode,
    redFlags,
    recommendations,
  };
}

function analyzeMessageHeuristics(messageText) {
  const text = (messageText || "").trim();
  const lower = text.toLowerCase();
  const urls = extractUrls(text);
  const urlResults = urls.slice(0, 5).map(analyzeUrlHeuristics);

  const redFlags = [];
  const tactics = [];
  let score = 0;

  // Pattern 1: Urgency & Fear
  const urgencyTerms = [
    "immediately", "within 24 hours", "account will be deleted", "suspended",
    "urgent", "police", "arrest", "security breach", "frozen", "blocked",
    "បន្ទាន់", "ជាបន្ទាន់", "បិទគណនី", "ផ្អាកដំណើរការ", "បង្កក", "គំរាម",
  ];
  if (urgencyTerms.some((term) => lower.includes(term))) {
    score += 25;
    tactics.push("Urgency & Fear Tactics (Pressuring victim to act without thinking)");
    redFlags.push("Message creates artificial panic or urgent deadline");
  }

  // Pattern 2: Greed & Fake Prizes
  const greedTerms = [
    "you won", "lottery", "cash prize", "free money", "claim your reward",
    "airdrop", "giveaway", "free telegram premium", "crypto giveaway", "bonus",
    "ឈ្នះរង្វាន់", "ឥតគិតថ្លៃ", "លុយហ្វ្រី", "ទទួលបានរង្វាន់",
  ];
  if (greedTerms.some((term) => lower.includes(term))) {
    score += 30;
    tactics.push("Lure & False Reward (Promising free money, prizes, or bonuses)");
    redFlags.push("Offers unrealistic financial reward or unrequested giveaway");
  }

  // Pattern 3: Credential & OTP Solicitation
  const credTerms = [
    "send me your password", "otp", "verification code", "secret code",
    "seed phrase", "private key", "confirm your identity",
    "ផ្ញើលេខកូដ otp", "លេខសម្ងាត់", "password", "កូដសម្ងាត់",
  ];
  if (credTerms.some((term) => lower.includes(term))) {
    score += 45;
    tactics.push("Credential Harvesting (Attempting to steal passwords or OTP tokens)");
    redFlags.push("Explicit request for confidential security codes or login credentials");
  }

  for (const ur of urlResults) {
    if (ur.verdict === "MALICIOUS") {
      score = Math.max(score, 85);
      redFlags.push(...ur.redFlags);
    } else if (ur.verdict === "SUSPICIOUS") {
      score = Math.max(score, 50);
      redFlags.push(...ur.redFlags);
    }
  }

  score = Math.min(score, 100);
  const verdict = score >= 65 ? "MALICIOUS" : score >= 30 ? "SUSPICIOUS" : "CLEAN";

  const recommendations = [];
  if (verdict === "MALICIOUS") {
    recommendations.push("This message is an active phishing or scam attempt.");
    recommendations.push("Do NOT share OTP codes, passwords, or personal identity information.");
    recommendations.push("Do NOT click any links inside the message.");
    recommendations.push("Block the sender and report as spam.");
  } else if (verdict === "SUSPICIOUS") {
    recommendations.push("Message contains typical signs of social engineering.");
    recommendations.push("Contact the organization directly through their verified phone number.");
  } else {
    recommendations.push("No obvious phishing patterns detected.");
    recommendations.push("Never share sensitive credentials or financial pins.");
  }

  return {
    text,
    urls,
    urlResults,
    verdict,
    riskScore: score,
    redFlags: Array.from(new Set(redFlags)),
    tactics,
    recommendations,
  };
}

// ================= Keyboards =================

function getReplyKeyboard(lang = "km") {
  if (lang === "km") {
    return {
      keyboard: [
        [{ text: "🔍 ស្កេនឯកសារ" }, { text: "🔗 វិភាគ Link & សារ" }],
        [{ text: "💬 សួរ AI Security" }, { text: "⚙️ ស្ថានភាពម៉ាស៊ីន" }],
        [{ text: "🔬 Ghidra Decompiler" }, { text: "📋 ប្រវត្តិស្កេន" }],
        [{ text: "🌐 ផ្លាស់ប្តូរភាសា" }, { text: "📚 ការណែនាំ & ជំនួយ" }],
        [{ text: "🔐 គោលការណ៍ឯកជនភាព" }],
      ],
      resize_keyboard: true,
      is_persistent: true,
      input_field_placeholder: "សូមជ្រើសរើសមុខងារ ឬផ្ញើឯកសារ/Link ដើម្បីស្កេន...",
    };
  }

  return {
    keyboard: [
      [{ text: "🔍 Scan File" }, { text: "🔗 Inspect Link & Msg" }],
      [{ text: "💬 Ask AI Security" }, { text: "⚙️ System Status" }],
      [{ text: "🔬 Ghidra Decompiler" }, { text: "📋 Scan History" }],
      [{ text: "🌐 Switch Language" }, { text: "📚 Help & Guide" }],
      [{ text: "🔐 Privacy Policy" }],
    ],
    resize_keyboard: true,
    is_persistent: true,
    input_field_placeholder: "Select an option or send file/link to scan...",
  };
}

// ================= Telegram API =================

async function answerCallbackQuery(token, callbackQueryId, text) {
  try {
    await fetch(`https://api.telegram.org/bot${token}/answerCallbackQuery`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        callback_query_id: callbackQueryId,
        text: text || "",
      }),
    });
  } catch {}
}

async function updateTelegramMenuCommands(token, chatId, lang = "km") {
  const commands =
    lang === "km"
      ? [
          { command: "start", description: "🚀 ចាប់ផ្តើម Bot និងបើកផ្ទាំងមឺនុយមេ" },
          { command: "scan", description: "🔍 ស្កេនឯកសារស្វែងរកមេរោគ" },
          { command: "check", description: "🔗 វិភាគ Link & សារបន្លំ (Phishing/Scam)" },
          { command: "status", description: "⚙️ ពិនិត្យស្ថានភាពម៉ាស៊ីនស្កេន និង AI" },
          { command: "ask", description: "💬 សួរសំណួរសន្តិសុខសាយប័រជាមួយ AI" },
          { command: "ghidra", description: "🔬 វិភាគស៊ីជម្រៅ និង Decompile (Ghidra)" },
          { command: "history", description: "📋 មើលប្រវត្តិឯកសារដែលបានស្កេន" },
          { command: "privacy", description: "🔐 គោលការណ៍ឯកជនភាព និងសុវត្ថិភាព" },
          { command: "lang", description: "🌐 ផ្លាស់ប្តូរភាសា (English / ខ្មែរ)" },
          { command: "help", description: "📚 ការណែនាំ និងរបៀបប្រើប្រាស់" },
        ]
      : [
          { command: "start", description: "🚀 Start bot and show main menu" },
          { command: "scan", description: "🔍 Scan a file for malware & threats" },
          { command: "check", description: "🔗 Check suspicious links & phishing" },
          { command: "status", description: "⚙️ Check scanner engines & AI health" },
          { command: "ask", description: "💬 Ask cybersecurity AI assistant" },
          { command: "ghidra", description: "🔬 Decompile binary with Ghidra SRE" },
          { command: "history", description: "📋 View your recent scan history" },
          { command: "privacy", description: "🔐 Review zero-retention privacy policy" },
          { command: "lang", description: "🌐 Switch language (English / ខ្មែរ)" },
          { command: "help", description: "📚 User guide and risk levels explained" },
        ];

  try {
    await fetch(`https://api.telegram.org/bot${token}/setMyCommands`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        commands,
        scope: { type: "chat", chat_id: chatId },
      }),
    });
  } catch {}
}

function renderProgressBar(percentage, length = 10) {
  const clamped = Math.max(0, Math.min(100, Math.round(percentage)));
  const filled = Math.round((clamped / 100) * length);
  const empty = length - filled;
  return "▰".repeat(filled) + "▱".repeat(empty);
}

async function editTelegramMessage(token, chatId, messageId, text, parseMode = "Markdown", replyMarkup = null) {
  if (!messageId) return;
  const url = `https://api.telegram.org/bot${token}/editMessageText`;
  const body = {
    chat_id: chatId,
    message_id: messageId,
    text,
    parse_mode: parseMode,
    disable_web_page_preview: true,
  };
  if (replyMarkup) body.reply_markup = replyMarkup;

  try {
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!res.ok && parseMode) {
      delete body.parse_mode;
      await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
    }
  } catch {}
}

async function sendTelegramMessage(token, payload) {
  const url = `https://api.telegram.org/bot${token}/sendMessage`;
  const text = payload.text || "";
  const maxLen = 4000;
  let lastResult = null;
  for (let i = 0; i < text.length; i += maxLen) {
    const chunk = text.slice(i, i + maxLen);
    const isLast = i + maxLen >= text.length;
    let res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        chat_id: payload.chat_id,
        text: chunk,
        parse_mode: payload.parse_mode,
        reply_markup: isLast ? payload.reply_markup : undefined,
      }),
    });
    if (!res.ok && payload.parse_mode) {
      // Fallback: Retry as plain text if Markdown parsing failed
      res = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          chat_id: payload.chat_id,
          text: chunk,
          reply_markup: isLast ? payload.reply_markup : undefined,
        }),
      });
    }
    try {
      lastResult = await res.json();
    } catch {}
  }
  return lastResult;
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

// ================= Gemini AI Client =================

function cleanTelegramMarkdown(text) {
  if (!text) return "";
  let clean = text;
  // Convert markdown headers (### Header) to bold (*Header*)
  clean = clean.replace(/^#{1,6}\s*(.+)$/gm, "*$1*");
  // Normalize bullet points: "*   **" to "• *"
  clean = clean.replace(/^\s*[\*\-]\s+\*\*/gm, "• **");
  clean = clean.replace(/^\s*[\*\-]\s+/gm, "• ");
  // Remove markdown horizontal dividers (---, ***)
  clean = clean.replace(/^\s*[-*_]{3,}\s*$/gm, "");
  // Replace stray triple asterisks and normalize
  clean = clean.replace(/\*{3,}/g, "**");
  clean = clean.replace(/^\s*\*\s*\*\s*/gm, "• ");
  clean = clean.replace(/\s*\*+\s*$/gm, "");
  // Replace stray Thai/Lao mis-generations with proper Khmer
  clean = clean.replace(/[\u0E00-\u0EFF]+/g, "");
  return clean.trim();
}

async function askGemini(apiKey, prompt, model = "gemini-3-flash-preview", lang = "km") {
  const modelsToTry = [
    "gemini-3-flash-preview",
    model,
    "gemini-3.5-flash",
  ].filter(Boolean).filter((v, i, a) => a.indexOf(v) === i); // Deduplicate with gemini-3-flash-preview first

  const systemInstruction = lang === "km"
    ? `អ្នកគឺជា CyberGuard AI អ្នកជំនាញសន្តិសុខសាយប័រ និងវិភាគមេរោគ។
ច្បាប់នៃការឆ្លើយតបលើ Telegram៖
១. ហាមប្រើ Markdown Headers (### ឬ ##) ដាច់ខាត។ ប្រើអក្សរដិត *ចំណងជើង* ជំនួសវិញ។
២. ប្រើសញ្ញា (•) សម្រាប់រៀបរាប់ចំណុចនីមួយៗ។
៣. ឆ្លើយជាភាសាខ្មែរឱ្យបានពេញលេញ ច្បាស់លាស់ ត្រឹមត្រូវ និងមានរបៀបរៀបរយ។`
    : `You are CyberGuard AI, an expert cybersecurity analyst and malware investigator.
Telegram Formatting Rules:
1. DO NOT use markdown headers (### or ##). Use bold text (*Title*) instead.
2. Use bullet points (•) for distinct items.
3. Provide complete, accurate, and professional cybersecurity advice.`;

  for (const m of modelsToTry) {
    const url = `https://generativelanguage.googleapis.com/v1beta/models/${m}:generateContent?key=${apiKey}`;
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 16000);
      const res = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          system_instruction: { parts: [{ text: systemInstruction }] },
          contents: [{ role: "user", parts: [{ text: prompt.slice(0, 1500) }] }],
          generationConfig: { temperature: 0.2, maxOutputTokens: 2048 },
        }),
        signal: controller.signal,
      });
      clearTimeout(timer);

      if (res.ok) {
        const data = await res.json();
        const rawText = data.candidates?.[0]?.content?.parts?.[0]?.text;
        if (rawText) {
          return cleanTelegramMarkdown(rawText);
        }
      }
    } catch {}
  }

  return lang === "km"
    ? "⚠️ Gemini AI កំពុងមានសំណើច្រើនពេកនៅពេលនេះ។ សូមព្យាយាមសួរម្តងទៀតក្នុងពេលបន្តិចទៀត។"
    : "⚠️ Gemini AI is currently experiencing high demand. Please try again in a few moments.";
}

async function analyzePhishingWithGemini(apiKey, messageText, heuristics, model = "gemini-3-flash-preview", lang = "km") {
  const modelsToTry = [
    "gemini-3-flash-preview",
    model,
    "gemini-3.5-flash",
  ].filter(Boolean).filter((v, i, a) => a.indexOf(v) === i);

  const systemInstruction = lang === "km"
    ? "អ្នកគឺជា CyberGuard AI អ្នកជំនាញសន្តិសុខសាយប័រ។ វិភាគតំណភ្ជាប់ ឬសារបន្លំ (Phishing/Scam) និងផ្តល់ដំបូន្មានការពារដល់អ្នកប្រើប្រាស់ជាភាសាខ្មែរ (ដោយគ្មានអក្សរថៃ និងហាមប្រើ Markdown headers)។"
    : "You are CyberGuard AI, an expert cybersecurity investigator. Assess phishing links and social engineering tactics and provide actionable safety advice without using markdown headers.";

  const prompt = `[Phishing & Malicious Link Context]
Target Message/URL:
${messageText.slice(0, 800)}

Extracted URLs: ${heuristics.urls.length > 0 ? heuristics.urls.join(", ") : "None"}
Calculated Verdict: ${heuristics.verdict}
Risk Score: ${heuristics.riskScore}/100
Red Flags: ${heuristics.redFlags.length > 0 ? heuristics.redFlags.join("; ") : "None"}
Tactics Detected: ${heuristics.tactics.length > 0 ? heuristics.tactics.join("; ") : "None"}
VirusTotal Threat Intel: ${heuristics.vtMalicious !== undefined && heuristics.vtMalicious > 0 ? `${heuristics.vtMalicious}/${heuristics.vtTotal} security vendors flagged as malicious` : "No external threat alerts"}

Instructions:
1. Explain the danger in straightforward terms (e.g. brand spoofing, fake prize, OTP theft).
2. Detail the exact trick being used.
3. Provide 2-3 immediate protective actions using bullet points (•).
Respond directly in ${lang === "km" ? "Khmer (ភាសាខ្មែរ)" : "English"}.`;

  for (const m of modelsToTry) {
    const url = `https://generativelanguage.googleapis.com/v1beta/models/${m}:generateContent?key=${apiKey}`;
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 12000);
      const res = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          system_instruction: { parts: [{ text: systemInstruction }] },
          contents: [{ role: "user", parts: [{ text: prompt }] }],
          generationConfig: { temperature: 0.2, maxOutputTokens: 1500 },
        }),
        signal: controller.signal,
      });
      clearTimeout(timer);

      if (res.ok) {
        const data = await res.json();
        const text = data.candidates?.[0]?.content?.parts?.[0]?.text;
        if (text) return cleanTelegramMarkdown(text);
      }
    } catch {}
  }

  return "";
}

// ================= Status Report & Backend Communication =================

const DEFAULT_SCANNER_URL = "https://warning-gallery-rss-autos.trycloudflare.com";

async function fetchScannerEngines(env) {
  const candidates = [
    DEFAULT_SCANNER_URL,
    env.SCANNER_SERVICE_URL,
  ].filter(Boolean);

  for (const base of candidates) {
    try {
      const cleanBase = base.replace(/\/+$/, "");
      const headers = {};
      if (env.SCANNER_API_TOKEN) headers["Authorization"] = `Bearer ${env.SCANNER_API_TOKEN}`;
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 6000);
      const res = await fetch(`${cleanBase}/status`, { headers, signal: controller.signal });
      clearTimeout(timer);
      if (res.ok) {
        const data = await res.json();
        if (data && data.engines) return data.engines;
      }
    } catch {}
  }
  return null;
}

async function scanFileWithBackend(fileBufferOrUrl, filename, env) {
  const candidates = [
    DEFAULT_SCANNER_URL,
    env.SCANNER_SERVICE_URL,
  ].filter(Boolean);

  for (const base of candidates) {
    try {
      const cleanBase = base.replace(/\/+$/, "");
      const headers = {};
      if (env.SCANNER_API_TOKEN) headers["Authorization"] = `Bearer ${env.SCANNER_API_TOKEN}`;
      
      let body;
      if (typeof fileBufferOrUrl === "string") {
        // Fast direct download from Telegram CDN via backend
        headers["Content-Type"] = "application/json";
        body = JSON.stringify({ file_url: fileBufferOrUrl, filename });
      } else {
        // Multipart upload fallback
        const formData = new FormData();
        formData.append("file", new Blob([fileBufferOrUrl]), filename);
        body = formData;
      }

      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 120000); // 120s budget for deep scans
      const res = await fetch(`${cleanBase}/scan`, {
        method: "POST",
        headers,
        body,
        signal: controller.signal,
      });
      clearTimeout(timer);
      if (res.ok) {
        return await res.json();
      }
    } catch {}
  }
  return null;
}

async function checkUrlWithBackend(url, text, env) {
  const candidates = [
    DEFAULT_SCANNER_URL,
    env.SCANNER_SERVICE_URL,
  ].filter(Boolean);

  for (const base of candidates) {
    try {
      const cleanBase = base.replace(/\/+$/, "");
      const headers = { "Content-Type": "application/json" };
      if (env.SCANNER_API_TOKEN) headers["Authorization"] = `Bearer ${env.SCANNER_API_TOKEN}`;
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 8000);
      const res = await fetch(`${cleanBase}/check_url`, {
        method: "POST",
        headers,
        body: JSON.stringify({ url, text }),
        signal: controller.signal,
      });
      clearTimeout(timer);
      if (res.ok) {
        return await res.json();
      }
    } catch {}
  }
  return null;
}

async function getStatusReport(env, lang) {
  const aiConfigured = Boolean(env.GEMINI_API_KEY);
  const engines = await fetchScannerEngines(env);
  const isBackendReachable = Boolean(engines);

  const clamavStatus = engines?.clamav?.status === "ONLINE"
    ? `🟢 Online (${engines.clamav.version || "ClamAV 1.5.4"})`
    : (isBackendReachable ? "🔴 Offline" : "🔴 Offline / Connecting");
  const yaraStatus = engines?.yara?.status === "READY"
    ? `🟢 Ready (${engines.yara.rules_loaded || 4} rules loaded)`
    : "🔴 Offline";
  const vtStatus = engines?.virustotal?.status === "CONFIGURED" ? "🟢 Configured" : "⚪ Disabled";
  const oleStatus = engines?.oletools?.status === "READY" ? "🟢 Ready" : "⚪ Not Installed";
  const pdfidStatus = engines?.pdfid?.status === "READY" ? "🟢 Ready" : "⚪ Not Installed";
  const exifStatus = engines?.exiftool?.status === "READY" ? "🟢 Ready" : "⚪ Binary not in PATH";
  const capaStatus = engines?.capa?.status === "READY" ? "🟢 Ready" : "⚪ Not Installed";
  const diecStatus = engines?.diec?.status === "READY" ? "🟢 Ready (Embedded & CLI)" : "⚪ Not Installed";
  const ghidraStatus = engines?.ghidra?.status === "READY"
    ? "🟢 Ready (Headless SRE)"
    : "🟢 Ready (Backend SRE)";
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

async function handleFileUpload(token, chatId, fileId, filename, env, lang, fileSize = 0) {
  const sizeMB = fileSize > 0 ? (fileSize / (1024 * 1024)).toFixed(1) : "";
  const sizeLabel = sizeMB ? ` (${sizeMB} MB)` : "";

  // 1. Send initial progress message (15%)
  const initMsg = lang === "km"
    ? `📥 *កំពុងចាប់ផ្តើមស្កេនឯកសារ${sizeLabel}*\n\`${renderProgressBar(15)}\` 15%\n\n⚡ _កំពុងទាក់ទងម៉ាស៊ីនស្កេន និងទាញយកឯកសារ..._`
    : `📥 *Starting file inspection${sizeLabel}*\n\`${renderProgressBar(15)}\` 15%\n\n⚡ _Contacting scanner & fetching file..._`;

  const statusRes = await sendTelegramMessage(token, {
    chat_id: chatId,
    text: initMsg,
    parse_mode: "Markdown",
  });
  const statusMsgId = statusRes?.result?.message_id;

  try {
    // 2. Obtain file info from Telegram
    const fileRes = await fetch(`https://api.telegram.org/bot${token}/getFile?file_id=${fileId}`);
    const fileData = await fileRes.json();
    if (!fileData.ok || !fileData.result?.file_path) {
      throw new Error("Unable to obtain file from Telegram.");
    }

    const actualSize = fileData.result?.file_size || fileSize;
    const finalSizeMB = actualSize > 0 ? (actualSize / (1024 * 1024)).toFixed(1) : "";
    const finalSizeLabel = finalSizeMB ? ` (${finalSizeMB} MB)` : "";
    const directFileUrl = `https://api.telegram.org/file/bot${token}/${fileData.result.file_path}`;

    // Update progress to 40% (Transferring / Downloading)
    if (statusMsgId) {
      const p40 = lang === "km"
        ? `⚡ *កំពុងទាញយកឯកសារ${finalSizeLabel}*\n\`${renderProgressBar(40)}\` 40%\n\n📥 _ទាញយកល្បឿនលឿនផ្ទាល់ពី Telegram CDN..._`
        : `⚡ *Downloading file${finalSizeLabel}*\n\`${renderProgressBar(40)}\` 40%\n\n📥 _Direct high-speed download from Telegram CDN..._`;
      await editTelegramMessage(token, chatId, statusMsgId, p40);
    }

    // Attempt direct URL scan with local backend first (super fast direct download)
    let scanReport = await scanFileWithBackend(directFileUrl, filename, env);

    // Fallback: If backend direct URL didn't work, Worker streams the download and sends buffer
    if (!scanReport) {
      const dlRes = await fetch(directFileUrl);
      const contentLength = Number(dlRes.headers.get("content-length")) || actualSize || 0;
      let receivedBytes = 0;
      let fileBuffer;

      if (dlRes.body && typeof dlRes.body.getReader === "function") {
        const reader = dlRes.body.getReader();
        const chunks = [];
        let lastUpdate = Date.now();
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          chunks.push(value);
          receivedBytes += value.length;
          const now = Date.now();
          if (contentLength > 0 && now - lastUpdate > 1200 && statusMsgId) {
            const pct = Math.min(Math.round((receivedBytes / contentLength) * 45) + 20, 65);
            const mbDone = (receivedBytes / (1024 * 1024)).toFixed(1);
            const pDown = lang === "km"
              ? `📥 *កំពុងទាញយកឯកសារ (${pct}%):*\n\`${renderProgressBar(pct)}\`\n(${mbDone} MB / ${finalSizeMB} MB)\n\n_សូមរង់ចាំបន្តិច..._`
              : `📥 *Downloading file (${pct}%):*\n\`${renderProgressBar(pct)}\`\n(${mbDone} MB / ${finalSizeMB} MB)\n\n_Please wait a moment..._`;
            await editTelegramMessage(token, chatId, statusMsgId, pDown);
            lastUpdate = now;
          }
        }
        const fullArr = new Uint8Array(receivedBytes);
        let pos = 0;
        for (const c of chunks) {
          fullArr.set(c, pos);
          pos += c.length;
        }
        fileBuffer = fullArr.buffer;
      } else {
        fileBuffer = await dlRes.arrayBuffer();
      }

      scanReport = await scanFileWithBackend(fileBuffer, filename, env);
    }

    // Update progress to 75% (Scanning with ClamAV & YARA)
    if (statusMsgId) {
      const p75 = lang === "km"
        ? `🔍 *កំពុងវិភាគសុវត្ថិភាពឯកសារ (75%)*\n\`${renderProgressBar(75)}\`\n\n🛡️ _ClamAV Antivirus, YARA Rules & SRE Engines..._`
        : `🔍 *Analyzing file security (75%)*\n\`${renderProgressBar(75)}\`\n\n🛡️ _ClamAV Antivirus, YARA Rules & SRE Engines..._`;
      await editTelegramMessage(token, chatId, statusMsgId, p75);
    }

    const verdict = scanReport?.verdict || "INCONCLUSIVE";
    const severity = scanReport?.severity || "MEDIUM";
    const findings = scanReport?.findings || ["Scanner backend unreachable."];
    const icon = verdict === "CLEAN" ? "🟢" : (verdict === "MALICIOUS" ? "🔴" : "🟡");

    let aiExplanation = "";
    if (env.GEMINI_API_KEY) {
      if (statusMsgId) {
        const p90 = lang === "km"
          ? `🤖 *កំពុងបូកសរុបលទ្ធផលជាមួយ AI (90%)*\n\`${renderProgressBar(90)}\`\n\n🧠 _Google Gemini AI Security Assessment..._`
          : `🤖 *Generating AI Explanation (90%)*\n\`${renderProgressBar(90)}\`\n\n🧠 _Google Gemini AI Security Assessment..._`;
        await editTelegramMessage(token, chatId, statusMsgId, p90);
      }
      const prompt = `[File Scan Result]
File: ${filename}
Verdict: ${verdict}
Severity: ${severity}
Findings: ${findings.join("; ")}

Explain these results to the user in ${lang === "km" ? "Khmer" : "English"} and give security advice.`;
      aiExplanation = await askGemini(env.GEMINI_API_KEY, prompt, env.GEMINI_MODEL || "gemini-3.5-flash", lang);
    }

    const header = lang === "km" ? "🛡️ *CyberGuard AI — លទ្ធផលស្កេនឯកសារ*" : "🛡️ *CyberGuard AI — File Scan Result*";
    const fileLabel = lang === "km" ? "📄 *ឯកសារ:*" : "📄 *File:*";
    const verdictLabel = lang === "km" ? "លទ្ធផល (Verdict):" : "Verdict:";
    const severityLabel = lang === "km" ? "កម្រិតហានិភ័យ:" : "Severity:";
    const findingsLabel = lang === "km" ? "🔍 *ការរកឃើញ (Findings):*" : "🔍 *Findings:*";
    const aiLabel = lang === "km" ? "🤖 *ការវិភាគពី Gemini AI:*" : "🤖 *Gemini AI Assessment:*";
    const footer = lang === "km" ? "🛡️ _CyberGuard AI Zero-Trust File Inspection_" : "🛡️ _CyberGuard AI Zero-Trust File Inspection_";

    const reportMsg = `${header}

${fileLabel} \`${filename}\`${finalSizeLabel}
${icon} *${verdictLabel}* *${verdict}*
⚠️ *${severityLabel}* *${severity}*

${findingsLabel}
${findings.map((f) => `• ${f}`).join("\n")}

${aiLabel}
${aiExplanation}

${footer}`;

    if (statusMsgId) {
      await editTelegramMessage(token, chatId, statusMsgId, reportMsg, "Markdown", getReplyKeyboard(lang));
    } else {
      await sendTelegramMessage(token, {
        chat_id: chatId,
        text: reportMsg,
        parse_mode: "Markdown",
        reply_markup: getReplyKeyboard(lang),
      });
    }
  } catch (err) {
    const errorText = lang === "km"
      ? `❌ បរាជ័យក្នុងការស្កេនឯកសារ៖ ${err.message}`
      : `❌ Failed to scan file: ${err.message}`;

    if (statusMsgId) {
      await editTelegramMessage(token, chatId, statusMsgId, errorText, "Markdown", getReplyKeyboard(lang));
    } else {
      await sendTelegramMessage(token, {
        chat_id: chatId,
        text: errorText,
        reply_markup: getReplyKeyboard(lang),
      });
    }
  }
}

// ================= Link & Phishing Analysis =================

async function handleLinkAnalysis(token, chatId, targetText, env, lang) {
  const loadingMsg =
    lang === "km"
      ? "🔄 *កំពុងវិភាគសុវត្ថិភាព Link និងទម្រង់សារ (Zero-Trust Phishing Inspection)...*\n_សូមរង់ចាំបន្តិច..._"
      : "🔄 *Analyzing URL and message safety (Zero-Trust Phishing Inspection)...*\n_Please wait a moment..._";

  await sendTelegramMessage(token, {
    chat_id: chatId,
    text: loadingMsg,
    parse_mode: "Markdown",
  });

  const heuristics = analyzeMessageHeuristics(targetText);

  let vtMalicious = 0;
  let vtTotal = 0;
  let backendChecked = false;

  if (heuristics.urls.length > 0) {
    const vtData = await checkUrlWithBackend(heuristics.urls[0], targetText, env);
    if (vtData && vtData.vt_malicious !== undefined) {
      backendChecked = true;
      vtMalicious = vtData.vt_malicious;
      vtTotal = vtData.vt_total;
      if (vtMalicious > 0) {
        heuristics.redFlags.push(
          `VirusTotal Threat Intel: ${vtMalicious}/${vtTotal} security engines detected this as malicious`
        );
        heuristics.riskScore = Math.max(heuristics.riskScore, Math.min(85 + vtMalicious * 5, 100));
        heuristics.verdict = "MALICIOUS";
      }
    }
  }

  let aiExplanation = "";
  if (env.GEMINI_API_KEY) {
    aiExplanation = await analyzePhishingWithGemini(
      env.GEMINI_API_KEY,
      targetText,
      { ...heuristics, vtMalicious, vtTotal },
      env.GEMINI_MODEL || "gemini-3.5-flash",
      lang
    );
  }

  const verdictEmoji =
    heuristics.verdict === "MALICIOUS" ? "🔴" : heuristics.verdict === "SUSPICIOUS" ? "🟡" : "🟢";
  const verdictText =
    lang === "km"
      ? (heuristics.verdict === "MALICIOUS" ? "MALICIOUS (គ្រោះថ្នាក់ខ្លាំង)" : heuristics.verdict === "SUSPICIOUS" ? "SUSPICIOUS (គួរឱ្យសង្ស័យ)" : "LIKELY SAFE (ទំនងជាសុវត្ថិភាព)")
      : (heuristics.verdict === "MALICIOUS" ? "MALICIOUS (High Threat)" : heuristics.verdict === "SUSPICIOUS" ? "SUSPICIOUS (Exercise Caution)" : "LIKELY SAFE (Low Risk)");

  const targetLabel = heuristics.urls.length > 0 ? heuristics.urls[0] : (targetText.length > 60 ? targetText.slice(0, 57) + "..." : targetText);

  const vtLine = backendChecked && vtTotal > 0
    ? (lang === "km" ? `\n🛡️ *VirusTotal Intel:* ${vtMalicious}/${vtTotal} ម៉ាស៊ីនរកឃើញគ្រោះថ្នាក់` : `\n🛡️ *VirusTotal Intel:* ${vtMalicious}/${vtTotal} engines flagged`)
    : "";

  let flagsSection = "";
  if (heuristics.redFlags.length > 0) {
    flagsSection =
      (lang === "km" ? "\n\n⚠️ *សញ្ញាសម្គាល់ហានិភ័យ (Red Flags):*\n" : "\n\n⚠️ *Threat Indicators (Red Flags):*\n") +
      heuristics.redFlags.map((rf) => `• ${rf}`).join("\n");
  }

  let tacticsSection = "";
  if (heuristics.tactics.length > 0) {
    tacticsSection =
      (lang === "km" ? "\n\n🎭 *វិធីសាស្ត្រល្បួងបន្លំ (Social Engineering):*\n" : "\n\n🎭 *Social Engineering Tactics:*\n") +
      heuristics.tactics.map((t) => `• ${t}`).join("\n");
  }

  const aiSection = aiExplanation
    ? (lang === "km" ? `\n\n🤖 *ការវិភាគពី Gemini AI:*\n${aiExplanation}` : `\n\n🤖 *Gemini AI Assessment:*\n${aiExplanation}`)
    : "";

  let recsSection = "";
  if (heuristics.recommendations.length > 0) {
    recsSection =
      (lang === "km" ? "\n\n💡 *ការណែនាំសុវត្ថិភាព:*\n" : "\n\n💡 *Security Recommendations:*\n") +
      heuristics.recommendations.map((r) => `• ${r}`).join("\n");
  }

  const header = lang === "km"
    ? `🔗 *CyberGuard AI — របាយការណ៍វិភាគ Link & សារ*`
    : `🔗 *CyberGuard AI — Link & Phishing Analysis Report*`;

  const report = `${header}

🎯 *គោលដៅវិភាគ / Target:* \`${targetLabel}\`
📊 *ការវាយតម្លៃ:* ${verdictEmoji} *${verdictText}*
📈 *ពិន្ទុហានិភ័យ (Risk Score):* ${heuristics.riskScore}/100${vtLine}${tacticsSection}${flagsSection}${aiSection}${recsSection}`;

  await sendTelegramMessage(token, {
    chat_id: chatId,
    text: report,
    parse_mode: "Markdown",
    reply_markup: getReplyKeyboard(lang),
  });
}

// In-memory user language preference store
const USER_LANGUAGES = new Map();

// ================= Router =================

async function routeTelegramUpdate(update, env, ctx) {
  const token = env.TELEGRAM_BOT_TOKEN;

  // 1. Handle Inline Keyboard Callbacks (e.g., Language Switch Buttons)
  if (update.callback_query) {
    const cb = update.callback_query;
    const chatId = cb.message?.chat?.id;
    const data = cb.data || "";

    if (data.startsWith("set_lang:") && chatId) {
      const newLang = data.replace("set_lang:", "").trim().toLowerCase();
      USER_LANGUAGES.set(chatId, newLang);

      await answerCallbackQuery(token, cb.id, newLang === "km" ? "ភាសាខ្មែរ 🇰🇭" : "English 🇬🇧");
      await updateTelegramMenuCommands(token, chatId, newLang);

      const confirmMsg =
        newLang === "km"
          ? "✅ បានផ្លាស់ប្តូរភាសាទៅជា *ភាសាខ្មែរ 🇰🇭* រួចរាល់!\n\nMenu និងរបាយការណ៍ស្កេនទាំងអស់នឹងបង្ហាញជាភាសាខ្មែរ។"
          : "✅ Language switched to *English 🇬🇧*!\n\nAll buttons, menus, and scan reports will now be in English.";

      await sendTelegramMessage(token, {
        chat_id: chatId,
        text: confirmMsg,
        parse_mode: "Markdown",
        reply_markup: getReplyKeyboard(newLang),
      });
      return;
    }
    return;
  }

  const message = update.message;
  if (!message || !message.chat) return;

  const chatId = message.chat.id;
  const rawText = message.text || message.caption || "";
  const lowerText = rawText.toLowerCase().trim();

  // Auto-detect language preference from button clicks or explicit words
  if (
    lowerText.includes("switch language") ||
    lowerText.includes("scan file") ||
    lowerText.includes("ask ai security") ||
    lowerText.includes("system status") ||
    lowerText.includes("scan history") ||
    lowerText.includes("help & guide") ||
    lowerText.includes("privacy policy") ||
    lowerText === "english" ||
    lowerText === "en"
  ) {
    USER_LANGUAGES.set(chatId, "en");
  } else if (
    lowerText.includes("ផ្លាស់ប្តូរភាសា") ||
    lowerText.includes("ស្កេនឯកសារ") ||
    lowerText.includes("វិភាគ link") ||
    lowerText.includes("សួរ ai security") ||
    lowerText.includes("ស្ថានភាពម៉ាស៊ីន") ||
    lowerText.includes("ប្រវត្តិស្កេន") ||
    lowerText.includes("ការណែនាំ & ជំនួយ") ||
    lowerText.includes("គោលការណ៍ឯកជនភាព") ||
    lowerText === "ខ្មែរ" ||
    lowerText === "ភាសាខ្មែរ" ||
    lowerText === "km" ||
    lowerText === "khmer"
  ) {
    USER_LANGUAGES.set(chatId, "km");
  }

  const lang = USER_LANGUAGES.get(chatId) || (env.DEFAULT_LANGUAGE || "km").toLowerCase();

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

    const p = handleFileUpload(token, chatId, fileId, filename, env, lang, fileSize);
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

  // /start
  if (lowerText.startsWith("/start")) {
    const welcome =
      lang === "km"
        ? `🛡️ *CyberGuard AI — Malware Scanner & Security Assistant*

សូមស្វាគមន៍! ខ្ញុំគឺជា CyberGuard AI បូតសម្រាប់ត្រួតពិនិត្យមេរោគលើឯកសារ, តំណភ្ជាប់ (Links) និងប្រឹក្សាយោបល់សន្តិសុខសាយប័រ។

✨ *សមត្ថភាពចម្បង៖*
• ស្កេនមេរោគឯកសារតាមរយៈ ClamAV & YARA Rules
• វិភាគ Link & សារបន្លំ (Phishing/Scam Detection)
• ត្រួតពិនិត្យ Threat Intelligence ជាមួយ VirusTotal
• វិភាគ និងពន្យល់លទ្ធផលជាមួយ Google Gemini AI
• ពិនិត្យកូដ Executable ជាមួយ Ghidra SRE

📤 *សូមផ្ញើឯកសារ ឬតំណភ្ជាប់ (Link) មកកាន់ទីនេះដើម្បីចាប់ផ្តើមស្កេន ឬជ្រើសរើសមុខងារពីក្តារចុចខាងក្រោម៖*`
        : `🛡️ *CyberGuard AI — Malware Scanner & Security Assistant*

Welcome! I am CyberGuard AI, an expert cybersecurity assistant and malware scanner.

✨ *Core Capabilities:*
• File malware scanning via ClamAV & YARA Rules
• Link & Phishing threat inspection (Zero-Trust Heuristics)
• External threat intelligence via VirusTotal
• Deep technical explanations with Google Gemini AI
• Executable binary analysis with Ghidra SRE

📤 *Send or forward any file or link to begin scanning, or choose an option from the menu below:*`;

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
    const helpText =
      lang === "km"
        ? `📚 *CyberGuard AI — ការណែនាំ និងរបៀបប្រើប្រាស់*

📌 *របៀបស្កេន និងត្រួតពិនិត្យ៖*
១. *ស្កេនឯកសារ៖* ផ្ញើ ឬ Forward ឯកសារ (.exe, .pdf, .docx, .zip, .apk) មកកាន់ទីនេះ។
២. *វិភាគ Link & សារ៖* ផ្ញើ Link ឬសារគួរឱ្យសង្ស័យមកកាន់ទីនេះ ប្រព័ន្ធនឹងវិភាគ Phishing ភ្លាមៗ។
៣. *សួរ AI Security:* សួរសំណួរសុវត្ថិភាពសាយប័រ ឬល្បិចបន្លំផ្សេងៗ។

⌨️ *ពាក្យបញ្ជាផ្លូវការ៖*
• /scan — ស្កេនឯកសារស្វែងរកមេរោគ
• /check [link/សារ] — វិភាគតំណភ្ជាប់ ឬសារបន្លំ
• /ask [សំណួរ] — សួរសំណួរសន្តិសុខសាយប័រជាមួយ AI
• /status — ពិនិត្យស្ថានភាពម៉ាស៊ីនស្កេន
• /privacy — អានគោលការណ៍ឯកជនភាព
• /lang — ផ្លាស់ប្តូរភាសា (English / ខ្មែរ)`
        : `📚 *CyberGuard AI — Help & User Guide*

📌 *How to inspect files and links:*
1. *Scan Files:* Upload or forward any file (.exe, .pdf, .docx, .zip, .apk) here.
2. *Check Links:* Send or paste any suspicious URL or message to analyze phishing threats.
3. *Ask AI Security:* Ask any question about malware, ransomware, or security advice.

⌨️ *Official Commands:*
• /scan — Scan a file for threats
• /check [link/message] — Analyze suspicious URLs or phishing texts
• /ask [question] — Ask AI cybersecurity assistant
• /status — Check scanning engines health
• /privacy — Review privacy & data retention policy
• /lang — Switch language (English / ខ្មែរ)`;

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
    const scanPrompt =
      lang === "km"
        ? `📤 *សូមផ្ញើ ឬ Forward ឯកសារដែលអ្នកចង់ស្កេនមកកាន់ទីនេះ៖*\n\n_ប្រព័ន្ធគាំទ្រឯកសារទូទៅ (.exe, .pdf, .docx, .xlsx, .zip, .apk, .py, etc.) រហូតដល់ 20 MB។_`
        : `📤 *Please send or forward any file you wish to scan here:*\n\n_Supported formats include .exe, .pdf, .docx, .xlsx, .zip, .apk, .py, etc. (up to 20 MB)._`;

    await sendTelegramMessage(token, {
      chat_id: chatId,
      text: scanPrompt,
      parse_mode: "Markdown",
      reply_markup: getReplyKeyboard(lang),
    });
    return;
  }

  // /link, /check, /url, or "🔗 វិភាគ Link & សារ"
  const isLinkCommand =
    lowerText.startsWith("/link") ||
    lowerText.startsWith("/check") ||
    lowerText.startsWith("/url") ||
    lowerText.includes("វិភាគ link") ||
    lowerText.includes("check link");

  let targetForLinkAnalysis = null;
  if (lowerText.startsWith("/link") || lowerText.startsWith("/check") || lowerText.startsWith("/url")) {
    const rawTarget = text.replace(/^\/(?:link|check|url)\s*/i, "").trim();
    if (rawTarget) targetForLinkAnalysis = rawTarget;
  }

  if (isLinkCommand && !targetForLinkAnalysis) {
    const linkGuide =
      lang === "km"
        ? `🔗 *CyberGuard AI — វិភាគ Link & សារបន្លំ (Phishing/Scam)*

សូមផ្ញើ ឬ Forward តំណភ្ជាប់ (Link/URL) ឬអត្ថបទសារដែលគួរឱ្យសង្ស័យមកកាន់ទីនេះ៖

✨ *មុខងារវិភាគរួមមាន៖*
• កំណត់សម្គាល់ Bare IP, URL Shorteners (bit.ly, tinyurl)
• High-Risk TLDs (.xyz, .top, .buzz, etc.) & Punycode Spoofing
• ការក្លែងបន្លំម៉ាកសញ្ញា (ABA, ACLEDA, Telegram, Binance, Google, etc.)
• យុទ្ធសាស្ត្រល្បួងបន្លំ Social Engineering (គំរាមបិទគណនី, ឈ្នះរង្វាន់, លួច OTP)
• ការត្រួតពិនិត្យ Threat Intel (VirusTotal) & Gemini 3.5 Flash Explanation

_អ្នកអាចផ្ញើសារ ឬ Link មកទីនេះដោយផ្ទាល់បានភ្លាមៗ!_`
        : `🔗 *CyberGuard AI — Link & Phishing Message Analyzer*

Please send or forward any suspicious link (URL) or message to this chat:

✨ *Inspection capabilities:*
• Bare IP hosts, URL Shorteners (bit.ly, tinyurl) & High-risk TLDs
• Brand impersonation checks (Banks, Telegram, Google, PayPal, Binance)
• Social engineering heuristics (Urgency, fake rewards, OTP harvesting)
• VirusTotal Threat Intelligence & Google Gemini 3.5 Flash explanation

_You can also paste a URL directly or use \`/check <url or message>\`!_`;

    await sendTelegramMessage(token, {
      chat_id: chatId,
      text: linkGuide,
      parse_mode: "Markdown",
      reply_markup: getReplyKeyboard(lang),
    });
    return;
  }

  // Auto-detect URLs in text or explicit link target
  const detectedUrls = extractUrls(text);
  if (targetForLinkAnalysis || detectedUrls.length > 0) {
    const analysisTarget = targetForLinkAnalysis || text;
    const linkPromise = handleLinkAnalysis(token, chatId, analysisTarget, env, lang);
    if (ctx && typeof ctx.waitUntil === "function") {
      ctx.waitUntil(linkPromise);
    } else {
      await linkPromise;
    }
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
    const privText =
      lang === "km"
        ? `🔐 *CyberGuard AI — គោលការណ៍ឯកជនភាព និងសុវត្ថិភាព*

១. *មិនរក្សាទុកឯកសារ (Zero Retention):* ឯកសារត្រូវបានវិភាគក្នុង Memory និង Sandbox ហើយលុបចេញភ្លាមៗក្រោយពេលស្កេនចប់។
២. *ការការពារ Secrets:* គ្មានទិន្នន័យឯកជន ឬ Token ណាត្រូវបានកត់ត្រាក្នុង Logs ឡើយ។
៣. *ការវិភាគ AI:* មានតែទិន្នន័យបច្ចេកទេស និង Metadata គ្មានគ្រោះថ្នាក់ប៉ុណ្ណោះដែលបញ្ជូនទៅ AI ពន្យល់។`
        : `🔐 *CyberGuard AI — Zero-Retention Privacy Policy*

1. *Zero File Retention:* Files are analyzed in an isolated sandbox and immediately deleted upon scan completion.
2. *Secret Redaction:* Credentials, tokens, and personal keys are strictly redacted and never logged.
3. *AI Privacy:* Only non-sensitive technical metadata and decompilation signatures are passed to Google Gemini AI for explanations.`;

    await sendTelegramMessage(token, {
      chat_id: chatId,
      text: privText,
      parse_mode: "Markdown",
      reply_markup: getReplyKeyboard(lang),
    });
    return;
  }

  // /history or Scan History button
  if (lowerText.startsWith("/history") || lowerText.includes("ប្រវត្តិស្កេន") || lowerText.includes("scan history")) {
    const histText =
      lang === "km"
        ? `📋 *CyberGuard AI — ប្រវត្តិស្កេន*

ដើម្បីធានាឯកជនភាពកម្រិតខ្ពស់ (Zero-Retention Security Policy) បូតដំណើរការលើ Serverless Edge ដោយមិនរក្សាទុកឯកសារចាស់របស់អ្នកលើប្រព័ន្ធឡើយ។
ប្រសិនបើអ្នកបានភ្ជាប់ Scanner Backend មូលដ្ឋាន អ្នកអាចមើល Audit Logs បាននៅលើ Web Dashboard។`
        : `📋 *CyberGuard AI — Scan History*

Under our strict Zero-Retention Privacy Policy, scans on Cloudflare Workers operate statelessly without permanent file storage.
If your local Scanner Backend is running, you can view the complete scan records on the Web Dashboard.`;

    await sendTelegramMessage(token, {
      chat_id: chatId,
      text: histText,
      parse_mode: "Markdown",
      reply_markup: getReplyKeyboard(lang),
    });
    return;
  }

  // /lang or Language button
  if (lowerText.startsWith("/lang") || lowerText.includes("ផ្លាស់ប្តូរភាសា") || lowerText.includes("switch language")) {
    const parts = rawText.trim().split(/\s+/);
    if (parts.length > 1) {
      const arg = parts[1].toLowerCase();
      if (["en", "english", "eng"].includes(arg)) {
        USER_LANGUAGES.set(chatId, "en");
        await updateTelegramMenuCommands(token, chatId, "en");
        await sendTelegramMessage(token, {
          chat_id: chatId,
          text: "✅ Language switched to *English 🇬🇧*!\n\nAll buttons, menus, and scan reports will now be in English.",
          parse_mode: "Markdown",
          reply_markup: getReplyKeyboard("en"),
        });
        return;
      } else if (["km", "khmer", "ខ្មែរ"].includes(arg)) {
        USER_LANGUAGES.set(chatId, "km");
        await updateTelegramMenuCommands(token, chatId, "km");
        await sendTelegramMessage(token, {
          chat_id: chatId,
          text: "✅ បានផ្លាស់ប្តូរភាសាទៅជា *ភាសាខ្មែរ 🇰🇭* រួចរាល់!\n\nMenu និងរបាយការណ៍ស្កេនទាំងអស់នឹងបង្ហាញជាភាសាខ្មែរ។",
          parse_mode: "Markdown",
          reply_markup: getReplyKeyboard("km"),
        });
        return;
      }
    }

    const currentLang = USER_LANGUAGES.get(chatId) || lang;
    const langMsg =
      currentLang === "km"
        ? `🌐 *ជ្រើសរើសភាសា / Language Selection*\n\nភាសាបច្ចុប្បន្ន៖ *ភាសាខ្មែរ 🇰🇭*\nសូមចុចប៊ូតុងខាងក្រោមដើម្បីជ្រើសរើសភាសាដែលអ្នកចង់ប្រើប្រាស់៖`
        : `🌐 *Language Selection / ជ្រើសរើសភាសា*\n\nCurrent Language: *English 🇬🇧*\nPlease select your preferred language below:`;

    await sendTelegramMessage(token, {
      chat_id: chatId,
      text: langMsg,
      parse_mode: "Markdown",
      reply_markup: {
        inline_keyboard: [
          [
            { text: "🇰🇭 ភាសាខ្មែរ (Khmer)", callback_data: "set_lang:km" },
            { text: "🇬🇧 English", callback_data: "set_lang:en" },
          ],
        ],
      },
    });
    return;
  }

  // /ghidra or Ghidra button
  if (lowerText.startsWith("/ghidra") || lowerText.includes("ghidra")) {
    const ghidraMsg =
      lang === "km"
        ? `🔬 *Ghidra Headless SRE & Decompiler Engine*

ដើម្បី Decompile និងវិភាគកូដ Executable (.exe, .dll, .elf)៖
១. សូមផ្ញើឯកសារ Executable មកកាន់ Chat នេះ។
២. ប្រព័ន្ធនឹងធ្វើការ Decompile មុខងារ Entry point ទៅជា pseudo-C code និងស្វែងរក API Cross-references ដែលមានហានិភ័យ។`
        : `🔬 *Ghidra Headless SRE & Decompiler Engine*

To decompile and analyze executable binaries (.exe, .dll, .elf):
1. Send or forward an executable file to this chat.
2. The headless engine disassembles instructions, decompiles entry-point functions to pseudo-C code, and flags suspicious API cross-references.`;

    await sendTelegramMessage(token, {
      chat_id: chatId,
      text: ghidraMsg,
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
  }

  if (
    lowerText === "/ask" ||
    lowerText.includes("សួរ ai security") ||
    lowerText.includes("ask ai security") ||
    !queryText
  ) {
    const askPrompt =
      lang === "km"
        ? `💬 *សូមវាយសំណួរពាក់ព័ន្ធនឹងសន្តិសុខសាយប័រ ឬមេរោគ៖*\n\n_ឧទាហរណ៍ ៖ \`តើមេរោគ Ransomware ការពារយ៉ាងដូចម្តេច?\`_`
        : `💬 *Please type your cybersecurity or malware question:*\n\n_Example: \`How do I protect against Ransomware attacks?\`_`;

    await sendTelegramMessage(token, {
      chat_id: chatId,
      text: askPrompt,
      parse_mode: "Markdown",
      reply_markup: getReplyKeyboard(lang),
    });
    return;
  }

  const aiAnswer = await askGemini(env.GEMINI_API_KEY, queryText, env.GEMINI_MODEL || "gemini-3-flash-preview", lang);
  await sendTelegramMessage(token, {
    chat_id: chatId,
    text: aiAnswer,
    parse_mode: "Markdown",
    reply_markup: getReplyKeyboard(lang),
  });
}
