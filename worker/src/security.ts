/**
 * CyberGuard AI - Security & Cryptographic Utilities
 */

/**
 * Constant-time string comparison to prevent timing attacks on webhook secrets.
 */
export async function timingSafeEqual(a: string, b: string): Promise<boolean> {
  const enc = new TextEncoder();
  const aBuf = enc.encode(a);
  const bBuf = enc.encode(b);

  if (aBuf.byteLength !== bBuf.byteLength) {
    // Perform dummy comparison to equalize timing
    const dummy = new Uint8Array(aBuf.byteLength);
    crypto.getRandomValues(dummy);
    return false;
  }

  // Calculate HMAC-like digest or byte-by-byte XOR comparison
  let result = 0;
  for (let i = 0; i < aBuf.byteLength; i++) {
    result |= aBuf[i] ^ bBuf[i];
  }
  return result === 0;
}

/**
 * Computes cryptographic SHA-256 hexadecimal hash.
 */
export async function computeSHA256(data: ArrayBuffer): Promise<string> {
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Sanitizes untrusted filenames, preventing path traversal and control character attacks.
 */
export function sanitizeFilename(filename?: string): string {
  if (!filename || typeof filename !== "string") {
    return "unnamed_payload.bin";
  }

  // Strip null bytes and control characters
  let clean = filename.replace(/[\x00-\x1f\x7f-\x9f]/g, "");

  // Prevent path traversal sequences (../, ..\, etc.)
  clean = clean.replace(/(\.\.[\/\\])+/g, "");
  clean = clean.replace(/[\/\\]+/g, "_");

  // Trim whitespace
  clean = clean.trim();

  // Enforce max length
  if (clean.length > 120) {
    const ext = clean.includes(".") ? clean.slice(clean.lastIndexOf(".")) : "";
    clean = clean.slice(0, 110) + ext;
  }

  return clean || "unnamed_payload.bin";
}

/**
 * Masks sensitive tokens and strings for safe logging.
 */
export function maskSecret(secret?: string): string {
  if (!secret || secret.length < 8) return "[REDACTED]";
  return secret.slice(0, 4) + "..." + secret.slice(-4);
}

// ================= Link & Phishing Threat Intelligence Heuristics =================

const URL_REGEX = /(?:https?:\/\/|www\.)[^\s<>'\"{}|\\^`]+[^\s<>'\"{}|\\^`.,;:?!]/gi;
const IP_REGEX = /^https?:\/\/(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:\/.*)?$/i;

export const KNOWN_SHORTENERS = new Set([
  "bit.ly",
  "tinyurl.com",
  "t.co",
  "cutt.ly",
  "is.gd",
  "rb.gy",
  "shorturl.at",
  "ow.ly",
  "rebrand.ly",
  "bl.ink",
  "v.gd",
  "t.ly",
  "s.id",
  "soo.gd",
]);

export const HIGH_RISK_TLDS = new Set([
  "xyz",
  "top",
  "tk",
  "ml",
  "ga",
  "cf",
  "gq",
  "buzz",
  "fit",
  "work",
  "click",
  "rest",
  "icu",
  "cam",
  "live",
  "vip",
  "monster",
  "quest",
  "surf",
  "fun",
  "casa",
  "cfd",
  "sbs",
]);

export const OFFICIAL_DOMAINS: Record<string, string[]> = {
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

export const SENSITIVE_KEYWORDS = [
  "telegram",
  "whatsapp",
  "facebook",
  "meta",
  "google",
  "apple",
  "microsoft",
  "paypal",
  "binance",
  "coinbase",
  "trustwallet",
  "metamask",
  "aba",
  "acleda",
  "wing",
  "canadia",
  "login",
  "signin",
  "verify",
  "verification",
  "security",
  "account-update",
  "airdrop",
  "claim",
  "bonus",
  "free-gift",
  "customer-service",
  "support-team",
  "password-reset",
];

export interface UrlHeuristicResult {
  url: string;
  domain: string;
  verdict: "MALICIOUS" | "SUSPICIOUS" | "CLEAN";
  riskScore: number;
  isShortened: boolean;
  isIp: boolean;
  isPunycode: boolean;
  redFlags: string[];
  recommendations: string[];
}

export interface MessageHeuristicResult {
  text: string;
  urls: string[];
  urlResults: UrlHeuristicResult[];
  verdict: "MALICIOUS" | "SUSPICIOUS" | "CLEAN";
  riskScore: number;
  redFlags: string[];
  tactics: string[];
  recommendations: string[];
}

/**
 * Extracts unique URLs from user messages.
 */
export function extractUrls(text?: string): string[] {
  if (!text) return [];
  const matches = text.match(URL_REGEX);
  if (!matches) return [];

  const urls: string[] = [];
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

/**
 * Evaluates deterministic threat heuristics for a given URL.
 */
export function analyzeUrlHeuristics(targetUrl: string): UrlHeuristicResult {
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
    // Fallback if URL parsing fails
    const match = cleanUrl.match(/^https?:\/\/([^/?#]+)(?:[/?#]|$)/i);
    if (match) domain = match[1];
  }

  const domainLower = domain.toLowerCase();
  const pathLower = path.toLowerCase();
  const redFlags: string[] = [];
  let score = 0;

  const isIp = IP_REGEX.test(cleanUrl);
  const isShortened = KNOWN_SHORTENERS.has(domainLower);
  const isPunycode = domainLower.includes("xn--");

  // 1. Bare IP address check
  if (isIp) {
    score += 45;
    redFlags.push("Bare IP address used instead of domain name (common in phishing & C2 nodes)");
  }

  // 2. Punycode / Homograph check
  if (isPunycode) {
    score += 40;
    redFlags.push(`Punycode characters detected in domain '${domain}' (potential spoofing of trusted brand)`);
  }

  // 3. Shortener check
  if (isShortened) {
    score += 20;
    redFlags.push(`URL shortener '${domainLower}' conceals the true target destination`);
  }

  // 4. High-risk TLD check
  const parts = domainLower.split(".");
  const tld = parts.length > 1 ? parts[parts.length - 1] : "";
  if (HIGH_RISK_TLDS.has(tld)) {
    score += 30;
    redFlags.push(`Suspicious top-level domain '.${tld}' frequently linked to phishing infrastructure`);
  }

  // 5. Brand Impersonation in domain or path
  for (const [brand, officialList] of Object.entries(OFFICIAL_DOMAINS)) {
    if (domainLower.includes(brand)) {
      const isOfficial = officialList.some((off) => domainLower === off || domainLower.endsWith("." + off));
      if (!isOfficial) {
        score += 65;
        redFlags.push(`Impersonation detected: Contains '${brand}' but is NOT an official domain (${officialList.join(", ")})`);
      }
    }
  }

  // 6. Sensitive keywords in path or subdomain
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
  const verdict: "MALICIOUS" | "SUSPICIOUS" | "CLEAN" =
    score >= 60 ? "MALICIOUS" : score >= 25 ? "SUSPICIOUS" : "CLEAN";

  const recommendations: string[] = [];
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

/**
 * Analyzes arbitrary message text and embedded URLs for social engineering and phishing tactics.
 */
export function analyzeMessageHeuristics(messageText: string): MessageHeuristicResult {
  const text = (messageText || "").trim();
  const lower = text.toLowerCase();
  const urls = extractUrls(text);

  const urlResults = urls.slice(0, 5).map(analyzeUrlHeuristics);

  const redFlags: string[] = [];
  const tactics: string[] = [];
  let score = 0;

  // Social Engineering Pattern 1: Urgency & Fear
  const urgencyTerms = [
    "immediately",
    "within 24 hours",
    "account will be deleted",
    "suspended",
    "urgent",
    "police",
    "arrest",
    "security breach",
    "frozen",
    "blocked",
    "បន្ទាន់",
    "ជាបន្ទាន់",
    "បិទគណនី",
    "ផ្អាកដំណើរការ",
    "បង្កក",
    "គំរាម",
  ];
  if (urgencyTerms.some((term) => lower.includes(term))) {
    score += 25;
    tactics.push("Urgency & Fear Tactics (Pressuring victim to act without thinking)");
    redFlags.push("Message creates artificial panic or urgent deadline");
  }

  // Social Engineering Pattern 2: Greed & Fake Prizes
  const greedTerms = [
    "you won",
    "lottery",
    "cash prize",
    "free money",
    "claim your reward",
    "airdrop",
    "giveaway",
    "free telegram premium",
    "crypto giveaway",
    "bonus",
    "ឈ្នះរង្វាន់",
    "ឥតគិតថ្លៃ",
    "លុយហ្វ្រី",
    "ទទួលបានរង្វាន់",
  ];
  if (greedTerms.some((term) => lower.includes(term))) {
    score += 30;
    tactics.push("Lure & False Reward (Promising free money, prizes, or bonuses)");
    redFlags.push("Offers unrealistic financial reward or unrequested giveaway");
  }

  // Social Engineering Pattern 3: Credential & OTP Solicitation
  const credTerms = [
    "send me your password",
    "otp",
    "verification code",
    "secret code",
    "seed phrase",
    "private key",
    "confirm your identity",
    "ផ្ញើលេខកូដ otp",
    "លេខសម្ងាត់",
    "password",
    "កូដសម្ងាត់",
  ];
  if (credTerms.some((term) => lower.includes(term))) {
    score += 45;
    tactics.push("Credential Harvesting (Attempting to steal passwords or OTP tokens)");
    redFlags.push("Explicit request for confidential security codes or login credentials");
  }

  // Factor in URL scores
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
  const verdict: "MALICIOUS" | "SUSPICIOUS" | "CLEAN" =
    score >= 65 ? "MALICIOUS" : score >= 30 ? "SUSPICIOUS" : "CLEAN";

  const recommendations: string[] = [];
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

  // Deduplicate red flags
  const uniqueRedFlags = Array.from(new Set(redFlags));

  return {
    text,
    urls,
    urlResults,
    verdict,
    riskScore: score,
    redFlags: uniqueRedFlags,
    tactics,
    recommendations,
  };
}
