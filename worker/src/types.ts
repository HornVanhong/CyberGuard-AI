/**
 * CyberGuard AI - Cloudflare Worker Type Definitions & Contracts
 */

export interface Env {
  // Required Cloudflare Secrets
  TELEGRAM_BOT_TOKEN: string;
  GEMINI_API_KEY: string;
  TELEGRAM_WEBHOOK_SECRET: string;

  // Optional Scanner Service Configuration
  SCANNER_SERVICE_URL?: string;
  SCANNER_API_TOKEN?: string;

  // Optional Environment Variables
  GEMINI_MODEL?: string;
  MAX_FILE_SIZE_BYTES?: string;
  DEFAULT_LANGUAGE?: string;
}

// ================= Telegram API Types =================

export interface TelegramUser {
  id: number;
  is_bot: boolean;
  first_name: string;
  last_name?: string;
  username?: string;
  language_code?: string;
}

export interface TelegramChat {
  id: number;
  type: "private" | "group" | "supergroup" | "channel";
  title?: string;
  username?: string;
  first_name?: string;
  last_name?: string;
}

export interface TelegramDocument {
  file_id: string;
  file_unique_id: string;
  file_name?: string;
  mime_type?: string;
  file_size?: number;
}

export interface TelegramPhotoSize {
  file_id: string;
  file_unique_id: string;
  width: number;
  height: number;
  file_size?: number;
}

export interface TelegramMessage {
  message_id: number;
  from?: TelegramUser;
  chat: TelegramChat;
  date: number;
  text?: string;
  caption?: string;
  document?: TelegramDocument;
  photo?: TelegramPhotoSize[];
}

export interface TelegramCallbackQuery {
  id: string;
  from: TelegramUser;
  message?: TelegramMessage;
  data?: string;
}

export interface TelegramUpdate {
  update_id: number;
  message?: TelegramMessage;
  callback_query?: TelegramCallbackQuery;
}

export interface InlineKeyboardButton {
  text: string;
  callback_data?: string;
  url?: string;
}

export interface InlineKeyboardMarkup {
  inline_keyboard: InlineKeyboardButton[][];
}

export interface KeyboardButton {
  text: string;
}

export interface ReplyKeyboardMarkup {
  keyboard: KeyboardButton[][];
  resize_keyboard?: boolean;
  one_time_keyboard?: boolean;
  is_persistent?: boolean;
  input_field_placeholder?: string;
}

export interface SendMessagePayload {
  chat_id: number;
  text: string;
  parse_mode?: "Markdown" | "HTML";
  reply_markup?: InlineKeyboardMarkup | ReplyKeyboardMarkup;
  disable_web_page_preview?: boolean;
}

export interface TelegramFileResponse {
  ok: boolean;
  result?: {
    file_id: string;
    file_unique_id: string;
    file_size?: number;
    file_path?: string;
  };
  description?: string;
}

// ================= Malware Scanner Contracts =================

export type ScanStatus = "COMPLETED" | "FAILED" | "UNAVAILABLE" | "TIMEOUT";
export type ThreatVerdict = "MALICIOUS" | "SUSPICIOUS" | "CLEAN" | "INCONCLUSIVE";
export type SeverityLevel = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "CLEAN";

export interface ClamAVScanResult {
  status: ScanStatus;
  detected: boolean;
  virus_name?: string;
  version?: string;
  error?: string;
}

export interface YARAMatch {
  rule_name: string;
  namespace?: string;
  tags?: string[];
  description?: string;
}

export interface YARAScanResult {
  status: ScanStatus;
  matches: YARAMatch[];
  rules_evaluated?: number;
  error?: string;
}

export interface NormalizedScanReport {
  scan_id: string;
  filename: string;
  file_size_bytes: number;
  sha256: string;
  verdict: ThreatVerdict;
  severity: SeverityLevel;
  clamav: ClamAVScanResult;
  yara: YARAScanResult;
  findings: string[];
  recommendations: string[];
  execution_time_ms: number;
}

// ================= Gemini AI Types =================

export interface GeminiExplanation {
  summary: string;
  threat_analysis: string;
  recommendations: string[];
  disclaimer: string;
}
