/**
 * CyberGuard AI - Telegram Bot API Client
 */

import {
  SendMessagePayload,
  TelegramFileResponse,
  ReplyKeyboardMarkup,
} from "./types";

const TELEGRAM_API_BASE = "https://api.telegram.org";

/**
 * Sends a message via the official Telegram Bot API with automatic message splitting.
 */
export async function sendTelegramMessage(
  token: string,
  payload: SendMessagePayload
): Promise<boolean> {
  const chunks = splitTelegramMessage(payload.text, 4000);

  for (let i = 0; i < chunks.length; i++) {
    const isLastChunk = i === chunks.length - 1;
    const body: SendMessagePayload = {
      chat_id: payload.chat_id,
      text: chunks[i],
      parse_mode: payload.parse_mode,
      disable_web_page_preview: payload.disable_web_page_preview ?? true,
      // Only attach reply_markup to the final message chunk
      reply_markup: isLastChunk ? payload.reply_markup : undefined,
    };

    const res = await fetch(`${TELEGRAM_API_BASE}/bot${token}/sendMessage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });

    if (!res.ok) {
      // Fallback: if Markdown parsing fails (e.g., special characters in code), retry as plain text
      if (payload.parse_mode === "Markdown") {
        await fetch(`${TELEGRAM_API_BASE}/bot${token}/sendMessage`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            ...body,
            parse_mode: undefined,
          }),
        });
      }
    }
  }

  return true;
}

/**
 * Sends chat action indicators (e.g., 'typing', 'upload_document').
 */
export async function sendChatAction(
  token: string,
  chatId: number,
  action: string = "typing"
): Promise<void> {
  try {
    await fetch(`${TELEGRAM_API_BASE}/bot${token}/sendChatAction`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ chat_id: chatId, action }),
    });
  } catch {
    // Non-critical action; ignore errors
  }
}

/**
 * Retrieves file path from Telegram servers.
 */
export async function getTelegramFile(
  token: string,
  fileId: string
): Promise<TelegramFileResponse> {
  const res = await fetch(`${TELEGRAM_API_BASE}/bot${token}/getFile?file_id=${fileId}`);
  if (!res.ok) {
    throw new Error(`Telegram getFile failed with HTTP status ${res.status}`);
  }
  return (await res.json()) as TelegramFileResponse;
}

/**
 * Downloads a file from Telegram storage into an ArrayBuffer.
 */
export async function downloadTelegramFile(
  token: string,
  filePath: string
): Promise<ArrayBuffer> {
  const downloadUrl = `${TELEGRAM_API_BASE}/file/bot${token}/${filePath}`;
  const res = await fetch(downloadUrl);
  if (!res.ok) {
    throw new Error(`Failed to download file from Telegram: HTTP ${res.status}`);
  }
  return await res.arrayBuffer();
}

/**
 * Splits long messages to fit within Telegram's 4096 character limit.
 */
export function splitTelegramMessage(text: string, maxLen: number = 4000): string[] {
  if (text.length <= maxLen) return [text];

  const chunks: string[] = [];
  let remaining = text;

  while (remaining.length > 0) {
    if (remaining.length <= maxLen) {
      chunks.push(remaining);
      break;
    }

    // Try splitting at line breaks
    let splitIdx = remaining.lastIndexOf("\n", maxLen);
    if (splitIdx === -1 || splitIdx < maxLen / 2) {
      // Try splitting at spaces
      splitIdx = remaining.lastIndexOf(" ", maxLen);
    }
    if (splitIdx === -1 || splitIdx < maxLen / 2) {
      splitIdx = maxLen;
    }

    chunks.push(remaining.slice(0, splitIdx));
    remaining = remaining.slice(splitIdx).trimStart();
  }

  return chunks;
}

/**
 * Returns the persistent bottom keyboard matching the user's preferred language.
 */
export function getReplyKeyboard(lang: string = "km"): ReplyKeyboardMarkup {
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
      [{ text: "🔍 Scan File" }, { text: "🔗 វិភាគ Link & សារ" }],
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
