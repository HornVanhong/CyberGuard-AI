/**
 * CyberGuard AI - Cloudflare Worker Comprehensive Test Suite
 * Covers 26 security, routing, Gemini AI, ClamAV/YARA, and edge handling scenarios.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import worker from "../src/index";
import { timingSafeEqual, sanitizeFilename, maskSecret } from "../src/security";
import { Env, TelegramUpdate } from "../src/types";

const mockEnv: Env = {
  TELEGRAM_BOT_TOKEN: "123456789:ABCdefGhIJKlmNoPQRsTUVwxyZ",
  GEMINI_API_KEY: "AIzaSyFakeGeminiApiKeyForTesting12345",
  TELEGRAM_WEBHOOK_SECRET: "CyberGuard_Super_Secret_Webhook_Token_2026",
  SCANNER_SERVICE_URL: "https://scanner.internal.local",
  SCANNER_API_TOKEN: "scanner-secret-token-12345",
  GEMINI_MODEL: "gemini-3.5-flash",
  MAX_FILE_SIZE_BYTES: "20971520",
  DEFAULT_LANGUAGE: "km",
};

describe("CyberGuard AI Cloudflare Worker", () => {
  let originalFetch: typeof globalThis.fetch;
  let fetchMock: ReturnType<typeof vi.fn>;
  let waitUntilPromises: Promise<any>[] = [];

  const mockCtx: ExecutionContext = {
    waitUntil: vi.fn((promise: Promise<any>) => {
      waitUntilPromises.push(promise);
    }),
    passThroughOnException: vi.fn(),
  } as unknown as ExecutionContext;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
    fetchMock = vi.fn();
    globalThis.fetch = fetchMock;
    waitUntilPromises = [];
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  // ================= 1. Health & Status Endpoints =================

  it("1. GET / returns HTTP 200 with online gateway status", async () => {
    const req = new Request("https://telegram-scan-bot.vanhonghorn37.workers.dev/", {
      method: "GET",
    });

    const res = await worker.fetch(req, mockEnv, mockCtx);
    expect(res.status).toBe(200);

    const body = (await res.json()) as any;
    expect(body.status).toBe("online");
    expect(body.service).toContain("CyberGuard AI");
    expect(body.gemini_ai).toBe("configured");
    expect(body.scanner_service).toBe("configured");
    expect(body.timestamp).toBeDefined();
  });

  it("2. GET /health returns HTTP 200 with online status", async () => {
    const req = new Request("https://telegram-scan-bot.vanhonghorn37.workers.dev/health", {
      method: "GET",
    });

    const res = await worker.fetch(req, mockEnv, mockCtx);
    expect(res.status).toBe(200);

    const body = (await res.json()) as any;
    expect(body.status).toBe("online");
  });

  // ================= 2. Method Validation =================

  it("3. Non-POST methods (PUT, DELETE, PATCH) return HTTP 405 Method Not Allowed", async () => {
    for (const method of ["PUT", "DELETE", "PATCH"]) {
      const req = new Request("https://telegram-scan-bot.vanhonghorn37.workers.dev/webhook", {
        method,
      });

      const res = await worker.fetch(req, mockEnv, mockCtx);
      expect(res.status).toBe(405);
      expect(res.headers.get("Allow")).toContain("POST");

      const body = (await res.json()) as any;
      expect(body.error).toBe("Method Not Allowed");
    }
  });

  // ================= 3. Webhook Authentication =================

  it("4. POST without X-Telegram-Bot-Api-Secret-Token returns HTTP 401 Unauthorized", async () => {
    const req = new Request("https://telegram-scan-bot.vanhonghorn37.workers.dev/", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ update_id: 100 }),
    });

    const res = await worker.fetch(req, mockEnv, mockCtx);
    expect(res.status).toBe(401);

    const body = (await res.json()) as any;
    expect(body.error).toBe("Unauthorized");
  });

  it("5. POST with invalid X-Telegram-Bot-Api-Secret-Token returns HTTP 401 Unauthorized", async () => {
    const req = new Request("https://telegram-scan-bot.vanhonghorn37.workers.dev/", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Telegram-Bot-Api-Secret-Token": "wrong-secret-token",
      },
      body: JSON.stringify({ update_id: 100 }),
    });

    const res = await worker.fetch(req, mockEnv, mockCtx);
    expect(res.status).toBe(401);

    const body = (await res.json()) as any;
    expect(body.error).toBe("Unauthorized");
  });

  // ================= 4. Body & Payload Limits =================

  it("6. POST with Content-Length > 512 KB returns HTTP 413 Payload Too Large", async () => {
    const req = new Request("https://telegram-scan-bot.vanhonghorn37.workers.dev/", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Telegram-Bot-Api-Secret-Token": mockEnv.TELEGRAM_WEBHOOK_SECRET,
        "Content-Length": "600000",
      },
      body: JSON.stringify({ update_id: 100 }),
    });

    const res = await worker.fetch(req, mockEnv, mockCtx);
    expect(res.status).toBe(413);

    const body = (await res.json()) as any;
    expect(body.error).toBe("Payload Too Large");
  });

  it("7. POST with actual body > 512 KB returns HTTP 413 Payload Too Large", async () => {
    const largeString = "A".repeat(600 * 1024);
    const req = new Request("https://telegram-scan-bot.vanhonghorn37.workers.dev/", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Telegram-Bot-Api-Secret-Token": mockEnv.TELEGRAM_WEBHOOK_SECRET,
      },
      body: largeString,
    });

    const res = await worker.fetch(req, mockEnv, mockCtx);
    expect(res.status).toBe(413);
  });

  it("8. POST with malformed JSON returns HTTP 400 Bad Request", async () => {
    const req = new Request("https://telegram-scan-bot.vanhonghorn37.workers.dev/", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Telegram-Bot-Api-Secret-Token": mockEnv.TELEGRAM_WEBHOOK_SECRET,
      },
      body: "{ not valid json: true }",
    });

    const res = await worker.fetch(req, mockEnv, mockCtx);
    expect(res.status).toBe(400);

    const body = (await res.json()) as any;
    expect(body.error).toBe("Bad Request");
    expect(body.message).toContain("Malformed JSON");
  });

  it("9. POST with non-object or missing update_id returns HTTP 400 Bad Request", async () => {
    const req = new Request("https://telegram-scan-bot.vanhonghorn37.workers.dev/", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Telegram-Bot-Api-Secret-Token": mockEnv.TELEGRAM_WEBHOOK_SECRET,
      },
      body: JSON.stringify({ not_an_update: "missing update_id" }),
    });

    const res = await worker.fetch(req, mockEnv, mockCtx);
    expect(res.status).toBe(400);

    const body = (await res.json()) as any;
    expect(body.message).toContain("Invalid Telegram update structure");
  });

  it("10. Valid POST with secret and unhandled update returns HTTP 200 OK", async () => {
    const update: TelegramUpdate = {
      update_id: 12345,
    };

    const req = new Request("https://telegram-scan-bot.vanhonghorn37.workers.dev/", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Telegram-Bot-Api-Secret-Token": mockEnv.TELEGRAM_WEBHOOK_SECRET,
      },
      body: JSON.stringify(update),
    });

    const res = await worker.fetch(req, mockEnv, mockCtx);
    expect(res.status).toBe(200);

    const body = (await res.json()) as any;
    expect(body.ok).toBe(true);
  });

  // ================= 5. Command Routing Scenarios =================

  it("11. /start command routes to welcome message with ReplyKeyboardMarkup", async () => {
    fetchMock.mockResolvedValueOnce(new Response(JSON.stringify({ ok: true }), { status: 200 }));

    const update: TelegramUpdate = {
      update_id: 101,
      message: {
        message_id: 1,
        chat: { id: 987654321, type: "private" },
        date: Math.floor(Date.now() / 1000),
        text: "/start",
      },
    };

    const req = new Request("https://telegram-scan-bot.vanhonghorn37.workers.dev/", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Telegram-Bot-Api-Secret-Token": mockEnv.TELEGRAM_WEBHOOK_SECRET,
      },
      body: JSON.stringify(update),
    });

    const res = await worker.fetch(req, mockEnv, mockCtx);
    expect(res.status).toBe(200);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [callUrl, callOptions] = fetchMock.mock.calls[0];
    expect(callUrl).toContain("/sendMessage");
    const payload = JSON.parse(callOptions.body);
    expect(payload.chat_id).toBe(987654321);
    expect(payload.text).toContain("CyberGuard AI");
    expect(payload.reply_markup?.keyboard).toBeDefined();
    expect(payload.reply_markup.keyboard.length).toBeGreaterThan(0);
  });

  it("12. /help command routes to user guide", async () => {
    fetchMock.mockResolvedValueOnce(new Response(JSON.stringify({ ok: true }), { status: 200 }));

    const update: TelegramUpdate = {
      update_id: 102,
      message: {
        message_id: 2,
        chat: { id: 987654321, type: "private" },
        date: Math.floor(Date.now() / 1000),
        text: "/help",
      },
    };

    const req = new Request("https://telegram-scan-bot.vanhonghorn37.workers.dev/", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Telegram-Bot-Api-Secret-Token": mockEnv.TELEGRAM_WEBHOOK_SECRET,
      },
      body: JSON.stringify(update),
    });

    const res = await worker.fetch(req, mockEnv, mockCtx);
    expect(res.status).toBe(200);

    const payload = JSON.parse(fetchMock.mock.calls[0][1].body);
    expect(payload.text).toContain("ការណែនាំ");
    expect(payload.text).toContain("/scan");
  });

  it("13. /scan command prompts user to send a file", async () => {
    fetchMock.mockResolvedValueOnce(new Response(JSON.stringify({ ok: true }), { status: 200 }));

    const update: TelegramUpdate = {
      update_id: 103,
      message: {
        message_id: 3,
        chat: { id: 987654321, type: "private" },
        date: Math.floor(Date.now() / 1000),
        text: "/scan",
      },
    };

    const req = new Request("https://telegram-scan-bot.vanhonghorn37.workers.dev/", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Telegram-Bot-Api-Secret-Token": mockEnv.TELEGRAM_WEBHOOK_SECRET,
      },
      body: JSON.stringify(update),
    });

    const res = await worker.fetch(req, mockEnv, mockCtx);
    expect(res.status).toBe(200);

    const payload = JSON.parse(fetchMock.mock.calls[0][1].body);
    expect(payload.text).toContain("សូមផ្ញើ ឬ Forward ឯកសារ");
  });

  it("14. /status command reports health of engines", async () => {
    fetchMock.mockResolvedValueOnce(new Response(JSON.stringify({ ok: true }), { status: 200 }));

    const update: TelegramUpdate = {
      update_id: 104,
      message: {
        message_id: 4,
        chat: { id: 987654321, type: "private" },
        date: Math.floor(Date.now() / 1000),
        text: "/status",
      },
    };

    const req = new Request("https://telegram-scan-bot.vanhonghorn37.workers.dev/", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Telegram-Bot-Api-Secret-Token": mockEnv.TELEGRAM_WEBHOOK_SECRET,
      },
      body: JSON.stringify(update),
    });

    const res = await worker.fetch(req, mockEnv, mockCtx);
    expect(res.status).toBe(200);

    const payload = JSON.parse(fetchMock.mock.calls[0][1].body);
    expect(payload.text).toContain("ស្ថានភាពម៉ាស៊ីនវិភាគ");
    expect(payload.text).toContain("ClamAV Antivirus");
    expect(payload.text).toContain("YARA Rules Engine");
    expect(payload.text).toContain("Google Gemini AI");
  });

  it("15. /privacy command sends zero-trust privacy policy", async () => {
    fetchMock.mockResolvedValueOnce(new Response(JSON.stringify({ ok: true }), { status: 200 }));

    const update: TelegramUpdate = {
      update_id: 105,
      message: {
        message_id: 5,
        chat: { id: 987654321, type: "private" },
        date: Math.floor(Date.now() / 1000),
        text: "/privacy",
      },
    };

    const req = new Request("https://telegram-scan-bot.vanhonghorn37.workers.dev/", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Telegram-Bot-Api-Secret-Token": mockEnv.TELEGRAM_WEBHOOK_SECRET,
      },
      body: JSON.stringify(update),
    });

    const res = await worker.fetch(req, mockEnv, mockCtx);
    expect(res.status).toBe(200);

    const payload = JSON.parse(fetchMock.mock.calls[0][1].body);
    expect(payload.text).toContain("គោលការណ៍ឯកជនភាព");
  });

  it("16. /lang command instructs user how to configure language", async () => {
    fetchMock.mockResolvedValueOnce(new Response(JSON.stringify({ ok: true }), { status: 200 }));

    const update: TelegramUpdate = {
      update_id: 106,
      message: {
        message_id: 6,
        chat: { id: 987654321, type: "private" },
        date: Math.floor(Date.now() / 1000),
        text: "/lang",
      },
    };

    const req = new Request("https://telegram-scan-bot.vanhonghorn37.workers.dev/", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Telegram-Bot-Api-Secret-Token": mockEnv.TELEGRAM_WEBHOOK_SECRET,
      },
      body: JSON.stringify(update),
    });

    const res = await worker.fetch(req, mockEnv, mockCtx);
    expect(res.status).toBe(200);

    const payload = JSON.parse(fetchMock.mock.calls[0][1].body);
    expect(payload.text).toContain("ភាសា");
  });

  it("17. /ghidra command explains Ghidra reverse engineering", async () => {
    fetchMock.mockResolvedValueOnce(new Response(JSON.stringify({ ok: true }), { status: 200 }));

    const update: TelegramUpdate = {
      update_id: 107,
      message: {
        message_id: 7,
        chat: { id: 987654321, type: "private" },
        date: Math.floor(Date.now() / 1000),
        text: "/ghidra",
      },
    };

    const req = new Request("https://telegram-scan-bot.vanhonghorn37.workers.dev/", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Telegram-Bot-Api-Secret-Token": mockEnv.TELEGRAM_WEBHOOK_SECRET,
      },
      body: JSON.stringify(update),
    });

    const res = await worker.fetch(req, mockEnv, mockCtx);
    expect(res.status).toBe(200);

    const payload = JSON.parse(fetchMock.mock.calls[0][1].body);
    expect(payload.text).toContain("Ghidra");
  });

  it("18. Reply Keyboard button routing properly invokes handlers", async () => {
    fetchMock.mockResolvedValueOnce(new Response(JSON.stringify({ ok: true }), { status: 200 }));

    const update: TelegramUpdate = {
      update_id: 108,
      message: {
        message_id: 8,
        chat: { id: 987654321, type: "private" },
        date: Math.floor(Date.now() / 1000),
        text: "🔍 ស្កេនឯកសារ",
      },
    };

    const req = new Request("https://telegram-scan-bot.vanhonghorn37.workers.dev/", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Telegram-Bot-Api-Secret-Token": mockEnv.TELEGRAM_WEBHOOK_SECRET,
      },
      body: JSON.stringify(update),
    });

    const res = await worker.fetch(req, mockEnv, mockCtx);
    expect(res.status).toBe(200);

    const payload = JSON.parse(fetchMock.mock.calls[0][1].body);
    expect(payload.text).toContain("សូមផ្ញើ ឬ Forward ឯកសារ");
  });

  // ================= 6. Gemini AI Question & Explanations =================

  it("19. Free-form text query invokes Gemini API and returns cybersecurity response", async () => {
    // 1. sendChatAction ("typing")
    fetchMock.mockResolvedValueOnce(new Response(JSON.stringify({ ok: true }), { status: 200 }));
    // 2. Gemini API call
    fetchMock.mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          candidates: [
            {
              content: {
                parts: [{ text: "Ransomware គឺជាកម្មវិធីមេរោគដែលធ្វើការចាក់សោរឯកសារ..." }],
              },
            },
          ],
        }),
        { status: 200 }
      )
    );
    // 3. Telegram sendMessage
    fetchMock.mockResolvedValueOnce(new Response(JSON.stringify({ ok: true }), { status: 200 }));

    const update: TelegramUpdate = {
      update_id: 109,
      message: {
        message_id: 9,
        chat: { id: 987654321, type: "private" },
        date: Math.floor(Date.now() / 1000),
        text: "តើអ្វីទៅជា Ransomware ហើយការពារដូចម្ដេច?",
      },
    };

    const req = new Request("https://telegram-scan-bot.vanhonghorn37.workers.dev/", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Telegram-Bot-Api-Secret-Token": mockEnv.TELEGRAM_WEBHOOK_SECRET,
      },
      body: JSON.stringify(update),
    });

    const res = await worker.fetch(req, mockEnv, mockCtx);
    expect(res.status).toBe(200);

    // Verify Gemini API was called with system instruction and prompt
    const geminiCall = fetchMock.mock.calls.find((c) =>
      c[0].includes("generativelanguage.googleapis.com")
    );
    expect(geminiCall).toBeDefined();
    const geminiPayload = JSON.parse(geminiCall![1].body);
    expect(geminiPayload.system_instruction).toBeDefined();

    // Verify Telegram sendMessage delivered the response
    const lastSendCall = fetchMock.mock.calls[fetchMock.mock.calls.length - 1];
    const sendPayload = JSON.parse(lastSendCall[1].body);
    expect(sendPayload.text).toContain("Ransomware");
  });

  it("20. Gemini API failure or timeout is handled gracefully", async () => {
    // 1. sendChatAction
    fetchMock.mockResolvedValueOnce(new Response(JSON.stringify({ ok: true }), { status: 200 }));
    // 2. Gemini API 500 error
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify({ error: { message: "Internal server error" } }), {
        status: 500,
      })
    );
    // 3. Telegram sendMessage fallback
    fetchMock.mockResolvedValueOnce(new Response(JSON.stringify({ ok: true }), { status: 200 }));

    const update: TelegramUpdate = {
      update_id: 110,
      message: {
        message_id: 10,
        chat: { id: 987654321, type: "private" },
        date: Math.floor(Date.now() / 1000),
        text: "Tell me about phishing attacks",
      },
    };

    const req = new Request("https://telegram-scan-bot.vanhonghorn37.workers.dev/", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Telegram-Bot-Api-Secret-Token": mockEnv.TELEGRAM_WEBHOOK_SECRET,
      },
      body: JSON.stringify(update),
    });

    const res = await worker.fetch(req, mockEnv, mockCtx);
    expect(res.status).toBe(200);

    const lastSendCall = fetchMock.mock.calls[fetchMock.mock.calls.length - 1];
    const sendPayload = JSON.parse(lastSendCall[1].body);
    expect(sendPayload.text).toContain("Gemini AI ជួបបញ្ហា");
  });

  // ================= 7. File Upload & Malware Scanning Boundary =================

  it("21. File upload with CLEAN scan produces clean verdict report", async () => {
    // 1. send initial "Processing file..." message
    fetchMock.mockResolvedValueOnce(new Response(JSON.stringify({ ok: true }), { status: 200 }));
    // 2. getFile
    fetchMock.mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          ok: true,
          result: { file_id: "file-clean-123", file_path: "documents/sample.pdf" },
        }),
        { status: 200 }
      )
    );
    // 3. downloadFile
    fetchMock.mockResolvedValueOnce(
      new Response(new TextEncoder().encode("%PDF-1.4 sample safe pdf content"), {
        status: 200,
      })
    );
    // 4. Scanner service POST /scan (Clean result)
    fetchMock.mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          verdict: "CLEAN",
          severity: "CLEAN",
          clamav: { status: "COMPLETED", detected: false },
          yara: { status: "COMPLETED", matches: [], rules_evaluated: 450 },
          findings: ["No known signatures found."],
          recommendations: ["File appears clean."],
        }),
        { status: 200 }
      )
    );
    // 5. Gemini API summary explanation
    fetchMock.mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          candidates: [
            {
              content: {
                parts: [{ text: "ឯកសារនេះត្រូវបានស្កេនយ៉ាងល្អិតល្អន់ ហើយមិនឃើញមានកូដមេរោគឡើយ។" }],
              },
            },
          ],
        }),
        { status: 200 }
      )
    );
    // 6. Telegram sendMessage with scan report
    fetchMock.mockResolvedValueOnce(new Response(JSON.stringify({ ok: true }), { status: 200 }));

    const update: TelegramUpdate = {
      update_id: 111,
      message: {
        message_id: 11,
        chat: { id: 987654321, type: "private" },
        date: Math.floor(Date.now() / 1000),
        document: {
          file_id: "file-clean-123",
          file_unique_id: "uniq-123",
          file_name: "invoice.pdf",
          file_size: 1024,
        },
      },
    };

    const req = new Request("https://telegram-scan-bot.vanhonghorn37.workers.dev/", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Telegram-Bot-Api-Secret-Token": mockEnv.TELEGRAM_WEBHOOK_SECRET,
      },
      body: JSON.stringify(update),
    });

    const res = await worker.fetch(req, mockEnv, mockCtx);
    expect(res.status).toBe(200);

    // Await background execution from ctx.waitUntil
    await Promise.all(waitUntilPromises);

    // Verify scan report sent to Telegram
    const lastSendCall = fetchMock.mock.calls[fetchMock.mock.calls.length - 1];
    expect(lastSendCall).toBeDefined();
    const sendPayload = JSON.parse(lastSendCall[1].body);
    expect(sendPayload.text).toContain("CLEAN");
    expect(sendPayload.text).toContain("invoice.pdf");
    expect(sendPayload.text).toContain("SHA-256");
  });

  it("22. File upload with ClamAV / YARA detection produces MALICIOUS alert and high risk", async () => {
    // 1. send initial message
    fetchMock.mockResolvedValueOnce(new Response(JSON.stringify({ ok: true }), { status: 200 }));
    // 2. getFile
    fetchMock.mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          ok: true,
          result: { file_id: "file-bad-456", file_path: "documents/malware.exe" },
        }),
        { status: 200 }
      )
    );
    // 3. downloadFile
    fetchMock.mockResolvedValueOnce(
      new Response(new TextEncoder().encode("MZ executable payload with malicious code"), {
        status: 200,
      })
    );
    // 4. Scanner service detects Trojan
    fetchMock.mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          verdict: "MALICIOUS",
          severity: "CRITICAL",
          clamav: {
            status: "COMPLETED",
            detected: true,
            virus_name: "Win32.Trojan.AgentTesla",
          },
          yara: {
            status: "COMPLETED",
            matches: [{ rule_name: "suspicious_obfuscation" }],
            rules_evaluated: 450,
          },
          findings: [
            "ClamAV detected: Win32.Trojan.AgentTesla",
            "YARA rule matched: suspicious_obfuscation",
          ],
          recommendations: ["Do NOT execute or open this file."],
        }),
        { status: 200 }
      )
    );
    // 5. Gemini explanation
    fetchMock.mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          candidates: [
            {
              content: {
                parts: [{ text: "ព្រមាន៖ ឯកសារនេះមានផ្ទុកមេរោគ AgentTesla Spyware ដ៏គ្រោះថ្នាក់បំផុត!" }],
              },
            },
          ],
        }),
        { status: 200 }
      )
    );
    // 6. Telegram sendMessage
    fetchMock.mockResolvedValueOnce(new Response(JSON.stringify({ ok: true }), { status: 200 }));

    const update: TelegramUpdate = {
      update_id: 112,
      message: {
        message_id: 12,
        chat: { id: 987654321, type: "private" },
        date: Math.floor(Date.now() / 1000),
        document: {
          file_id: "file-bad-456",
          file_unique_id: "uniq-bad",
          file_name: "payload.exe",
          file_size: 4096,
        },
      },
    };

    const req = new Request("https://telegram-scan-bot.vanhonghorn37.workers.dev/", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Telegram-Bot-Api-Secret-Token": mockEnv.TELEGRAM_WEBHOOK_SECRET,
      },
      body: JSON.stringify(update),
    });

    const res = await worker.fetch(req, mockEnv, mockCtx);
    expect(res.status).toBe(200);

    // Await background execution
    await Promise.all(waitUntilPromises);

    const lastSendCall = fetchMock.mock.calls[fetchMock.mock.calls.length - 1];
    expect(lastSendCall).toBeDefined();
    const sendPayload = JSON.parse(lastSendCall[1].body);
    expect(sendPayload.text).toContain("MALICIOUS");
    expect(sendPayload.text).toContain("Win32.Trojan.AgentTesla");
    expect(sendPayload.text).toContain("CRITICAL");
  });

  it("23. Scanner service unavailable marks file INCONCLUSIVE and never marks CLEAN", async () => {
    // 1. send initial message
    fetchMock.mockResolvedValueOnce(new Response(JSON.stringify({ ok: true }), { status: 200 }));
    // 2. getFile
    fetchMock.mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          ok: true,
          result: { file_id: "file-unknown-789", file_path: "documents/unknown.bin" },
        }),
        { status: 200 }
      )
    );
    // 3. downloadFile
    fetchMock.mockResolvedValueOnce(
      new Response(new TextEncoder().encode("binary test data"), { status: 200 })
    );
    // 4. Scanner service returns 503 Service Unavailable
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify({ error: "ClamAV daemon offline" }), { status: 503 })
    );
    // 5. Gemini explanation
    fetchMock.mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          candidates: [
            {
              content: {
                parts: [{ text: "ម៉ាស៊ីនស្កេនមេរោគកំពុងមានបញ្ហាបច្ចេកទេស។ សូមកុំទាន់បើកឯកសារនេះ។" }],
              },
            },
          ],
        }),
        { status: 200 }
      )
    );
    // 6. Telegram sendMessage
    fetchMock.mockResolvedValueOnce(new Response(JSON.stringify({ ok: true }), { status: 200 }));

    const update: TelegramUpdate = {
      update_id: 113,
      message: {
        message_id: 13,
        chat: { id: 987654321, type: "private" },
        date: Math.floor(Date.now() / 1000),
        document: {
          file_id: "file-unknown-789",
          file_unique_id: "uniq-unknown",
          file_name: "unknown.bin",
          file_size: 2048,
        },
      },
    };

    const req = new Request("https://telegram-scan-bot.vanhonghorn37.workers.dev/", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Telegram-Bot-Api-Secret-Token": mockEnv.TELEGRAM_WEBHOOK_SECRET,
      },
      body: JSON.stringify(update),
    });

    const res = await worker.fetch(req, mockEnv, mockCtx);
    expect(res.status).toBe(200);

    // Await background execution
    await Promise.all(waitUntilPromises);

    const lastSendCall = fetchMock.mock.calls[fetchMock.mock.calls.length - 1];
    expect(lastSendCall).toBeDefined();
    const sendPayload = JSON.parse(lastSendCall[1].body);
    expect(sendPayload.text).toContain("INCONCLUSIVE");
    expect(sendPayload.text).not.toContain("Verdict: 🟢 CLEAN");
  });

  it("24. File exceeding size limit is rejected without downloading", async () => {
    fetchMock.mockResolvedValueOnce(new Response(JSON.stringify({ ok: true }), { status: 200 }));

    const update: TelegramUpdate = {
      update_id: 114,
      message: {
        message_id: 14,
        chat: { id: 987654321, type: "private" },
        date: Math.floor(Date.now() / 1000),
        document: {
          file_id: "file-huge-999",
          file_unique_id: "uniq-huge",
          file_name: "huge_archive.zip",
          file_size: 50 * 1024 * 1024, // 50 MB > 20 MB limit
        },
      },
    };

    const req = new Request("https://telegram-scan-bot.vanhonghorn37.workers.dev/", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Telegram-Bot-Api-Secret-Token": mockEnv.TELEGRAM_WEBHOOK_SECRET,
      },
      body: JSON.stringify(update),
    });

    const res = await worker.fetch(req, mockEnv, mockCtx);
    expect(res.status).toBe(200);

    const sendCall = fetchMock.mock.calls[0];
    const sendPayload = JSON.parse(sendCall[1].body);
    expect(sendPayload.text).toContain("ឯកសារធំពេក");
    // Verify getFile was NEVER called
    expect(fetchMock.mock.calls.some((c) => c[0].includes("/getFile"))).toBe(false);
  });

  // ================= 8. Security Utilities =================

  it("25. timingSafeEqual validates matching and non-matching tokens securely", async () => {
    const token = "cyberguard-secret-token-123456789";
    expect(await timingSafeEqual(token, token)).toBe(true);
    expect(await timingSafeEqual(token, "cyberguard-secret-token-123456780")).toBe(false);
    expect(await timingSafeEqual(token, "short-token")).toBe(false);
    expect(await timingSafeEqual(token, token + "-extra")).toBe(false);
  });

  it("26. sanitizeFilename cleans path traversal and control characters", () => {
    expect(sanitizeFilename("../../etc/passwd")).toBe("etc_passwd");
    expect(sanitizeFilename("..\\..\\windows\\system32\\calc.exe")).toBe("windows_system32_calc.exe");
    expect(sanitizeFilename("malware\x00test.exe")).toBe("malwaretest.exe");
    expect(sanitizeFilename("")).toBe("unnamed_payload.bin");
    expect(sanitizeFilename(undefined)).toBe("unnamed_payload.bin");

    // maskSecret masks tokens cleanly
    expect(maskSecret("1234567890abcdef")).toBe("1234...cdef");
    expect(maskSecret("short")).toBe("[REDACTED]");
  });
});
