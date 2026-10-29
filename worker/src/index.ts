/**
 * CyberGuard AI - Cloudflare Worker Entry Point
 * Telegram Webhook Gateway & AI Malware Analysis Orchestrator
 */

import { routeTelegramUpdate } from "./router";
import { timingSafeEqual } from "./security";
import { Env, TelegramUpdate } from "./types";

const MAX_PAYLOAD_BYTES = 512 * 1024; // 512 KB

export default {
  async fetch(
    request: Request,
    env: Env,
    ctx: ExecutionContext
  ): Promise<Response> {
    const url = new URL(request.url);
    const method = request.method.toUpperCase();

    // 1. Health check & status endpoint (GET / or GET /health)
    if (url.pathname === "/" || url.pathname === "/health") {
      if (method === "GET") {
        return new Response(
          JSON.stringify({
            status: "online",
            service: "CyberGuard AI Telegram Webhook Gateway",
            platform: "Cloudflare Workers",
            scanner_service: env.SCANNER_SERVICE_URL ? "configured" : "unconfigured",
            gemini_ai: env.GEMINI_API_KEY ? "configured" : "unconfigured",
            timestamp: new Date().toISOString(),
          }),
          {
            status: 200,
            headers: {
              "Content-Type": "application/json",
              "Cache-Control": "no-store",
            },
          }
        );
      }
    }

    // 2. Reject non-POST requests to webhook endpoint with HTTP 405
    if (method !== "POST") {
      return new Response(
        JSON.stringify({
          error: "Method Not Allowed",
          message: "Telegram webhook updates must be sent via HTTP POST.",
        }),
        {
          status: 405,
          headers: {
            "Content-Type": "application/json",
            Allow: "POST, GET",
          },
        }
      );
    }

    // 3. Webhook Authentication: Verify X-Telegram-Bot-Api-Secret-Token
    const secretTokenHeader = request.headers.get("X-Telegram-Bot-Api-Secret-Token");
    if (!secretTokenHeader || !env.TELEGRAM_WEBHOOK_SECRET) {
      return new Response(
        JSON.stringify({
          error: "Unauthorized",
          message: "Missing or invalid webhook secret token.",
        }),
        {
          status: 401,
          headers: { "Content-Type": "application/json" },
        }
      );
    }

    const isValidSecret = await timingSafeEqual(
      secretTokenHeader,
      env.TELEGRAM_WEBHOOK_SECRET
    );

    if (!isValidSecret) {
      return new Response(
        JSON.stringify({
          error: "Unauthorized",
          message: "Invalid webhook secret token.",
        }),
        {
          status: 401,
          headers: { "Content-Type": "application/json" },
        }
      );
    }

    // 4. Request Body Size Limit Check
    const contentLength = request.headers.get("content-length");
    if (contentLength && parseInt(contentLength, 10) > MAX_PAYLOAD_BYTES) {
      return new Response(
        JSON.stringify({
          error: "Payload Too Large",
          message: `Request body exceeds maximum allowed size of ${MAX_PAYLOAD_BYTES} bytes.`,
        }),
        {
          status: 413,
          headers: { "Content-Type": "application/json" },
        }
      );
    }

    let rawBody: string;
    try {
      rawBody = await request.text();
    } catch {
      return new Response(
        JSON.stringify({ error: "Bad Request", message: "Failed to read request body." }),
        {
          status: 400,
          headers: { "Content-Type": "application/json" },
        }
      );
    }

    if (rawBody.length > MAX_PAYLOAD_BYTES) {
      return new Response(
        JSON.stringify({
          error: "Payload Too Large",
          message: `Request body exceeds maximum allowed size of ${MAX_PAYLOAD_BYTES} bytes.`,
        }),
        {
          status: 413,
          headers: { "Content-Type": "application/json" },
        }
      );
    }

    // 5. Parse and Validate Telegram Update
    let update: TelegramUpdate;
    try {
      update = JSON.parse(rawBody);
    } catch {
      return new Response(
        JSON.stringify({
          error: "Bad Request",
          message: "Malformed JSON payload.",
        }),
        {
          status: 400,
          headers: { "Content-Type": "application/json" },
        }
      );
    }

    if (!update || typeof update !== "object" || typeof update.update_id !== "number") {
      return new Response(
        JSON.stringify({
          error: "Bad Request",
          message: "Invalid Telegram update structure.",
        }),
        {
          status: 400,
          headers: { "Content-Type": "application/json" },
        }
      );
    }

    // 6. Dispatch Update to Router
    try {
      await routeTelegramUpdate(update, env, ctx);
    } catch (err: unknown) {
      const errMsg = err instanceof Error ? err.message : "Unknown error";
      console.error(`[CyberGuard Worker] Router error: ${errMsg}`);
      // Return 200 OK so Telegram doesn't retry looping failed messages endlessly
    }

    return new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  },
};
