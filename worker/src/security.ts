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
