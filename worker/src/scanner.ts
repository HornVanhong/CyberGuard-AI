/**
 * CyberGuard AI - ClamAV & YARA Malware Scanner Client
 *
 * Cloudflare Workers runtime (V8 Isolate) does not execute native Linux binaries.
 * This module defines the secure HTTPS integration boundary communicating with
 * the isolated CyberGuard AI scanning service worker or ClamAV/YARA daemon API.
 */

import { computeSHA256, sanitizeFilename } from "./security";
import {
  Env,
  NormalizedScanReport,
  ClamAVScanResult,
  YARAScanResult,
  ThreatVerdict,
  SeverityLevel,
} from "./types";

/**
 * Submits an uploaded file buffer to the authenticated scanning service.
 * Enforces timeouts, authenticates via separate SCANNER_API_TOKEN, and normalizes findings.
 */
export async function scanFile(
  fileBuffer: ArrayBuffer,
  filename: string,
  env: Env
): Promise<NormalizedScanReport> {
  const startTime = Date.now();
  const sha256 = await computeSHA256(fileBuffer);
  const cleanName = sanitizeFilename(filename);
  const scanId = crypto.randomUUID().slice(0, 8);

  const scannerUrl = env.SCANNER_SERVICE_URL || "https://warning-gallery-rss-autos.trycloudflare.com";

  // If scanner service endpoint is not configured, report accurately as UNAVAILABLE
  if (!scannerUrl) {
    return createInconclusiveReport(
      scanId,
      cleanName,
      fileBuffer.byteLength,
      sha256,
      Date.now() - startTime,
      "Scanner service URL not configured (SCANNER_SERVICE_URL). Native ClamAV and YARA engines unavailable."
    );
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 20000); // 20s execution budget

  try {
    const formData = new FormData();
    formData.append("file", new Blob([fileBuffer]), cleanName);

    const headers: Record<string, string> = {};
    if (env.SCANNER_API_TOKEN) {
      headers["Authorization"] = `Bearer ${env.SCANNER_API_TOKEN}`;
    }

    const res = await fetch(`${scannerUrl}/scan`, {
      method: "POST",
      headers,
      body: formData,
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    if (res.status === 401 || res.status === 403) {
      return createInconclusiveReport(
        scanId,
        cleanName,
        fileBuffer.byteLength,
        sha256,
        Date.now() - startTime,
        "Scanner service authentication failed. Invalid or missing SCANNER_API_TOKEN."
      );
    }

    if (!res.ok) {
      return createInconclusiveReport(
        scanId,
        cleanName,
        fileBuffer.byteLength,
        sha256,
        Date.now() - startTime,
        `Scanner service returned HTTP error ${res.status}.`
      );
    }

    const rawData = (await res.json()) as any;
    return normalizeScannerOutput(
      scanId,
      cleanName,
      fileBuffer.byteLength,
      sha256,
      Date.now() - startTime,
      rawData
    );
  } catch (err: any) {
    clearTimeout(timeoutId);
    const isTimeout = err.name === "AbortError";
    const errorMsg = isTimeout
      ? "Malware scanning timed out after 20 seconds."
      : `Unable to connect to malware scanner service: ${err.message || "Network error"}`;

    return createInconclusiveReport(
      scanId,
      cleanName,
      fileBuffer.byteLength,
      sha256,
      Date.now() - startTime,
      errorMsg,
      isTimeout ? "TIMEOUT" : "FAILED"
    );
  }
}

/**
 * Normalizes raw scanner service findings into a standard assessment contract.
 */
function normalizeScannerOutput(
  scanId: string,
  filename: string,
  fileSizeBytes: number,
  sha256: string,
  elapsedMs: number,
  data: any
): NormalizedScanReport {
  const clamav: ClamAVScanResult = {
    status: data.clamav?.status === "COMPLETED" ? "COMPLETED" : "FAILED",
    detected: Boolean(data.clamav?.detected),
    virus_name: data.clamav?.virus_name || undefined,
    version: data.clamav?.version || "ClamAV 1.4+",
    error: data.clamav?.error || undefined,
  };

  const yara: YARAScanResult = {
    status: data.yara?.status === "COMPLETED" ? "COMPLETED" : "FAILED",
    matches: Array.isArray(data.yara?.matches) ? data.yara.matches : [],
    rules_evaluated: data.yara?.rules_evaluated || 0,
    error: data.yara?.error || undefined,
  };

  const findings: string[] = [];
  const recommendations: string[] = [];

  // Determine Verdict and Severity
  let verdict: ThreatVerdict = "CLEAN";
  let severity: SeverityLevel = "CLEAN";

  // 1. ClamAV evaluation
  if (clamav.detected) {
    verdict = "MALICIOUS";
    severity = "CRITICAL";
    findings.push(`[ClamAV Antivirus] Known malware signature: ${clamav.virus_name || "Detected"}`);
    recommendations.push("DO NOT OPEN OR EXECUTE THIS FILE. Delete immediately.");
  }

  // 2. YARA evaluation
  if (yara.matches.length > 0) {
    const matchNames = yara.matches.map((m) => m.rule_name).join(", ");
    findings.push(`[YARA Rules] Heuristic rule matches: ${matchNames}`);
    if (verdict !== "MALICIOUS") {
      verdict = "SUSPICIOUS";
      severity = "HIGH";
      recommendations.push("Exercise zero-trust caution. File contains suspicious executable or script patterns.");
    }
  }

  // 3. Scanner availability / failure evaluation
  if (clamav.status !== "COMPLETED" || yara.status !== "COMPLETED") {
    if (verdict === "CLEAN") {
      verdict = "INCONCLUSIVE";
      severity = "MEDIUM";
      findings.push("One or more required security scanners (ClamAV / YARA) failed or were unavailable.");
      recommendations.push("Analysis is incomplete. Do not assume file is safe.");
    }
  }

  if (findings.length === 0) {
    recommendations.push("No known threats detected by enabled engines. Continue exercising zero-trust caution.");
  }

  return {
    scan_id: scanId,
    filename,
    file_size_bytes: fileSizeBytes,
    sha256,
    verdict,
    severity,
    clamav,
    yara,
    findings,
    recommendations,
    execution_time_ms: elapsedMs,
  };
}

/**
 * Creates a safe, defensive INCONCLUSIVE report when scanners fail or are unavailable.
 * NEVER falsely reports a file as safe.
 */
function createInconclusiveReport(
  scanId: string,
  filename: string,
  fileSizeBytes: number,
  sha256: string,
  elapsedMs: number,
  reason: string,
  status: "UNAVAILABLE" | "FAILED" | "TIMEOUT" = "UNAVAILABLE"
): NormalizedScanReport {
  return {
    scan_id: scanId,
    filename,
    file_size_bytes: fileSizeBytes,
    sha256,
    verdict: "INCONCLUSIVE",
    severity: "MEDIUM",
    clamav: { status, detected: false, error: reason },
    yara: { status, matches: [], error: reason },
    findings: [`Scanner Service Error: ${reason}`],
    recommendations: [
      "Analysis could not be completed safely. Do not treat this file as safe.",
      "Verify that the CyberGuard AI backend scanner worker is running.",
    ],
    execution_time_ms: elapsedMs,
  };
}
