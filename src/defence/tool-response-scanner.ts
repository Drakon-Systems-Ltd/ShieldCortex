/**
 * Tool Response Scanner
 *
 * Defence scanner for MCP tool outputs (read-path). Tool output is the #1 MCP
 * attack surface, so the read path shares the WRITE-path detection surface
 * instead of running a thinner pattern set:
 *
 *   - scanForInjection   — Iron Dome regex set (named-pattern reporting)
 *   - detectInstructions — write-path instruction detector; folds cross-script
 *                          homoglyphs and scans in windows (catches `ignorе …`)
 *   - detectEncoding     — write-path encoding detector; decodes base64/hex/url
 *                          blobs so a BARE blob that decodes to an injection is
 *                          re-scanned on the plaintext (decode-and-rescan)
 *   - detectMarkdownImageExfil — markdown image whose URL smuggles data out
 *   - scanForCredentials — credential leak scanning (retained)
 *
 * It deliberately does NOT pull in the write-path's trust scoring, anomaly,
 * privilege, fragmentation or sensitivity layers — those are write concerns.
 *
 * Advisory by default: logs threats but leaves the response untouched. In
 * enforce mode the scanner additionally computes `sanitisedContent` — the bytes
 * the agent should actually receive (injection withheld, secrets redacted, exfil
 * links stripped) — via the neutraliseToolResponse action layer. Callers
 * (withResponseScan, the scan_tool_response tool) swap in sanitisedContent when
 * present; the scanner never blocks tool EXECUTION, only the threatening output.
 */

import { scanForInjection } from './iron-dome/injection-scanner.js';
import { scanForCredentials } from './credential-leak/index.js';
import { detectInstructions } from './firewall/instruction-detector.js';
import { detectEncoding } from './firewall/encoding-detector.js';
import { detectMarkdownImageExfil } from './firewall/markdown-image-detector.js';
import { neutraliseToolResponse } from './tool-response-enforce.js';
import { logAudit } from './audit/logger.js';
import { isDatabaseInitialized } from '../database/init.js';
import { getToolResponseScanConfig } from '../cloud/config.js';
import type { ThreatIndicator, ToolResponseScanResult } from './types.js';
import { persistEvent } from '../api/events.js';

// ../api/events.js is imported statically. Safe at module-eval time: there is no
// import cycle on this edge — events imports only an EventEmitter, getDatabase
// and types, never back into this module — and it does no work at import (no
// server/ws stack). persistEvent is only called inside scanToolResponse. The
// try/catch below stays — dashboard event persistence is best-effort and must
// never affect tool-response delivery.

// Tools that return memory/knowledge content (worth scanning)
const HIGH_RISK_TOOLS = new Set([
  'recall',
  'get_context',
  'get_memory',
  'get_related',
  'graph_query',
  'graph_explain',
  'graph_entities',
  'export_memories',
  'detect_contradictions',
]);

// Instruction-detector pattern groups that are WRITE-path concerns and over-fire
// on legitimate tool OUTPUT (instructional docs telling the agent which tool to
// call). Excluded from the read-path instruction signal; real injection groups
// (system_prompt_marker, hidden_instruction, prompt_extraction, …) still apply.
const READ_PATH_EXCLUDED_INSTRUCTION_PATTERNS = new Set(['imperative_tool_call']);

// Tools that only return metadata/stats (not worth scanning)
const METADATA_ONLY_TOOLS = new Set([
  'memory_stats',
  'defence_stats',
  'iron_dome_status',
  'get_project',
  'audit_query',
]);

/**
 * Check if a tool's response should be scanned.
 * Unknown tools (e.g. external MCP servers) default to scanned.
 */
export function shouldScanToolResponse(toolName: string): boolean {
  if (HIGH_RISK_TOOLS.has(toolName)) return true;
  if (METADATA_ONLY_TOOLS.has(toolName)) return false;
  return true;
}

/**
 * Scan a tool response for threats.
 *
 * Shares the write-path detection surface: Iron Dome injection patterns,
 * instruction detection (with homoglyph folding + windowed scanning), encoding
 * decode-and-rescan, markdown-image exfiltration, and credential leak detection.
 * In advisory mode, threats are logged but the response is never blocked.
 */
export function scanToolResponse(
  toolName: string,
  content: string,
  mode?: 'advisory' | 'enforce',
): ToolResponseScanResult {
  const startTime = performance.now();
  const resolvedMode = mode ?? getToolResponseScanConfig().toolResponseMode;

  // Skip tiny responses (confirmations, error messages)
  if (!content || content.length < 20) {
    return {
      clean: true,
      mode: resolvedMode,
      toolName,
      injection: { clean: true, riskLevel: 'NONE', detections: [], textLength: content?.length ?? 0, summary: 'No patterns detected.' },
      credentials: { leaked: false, findings: [] },
      threatIndicators: [],
      summary: `Tool response from "${toolName}" skipped (too short)`,
      durationMs: Math.round(performance.now() - startTime),
      auditId: -1,
      sanitisedContent: null,
      blocked: false,
      enforceActions: [],
    };
  }

  // 1. Injection scan (Iron Dome named patterns — drives the `injection` field
  //    of the result and the human-readable summary).
  const injection = scanForInjection(content);

  // 2. Write-path detectors (parity). detectInstructions folds homoglyphs and
  //    scans in windows; detectEncoding decodes base64/hex/url blobs.
  //
  //    FP reduction on the READ path: `imperative_tool_call` ("call the X tool")
  //    exists to catch injected directives at WRITE time. On tool OUTPUT it is
  //    legitimate instructional content (docs telling the agent which tool to
  //    use), so we exclude it here. Real injection phrasing ("ignore previous
  //    instructions", "you are now…") lives in the other groups + Iron Dome and
  //    is unaffected. Decoded snippets (below) keep full detection — an encoded
  //    imperative is inherently suspicious.
  const instructionsRaw = detectInstructions(content);
  const instructionPatterns = instructionsRaw.patterns.filter(
    (p) => !READ_PATH_EXCLUDED_INSTRUCTION_PATTERNS.has(p),
  );
  const instructions = { detected: instructionPatterns.length > 0, patterns: instructionPatterns };
  const encoding = detectEncoding(content);

  // 2b. Decode-and-rescan: re-run instruction + credential detection on each
  //     decoded snippet so a BARE base64/hex blob that decodes to an injection
  //     (the Iron Dome base64 rule only fires on literal framing words) is
  //     caught on its plaintext. Reuses the write-path detectors — no
  //     duplicated detection logic.
  let decodedInjection = false;
  let decodedCredentialLeak = false;
  for (const snippet of encoding.decodedSnippets) {
    if (!decodedInjection && detectInstructions(snippet).detected) {
      decodedInjection = true;
    }
    if (!decodedCredentialLeak && scanForCredentials(snippet).leaked) {
      decodedCredentialLeak = true;
    }
    if (decodedInjection && decodedCredentialLeak) break;
  }

  // 3. Markdown-image exfiltration (rendered image URL smuggling data out).
  const markdownImage = detectMarkdownImageExfil(content);

  // 4. Credential leak scan (retained from the original 2-layer read path).
  const credentials = scanForCredentials(content);

  // 5. Collect threat indicators across every layer.
  const threatIndicators: ThreatIndicator[] = [];
  const pushIndicator = (indicator: ThreatIndicator): void => {
    if (!threatIndicators.includes(indicator)) threatIndicators.push(indicator);
  };

  if (instructions.detected || decodedInjection) {
    pushIndicator('instruction_injection');
  }
  if (encoding.detected) {
    pushIndicator('encoding_obfuscation');
  }
  if (!injection.clean) {
    pushIndicator('instruction_injection');
    const categories = new Set(injection.detections.map(d => d.category));
    if (categories.has('credential_extraction')) {
      pushIndicator('credential_leak');
    }
    if (categories.has('encoding_trick')) {
      pushIndicator('encoding_obfuscation');
    }
  }
  if (markdownImage.detected) {
    pushIndicator('external_url');
  }
  if (credentials.leaked || decodedCredentialLeak) {
    pushIndicator('credential_leak');
  }

  const clean =
    injection.clean &&
    !instructions.detected &&
    !encoding.detected &&
    !decodedInjection &&
    !markdownImage.detected &&
    !credentials.leaked;
  const durationMs = Math.round(performance.now() - startTime);

  // 5b. Enforce action layer. Advisory mode only logs; enforce mode computes the
  //     content the agent should ACTUALLY receive (block injection, redact
  //     secrets, strip exfil links). Single source of truth in
  //     neutraliseToolResponse — the scanner just feeds it the signals it found.
  let sanitisedContent: string | null = null;
  let blocked = false;
  let enforceActions: string[] = [];
  if (!clean && resolvedMode === 'enforce') {
    const neutralisation = neutraliseToolResponse(content, {
      injectionRisk: injection.riskLevel,
      instructionsDetected: instructions.detected,
      decodedInjection,
      encodingDetected: encoding.detected,
      markdownImageUrls: markdownImage.urls,
      credentialsLeaked: credentials.leaked,
      decodedCredentialLeak,
    });
    sanitisedContent = neutralisation.sanitised;
    blocked = neutralisation.blocked;
    enforceActions = neutralisation.actions;
  }

  // Truthful firewall_result: advisory only observes (ALLOW); enforce that
  // withholds the whole payload is a BLOCK; enforce that surgically redacts but
  // still delivers is a QUARANTINE.
  const firewallResult = resolvedMode !== 'enforce' ? 'ALLOW' : blocked ? 'BLOCK' : 'QUARANTINE';

  // 6. Build summary
  let summary: string;
  if (clean) {
    summary = `Tool response from "${toolName}" is clean (${durationMs}ms)`;
  } else {
    const parts: string[] = [];
    if (!injection.clean) parts.push(`injection: ${injection.summary}`);
    if (instructions.detected) parts.push(`instructions: ${instructions.patterns.join(', ')}`);
    if (decodedInjection) parts.push('decoded payload contains injection');
    if (encoding.detected) parts.push(`encoding: ${encoding.encodingTypes.join(', ')}`);
    if (markdownImage.detected) parts.push(`markdown-image exfil: ${markdownImage.urls.length} URL(s)`);
    if (credentials.leaked) parts.push(`credentials: ${credentials.findings.length} finding(s)`);
    else if (decodedCredentialLeak) parts.push('decoded payload contains credentials');
    summary = `THREAT in "${toolName}" response: ${parts.join('; ')} (${durationMs}ms)`;
  }

  // 7. Anomaly score: CRITICAL Iron Dome risk pins to 1.0; any other detection
  //    (homoglyph, decoded payload, markdown-image exfil, etc.) scores 0.7.
  const anomalyScore = injection.riskLevel === 'CRITICAL' ? 1.0 : 0.7;

  // Blocked patterns reported to the audit/dashboard — Iron Dome named patterns
  // plus the parity detectors' own labels.
  const blockedPatterns = [
    ...injection.detections.map(d => d.pattern),
    ...instructions.patterns,
    ...encoding.encodingTypes,
    ...(decodedInjection ? ['decoded_injection'] : []),
    ...(markdownImage.detected ? ['markdown_image_exfil'] : []),
  ];

  // 8. Audit log (threats only)
  let auditId = -1;
  if (!clean && isDatabaseInitialized()) {
    try {
      auditId = logAudit({
        memory_id: null,
        project: null,
        timestamp: new Date().toISOString(),
        source_type: 'tool_response',
        source_identifier: toolName,
        trust_score: 0.5,
        sensitivity_level: (credentials.leaked || decodedCredentialLeak) ? 'CONFIDENTIAL' : 'PUBLIC',
        firewall_result: firewallResult,
        operation: 'read',
        anomaly_score: anomalyScore,
        threat_indicators: JSON.stringify(threatIndicators),
        blocked_patterns: JSON.stringify(blockedPatterns),
        reason: summary,
        fragmentation_score: null,
        pipeline_duration_ms: durationMs,
      });
    } catch {
      // Audit logging must never affect tool response delivery
    }

    // 9. Dashboard real-time event
    try {
      persistEvent('defence_event', {
        source_type: 'tool_response',
        source_identifier: toolName,
        firewall_result: firewallResult,
        trust_score: 0.5,
        anomaly_score: anomalyScore,
        reason: summary,
        threat_indicators: JSON.stringify(threatIndicators),
        timestamp: new Date().toISOString(),
      });
    } catch {
      // Event persistence is best-effort
    }
  }

  return {
    clean,
    mode: resolvedMode,
    toolName,
    injection,
    credentials,
    threatIndicators,
    summary,
    durationMs,
    auditId,
    sanitisedContent,
    blocked,
    enforceActions,
  };
}
