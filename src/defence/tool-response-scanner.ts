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
 *   - detectEncoding     — bounded full base64/hex/url decode-and-rescan, plus
 *                          a separate whole-document normalized-content channel
 *   - detectMarkdownImageExfil — markdown image whose URL smuggles data out
 *   - scanForCredentials — credential leak scanning (retained)
 *
 * It deliberately does NOT pull in the write-path's trust scoring, anomaly,
 * privilege, fragmentation or sensitivity layers — those are write concerns.
 *
 * Advisory by default: logs threats but leaves the response untouched. In
 * enforce mode the scanner additionally computes `sanitisedContent` — the bytes
 * the agent should actually receive (injection withheld, secrets redacted, exfil
 * links stripped). The neutraliseToolResponse action layer handles raw/decoded
 * signals; this scanner withholds normalized credentials, derived exfil images,
 * and incomplete encoding scans when safe original-byte redaction is unavailable.
 * Callers
 * (withResponseScan, the scan_tool_response tool) swap in sanitisedContent when
 * present; the scanner never blocks tool EXECUTION, only the threatening output.
 */

import { scanForInjection } from './iron-dome/injection-scanner.js';
import { scanForCredentials } from './credential-leak/index.js';
import { detectInstructions } from './firewall/instruction-detector.js';
import { detectEncoding } from './firewall/encoding-detector.js';
import { detectMarkdownImageExfil } from './firewall/markdown-image-detector.js';
import { detectHiddenWebInjection } from './hidden-web-injection.js';
import { neutraliseToolResponse, TOOL_OUTPUT_BLOCKED_PLACEHOLDER } from './tool-response-enforce.js';
import { attestedFlag, logAudit } from './audit/logger.js';
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
  /**
   * Attestation for the threat row. MUST be decided per call site, never a
   * constant here: withResponseScan binds a server-literal toolName (→ true).
   * For a CALLER-supplied toolName, OMIT the argument (NULL) — do not pass
   * false: tool_response:<name> keys are un-namespaced and shared with the
   * attested withResponseScan writes, and risk.ts resolves attestation
   * latest-non-null, so an explicit 0 under a victim's key would MUTE the
   * trust modifier that channel legitimately accrued. `false` is only safe
   * for keys namespaced away from attested writers.
   */
  attested?: boolean,
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

  // 2. Shared detectors, read-path policy. decodedSnippets contains actual full
  //    base64/hex/URL decoded blobs only. normalizedContents holds whole bounded
  //    documents after confusable/zero-width normalization, not encoded prose
  //    windows. The latter uses the SAME instruction exclusions as raw content.
  //
  //    FP reduction on the READ path: `imperative_tool_call` ("call the X tool")
  //    exists to catch injected directives at WRITE time. On tool OUTPUT it is
  //    legitimate instructional content (docs telling the agent which tool to
  //    use), so we exclude it here. Real injection phrasing ("ignore previous
  //    instructions", "you are now…") lives in the other groups + Iron Dome and
  //    is unaffected. Decoded snippets (below) keep full detection — an encoded
  //    imperative is inherently suspicious.
  const encoding = detectEncoding(content);
  const instructionPatterns = [content, ...encoding.normalizedContents]
    .flatMap(text => detectInstructions(text).patterns).filter(
    (p) => !READ_PATH_EXCLUDED_INSTRUCTION_PATTERNS.has(p),
  );
  const instructions = { detected: instructionPatterns.length > 0, patterns: [...new Set(instructionPatterns)] };

  // 2b. Decode-and-rescan: re-run instruction + credential detection on each
  //     decoded snippet so a BARE base64/hex blob that decodes to an injection
  //     (the Iron Dome base64 rule only fires on literal framing words) is
  //     caught on its plaintext. Reuses the write-path detectors — no
  //     duplicated detection logic. Normalized prose above keeps exactly the
  //     raw read-path exclusions; it is not an encoded imperative. Only BLOCKED
  //     credential findings on either derived channel justify full withholding.
  let decodedInjection = false;
  let decodedCredentialLeak = false;
  const normalizedCredentialLeak = encoding.normalizedContents.some(text =>
    scanForCredentials(text).findings.some(f => f.action === 'blocked'),
  );
  for (const snippet of encoding.decodedSnippets) {
    if (!decodedInjection && detectInstructions(snippet).detected) {
      decodedInjection = true;
    }
    if (!decodedCredentialLeak && scanForCredentials(snippet).findings.some(f => f.action === 'blocked')) {
      decodedCredentialLeak = true;
    }
    if (decodedInjection && decodedCredentialLeak) break;
  }

  // 3. Markdown-image exfiltration (rendered image URL smuggling data out).
  const markdownImage = detectMarkdownImageExfil(content);
  const derivedMarkdownExfil = [...encoding.decodedSnippets, ...encoding.normalizedContents]
    .some(text => detectMarkdownImageExfil(text).detected);

  // 4. Credential leak scan (retained from the original 2-layer read path).
  const credentials = scanForCredentials(content);

  // 4b. Environment Firewall (runtime): hidden-instruction injection in fetched
  //     web content — a concealed "ignore previous instructions" in white-on-white
  //     text, a display:none span, an HTML comment, or bidi/zero-width tricks.
  //     Runs only on HTML-ish content; memory/metadata tool output is unaffected.
  const hiddenWeb = detectHiddenWebInjection(content);

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
  if (markdownImage.detected || derivedMarkdownExfil) {
    pushIndicator('external_url');
  }
  if (credentials.leaked || decodedCredentialLeak || normalizedCredentialLeak) {
    pushIndicator('credential_leak');
  }
  if (hiddenWeb.detected) {
    pushIndicator('instruction_injection');
  }

  const clean =
    injection.clean &&
    !instructions.detected &&
    !encoding.detected &&
    !decodedInjection &&
    !decodedCredentialLeak &&
    !normalizedCredentialLeak &&
    !markdownImage.detected &&
    !derivedMarkdownExfil &&
    !credentials.leaked &&
    !hiddenWeb.detected;
  const durationMs = Math.round(performance.now() - startTime);

  // 5b. Advisory mode only logs. Enforce withholds unsafe derived content or
  //     incomplete coverage explicitly, otherwise delegates raw-byte redaction
  //     and decoded-injection/blocked-credential signals to the action layer.
  //     Warned/logged entropy findings must never become hard derived leakage.
  let sanitisedContent: string | null = null;
  let blocked = false;
  let enforceActions: string[] = [];
  if (!clean && resolvedMode === 'enforce' &&
      (encoding.scanIncomplete || normalizedCredentialLeak || derivedMarkdownExfil)) {
    // No reliable positional redaction from derived text back into the original.
    // Incomplete coverage is a separate fail-safe, not an invented injection.
    sanitisedContent = TOOL_OUTPUT_BLOCKED_PLACEHOLDER;
    blocked = true;
    if (encoding.scanIncomplete) enforceActions.push('blocked: encoding scan incomplete (budget exhausted)');
    if (normalizedCredentialLeak) enforceActions.push('blocked: normalized content contains a blocked credential');
    if (derivedMarkdownExfil) enforceActions.push('blocked: decoded/normalized markdown-image exfil');
  } else if (!clean && resolvedMode === 'enforce') {
    const neutralisation = neutraliseToolResponse(content, {
      injectionRisk: injection.riskLevel,
      instructionsDetected: instructions.detected || hiddenWeb.detected,
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
    if (normalizedCredentialLeak) parts.push('normalized content contains a blocked credential');
    if (derivedMarkdownExfil) parts.push('decoded/normalized markdown-image exfil');
    if (encoding.scanIncomplete) parts.push('encoding scan incomplete (budget exhausted)');
    if (encoding.detected) parts.push(`encoding: ${encoding.encodingTypes.join(', ')}`);
    if (markdownImage.detected) parts.push(`markdown-image exfil: ${markdownImage.urls.length} URL(s)`);
    if (credentials.leaked) parts.push(`credentials: ${credentials.findings.length} finding(s)`);
    else if (decodedCredentialLeak) parts.push('decoded payload contains credentials');
    if (hiddenWeb.detected) parts.push(`hidden web injection: ${hiddenWeb.techniques.join('/')}`);
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
    ...(normalizedCredentialLeak ? ['normalized_credential_leak'] : []),
    ...(derivedMarkdownExfil ? ['derived_markdown_image_exfil'] : []),
    ...(markdownImage.detected ? ['markdown_image_exfil'] : []),
    ...(hiddenWeb.detected ? hiddenWeb.techniques.map(t => `hidden_${t}`) : []),
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
        sensitivity_level: (credentials.leaked || decodedCredentialLeak || normalizedCredentialLeak) ? 'CONFIDENTIAL' : 'PUBLIC',
        firewall_result: firewallResult,
        operation: 'read',
        anomaly_score: anomalyScore,
        threat_indicators: JSON.stringify(threatIndicators),
        blocked_patterns: JSON.stringify(blockedPatterns),
        reason: summary,
        fragmentation_score: null,
        pipeline_duration_ms: durationMs,
        source_attested: attestedFlag(attested),
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
