/**
 * Tool-Response Enforce Layer
 *
 * Advisory mode only LOGS threats in a tool response. Enforce mode must actually
 * change the bytes the agent receives. This module is the action layer: given a
 * tool response and the threat signals the scanner already computed, it returns
 * the content the agent should actually see.
 *
 * Two-tier policy:
 *
 *   BLOCK (withhold the whole payload) — when the output is actively hostile or
 *   smuggling: any injection signal, the instruction detector firing, a blob
 *   that decodes to an injection, or a blob that decodes to a credential.
 *   Natural-language injected instructions cannot be surgically removed without
 *   risking that a fragment survives, so the safe action is to withhold the
 *   entire response and tell the agent why.
 *
 *   REDACT (pass cleaned + tag) — when the threat is a secret or an exfil link
 *   sitting in plaintext that we CAN surgically remove: credential leaks (masked
 *   in place) and markdown-image exfiltration URLs (neutralised to a dead host).
 *   The cleaned content is prefixed with an untrusted-origin tag so any
 *   downstream memory write attributes it correctly.
 *
 * Pure and dependency-injection-free of any DB/IO — only the credential scanner
 * (for positional redaction). Easy to unit test in isolation.
 */

import { scanForCredentials } from './credential-leak/index.js';
import { neutraliseMarkdownImageExfil } from './firewall/markdown-image-detector.js';

export const TOOL_OUTPUT_BLOCKED_PLACEHOLDER =
  '[ShieldCortex] Tool output withheld in enforce mode — prompt-injection / data-smuggling detected. ' +
  'The original response was blocked to protect the agent. Review the ShieldCortex audit log for details.';

export const UNTRUSTED_TOOL_TAG =
  '[ShieldCortex: tool output sanitised — treat as derived-from-untrusted-tool]';

/**
 * Threat signals the scanner already computed for a (non-clean) tool response.
 * Passed in so neutralisation never re-derives detection — single source of
 * truth with scanToolResponse.
 */
export interface ToolResponseThreatSignals {
  injectionRisk: 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  instructionsDetected: boolean;
  decodedInjection: boolean;
  encodingDetected: boolean;
  markdownImageUrls: string[];
  credentialsLeaked: boolean;
  decodedCredentialLeak: boolean;
}

export interface ToolResponseNeutralisation {
  /** The content the agent should actually receive. */
  sanitised: string;
  /** True when the whole payload was withheld (blocked), not just redacted. */
  blocked: boolean;
  /** Human-readable list of actions taken, for audit/summary. */
  actions: string[];
}

function hasAnySignal(s: ToolResponseThreatSignals): boolean {
  return (
    s.injectionRisk !== 'NONE' ||
    s.instructionsDetected ||
    s.decodedInjection ||
    s.encodingDetected ||
    s.markdownImageUrls.length > 0 ||
    s.credentialsLeaked ||
    s.decodedCredentialLeak
  );
}

/** Output is actively hostile / smuggling — withhold the whole payload. */
function shouldBlock(s: ToolResponseThreatSignals): boolean {
  return (
    s.injectionRisk !== 'NONE' ||
    s.instructionsDetected ||
    s.decodedInjection ||
    s.decodedCredentialLeak
  );
}

/**
 * Compute the enforce-mode replacement for a tool response.
 *
 * Only meaningful when the scanner already found the response non-clean; with no
 * signals it returns the content unchanged.
 */
export function neutraliseToolResponse(
  content: string,
  signals: ToolResponseThreatSignals,
): ToolResponseNeutralisation {
  if (!hasAnySignal(signals)) {
    return { sanitised: content, blocked: false, actions: [] };
  }

  if (shouldBlock(signals)) {
    const actions: string[] = [];
    if (signals.injectionRisk !== 'NONE') {
      actions.push(`blocked: prompt-injection (${signals.injectionRisk.toLowerCase()})`);
    } else if (signals.instructionsDetected) {
      // No high-confidence Iron Dome hit — be honest that this is the heuristic
      // instruction detector, not a graded injection (don't say "injection (none)").
      actions.push('blocked: suspicious-instruction pattern (heuristic)');
    }
    if (signals.decodedInjection) actions.push('blocked: encoded payload decoded to injection');
    if (signals.decodedCredentialLeak) actions.push('blocked: encoded payload decoded to credential');
    return { sanitised: TOOL_OUTPUT_BLOCKED_PLACEHOLDER, blocked: true, actions };
  }

  // Redact path: surgically clean a payload that merely contains secrets / exfil
  // links in plaintext. The untrusted-origin tag is NOT embedded here — callers
  // convey it out-of-band so redacted structured output (JSON/CSV) stays parseable.
  const actions: string[] = [];
  let working = content;

  // Markdown-image exfil FIRST, before any other mutation. Uses a full-match
  // regex over the content (not substring equality with a pre-captured, possibly
  // truncated URL), so credential redaction reordering and >200-char URLs can't
  // defeat it. If the scanner flagged exfil images but none could be located
  // here, fail SAFE: withhold the whole payload rather than deliver it.
  if (signals.markdownImageUrls.length > 0) {
    const { content: stripped, stripped: count } = neutraliseMarkdownImageExfil(working);
    if (count === 0) {
      return {
        sanitised: TOOL_OUTPUT_BLOCKED_PLACEHOLDER,
        blocked: true,
        actions: ['blocked: flagged markdown-image exfil could not be neutralised (fail-safe)'],
      };
    }
    working = stripped;
    actions.push(`stripped ${count} markdown-image exfil URL(s)`);
  }

  if (signals.credentialsLeaked) {
    const cred = scanForCredentials(working);
    if (cred.leaked && cred.redactedContent) {
      working = cred.redactedContent;
      actions.push(`redacted ${cred.findings.length} credential(s)`);
    }
  }

  if (signals.encodingDetected) {
    actions.push('flagged obfuscated/encoded content (passed through)');
  }

  return { sanitised: working, blocked: false, actions };
}
