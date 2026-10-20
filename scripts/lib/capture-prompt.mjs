/**
 * Hook-side prompt capture sanitiser (Fix #10).
 *
 * UserPromptSubmit historically stored the raw prompt text verbatim into
 * `session_events`. Pasting a `.env` file (or any other credential-laden
 * snippet) into Claude Code persisted it forever and the dashboard's session
 * replay UI surfaced it on demand.
 *
 * This module runs the defence pipeline's credential redaction + sensitivity
 * classifier against the prompt BEFORE it lands in `session_events`, returning:
 *   - redactedText: prompt with credentials replaced by [REDACTED-…] markers
 *   - sensitivity: classifier level (PUBLIC | INTERNAL | CONFIDENTIAL | RESTRICTED)
 *   - findings: credential scan findings (already-redacted match previews)
 *   - redactedCount: number of credentials that were rewritten
 *
 * Fail-closed: if the dist defence modules cannot be loaded (dev workspace
 * without `npm run build`, missing dist/, broken import), the caller gets a
 * placeholder payload tagged RESTRICTED and a stderr warning. That keeps the
 * raw text out of the database under all failure modes.
 *
 * Mirrors the lazy-loader pattern used by scripts/lib/save-memory.mjs so both
 * hooks share the same dist resolution rules.
 */

import { dirname, resolve } from 'path';
import { fileURLToPath, pathToFileURL } from 'url';

const FAIL_CLOSED_PLACEHOLDER = '[defence_unavailable: prompt suppressed]';

let _defenceCache = null;
let _defenceCacheKey = null;

/**
 * Sanitise a raw user prompt for safe storage in `session_events`.
 *
 * @param {string} rawText - The raw user prompt as received by the hook.
 * @returns {Promise<{ redactedText: string, sensitivity: string, findings: Array, redactedCount: number }>}
 */
export async function captureForSessionEvent(rawText) {
  const text = typeof rawText === 'string' ? rawText : '';

  const defence = await loadDefenceModules();
  if (!defence) {
    process.stderr.write(
      '[shieldcortex capture-prompt] defence modules unavailable — prompt suppressed (fail-closed)\n',
    );
    return {
      redactedText: FAIL_CLOSED_PLACEHOLDER,
      sensitivity: 'RESTRICTED',
      findings: [],
      redactedCount: 0,
    };
  }

  // ── Credential redaction ──
  // scanForCredentials gives both the redacted body and the findings array.
  // redactCredentials would do the same string transform but throw away the
  // findings — we want both so the caller can count and (later) audit.
  let scan;
  try {
    scan = defence.scanForCredentials(text);
  } catch (err) {
    const msg = err && err.message ? err.message : String(err);
    process.stderr.write(
      `[shieldcortex capture-prompt] credential scan failed (${msg}) — prompt suppressed (fail-closed)\n`,
    );
    return {
      redactedText: FAIL_CLOSED_PLACEHOLDER,
      sensitivity: 'RESTRICTED',
      findings: [],
      redactedCount: 0,
    };
  }

  const findings = Array.isArray(scan?.findings) ? scan.findings : [];
  const redactedText = scan?.redactedContent ?? text;
  const redactedCount = findings.length;

  // ── Sensitivity classification ──
  // Classifier is sync and pattern-based — failures here shouldn't fail-close
  // the whole capture (we still have a useful redaction). Degrade to INTERNAL.
  let sensitivity = 'INTERNAL';
  try {
    const classification = defence.classifySensitivity(text, '');
    if (classification && typeof classification.level === 'string') {
      sensitivity = classification.level;
    }
  } catch {
    // Best-effort — keep INTERNAL default.
  }

  // If credentials were found, force at least CONFIDENTIAL. The classifier
  // catches "api_key=" style markers but raw secret strings without context
  // can slip past it, and we never want a prompt full of secrets tagged
  // PUBLIC or INTERNAL just because the surrounding text was unremarkable.
  if (redactedCount > 0 && (sensitivity === 'PUBLIC' || sensitivity === 'INTERNAL')) {
    sensitivity = 'CONFIDENTIAL';
  }

  return {
    redactedText,
    sensitivity,
    findings,
    redactedCount,
  };
}

// ==================== Internal: lazy dist loader ====================

async function loadDefenceModules() {
  // capture-prompt.mjs lives at scripts/lib/, so dist is two directories up.
  const here = dirname(fileURLToPath(import.meta.url));
  const distRoot = resolve(here, '..', '..', 'dist');

  if (_defenceCache && _defenceCacheKey === distRoot) {
    return _defenceCache;
  }

  try {
    const credentialUrl = pathToFileURL(
      resolve(distRoot, 'defence', 'credential-leak', 'index.js'),
    ).href;
    const sensitivityUrl = pathToFileURL(
      resolve(distRoot, 'defence', 'sensitivity', 'index.js'),
    ).href;

    const [credentialMod, sensitivityMod] = await Promise.all([
      import(credentialUrl),
      import(sensitivityUrl),
    ]);

    if (
      typeof credentialMod.scanForCredentials !== 'function'
      || typeof credentialMod.redactCredentials !== 'function'
      || typeof sensitivityMod.classifySensitivity !== 'function'
    ) {
      return null;
    }

    _defenceCache = {
      scanForCredentials: credentialMod.scanForCredentials,
      redactCredentials: credentialMod.redactCredentials,
      classifySensitivity: sensitivityMod.classifySensitivity,
    };
    _defenceCacheKey = distRoot;
    return _defenceCache;
  } catch {
    return null;
  }
}

/**
 * Test-only: reset the lazy-load cache so unit tests can simulate dist-missing
 * failure modes without spinning up a second process. Not exported via the
 * scripts barrel — only the tests reach for it.
 */
export function __resetCacheForTests() {
  _defenceCache = null;
  _defenceCacheKey = null;
}
