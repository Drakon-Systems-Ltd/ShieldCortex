/**
 * Capture distill helpers — Memory SOTA Track C (P0 scaffold).
 *
 * Fail-closed: provider/schema failure → skip (no silent regex fallback).
 * L1 salience cap 0.7. Distill output must still pass defence before save.
 */

export const CAPTURE_MODE = Object.freeze({
  REGEX: 'regex',
  DISTILL: 'distill',
  DISTILL_REQUIRED: 'distill_required',
});

export const L1_SALIENCE_CAP = 0.7;

/**
 * @param {unknown} mode
 * @param {{ providerConfigured?: boolean }} opts
 */
export function resolveCaptureMode(mode, opts = {}) {
  const m = typeof mode === 'string' ? mode.trim().toLowerCase() : '';
  if (m === CAPTURE_MODE.REGEX || m === CAPTURE_MODE.DISTILL || m === CAPTURE_MODE.DISTILL_REQUIRED) {
    return m;
  }
  // After C: default distill when provider configured; else explicit skip posture
  if (opts.providerConfigured) return CAPTURE_MODE.DISTILL;
  return CAPTURE_MODE.REGEX; // only when explicitly on legacy path / unconfigured pre-cut hosts
}

/**
 * Fail-closed distill result.
 * @returns {{ ok: true, memories: object[] } | { ok: false, reason: string, memories: [] }}
 */
export function failClosedDistill(errOrNull, memories) {
  if (errOrNull) {
    return { ok: false, reason: String(errOrNull?.message || errOrNull), memories: [] };
  }
  if (!Array.isArray(memories)) {
    return { ok: false, reason: 'invalid-schema', memories: [] };
  }
  const cleaned = [];
  for (const m of memories) {
    if (!m || typeof m !== 'object') continue;
    const title = typeof m.title === 'string' ? m.title.trim() : '';
    const content = typeof m.content === 'string' ? m.content.trim() : (typeof m.fact === 'string' ? m.fact.trim() : '');
    if (!title || !content) continue;
    let salience = typeof m.salience === 'number' ? m.salience : 0.55;
    if (salience > L1_SALIENCE_CAP) salience = L1_SALIENCE_CAP;
    cleaned.push({
      title: title.slice(0, 200),
      content: content.slice(0, 4000),
      category: typeof m.category === 'string' ? m.category : 'note',
      salience,
      capture_layer: 'L1',
      source_kind: 'distill',
    });
  }
  return { ok: true, memories: cleaned };
}

/**
 * Whether to run regex L0 after distill failure.
 * Silent fallback is forbidden; only explicit regex mode.
 */
export function allowRegexFallback(mode) {
  return resolveCaptureMode(mode) === CAPTURE_MODE.REGEX;
}
