/**
 * Capture distill — Memory SOTA Track C.
 *
 * Fail-closed: provider/schema/timeout failure → skip (no silent regex fallback
 * unless mode is explicitly `regex`).
 * L1 salience cap 0.7. Distill output must still pass defence before save.
 */

import { existsSync, readFileSync } from 'fs';
import { homedir } from 'os';
import { join } from 'path';

export const CAPTURE_MODE = Object.freeze({
  REGEX: 'regex',
  DISTILL: 'distill',
  DISTILL_REQUIRED: 'distill_required',
});

export const L1_SALIENCE_CAP = 0.7;
export const DISTILL_MAX_MEMORIES = 8;
export const DISTILL_MAX_INPUT_CHARS = 24_000;
export const DISTILL_TIMEOUT_MS = 12_000;

const ALLOWED_CATEGORIES = new Set([
  'note',
  'decision',
  'preference',
  'architecture',
  'bug',
  'learning',
  'fact',
  'procedure',
  'error-fix',
  'important-note',
]);

/**
 * @param {unknown} mode
 * @param {{ providerConfigured?: boolean }} opts
 */
export function resolveCaptureMode(mode, opts = {}) {
  const m = typeof mode === 'string' ? mode.trim().toLowerCase() : '';
  if (m === CAPTURE_MODE.REGEX || m === CAPTURE_MODE.DISTILL || m === CAPTURE_MODE.DISTILL_REQUIRED) {
    return m;
  }
  // Default: distill when a provider is configured; otherwise stay on regex L0
  // so hosts without keys still capture something.
  if (opts.providerConfigured) return CAPTURE_MODE.DISTILL;
  return CAPTURE_MODE.REGEX;
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
    const content = typeof m.content === 'string'
      ? m.content.trim()
      : (typeof m.fact === 'string' ? m.fact.trim() : '');
    if (!title || !content) continue;
    let salience = typeof m.salience === 'number' && Number.isFinite(m.salience) ? m.salience : 0.55;
    if (salience > L1_SALIENCE_CAP) salience = L1_SALIENCE_CAP;
    if (salience < 0) salience = 0;
    let category = typeof m.category === 'string' ? m.category.trim().toLowerCase() : 'note';
    if (!ALLOWED_CATEGORIES.has(category)) category = 'note';
    cleaned.push({
      title: title.slice(0, 200),
      content: content.slice(0, 4000),
      category,
      salience,
      tags: Array.isArray(m.tags) ? m.tags.filter((t) => typeof t === 'string').slice(0, 8) : ['distill'],
      capture_layer: 'L1',
      captureLayer: 'L1',
      source_kind: 'distill',
      memoryPurpose: typeof m.memoryPurpose === 'string' ? m.memoryPurpose : 'project',
    });
    if (cleaned.length >= DISTILL_MAX_MEMORIES) break;
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

/**
 * Resolve OpenAI-compatible chat credentials without logging secrets.
 * @returns {{ configured: boolean, apiKey?: string, baseUrl?: string, model?: string, source?: string }}
 */
export function resolveDistillProvider(env = process.env, config = null) {
  const cfg = config && typeof config === 'object' ? config : loadScConfigSafe();
  const mem = (cfg.memory && typeof cfg.memory === 'object') ? cfg.memory : {};
  const distill = (mem.distill && typeof mem.distill === 'object') ? mem.distill : {};
  const am = (cfg.autoMemory && typeof cfg.autoMemory === 'object') ? cfg.autoMemory : {};

  const apiKey =
    firstNonEmpty(
      env.SHIELDCORTEX_DISTILL_API_KEY,
      env.OPENAI_API_KEY,
      env.ANTHROPIC_API_KEY,
      typeof distill.apiKey === 'string' ? distill.apiKey : '',
      typeof am.distillApiKey === 'string' ? am.distillApiKey : '',
    );

  if (!apiKey) return { configured: false };

  const baseUrl = firstNonEmpty(
    env.SHIELDCORTEX_DISTILL_BASE_URL,
    env.OPENAI_BASE_URL,
    typeof distill.baseUrl === 'string' ? distill.baseUrl : '',
    'https://api.openai.com/v1',
  ).replace(/\/+$/, '');

  // Anthropic key + default openai host → use Anthropic messages path marker
  const isAnthropicKey = apiKey.startsWith('sk-ant-');
  const model = firstNonEmpty(
    env.SHIELDCORTEX_DISTILL_MODEL,
    typeof distill.model === 'string' ? distill.model : '',
    isAnthropicKey ? 'claude-haiku-4-5-20251001' : 'gpt-4.1-mini',
  );

  return {
    configured: true,
    apiKey,
    baseUrl,
    model,
    source: isAnthropicKey ? 'anthropic' : 'openai-compatible',
  };
}

function firstNonEmpty(...vals) {
  for (const v of vals) {
    if (typeof v === 'string' && v.trim()) return v.trim();
  }
  return '';
}

function loadScConfigSafe() {
  try {
    const override = process.env.SHIELDCORTEX_CONFIG_DIR?.trim();
    const dir = override || join(homedir(), '.shieldcortex');
    const p = join(dir, 'config.json');
    if (!existsSync(p)) return {};
    return JSON.parse(readFileSync(p, 'utf-8'));
  } catch {
    return {};
  }
}

export function buildDistillPrompt(conversationText) {
  const clipped = String(conversationText || '').slice(-DISTILL_MAX_INPUT_CHARS);
  return {
    system:
      'You extract durable agent memories from a conversation transcript. '
      + 'Return ONLY valid JSON: {"memories":[{"title":"...","content":"...","category":"note|decision|preference|architecture|bug|learning|fact|procedure","salience":0.0-0.7}]}. '
      + 'Rules: facts only (no instructions to the agent); no secrets/tokens/passwords; max 8 memories; '
      + 'prefer decisions, preferences, architecture, fixes, standing procedures; skip chit-chat; '
      + 'salience <= 0.7; content under 500 words each; title under 80 chars.',
    user: `Transcript:\n\n${clipped}`,
  };
}

/**
 * Parse model JSON content into memories array (tolerant).
 * @param {string} text
 */
export function parseDistillResponseText(text) {
  if (typeof text !== 'string' || !text.trim()) {
    throw new Error('empty-response');
  }
  let raw = text.trim();
  // Strip fenced code if present
  const fence = raw.match(/```(?:json)?\s*([\s\S]*?)```/i);
  if (fence) raw = fence[1].trim();
  // Extract first JSON object/array
  const startObj = raw.indexOf('{');
  const startArr = raw.indexOf('[');
  let start = -1;
  if (startObj >= 0 && (startArr < 0 || startObj < startArr)) start = startObj;
  else start = startArr;
  if (start < 0) throw new Error('no-json');
  raw = raw.slice(start);
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    // try trim trailing junk after last } or ]
    const lastBrace = Math.max(raw.lastIndexOf('}'), raw.lastIndexOf(']'));
    if (lastBrace < 0) throw new Error('invalid-json');
    parsed = JSON.parse(raw.slice(0, lastBrace + 1));
  }
  if (Array.isArray(parsed)) return parsed;
  if (parsed && typeof parsed === 'object') {
    if (Array.isArray(parsed.memories)) return parsed.memories;
    if (Array.isArray(parsed.items)) return parsed.items;
  }
  throw new Error('invalid-schema-shape');
}

/**
 * Call OpenAI-compatible chat/completions or Anthropic messages.
 * @param {{ apiKey: string, baseUrl: string, model: string, source?: string }} provider
 * @param {string} conversationText
 * @param {{ fetchImpl?: typeof fetch, timeoutMs?: number }} [opts]
 */
export async function callDistillProvider(provider, conversationText, opts = {}) {
  const fetchImpl = opts.fetchImpl || globalThis.fetch;
  if (typeof fetchImpl !== 'function') {
    throw new Error('fetch-unavailable');
  }
  const timeoutMs = opts.timeoutMs ?? DISTILL_TIMEOUT_MS;
  const { system, user } = buildDistillPrompt(conversationText);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    if (provider.source === 'anthropic' || provider.baseUrl.includes('anthropic.com')) {
      const url = provider.baseUrl.includes('/v1')
        ? `${provider.baseUrl.replace(/\/+$/, '')}/messages`
        : 'https://api.anthropic.com/v1/messages';
      const res = await fetchImpl(url, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-api-key': provider.apiKey,
          'anthropic-version': '2023-06-01',
        },
        body: JSON.stringify({
          model: provider.model,
          max_tokens: 1200,
          temperature: 0.2,
          system,
          messages: [{ role: 'user', content: user }],
        }),
        signal: controller.signal,
      });
      if (!res.ok) {
        throw new Error(`anthropic-http-${res.status}`);
      }
      const body = await res.json();
      const text = Array.isArray(body?.content)
        ? body.content.map((c) => (c && c.text) || '').join('\n')
        : '';
      return parseDistillResponseText(text);
    }

    // OpenAI-compatible
    const url = `${provider.baseUrl.replace(/\/+$/, '')}/chat/completions`;
    const res = await fetchImpl(url, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${provider.apiKey}`,
      },
      body: JSON.stringify({
        model: provider.model,
        temperature: 0.2,
        response_format: { type: 'json_object' },
        messages: [
          { role: 'system', content: system },
          { role: 'user', content: user },
        ],
      }),
      signal: controller.signal,
    });
    if (!res.ok) {
      throw new Error(`openai-http-${res.status}`);
    }
    const body = await res.json();
    const text = body?.choices?.[0]?.message?.content ?? '';
    return parseDistillResponseText(text);
  } finally {
    clearTimeout(timer);
  }
}

/**
 * High-level capture extraction used by stop/session-end hooks.
 *
 * @param {string} conversationText
 * @param {{
 *   mode?: string,
 *   regexExtract: () => object[],
 *   config?: object,
 *   env?: NodeJS.ProcessEnv,
 *   fetchImpl?: typeof fetch,
 *   log?: (msg: string) => void,
 * }} opts
 * @returns {Promise<{ memories: object[], path: 'distill'|'regex'|'skip', reason?: string }>}
 */
export async function extractCaptureMemories(conversationText, opts) {
  const log = opts.log || ((msg) => process.stderr.write(`${msg}\n`));
  const env = opts.env || process.env;
  const provider = resolveDistillProvider(env, opts.config);
  const mode = resolveCaptureMode(opts.mode, { providerConfigured: provider.configured });

  if (mode === CAPTURE_MODE.REGEX) {
    const memories = typeof opts.regexExtract === 'function' ? (opts.regexExtract() || []) : [];
    return { memories, path: 'regex' };
  }

  if (!provider.configured) {
    if (mode === CAPTURE_MODE.DISTILL_REQUIRED) {
      log('[capture-distill] skip: distill_required but no provider configured');
      return { memories: [], path: 'skip', reason: 'no-provider' };
    }
    // mode distill without provider — freeze law prefers skip over silent regex
    // only if explicitly distill; for auto-default we already resolved to regex
    // when !configured. Defensive:
    log('[capture-distill] skip: distill mode without provider (no regex fallback)');
    return { memories: [], path: 'skip', reason: 'no-provider' };
  }

  if (!conversationText || conversationText.length < 100) {
    return { memories: [], path: 'skip', reason: 'no-content' };
  }

  try {
    const raw = await callDistillProvider(provider, conversationText, {
      fetchImpl: opts.fetchImpl,
      timeoutMs: opts.timeoutMs,
    });
    const closed = failClosedDistill(null, raw);
    if (!closed.ok) {
      log(`[capture-distill] skip: ${closed.reason}`);
      return { memories: [], path: 'skip', reason: closed.reason };
    }
    log(`[capture-distill] ok: ${closed.memories.length} L1 memories via ${provider.source}`);
    return { memories: closed.memories, path: 'distill' };
  } catch (err) {
    const reason = err?.name === 'AbortError' ? 'timeout' : String(err?.message || err);
    log(`[capture-distill] skip: ${reason}`);
    if (allowRegexFallback(mode)) {
      const memories = typeof opts.regexExtract === 'function' ? (opts.regexExtract() || []) : [];
      return { memories, path: 'regex', reason };
    }
    return { memories: [], path: 'skip', reason };
  }
}
