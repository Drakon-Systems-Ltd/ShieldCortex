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
import { spawnSync } from 'child_process';

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
  // Must match memories.valid_category CHECK constraint.
  'architecture',
  'pattern',
  'preference',
  'error',
  'context',
  'learning',
  'todo',
  'note',
  'relationship',
  'custom',
]);

/** Map common distill labels → schema categories. */
const CATEGORY_ALIASES = {
  decision: 'architecture',
  bug: 'error',
  fact: 'note',
  procedure: 'pattern',
  pref: 'preference',
  fix: 'error',
  ops: 'context',
};

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
    if (CATEGORY_ALIASES[category]) category = CATEGORY_ALIASES[category];
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
 *
 * Priority (zero-config):
 *   1. Explicit env/config API keys (SHIELDCORTEX_DISTILL_* / OPENAI_* / ANTHROPIC_*)
 *   2. On-disk auth already present:
 *        Hermes active_provider → OAuth (xai/codex/qwen/minimax/nous) →
 *        Hermes API-key pools (anthropic/openai/gemini/…) → Claude Max OAuth
 *      Each provider gets a **cheap** default model (not the main chat model).
 *
 * Users do not need to set distill keys/models if Hermes or Claude is already
 * logged in. Opt out: SHIELDCORTEX_DISTILL_OAUTH=0. Force provider list:
 * SHIELDCORTEX_DISTILL_OAUTH_PROVIDER=xai-oauth,anthropic,claude-oauth
 * Upgrade model: SHIELDCORTEX_DISTILL_MODEL=grok-4.6
 *
 * @returns {{ configured: boolean, apiKey?: string, baseUrl?: string, model?: string, source?: string, auth?: string }}
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

  if (apiKey) {
    const baseUrl = firstNonEmpty(
      env.SHIELDCORTEX_DISTILL_BASE_URL,
      env.OPENAI_BASE_URL,
      typeof distill.baseUrl === 'string' ? distill.baseUrl : '',
      'https://api.openai.com/v1',
    ).replace(/\/+$/, '');

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
      auth: 'api-key',
    };
  }

  // Genius path: reuse Hermes OAuth already on the host (no new API key).
  const oauth = resolveHermesOAuthProvider(env, cfg);
  if (oauth.configured) return oauth;

  return { configured: false };
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

/**
 * Zero-config on-disk credentials for distill.
 *
 * Covers:
 *   - Hermes OAuth: xai-oauth, openai-codex, qwen-oauth, minimax-oauth, nous
 *   - Hermes API-key pools: anthropic, openai-api, gemini, xai, deepseek, …
 *   - Claude Max / Claude Code OAuth: ~/.claude/.credentials.json
 *
 * Preference: explicit SHIELDCORTEX_DISTILL_OAUTH_PROVIDER list, else Hermes
 * active_provider first, then a cheap multi-provider chain. Never logs secrets.
 */
export function resolveHermesOAuthProvider(env = process.env, config = null) {
  const cfg = config && typeof config === 'object' ? config : loadScConfigSafe();
  const mem = (cfg.memory && typeof cfg.memory === 'object') ? cfg.memory : {};
  const distill = (mem.distill && typeof mem.distill === 'object') ? mem.distill : {};

  const disabled =
    env.SHIELDCORTEX_DISTILL_OAUTH === '0'
    || env.SHIELDCORTEX_DISTILL_OAUTH === 'false'
    || distill.oauth === false;
  if (disabled) return { configured: false };

  const hermesHome = firstNonEmpty(env.HERMES_HOME, join(homedir(), '.hermes'));
  const agentRoot = firstNonEmpty(env.HERMES_AGENT_ROOT, join(hermesHome, 'hermes-agent'));
  const preferred = resolveProviderPreference(env, distill, hermesHome);

  for (const providerId of preferred) {
    const viaPy = resolveHermesProviderViaPython(providerId, agentRoot, hermesHome, env);
    if (viaPy?.configured) {
      return withDefaultModel(viaPy, providerId, env, distill);
    }
  }

  for (const providerId of preferred) {
    if (providerId === 'claude-oauth' || providerId === 'claude-max' || providerId === 'claude') {
      const viaClaude = resolveClaudeCodeOAuthProvider(env);
      if (viaClaude?.configured) return withDefaultModel(viaClaude, 'claude-oauth', env, distill);
      continue;
    }
    const viaFile = resolveHermesProviderFromAuthJson(providerId, hermesHome);
    if (viaFile?.configured) return withDefaultModel(viaFile, providerId, env, distill);
  }

  // Final Claude Max fallback even if not listed (common non-Hermes hosts)
  if (!preferred.includes('claude-oauth')) {
    const viaClaude = resolveClaudeCodeOAuthProvider(env);
    if (viaClaude?.configured) return withDefaultModel(viaClaude, 'claude-oauth', env, distill);
  }

  return { configured: false };
}

/** @deprecated alias — resolveHermesOAuthProvider is now multi-provider on-disk auth */
export function resolveOnDiskDistillProvider(env = process.env, config = null) {
  return resolveHermesOAuthProvider(env, config);
}

function withDefaultModel(provider, providerId, env, distill) {
  return {
    ...provider,
    model: firstNonEmpty(
      env.SHIELDCORTEX_DISTILL_MODEL,
      typeof distill?.model === 'string' ? distill.model : '',
      defaultModelForProvider(providerId, provider),
    ),
  };
}

/**
 * Build provider try-order.
 * Explicit env/config wins; else active Hermes provider first, then broad chain.
 */
export function resolveProviderPreference(env = process.env, distill = {}, hermesHome = join(homedir(), '.hermes')) {
  const explicit = firstNonEmpty(
    env.SHIELDCORTEX_DISTILL_OAUTH_PROVIDER,
    typeof distill?.oauthProvider === 'string' ? distill.oauthProvider : '',
  );
  if (explicit) {
    return explicit.split(',').map((s) => s.trim()).filter(Boolean);
  }

  const chain = [];
  const active = readHermesActiveProvider(hermesHome);
  if (active) chain.push(normalizeProviderId(active));

  // Broad zero-config chain — first configured wins. Cheap models applied per id.
  const defaults = [
    'xai-oauth',
    'openai-codex',
    'anthropic',
    'claude-oauth',
    'qwen-oauth',
    'minimax-oauth',
    'nous',
    'openai-api',
    'gemini',
    'xai',
    'deepseek',
    'openrouter',
  ];
  for (const id of defaults) {
    if (!chain.includes(id)) chain.push(id);
  }
  return chain;
}

function normalizeProviderId(id) {
  const s = String(id || '').trim().toLowerCase();
  if (!s) return s;
  if (s === 'xai' || s === 'grok-oauth' || s === 'x-ai-oauth') return 'xai-oauth';
  if (s === 'codex' || s === 'chatgpt') return 'openai-codex';
  if (s === 'qwen' || s === 'qwen-cli') return 'qwen-oauth';
  if (s === 'minimax') return 'minimax-oauth';
  if (s === 'claude' || s === 'claude-max' || s === 'claude-code') return 'claude-oauth';
  return s;
}

function readHermesActiveProvider(hermesHome) {
  try {
    const authPath = join(hermesHome, 'auth.json');
    if (!existsSync(authPath)) return '';
    const raw = JSON.parse(readFileSync(authPath, 'utf-8'));
    return typeof raw.active_provider === 'string' ? raw.active_provider : '';
  } catch {
    return '';
  }
}

/**
 * Cheap defaults for background distill (not the user's main chat model).
 * Override with SHIELDCORTEX_DISTILL_MODEL or memory.distill.model.
 */
function defaultModelForProvider(providerId, provider = null) {
  const id = String(providerId || provider?.auth || '');
  if (id.includes('claude') || id.includes('anthropic')) return 'claude-haiku-4-5-20251001';
  if (id.startsWith('xai') || id.includes('grok')) return 'grok-4.3';
  if (id.includes('codex')) return 'gpt-5.5';
  if (id.includes('openai')) return 'gpt-4.1-mini';
  if (id.includes('qwen')) return 'qwen3-coder-flash';
  if (id.includes('minimax')) return 'MiniMax-M2';
  if (id.includes('nous')) return 'hermes-3-llama-3.1-8b'; // portal default-ish; override if needed
  if (id.includes('gemini') || id.includes('google')) return 'gemini-2.0-flash';
  if (id.includes('deepseek')) return 'deepseek-chat';
  if (id.includes('openrouter')) return 'openai/gpt-4.1-mini';
  return 'grok-4.3';
}

/**
 * Refresh-aware resolve via Hermes Python auth helpers.
 * Spawns a tiny python one-shot; prints JSON with apiKey/baseUrl only on stdout.
 */
function resolveHermesProviderViaPython(providerId, agentRoot, hermesHome, env) {
  try {
    const py = firstNonEmpty(env.PYTHON, env.SHIELDCORTEX_PYTHON, 'python3');
    const nl = '\n';
    const pid = normalizeProviderId(providerId);
    if (pid === 'claude-oauth') return null; // handled separately
    const script = [
      'import json,os,sys',
      'sys.path.insert(0, ' + JSON.stringify(agentRoot) + ')',
      'os.environ.setdefault("HERMES_HOME", ' + JSON.stringify(hermesHome) + ')',
      'pid = ' + JSON.stringify(pid),
      'out = {"configured": False}',
      'try:',
      '  from hermes_cli import auth as A',
      '  creds = None',
      '  if pid in ("xai-oauth", "xai", "grok-oauth"):',
      '    fn = getattr(A, "resolve_xai_oauth_runtime_credentials", None)',
      '    creds = fn() if callable(fn) else None',
      '  elif pid in ("openai-codex", "codex"):',
      '    fn = getattr(A, "resolve_codex_runtime_credentials", None)',
      '    creds = fn() if callable(fn) else None',
      '  elif pid in ("qwen-oauth", "qwen"):',
      '    fn = getattr(A, "resolve_qwen_runtime_credentials", None)',
      '    creds = fn() if callable(fn) else None',
      '  elif pid in ("minimax-oauth", "minimax"):',
      '    fn = getattr(A, "resolve_minimax_oauth_runtime_credentials", None)',
      '    creds = fn() if callable(fn) else None',
      '  elif pid in ("nous", "nous-portal"):',
      '    fn = getattr(A, "resolve_nous_runtime_credentials", None)',
      '    creds = fn() if callable(fn) else None',
      '  else:',
      '    # API-key / pool providers (anthropic, openai-api, gemini, xai, deepseek, …)',
      '    fn = getattr(A, "resolve_api_key_provider_credentials", None)',
      '    try:',
      '      creds = fn(pid) if callable(fn) else None',
      '    except Exception:',
      '      creds = None',
      '  if isinstance(creds, dict) and creds.get("api_key"):',
      '    prov = str(creds.get("provider") or pid)',
      '    base = (creds.get("base_url") or "").rstrip("/")',
      '    source = "anthropic" if ("anthropic" in prov or "claude" in prov or (base.find("anthropic.com") >= 0)) else "openai-compatible"',
      '    # Gemini OpenAI-compat often needs /openai suffix — leave base as Hermes provided',
      '    out = {',
      '      "configured": True,',
      '      "apiKey": creds.get("api_key"),',
      '      "baseUrl": base,',
      '      "source": source,',
      '      "auth": "hermes:" + prov,',
      '    }',
      'except Exception as e:',
      '  out = {"configured": False, "reason": type(e).__name__}',
      'print(json.dumps(out))',
    ].join(nl);
    const res = spawnSync(py, ['-c', script], {
      encoding: 'utf-8',
      timeout: 15_000,
      env: { ...process.env, HERMES_HOME: hermesHome },
      maxBuffer: 2 * 1024 * 1024,
    });
    if (res.error || res.status !== 0) return null;
    const line = String(res.stdout || '').trim().split(nl).filter(Boolean).pop();
    if (!line) return null;
    const parsed = JSON.parse(line);
    if (!parsed || !parsed.configured || typeof parsed.apiKey !== 'string' || !parsed.apiKey) {
      return null;
    }
    return {
      configured: true,
      apiKey: parsed.apiKey,
      baseUrl: (parsed.baseUrl || defaultBaseForProvider(pid)).replace(/\/+$/, ''),
      source: parsed.source || 'openai-compatible',
      auth: parsed.auth || `hermes:${pid}`,
    };
  } catch {
    return null;
  }
}

/**
 * Claude Code / Claude Max OAuth on disk (~/.claude/.credentials.json).
 */
export function resolveClaudeCodeOAuthProvider(env = process.env) {
  try {
    const claudeHome = firstNonEmpty(env.CLAUDE_CONFIG_DIR, join(homedir(), '.claude'));
    const credPath = join(claudeHome, '.credentials.json');
    if (!existsSync(credPath)) return { configured: false };
    const raw = JSON.parse(readFileSync(credPath, 'utf-8'));
    const block = raw?.claudeAiOauth || raw?.claude || raw;
    const token = firstNonEmpty(
      block?.accessToken,
      block?.access_token,
      raw?.accessToken,
      raw?.access_token,
    );
    if (!token) return { configured: false };
    // Expiry check when present (ms epoch)
    const exp = block?.expiresAt ?? block?.expires_at ?? null;
    if (typeof exp === 'number' && Number.isFinite(exp) && exp > 0 && Date.now() > exp) {
      return { configured: false, reason: 'claude-oauth-expired' };
    }
    return {
      configured: true,
      apiKey: token,
      baseUrl: 'https://api.anthropic.com',
      source: 'anthropic',
      auth: 'claude-oauth',
      anthropicAuth: 'bearer', // OAuth uses Authorization Bearer, not x-api-key
    };
  } catch {
    return { configured: false };
  }
}

/**
 * Last-resort: read pool access_token / api keys from ~/.hermes/auth.json (no refresh).
 */
function resolveHermesProviderFromAuthJson(providerId, hermesHome) {
  try {
    const authPath = join(hermesHome, 'auth.json');
    if (!existsSync(authPath)) return { configured: false };
    const raw = JSON.parse(readFileSync(authPath, 'utf-8'));
    const pid = normalizeProviderId(providerId);

    const pool = raw?.credential_pool?.[pid] || raw?.credential_pool?.[providerId];
    if (Array.isArray(pool)) {
      for (const entry of pool) {
        if (!entry || typeof entry !== 'object') continue;
        const token = firstNonEmpty(entry.access_token, entry.api_key, entry.token);
        if (!token) continue;
        const baseUrl = typeof entry.base_url === 'string' && entry.base_url.trim()
          ? entry.base_url.trim().replace(/\/+$/, '')
          : defaultBaseForProvider(pid);
        const source = (pid.includes('anthropic') || baseUrl.includes('anthropic.com'))
          ? 'anthropic'
          : 'openai-compatible';
        return {
          configured: true,
          apiKey: token,
          baseUrl,
          source,
          auth: `hermes-authjson:${pid}`,
          anthropicAuth: source === 'anthropic' && !String(token).startsWith('sk-ant-') ? 'bearer' : undefined,
        };
      }
    }

    const prov = raw?.providers?.[pid] || raw?.providers?.[providerId];
    const tokens = prov?.tokens;
    if (tokens && typeof tokens === 'object') {
      const token = firstNonEmpty(tokens.access_token, tokens.id_token);
      if (token) {
        return {
          configured: true,
          apiKey: token,
          baseUrl: defaultBaseForProvider(pid),
          source: 'openai-compatible',
          auth: `hermes-provider-tokens:${pid}`,
        };
      }
    }
  } catch {
    return { configured: false };
  }
  return { configured: false };
}

function defaultBaseForProvider(providerId) {
  const id = String(providerId || '');
  if (id.startsWith('xai') || id.includes('grok')) return 'https://api.x.ai/v1';
  if (id.includes('codex')) return 'https://chatgpt.com/backend-api/codex';
  if (id.includes('anthropic') || id.includes('claude')) return 'https://api.anthropic.com';
  if (id.includes('qwen')) return 'https://portal.qwen.ai/v1';
  if (id.includes('minimax')) return 'https://api.minimax.io/v1';
  if (id.includes('gemini')) return 'https://generativelanguage.googleapis.com/v1beta/openai';
  if (id.includes('deepseek')) return 'https://api.deepseek.com/v1';
  if (id.includes('openrouter')) return 'https://openrouter.ai/api/v1';
  if (id.includes('nous')) return 'https://inference-api.nousresearch.com/v1';
  return 'https://api.openai.com/v1';
}

export function buildDistillPrompt(conversationText) {
  const clipped = String(conversationText || '').slice(-DISTILL_MAX_INPUT_CHARS);
  return {
    system:
      'You extract durable agent memories from a conversation transcript. '
      + 'Return ONLY valid JSON: {"memories":[{"title":"...","content":"...","category":"architecture|pattern|preference|error|context|learning|todo|note|relationship|custom","salience":0.0-0.7}]}. '
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
    if (provider.source === 'anthropic' || (provider.baseUrl || '').includes('anthropic.com')) {
      const url = (provider.baseUrl || '').includes('/v1')
        ? `${provider.baseUrl.replace(/\/+$/, '')}/messages`
        : 'https://api.anthropic.com/v1/messages';
      const useBearer = provider.anthropicAuth === 'bearer'
        || provider.auth === 'claude-oauth'
        || (typeof provider.auth === 'string' && provider.auth.includes('claude'))
        || (typeof provider.apiKey === 'string' && !provider.apiKey.startsWith('sk-ant-'));
      const headers = {
        'content-type': 'application/json',
        'anthropic-version': '2023-06-01',
      };
      if (useBearer) {
        headers.authorization = `Bearer ${provider.apiKey}`;
        // Claude Code OAuth commonly requires this beta flag
        headers['anthropic-beta'] = 'oauth-2025-04-20';
      } else {
        headers['x-api-key'] = provider.apiKey;
      }
      const res = await fetchImpl(url, {
        method: 'POST',
        headers,
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
