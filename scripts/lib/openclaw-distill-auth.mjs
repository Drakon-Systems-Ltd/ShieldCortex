/**
 * OpenClaw on-disk / env credential resolve for Memory SOTA capture distill.
 *
 * Pure-ish: fs + env only. No DB. Never logs secret values.
 *
 * Sources (first hit wins):
 *   1. Explicit distill/env API keys (via caller / shared capture-distill)
 *   2. OpenClaw auth.profiles + credentials/auth-profiles
 *   3. models.providers.*.apiKey when it's a plain string
 *   4. Common provider env vars the gateway may already have
 *
 * SecretRefs / 1P dicts are skipped (cannot resolve offline here).
 */

import { existsSync, readFileSync, readdirSync, statSync } from 'fs';
import { homedir } from 'os';
import { join } from 'path';

const PROVIDER_ENV = Object.freeze({
  anthropic: ['ANTHROPIC_API_KEY', 'CLAUDE_API_KEY'],
  openai: ['OPENAI_API_KEY'],
  xai: ['XAI_API_KEY', 'GROK_API_KEY'],
  google: ['GOOGLE_API_KEY', 'GEMINI_API_KEY'],
  openrouter: ['OPENROUTER_API_KEY'],
  deepseek: ['DEEPSEEK_API_KEY'],
});

const CHEAP_MODEL = Object.freeze({
  anthropic: 'claude-haiku-4-5-20251001',
  'claude-cli': 'claude-haiku-4-5-20251001',
  openai: 'gpt-4.1-mini',
  xai: 'grok-4.3',
  google: 'gemini-2.0-flash',
  openrouter: 'openai/gpt-4.1-mini',
  deepseek: 'deepseek-chat',
});

const BASE_URL = Object.freeze({
  anthropic: 'https://api.anthropic.com',
  'claude-cli': 'https://api.anthropic.com',
  openai: 'https://api.openai.com/v1',
  xai: 'https://api.x.ai/v1',
  google: 'https://generativelanguage.googleapis.com/v1beta/openai',
  openrouter: 'https://openrouter.ai/api/v1',
  deepseek: 'https://api.deepseek.com/v1',
});

/**
 * @param {{ openclawHome?: string, env?: NodeJS.ProcessEnv, config?: object }} [opts]
 * @returns {{ configured: boolean, apiKey?: string, baseUrl?: string, model?: string, source?: string, auth?: string, anthropicAuth?: string }}
 */
export function resolveOpenClawDistillProvider(opts = {}) {
  const env = opts.env || process.env;
  const ocHome = opts.openclawHome || firstNonEmpty(env.OPENCLAW_HOME, join(homedir(), '.openclaw'));
  const oc = opts.config && typeof opts.config === 'object'
    ? opts.config
    : loadJsonSafe(join(ocHome, 'openclaw.json'));

  const preferred = preferredProviders(oc, env);

  // 1) env keys for preferred providers
  for (const provider of preferred) {
    const fromEnv = fromProviderEnv(provider, env);
    if (fromEnv) return decorate(provider, fromEnv, oc, 'openclaw-env');
  }

  // 2) auth-profiles credential files
  for (const provider of preferred) {
    const fromFile = fromAuthProfiles(ocHome, provider, oc);
    if (fromFile) return decorate(provider, fromFile, oc, 'openclaw-auth-profiles');
  }

  // 3) plain-string apiKey on models.providers
  for (const provider of preferred) {
    const fromModels = fromModelsProviders(oc, provider);
    if (fromModels) return decorate(provider, fromModels, oc, 'openclaw-models-providers');
  }

  // 4) any env provider at all
  for (const provider of Object.keys(PROVIDER_ENV)) {
    if (preferred.includes(provider)) continue;
    const fromEnv = fromProviderEnv(provider, env);
    if (fromEnv) return decorate(provider, fromEnv, oc, 'openclaw-env-any');
  }

  return { configured: false };
}

/**
 * Provider try-order from OC config: active primary model family first.
 */
export function preferredProviders(oc = {}, env = process.env) {
  const explicit = firstNonEmpty(env.SHIELDCORTEX_DISTILL_OAUTH_PROVIDER, '');
  if (explicit) {
    return explicit.split(',').map((s) => normalizeProvider(s)).filter(Boolean);
  }

  const chain = [];
  const primary = oc?.agents?.defaults?.model?.primary
    || oc?.agents?.defaults?.model
    || '';
  const primaryStr = typeof primary === 'string' ? primary : (primary?.id || '');
  const fromPrimary = providerFromModelRef(primaryStr);
  if (fromPrimary) chain.push(fromPrimary);

  // auth.profiles order
  const profiles = oc?.auth?.profiles;
  if (profiles && typeof profiles === 'object') {
    for (const meta of Object.values(profiles)) {
      const p = normalizeProvider(meta?.provider);
      if (p && !chain.includes(p)) chain.push(p);
    }
  }

  // models.providers keys
  const prov = oc?.models?.providers;
  if (prov && typeof prov === 'object') {
    for (const k of Object.keys(prov)) {
      const p = normalizeProvider(k);
      if (p && !chain.includes(p)) chain.push(p);
    }
  }

  for (const p of ['anthropic', 'openai', 'xai', 'google', 'openrouter', 'deepseek', 'claude-cli']) {
    if (!chain.includes(p)) chain.push(p);
  }
  return chain;
}

function providerFromModelRef(ref) {
  const s = String(ref || '').toLowerCase();
  if (!s) return '';
  // clawd/claude-opus-5, anthropic/claude-..., openai/gpt-..., xai/grok-...
  if (s.includes('claude') || s.includes('anthropic') || s.startsWith('clawd/')) return 'anthropic';
  if (s.includes('openai') || s.includes('gpt-') || s.includes('codex')) return 'openai';
  if (s.includes('xai') || s.includes('grok')) return 'xai';
  if (s.includes('gemini') || s.includes('google')) return 'google';
  if (s.includes('openrouter')) return 'openrouter';
  if (s.includes('deepseek')) return 'deepseek';
  const head = s.split(/[/:]/)[0];
  return normalizeProvider(head);
}

function normalizeProvider(id) {
  const s = String(id || '').trim().toLowerCase();
  if (!s) return '';
  if (s === 'claude' || s === 'claude-cli' || s === 'clawd') return s === 'claude-cli' ? 'claude-cli' : 'anthropic';
  if (s === 'grok') return 'xai';
  if (s === 'gemini') return 'google';
  return s;
}

function fromProviderEnv(provider, env) {
  const keys = PROVIDER_ENV[provider] || PROVIDER_ENV[normalizeProvider(provider)] || [];
  for (const k of keys) {
    const v = typeof env[k] === 'string' ? env[k].trim() : '';
    if (v) return { apiKey: v };
  }
  return null;
}

function fromModelsProviders(oc, provider) {
  const block = oc?.models?.providers?.[provider] || oc?.models?.providers?.[normalizeProvider(provider)];
  if (!block || typeof block !== 'object') return null;
  const key = block.apiKey;
  if (typeof key === 'string' && key.trim()) {
    return { apiKey: key.trim(), baseUrl: typeof block.baseUrl === 'string' ? block.baseUrl : undefined };
  }
  // SecretRef dict — skip
  return null;
}

function fromAuthProfiles(ocHome, provider, oc) {
  const dir = join(ocHome, 'credentials', 'auth-profiles');
  const file = join(ocHome, 'credentials', 'auth-profiles.json');
  const candidates = [];

  if (existsSync(file) && statSync(file).isFile()) {
    candidates.push(file);
  }
  if (existsSync(dir) && statSync(dir).isDirectory()) {
    try {
      for (const name of readdirSync(dir)) {
        candidates.push(join(dir, name));
      }
    } catch { /* */ }
  }

  // Also scan profile ids from config that match provider
  const profiles = oc?.auth?.profiles || {};
  for (const [profileId, meta] of Object.entries(profiles)) {
    if (normalizeProvider(meta?.provider) !== normalizeProvider(provider)
      && !String(profileId).toLowerCase().startsWith(String(provider).toLowerCase())) {
      continue;
    }
    candidates.push(join(dir, profileId));
    candidates.push(join(dir, `${profileId}.json`));
  }

  for (const p of candidates) {
    if (!existsSync(p) || !statSync(p).isFile()) continue;
    let raw;
    try {
      raw = JSON.parse(readFileSync(p, 'utf-8'));
    } catch {
      continue;
    }
    const token = pickToken(raw);
    if (!token) continue;
    const baseUrl = typeof raw.baseUrl === 'string' ? raw.baseUrl
      : (typeof raw.base_url === 'string' ? raw.base_url : undefined);
    const mode = String(raw.mode || raw.auth_mode || '').toLowerCase();
    return {
      apiKey: token,
      baseUrl,
      oauth: mode.includes('oauth') || Boolean(raw.accessToken || raw.access_token),
    };
  }
  return null;
}

function pickToken(raw) {
  if (!raw || typeof raw !== 'object') return '';
  const direct = firstNonEmpty(
    raw.accessToken,
    raw.access_token,
    raw.apiKey,
    raw.api_key,
    raw.token,
    raw.oauthToken,
  );
  if (direct) return direct;
  // nested
  for (const k of ['credentials', 'auth', 'oauth', 'tokens']) {
    const nested = raw[k];
    if (nested && typeof nested === 'object') {
      const t = firstNonEmpty(
        nested.accessToken,
        nested.access_token,
        nested.apiKey,
        nested.api_key,
        nested.token,
      );
      if (t) return t;
    }
  }
  return '';
}

function decorate(provider, cred, oc, authTag) {
  const p = normalizeProvider(provider) || provider;
  const modelsBlock = oc?.models?.providers?.[p] || {};
  const baseUrl = firstNonEmpty(
    cred.baseUrl,
    typeof modelsBlock.baseUrl === 'string' ? modelsBlock.baseUrl : '',
    BASE_URL[p],
    'https://api.openai.com/v1',
  ).replace(/\/+$/, '');

  const isAnthropic = p === 'anthropic' || p === 'claude-cli' || baseUrl.includes('anthropic.com');
  const model = CHEAP_MODEL[p] || (isAnthropic ? CHEAP_MODEL.anthropic : 'gpt-4.1-mini');

  return {
    configured: true,
    apiKey: cred.apiKey,
    baseUrl,
    model,
    source: isAnthropic ? 'anthropic' : 'openai-compatible',
    auth: `${authTag}:${p}`,
    anthropicAuth: isAnthropic && (cred.oauth || !String(cred.apiKey).startsWith('sk-ant-'))
      ? 'bearer'
      : undefined,
  };
}

function loadJsonSafe(path) {
  try {
    if (!existsSync(path)) return {};
    return JSON.parse(readFileSync(path, 'utf-8'));
  } catch {
    return {};
  }
}

function firstNonEmpty(...vals) {
  for (const v of vals) {
    if (typeof v === 'string' && v.trim()) return v.trim();
  }
  return '';
}
