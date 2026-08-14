/**
 * #224 — bind every enforcement record to a plane, a host, a hook and an intent.
 *
 * Audit rows that cannot say which plane produced them, which gateway they
 * came from, or which intent they name cannot feed an acceptance contract or
 * an FP rate. This is the one source of those fields. Writers (Claude hook,
 * OpenClaw interceptor, conversation hooks) stamp; they do not invent a
 * second schema.
 *
 * `actionKey` is NOT the approval hash. Approvals stay exact-command
 * (`hashToolCall`) so approving `rm -rf /tmp/a` cannot release `/tmp/b`.
 * The action key collapses path *classes* and volatile args so Veronica's
 * FP denominator is distinct intents, not records.
 */
import { randomBytes, randomUUID } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

import { mkdirSecure } from '../../setup/state-permissions.js';
import { extractPath, extractUrl, normaliseToolName } from './tool-action-guard.js';

export const REQUIRED_BINDING_FIELDS = [
  'plane',
  'gatewayInstanceId',
  'hookName',
  'pluginId',
  'nonce',
  'seq',
  'actionKey',
] as const;

export type BindingField = (typeof REQUIRED_BINDING_FIELDS)[number];

export type EnforcementPlane = 'action_guard' | 'conversation_firewall';

const PLANES = new Set<string>(['action_guard', 'conversation_firewall']);

export interface EnforcementBinding {
  plane: EnforcementPlane;
  gatewayInstanceId: string;
  hookName: string;
  pluginId: string;
  nonce: string;
  seq: number;
  actionKey: string;
}

export interface BindingContext {
  plane: EnforcementPlane;
  hookName: string;
  pluginId: string;
  home?: string;
  gatewayPid?: number;
  tool?: string;
  args?: Record<string, unknown>;
  /** Override when the caller already knows the intent (conversation rows). */
  actionKey?: string;
}

export function hasRequiredBinding(entry: unknown): boolean {
  if (!entry || typeof entry !== 'object') return false;
  const rec = entry as Record<string, unknown>;
  if (!PLANES.has(String(rec.plane ?? ''))) return false;
  for (const field of REQUIRED_BINDING_FIELDS) {
    if (field === 'seq') {
      if (typeof rec.seq !== 'number' || !Number.isInteger(rec.seq) || rec.seq < 1) return false;
      continue;
    }
    const v = rec[field];
    if (typeof v !== 'string' || v.length === 0) return false;
  }
  if (!/^[0-9a-f]{32}$/.test(String(rec.nonce))) return false;
  return true;
}

export function attachEnforcementBinding<T extends Record<string, unknown>>(
  entry: T,
  ctx: BindingContext,
): T & EnforcementBinding {
  const home = ctx.home ?? homedir();
  const instance = resolveInstanceId(home);
  const gatewayInstanceId = ctx.gatewayPid
    ? `${instance}:gw:${ctx.gatewayPid}`
    : `${instance}:${ctx.plane === 'conversation_firewall' ? 'conversation' : ctx.hookName}`;
  const actionKey = ctx.actionKey
    ?? (ctx.tool ? actionKeyForToolCall(ctx.tool, ctx.args ?? {}) : `${ctx.plane}:${ctx.hookName}`);
  const binding: EnforcementBinding = {
    plane: ctx.plane,
    gatewayInstanceId,
    hookName: ctx.hookName,
    pluginId: ctx.pluginId,
    nonce: randomBytes(16).toString('hex'),
    seq: nextAuditSeq(home),
    actionKey,
  };
  return { ...entry, ...binding };
}

export function actionKeyForToolCall(tool: string, args: Record<string, unknown>): string {
  const command = commandFromArgs(args);
  if (command) return shapeCommand(command);
  const path = extractPath(args);
  if (path) return `${normaliseToolName(tool)}:${pathClass(path)}`;
  const url = extractUrl(args);
  if (url) return `${normaliseToolName(tool)}:${urlClass(url)}`;
  return normaliseToolName(tool);
}

function commandFromArgs(args: Record<string, unknown>): string {
  // Narrower than extractCommand: `code`/`input` are payload on many tools
  // and must not become the intent key.
  for (const key of ['command', 'cmd', 'script'] as const) {
    const v = args[key];
    if (typeof v === 'string' && v.trim()) return v;
  }
  return '';
}

function tokenize(cmd: string): string[] {
  const out: string[] = [];
  let cur = '';
  let quote: string | null = null;
  for (let i = 0; i < cmd.length; i++) {
    const c = cmd[i];
    if (quote) {
      if (c === quote) quote = null;
      else cur += c;
      continue;
    }
    if (c === '"' || c === "'") { quote = c; continue; }
    if (c === ' ' || c === '\t' || c === '\n') {
      if (cur) { out.push(cur); cur = ''; }
      continue;
    }
    cur += c;
  }
  if (cur) out.push(cur);
  return out;
}

function shapeCommand(cmd: string): string {
  const tokens = tokenize(cmd);
  const out: string[] = [];
  let seenKill = false;
  for (const raw of tokens) {
    if (!raw) continue;
    if (/^kill(?:all)?$/.test(raw)) { seenKill = true; out.push(raw); continue; }
    if (raw.startsWith('-')) { out.push(raw); continue; }
    if (seenKill && /^[0-9]+$/.test(raw)) { out.push('<pid>'); continue; }
    out.push(classifyPositional(raw));
  }
  return out.join(' ');
}

function classifyPositional(tok: string): string {
  if (looksLikeAbsPath(tok) || tok.startsWith('~/') || tok.startsWith('./') || tok.startsWith('../')) {
    return pathClass(tok);
  }
  if (tok.includes('/') && /\.\w+$/.test(tok)) return pathClass(tok);
  if (tok.includes('/')) return '<ref>';
  if (/^[0-9a-f]{7,40}$/.test(tok)) return '<hash>';
  return tok;
}

function looksLikeAbsPath(tok: string): boolean {
  return tok.startsWith('/') || tok === '~';
}

export function pathClass(tok: string): string {
  if (tok === '/' || tok === '/*' || tok === '/**') return '<root>';
  if (tok === '~' || tok === '~/' || tok === '$HOME' || tok === '$HOME/') return '<home>';
  if (/^\.[./]*$/.test(tok)) return '<cwd>';
  if (/^(?:\/tmp|\/var\/tmp|\/private\/var\/folders)(?:\/|$)/i.test(tok)) return '<tmp>';
  if (/^(?:~|\/Users\/|\/home\/)/.test(tok)) return '<home>';
  if (/^\/(?:etc|usr|var|bin|sbin|opt|root|System|private\/etc)(?:\/|$)/.test(tok)) return '<sys>';
  if (tok.startsWith('/')) return '<abs>';
  return '<rel>';
}

function urlClass(url: string): string {
  try {
    const u = new URL(url);
    return `<url:${u.protocol}//${u.hostname}>`;
  } catch {
    return '<url>';
  }
}

export function resolveInstanceId(home: string = homedir()): string {
  const dir = join(home, '.shieldcortex');
  mkdirSecure(dir);
  const file = join(dir, 'instance-id');
  try {
    if (existsSync(file)) {
      const existing = readFileSync(file, 'utf8').trim();
      if (/^[0-9a-f-]{36}$/i.test(existing)) return existing.toLowerCase();
    }
  } catch { /* mint a new one */ }
  const id = randomUUID();
  try { writeFileSync(file, `${id}\n`, { mode: 0o600 }); } catch { /* best-effort persist */ }
  return id;
}

export function nextAuditSeq(home: string = homedir()): number {
  const dir = join(home, '.shieldcortex', 'audit');
  mkdirSecure(dir);
  const file = join(dir, 'seq');
  let n = 0;
  try {
    if (existsSync(file)) n = parseInt(readFileSync(file, 'utf8').trim(), 10) || 0;
  } catch { n = 0; }
  n += 1;
  try { writeFileSync(file, `${n}\n`, { mode: 0o600 }); } catch { /* still return the next number */ }
  return n;
}

export function bindRuntimeInspectPayload(
  raw: unknown,
  opts: { configPath: string; pid: number | null; timestamp: string },
): Record<string, unknown> {
  const stamp = { configPath: opts.configPath, pid: opts.pid, timestamp: opts.timestamp };
  if (raw && typeof raw === 'object' && !Array.isArray(raw)) {
    return { ...(raw as Record<string, unknown>), ...stamp };
  }
  return { payload: raw, ...stamp };
}
