/**
 * Claude Code hook — process-side posture self-report (#613).
 *
 * The CLI (`doctor`, `policy-evidence`) runs in another process and cannot see
 * what the PreToolUse hook resolved: whether it is enabled, whether it
 * enforces, whether the guard loaded. So the hook says so itself, in a small
 * versioned file:
 *
 *   <config dir>/posture/claude_code/default/<instance>.json
 *
 * The hook is spawned once per tool call, so there is no resident process to
 * check. `<instance>` is derived from the Claude Code session id (hashed, never
 * the raw id), so two concurrent sessions are two records, never
 * last-writer-wins, and the report says `liveness: per-call`: recency within
 * max_age is its only evidence.
 *
 * The schema is closed and mirrored by src/posture/posture-record.ts
 * (parseSelfReport), plugins/openclaw/posture-report.ts and the Hermes
 * plugin's posture.py — build units that cannot share an import, pinned
 * together by tests that feed each writer's output to the CLI validator.
 *
 * Best-effort by contract: every export swallows its own failures and returns
 * nothing the gate reads. The hook loads this module with a guarded dynamic
 * import, so even a missing or broken copy changes no allow / ask / deny
 * decision (pinned by pre-tool-hook-posture-613.test.ts).
 *
 * Host-integrity limitation: a host-local file, not attestation.
 */

import { chmodSync, lstatSync, mkdirSync, readFileSync, readdirSync, renameSync, unlinkSync, writeFileSync } from 'fs';
import { createHash, randomBytes } from 'crypto';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';

const SCHEMA = 'shieldcortex.posture.self-report';
const MAX_BYTES = 8192;
const MAX_INTERVALS = 8;
const REASON_MAX = 120;
/** A fresh identical report is not rewritten more often than this. */
const REWRITE_MS = 5 * 60 * 1000;
/** Per-session reports untouched this long belong to sessions long over. */
const PRUNE_MS = 48 * 60 * 60 * 1000;
const ISO_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/;
const IDENT_RE = /^[A-Za-z0-9@/._:+-]{1,64}$/;
const SHA_RE = /^sha256:[0-9a-f]{64}$/;
const POSTURES = ['enforce', 'advisory', 'intentionally-off', 'unavailable', 'unknown'];
const DENIAL_KEYS = 'at,configured_posture,instance,plugin_hash,policy_hash,tested_path';

const here = dirname(fileURLToPath(import.meta.url));

/** What this hook process has resolved so far. `configured` null = nothing to report yet. */
const state = { configDir: null, configured: null, policyHash: null, scanner: 'unknown', reason: null, tool: null, instance: 'c-nosession' };

function stable(value) {
  if (Array.isArray(value)) return `[${value.map(stable).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${stable(value[k])}`).join(',')}}`;
  }
  return JSON.stringify(value ?? null);
}

/** Hash of the effective guard policy. Notify config (secrets) is left out. */
function policyHash(cfg) {
  try {
    const projection = {
      enabled: cfg.enabled === true,
      enforce: cfg.enforce !== false,
      autoApprove: [...(cfg.autoApprove ?? [])].sort(),
      auditAllows: cfg.auditAllows !== false,
      brokerEnabled: cfg.broker?.enabled === true,
      reviewedScripts: Array.isArray(cfg.reviewedScripts) ? cfg.reviewedScripts : null,
      retryCards: cfg.retry?.retryCards === true,
    };
    return `sha256:${createHash('sha256').update(stable(projection)).digest('hex')}`;
  } catch {
    return null;
  }
}

let hookHashMemo;
/** sha256 of the hook script plus this module: the code that gates. */
function pluginHash() {
  if (hookHashMemo === undefined) {
    try {
      const h = createHash('sha256');
      h.update(readFileSync(join(here, '..', 'pre-tool-hook.mjs')));
      h.update(readFileSync(fileURLToPath(import.meta.url)));
      hookHashMemo = `sha256:${h.digest('hex')}`;
    } catch {
      hookHashMemo = null;
    }
  }
  return hookHashMemo;
}

function pluginVersion() {
  try {
    const v = JSON.parse(readFileSync(join(here, '..', '..', 'package.json'), 'utf8')).version;
    return typeof v === 'string' && IDENT_RE.test(v) ? v : null;
  } catch {
    return null;
  }
}

function reasonText(text) {
  const clean = String(text ?? '').replace(/[^\x20-\x7e]/g, '?').slice(0, REASON_MAX);
  return clean || 'unspecified';
}

function readPrevious(file) {
  try {
    const st = lstatSync(file);
    if (!st.isFile() || st.size > MAX_BYTES) return null;
    const prev = JSON.parse(readFileSync(file, 'utf8'));
    return prev && typeof prev === 'object' && !Array.isArray(prev) ? prev : null;
  } catch {
    return null;
  }
}

function intervals(prev, scanner, reason, nowIso) {
  const kept = [];
  for (const d of Array.isArray(prev?.degraded_intervals) ? prev.degraded_intervals : []) {
    if (!d || typeof d !== 'object') continue;
    if (typeof d.from !== 'string' || !ISO_RE.test(d.from)) continue;
    if (d.to !== null && (typeof d.to !== 'string' || !ISO_RE.test(d.to))) continue;
    kept.push({ from: d.from, to: d.to, reason: reasonText(d.reason) });
  }
  const openLast = kept.length > 0 && kept[kept.length - 1].to === null;
  if (scanner === 'degraded' && !openLast) kept.push({ from: nowIso, to: null, reason: reasonText(reason ?? 'scanner-degraded') });
  else if (scanner === 'available' && openLast) kept[kept.length - 1].to = nowIso;
  return kept.slice(-MAX_INTERVALS);
}

/** A previous denial, kept only if well-formed and from THIS instance. */
function carriedDenial(d, key) {
  if (!d || typeof d !== 'object' || Array.isArray(d) || d.instance !== key) return null;
  if (Object.keys(d).sort().join(',') !== DENIAL_KEYS) return null;
  if (typeof d.at !== 'string' || !ISO_RE.test(d.at)) return null;
  if (typeof d.tested_path !== 'string' || !IDENT_RE.test(d.tested_path)) return null;
  for (const h of [d.plugin_hash, d.policy_hash]) {
    if (h !== null && (typeof h !== 'string' || !SHA_RE.test(h))) return null;
  }
  if (!POSTURES.includes(d.configured_posture)) return null;
  return { ...d };
}

function secureDir(dir) {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const st = lstatSync(dir);
  if (!st.isDirectory() || st.isSymbolicLink()) throw new Error('not a directory');
  if ((st.mode & 0o077) !== 0) chmodSync(dir, 0o700);
}

function prune(dir, keep, nowMs) {
  try {
    for (const name of readdirSync(dir)) {
      if (name === keep) continue;
      try {
        const full = join(dir, name);
        const st = lstatSync(full);
        if (!st.isFile()) continue;
        const tmp = name.includes('.tmp-');
        if ((tmp && nowMs - st.mtimeMs > 60 * 60 * 1000) || (!tmp && name.endsWith('.json') && nowMs - st.mtimeMs > PRUNE_MS)) {
          unlinkSync(full);
        }
      } catch { /* raced */ }
    }
  } catch { /* best-effort */ }
}

/** Where the hook's config lives, and the raw hook payload (for the session id only). */
export function noteContext(configDir, rawInput) {
  try {
    state.configDir = typeof configDir === 'string' ? configDir : null;
    const sid = JSON.parse(rawInput || '{}')?.session_id;
    state.instance = typeof sid === 'string' && sid.length > 0 && sid.length <= 512
      ? `c${createHash('sha256').update(sid).digest('hex').slice(0, 24)}`
      : 'c-nosession';
  } catch {
    state.instance = 'c-nosession';
  }
}

/** Record what the Action Guard config resolved to. */
export function noteConfig(cfg) {
  try {
    state.configured = !cfg.enabled ? 'intentionally-off' : cfg.enforce ? 'enforce' : 'advisory';
    state.policyHash = policyHash(cfg);
  } catch {
    state.configured = null;
  }
}

export function noteTool(toolName) {
  try {
    state.tool = typeof toolName === 'string' ? toolName : null;
  } catch { /* best-effort */ }
}

/** Record the scanner state and write (throttled). */
export function noteScanner(scanner, reason = null) {
  try {
    state.scanner = scanner === 'available' || scanner === 'degraded' ? scanner : 'unknown';
    state.reason = reason;
    writeReport();
  } catch { /* best-effort */ }
}

/** Write the report. `denial` records a blocked action on the current tool. Never throws. */
export function writeReport({ denial = false } = {}) {
  let tmp = null;
  try {
    if (!state.configured || !state.configDir) return;
    const root = join(state.configDir, 'posture');
    const dir = join(root, 'claude_code', 'default');
    const key = state.instance;
    const file = join(dir, `${key}.json`);
    const nowMs = Date.now();
    const nowIso = new Date(nowMs).toISOString();
    const prev = readPrevious(file);
    const ivs = intervals(prev, state.scanner, state.reason, nowIso);
    const hash = pluginHash();
    const prevAge = typeof prev?.heartbeat_at === 'string' ? nowMs - Date.parse(prev.heartbeat_at) : NaN;
    if (
      !denial && prev
      && prev.configured_posture === state.configured
      && prev.scanner === state.scanner
      && prev.policy_hash === state.policyHash
      && prev.plugin?.hash === hash
      && JSON.stringify(prev.degraded_intervals) === JSON.stringify(ivs)
      && prevAge >= 0 && prevAge < REWRITE_MS
    ) return;
    const prevDenials = prev?.denials && typeof prev.denials === 'object' ? prev.denials : {};
    let blocked = carriedDenial(prevDenials.blocked_action, key);
    const probe = carriedDenial(prevDenials.synthetic_probe, key);
    let count = Number.isInteger(prevDenials.blocked_action_count) && prevDenials.blocked_action_count >= 0
      ? Math.min(prevDenials.blocked_action_count, 1e9) : 0;
    if (denial) {
      const tool = String(state.tool ?? 'unknown').replace(/[^A-Za-z0-9._:+-]/g, '_').slice(0, 40) || 'unknown';
      blocked = {
        at: nowIso,
        tested_path: `PreToolUse:${tool}`.slice(0, 64),
        instance: key,
        plugin_hash: hash,
        policy_hash: state.policyHash,
        configured_posture: state.configured,
      };
      count = Math.min(count + 1, 1e9);
    }
    const startedAt = typeof prev?.instance?.started_at === 'string' && ISO_RE.test(prev.instance.started_at)
      && Date.parse(prev.instance.started_at) <= nowMs ? prev.instance.started_at : nowIso;
    const body = {
      schema: SCHEMA,
      version: 1,
      runtime: 'claude_code',
      profile: 'default',
      plane: 'tool-gate',
      instance: { key, pid: null, process_start: null, started_at: startedAt, liveness: 'per-call' },
      runtime_version: null,
      plugin: { id: 'shieldcortex-pre-tool-hook', version: pluginVersion(), hash },
      heartbeat_at: nowIso,
      loaded: true,
      configured_posture: state.configured,
      scanner: state.scanner,
      policy_hash: state.policyHash,
      degraded_intervals: ivs,
      denials: { blocked_action: blocked, synthetic_probe: probe, blocked_action_count: count },
    };
    let data = JSON.stringify(body);
    if (Buffer.byteLength(data) > MAX_BYTES) {
      body.degraded_intervals = body.degraded_intervals.slice(-1);
      data = JSON.stringify(body);
      if (Buffer.byteLength(data) > MAX_BYTES) return;
    }
    secureDir(root);
    secureDir(join(root, 'claude_code'));
    secureDir(dir);
    tmp = `${file}.tmp-${process.pid}-${randomBytes(4).toString('hex')}`;
    writeFileSync(tmp, data, { flag: 'wx', mode: 0o600 });
    renameSync(tmp, file);
    tmp = null;
    prune(dir, `${key}.json`, nowMs);
  } catch {
    // Best-effort. A posture report must never reach the gate.
  } finally {
    if (tmp) {
      try { unlinkSync(tmp); } catch { /* already gone */ }
    }
  }
}
