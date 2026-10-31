/**
 * ShieldCortex — Plane A held actions (#853): hold the ORIGINAL Claude Code
 * tool call while the owner answers one card, then resume it or refuse it.
 *
 * The 21 Oct ruling on #853 (under #875 principle 2) asks the PreToolUse
 * hook, on a session with no prompt surface under enforce, to keep the
 * original invocation pending, put ONE card in front of the owner, and
 * return `allow` to that same call on Approve — never a retry grant, never
 * out-of-band execution. #884 showed a Claude Code PreToolUse hook can stay
 * pending past 10 s and then let the same call run (proof up to 130 s).
 *
 * ## Why the hook owns the card connection
 *
 * The gateway scopes a pending plugin approval to the CONNECTION that asked
 * for it (openclaw-approval-channel.ts). The #143/#310 waiters had to be
 * detached processes because the hook used to answer at once. A held call
 * keeps the hook alive, so the hook itself makes the one long-lived
 * `openclaw gateway call plugin.approval.request --expect-final` and reads
 * the decision from its stdout. Consequences, all deliberate:
 *
 *   - Nothing spendable is ever written to disk. The decision only exists in
 *     this process, and only this process acts on it, for the call it holds.
 *   - The card's own `timeoutMs` is the hold window, so the card and the hold
 *     expire together.
 *   - When the harness or the parent cancels the hook, the child dies with
 *     it, so the card's connection goes with the call it was holding.
 *
 * ## Timing contract (#884 F1–F3)
 *
 * The hook's harness timeout is a static per-entry value in settings.json
 * and the hook cannot see it in its payload or env. A hold that overruns it
 * is killed and, by default, the tool call then RUNS (#884 C2). So the
 * hold window is bounded by the SMALLEST pre-tool timeout this module can
 * find in the settings that could have registered the hook, minus a 10 s
 * margin and the time already spent. If no timeout can be found, nothing is
 * held. The canonical timeout written by setup is `holdSeconds + 15`.
 *
 * ## The dedupe store
 *
 * `~/.shieldcortex/holds/<key>.json` records which action identity (tool +
 * canonical input + canonical cwd) has an open card, and how its last card
 * ended. It is never consulted to ALLOW anything: an `open` or recently
 * refused record only ever turns a second identical call into a refusal with
 * no second card. Forging it can suppress a card. It cannot run a call.
 */
import { spawn, type ChildProcess } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import {
  closeSync, constants, existsSync, lstatSync, mkdirSync, openSync, readdirSync, readFileSync,
  renameSync, rmSync, writeFileSync,
} from 'node:fs';
import { homedir } from 'node:os';
import { isAbsolute, join } from 'node:path';

import { formatApprovalCardLines, type ApprovalCardSummary } from './approval-card.js';

// ── Configuration ────────────────────────────────────────────────────────

/** `actionGuard.holdSeconds` default, from the ruling. */
export const HOLD_SECONDS_DEFAULT = 120;
/** Ruling cap. OpenClaw also caps a plugin approval at 600 s. */
export const HOLD_SECONDS_MAX = 600;
/** Below this a card cannot reasonably be answered; refuse rather than hold. */
export const HOLD_SECONDS_MIN = 30;
/** The internal deadline sits this far before the harness timeout. */
export const HOLD_HARNESS_MARGIN_SECONDS = 10;
/** Room for node start-up, the scan and the audit writes before the hold. */
export const HOLD_STARTUP_ALLOWANCE_SECONDS = 5;
/** One card per action identity per this window (ruling §3). */
export const HOLD_DEDUPE_WINDOW_MS = 10 * 60_000;

/** `actionGuard.holdSeconds`, clamped. Anything that is not a finite number
 *  is the default. An out-of-range value is clamped, never rejected, so a
 *  typo cannot turn holds off. */
export function normaliseHoldSeconds(raw: unknown): number {
  const n = typeof raw === 'number' ? raw : typeof raw === 'string' && raw.trim() !== '' ? Number(raw) : NaN;
  if (!Number.isFinite(n)) return HOLD_SECONDS_DEFAULT;
  return Math.min(HOLD_SECONDS_MAX, Math.max(HOLD_SECONDS_MIN, Math.floor(n)));
}

/** The PreToolUse `timeout` (seconds) settings.json must carry for a hold
 *  of `holdSeconds` to end on our deadline and not on the harness's kill. */
export function requiredPreToolTimeoutSeconds(holdSeconds: number = HOLD_SECONDS_DEFAULT): number {
  return normaliseHoldSeconds(holdSeconds) + HOLD_HARNESS_MARGIN_SECONDS + HOLD_STARTUP_ALLOWANCE_SECONDS;
}

/**
 * How long this hook may hold, in ms, or 0 when it may not hold at all.
 * `elapsedMs` is the time since the hook process started; the harness clock
 * started slightly earlier, which the margin covers.
 */
export function holdWindowMs(input: { holdSeconds: number; hookTimeoutSeconds: number | null; elapsedMs: number }): number {
  if (typeof input.hookTimeoutSeconds !== 'number' || !Number.isFinite(input.hookTimeoutSeconds)) return 0;
  const byHarness = input.hookTimeoutSeconds * 1000 - HOLD_HARNESS_MARGIN_SECONDS * 1000 - Math.max(0, input.elapsedMs);
  const window = Math.min(normaliseHoldSeconds(input.holdSeconds) * 1000, byHarness);
  return window >= HOLD_SECONDS_MIN * 1000 ? Math.floor(window) : 0;
}

// ── The harness timeout, read from the settings that could carry it ──────

export interface PreToolTimeoutSources {
  home?: string;
  /** `CLAUDE_PROJECT_DIR`, else the payload cwd. */
  projectDir?: string;
  /** argv of the Claude Code process (the hook's parent), when readable. */
  parentArgv?: string[] | null;
  readFile?: (path: string) => string;
  /** Managed-settings files to read; defaults to the platform locations. */
  managedPaths?: string[];
  /** hooks.json files contributed by plugins; defaults to a bounded walk of
   *  `~/.claude/plugins` and every `--plugin-dir` on the harness argv. */
  pluginHookFiles?: string[];
  /** Doctor only: there is no live harness to read, so report what the
   *  settings files alone say. The hook NEVER sets this. */
  assumeNoArgvFlags?: boolean;
}

/** Is this the Claude Code process? Native (`claude`) or the npm shim
 *  (`node …/claude` or `…/@anthropic-ai/claude-code/…`). */
export function isClaudeCodeArgv(argv: string[] | null | undefined): boolean {
  if (!Array.isArray(argv) || argv.length === 0) return false;
  return argv.slice(0, 2).some((a) => {
    const v = String(a);
    const base = v.split(/[\\/]/).pop() ?? '';
    return /^claude(?:\.exe)?$/i.test(base) || v.includes('@anthropic-ai/claude-code');
  });
}

/** hooks.json files under the given plugin roots, bounded in depth and count. */
export function findPluginHookFiles(roots: string[], maxDepth = 6, maxFiles = 200): string[] {
  const out: string[] = [];
  const walk = (dir: string, depth: number) => {
    if (depth > maxDepth || out.length >= maxFiles) return;
    let entries: import('node:fs').Dirent[];
    try { entries = readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (out.length >= maxFiles) return;
      const full = join(dir, e.name);
      if (e.isDirectory() && !e.isSymbolicLink()) walk(full, depth + 1);
      else if (e.isFile() && e.name === 'hooks.json') out.push(full);
    }
  };
  for (const r of roots) walk(r, 0);
  return out;
}

function pluginDirsFromArgv(argv: string[] | null | undefined): string[] {
  const out: string[] = [];
  if (!Array.isArray(argv)) return out;
  for (let i = 0; i < argv.length; i++) {
    const a = String(argv[i]);
    if (a === '--plugin-dir' && typeof argv[i + 1] === 'string') { out.push(argv[i + 1]); i++; }
    else if (a.startsWith('--plugin-dir=')) out.push(a.slice('--plugin-dir='.length));
  }
  return out;
}

/** Where Claude Code reads managed (policy) settings, per platform. */
export const MANAGED_SETTINGS_PATHS: readonly string[] = process.platform === 'darwin'
  ? ['/Library/Application Support/ClaudeCode/managed-settings.json']
  : process.platform === 'win32'
    ? ['C:\\ProgramData\\ClaudeCode\\managed-settings.json']
    : ['/etc/claude-code/managed-settings.json'];

export interface PreToolTimeoutReading {
  /** Smallest timeout of any ShieldCortex pre-tool entry found, or null. */
  seconds: number | null;
  /** Which sources held an entry (labels, no paths). */
  sources: string[];
  /** Why `seconds` is null, when it is. `harness-unproven`: the Claude Code
   *  command line (and so its `--settings` / `--setting-sources` / plugin
   *  overrides) could not be read and identified. `settings-unreadable`: a
   *  settings source exists or was named but could not be read or parsed. */
  reason?: 'no-entry' | 'entry-without-timeout' | 'harness-unproven' | 'settings-unreadable';
}

function isPreToolEntryCommand(command: unknown): boolean {
  return typeof command === 'string' && /shieldcortex/.test(command) && /\bpre-tool\b|pre-tool-hook\.mjs/.test(command);
}

/** Timeouts of every ShieldCortex pre-tool hook in one settings object.
 *  `null` in the list means an entry with no numeric timeout. */
export function preToolTimeoutsIn(settings: unknown): Array<number | null> {
  const out: Array<number | null> = [];
  const entries = (settings as { hooks?: { PreToolUse?: unknown } } | null)?.hooks?.PreToolUse;
  if (!Array.isArray(entries)) return out;
  for (const entry of entries) {
    const hooks = (entry as { hooks?: unknown })?.hooks;
    if (!Array.isArray(hooks)) continue;
    for (const h of hooks) {
      if (!isPreToolEntryCommand((h as { command?: unknown })?.command)) continue;
      const t = (h as { timeout?: unknown }).timeout;
      out.push(typeof t === 'number' && Number.isFinite(t) && t > 0 ? t : null);
    }
  }
  return out;
}

/** `--settings <file|json>` and `--setting-sources <list>` from a Claude
 *  Code argv. Both forms (`--flag value`, `--flag=value`). */
export function settingsFlagsFromArgv(argv: string[] | null | undefined): { settings: string[]; sources: string[] | null } {
  const settings: string[] = [];
  let sources: string[] | null = null;
  if (!Array.isArray(argv)) return { settings, sources };
  for (let i = 0; i < argv.length; i++) {
    const a = String(argv[i]);
    let value: string | undefined;
    let flag = a;
    const eq = a.indexOf('=');
    if (a.startsWith('--') && eq > 0) { flag = a.slice(0, eq); value = a.slice(eq + 1); }
    if (flag !== '--settings' && flag !== '--setting-sources') continue;
    if (value === undefined) { value = argv[i + 1]; i++; }
    if (typeof value !== 'string') continue;
    if (flag === '--settings') settings.push(value);
    else sources = value.split(',').map((s) => s.trim()).filter(Boolean);
  }
  return { settings, sources };
}

/**
 * The smallest ShieldCortex pre-tool timeout across user, project and local
 * settings (as filtered by `--setting-sources`), plus any `--settings`
 * file or inline JSON on the parent's command line. Conservative on purpose:
 * a hold is only as long as the shortest kill that could end it.
 */
export function readPreToolHookTimeout(src: PreToolTimeoutSources = {}): PreToolTimeoutReading {
  const read = src.readFile ?? ((p: string) => readFileSync(p, 'utf8'));
  const home = src.home ?? homedir();
  // #853 review (CRITICAL): the budget must be PROVEN. Without the harness's
  // own command line we cannot see `--settings`, `--setting-sources` or
  // `--plugin-dir`, any of which can carry a shorter timeout than the files
  // below — and a hold the harness kills RUNS the call (#884 C2). So: no
  // readable, identifiable Claude Code argv → no hold (macOS, no /proc, or a
  // launcher we do not recognise all land here).
  if (!src.assumeNoArgvFlags && !isClaudeCodeArgv(src.parentArgv)) {
    return { seconds: null, sources: [], reason: 'harness-unproven' };
  }
  const flags = settingsFlagsFromArgv(src.assumeNoArgvFlags ? null : src.parentArgv);
  const allowed = new Set(flags.sources ?? ['user', 'project', 'local']);
  // `optional`: may legitimately be absent (ENOENT). Anything else that
  // cannot be read or parsed — and ANY named `--settings` that cannot — makes
  // the reading unproven: Claude Code may have read a value we could not.
  const candidates: Array<{ label: string; load: () => unknown; optional: boolean }> = [];
  const fromFile = (p: string) => () => JSON.parse(read(p));
  // Managed (policy) settings are always loaded by Claude Code, whatever
  // `--setting-sources` says, so they always count here.
  for (const p of src.managedPaths ?? MANAGED_SETTINGS_PATHS) {
    candidates.push({ label: 'managed', load: fromFile(p), optional: true });
  }
  if (allowed.has('user')) candidates.push({ label: 'user', load: fromFile(join(home, '.claude', 'settings.json')), optional: true });
  if (src.projectDir) {
    if (allowed.has('project')) candidates.push({ label: 'project', load: fromFile(join(src.projectDir, '.claude', 'settings.json')), optional: true });
    if (allowed.has('local')) candidates.push({ label: 'local', load: fromFile(join(src.projectDir, '.claude', 'settings.local.json')), optional: true });
  }
  for (const s of flags.settings) {
    const trimmed = s.trim();
    if (!trimmed.startsWith('{') && !isAbsolute(trimmed)) {
      // Relative to the harness's cwd, which is not ours to know.
      return { seconds: null, sources: [], reason: 'settings-unreadable' };
    }
    candidates.push({
      label: '--settings',
      load: trimmed.startsWith('{') ? () => JSON.parse(trimmed) : fromFile(trimmed),
      optional: false,
    });
  }
  const pluginFiles = src.pluginHookFiles ?? findPluginHookFiles([
    join(home, '.claude', 'plugins'),
    ...(src.assumeNoArgvFlags ? [] : pluginDirsFromArgv(src.parentArgv)),
  ]);
  for (const p of pluginFiles) candidates.push({ label: 'plugin', load: fromFile(p), optional: false });

  const found: Array<number | null> = [];
  const sources: string[] = [];
  for (const c of candidates) {
    let parsed: unknown;
    try {
      parsed = c.load();
    } catch (err) {
      if (c.optional && (err as NodeJS.ErrnoException)?.code === 'ENOENT') continue;
      return { seconds: null, sources, reason: 'settings-unreadable' };
    }
    const t = preToolTimeoutsIn(parsed);
    if (t.length === 0) continue;
    sources.push(c.label);
    found.push(...t);
  }
  if (found.length === 0) return { seconds: null, sources, reason: 'no-entry' };
  if (found.some((t) => t === null)) return { seconds: null, sources, reason: 'entry-without-timeout' };
  return { seconds: Math.min(...(found as number[])), sources };
}

/** argv of a process from /proc (Linux). Null anywhere else. */
export function readProcessArgv(pid: number): string[] | null {
  try {
    if (!Number.isInteger(pid) || pid <= 1) return null;
    const raw = readFileSync(`/proc/${pid}/cmdline`, 'utf8');
    const parts = raw.split('\0');
    if (parts.length > 0 && parts[parts.length - 1] === '') parts.pop();
    return parts.length > 0 ? parts : null;
  } catch {
    return null;
  }
}

/**
 * Abort `controller` when this process is orphaned (its parent pid changes),
 * which is what happens when the harness kills the `shieldcortex hook`
 * launcher on timeout: the hook's answer can no longer reach the harness, so
 * the card must not stay open for a call that is gone. Returns a stop function.
 */
export function abortWhenOrphaned(
  controller: AbortController,
  opts: { intervalMs?: number; ppid?: () => number } = {},
): () => void {
  const ppidOf = opts.ppid ?? (() => process.ppid);
  const initial = ppidOf();
  const timer = setInterval(() => {
    if (ppidOf() !== initial) controller.abort();
  }, opts.intervalMs ?? 500);
  timer.unref?.();
  return () => clearInterval(timer);
}

// ── Action identity and the dedupe store ─────────────────────────────────

export type HoldTerminalState = 'approved' | 'denied' | 'expired' | 'cancelled' | 'card_failed';

interface HoldRecord {
  v: 1;
  actionId: string;
  state: 'open' | HoldTerminalState;
  pid: number;
  startedAt: number;
  deadlineAt: number;
  endedAt?: number;
}

/** Action identity: the #118 call hash bound to the canonical cwd. */
export function holdKey(callHash: string, canonicalCwd: string | undefined): string {
  return createHash('sha256').update(`${callHash}\0${canonicalCwd ?? ''}`).digest('hex').slice(0, 32);
}

function holdsDir(home: string): string {
  return join(home, '.shieldcortex', 'holds');
}

function ensureHoldsDir(home: string): string | null {
  const dir = holdsDir(home);
  try {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    const st = lstatSync(dir);
    return st.isDirectory() && !st.isSymbolicLink() ? dir : null;
  } catch {
    return null;
  }
}

function readRecord(file: string): HoldRecord | null {
  try {
    if (lstatSync(file).isSymbolicLink()) return null;
    const parsed = JSON.parse(readFileSync(file, 'utf8')) as HoldRecord;
    if (parsed && parsed.v === 1 && typeof parsed.actionId === 'string' && typeof parsed.state === 'string') return parsed;
    return null;
  } catch {
    return null;
  }
}

function pidAlive(pid: number): boolean {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try { process.kill(pid, 0); return true; } catch (err) { return (err as NodeJS.ErrnoException)?.code === 'EPERM'; }
}

function writeExclusive(file: string, rec: HoldRecord): boolean {
  let fd: number | undefined;
  try {
    fd = openSync(file, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
    writeFileSync(fd, JSON.stringify(rec));
    return true;
  } catch {
    return false;
  } finally {
    if (fd !== undefined) { try { closeSync(fd); } catch { /* ignore */ } }
  }
}

export type HoldClaim =
  | { ok: true; key: string; finish: (state: HoldTerminalState) => void }
  | { ok: false; reason: 'open' | 'recently-denied' | 'recently-expired'; heldActionId: string; untilMs?: number }
  | { ok: false; reason: 'store-unavailable' };

/**
 * Claim the one card for this action identity. `open` means another hook is
 * holding the same action right now; `recently-*` means its card ended in a
 * refusal less than {@link HOLD_DEDUPE_WINDOW_MS} ago. Both are refusals
 * with no second card. A stale `open` record (its holder is dead or past
 * its deadline) is taken over. So is an approved, cancelled or failed one:
 * those are not the owner saying no.
 */
export function claimHold(
  key: string,
  opts: {
    actionId: string; windowMs: number; home?: string; now?: number; pid?: number;
    /** Test seam: runs while the takeover lock is held, before the re-read. */
    beforeTakeover?: () => void;
  },
): HoldClaim {
  const home = opts.home ?? homedir();
  const now = opts.now ?? Date.now();
  const pid = opts.pid ?? process.pid;
  const dir = ensureHoldsDir(home);
  if (!dir) return { ok: false, reason: 'store-unavailable' };
  const file = join(dir, `${key}.json`);
  const lockFile = `${file}.lock`;
  const rec: HoldRecord = { v: 1, actionId: opts.actionId, state: 'open', pid, startedAt: now, deadlineAt: now + opts.windowMs };

  const claimed = (): HoldClaim => ({
    ok: true,
    key,
    finish: (state) => {
      const done: HoldRecord = { ...rec, state, endedAt: Date.now() };
      const tmp = `${file}.${randomBytes(6).toString('hex')}.tmp`;
      try {
        const cur = readRecord(file);
        // Never overwrite a record some other holder now owns.
        if (cur && cur.actionId !== rec.actionId) return;
        writeFileSync(tmp, JSON.stringify(done), { mode: 0o600, flag: 'wx' });
        renameSync(tmp, file);
      } catch {
        try { rmSync(tmp, { force: true }); } catch { /* ignore */ }
      }
    },
  });

  for (let attempt = 0; attempt < 3; attempt++) {
    if (writeExclusive(file, rec)) return claimed();
    if (!existsSync(file)) return { ok: false, reason: 'store-unavailable' };
    const raw = readRaw(file);
    const cur = readRecord(file);
    if (cur?.state === 'open' && pidAlive(cur.pid) && now < cur.deadlineAt + 5_000) {
      return { ok: false, reason: 'open', heldActionId: cur.actionId };
    }
    if (cur && (cur.state === 'denied' || cur.state === 'expired') && typeof cur.endedAt === 'number'
      && now - cur.endedAt < HOLD_DEDUPE_WINDOW_MS) {
      return {
        ok: false,
        reason: cur.state === 'denied' ? 'recently-denied' : 'recently-expired',
        heldActionId: cur.actionId,
        untilMs: cur.endedAt + HOLD_DEDUPE_WINDOW_MS,
      };
    }
    // Stale, finished without a refusal, or unreadable: take it over — but
    // only under the per-key takeover lock, and only if the record is still
    // byte-for-byte the one judged stale (#853 review: two hooks that both
    // saw the same stale record must not both delete-and-claim, the second
    // deleting the first's fresh claim and raising a second card).
    if (!acquireLock(lockFile)) {
      return { ok: false, reason: 'open', heldActionId: cur?.actionId ?? 'pending' };
    }
    try {
      opts.beforeTakeover?.();
      if (readRaw(file) !== raw || !existsSync(file)) continue;
      try { rmSync(file, { force: true }); } catch { return { ok: false, reason: 'store-unavailable' }; }
      if (writeExclusive(file, rec)) return claimed();
    } finally {
      try { rmSync(lockFile, { force: true }); } catch { /* a stale lock is broken by age */ }
    }
  }
  const cur = readRecord(file);
  return cur ? { ok: false, reason: 'open', heldActionId: cur.actionId } : { ok: false, reason: 'store-unavailable' };
}

/** A takeover lock older than this was left by a holder that died mid-takeover. */
const TAKEOVER_LOCK_STALE_MS = 10_000;

function acquireLock(lockFile: string): boolean {
  try {
    const st = lstatSync(lockFile);
    if (Date.now() - st.mtimeMs > TAKEOVER_LOCK_STALE_MS) rmSync(lockFile, { force: true });
  } catch { /* no lock */ }
  let fd: number | undefined;
  try {
    fd = openSync(lockFile, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
    return true;
  } catch {
    return false;
  } finally {
    if (fd !== undefined) { try { closeSync(fd); } catch { /* ignore */ } }
  }
}

/** The record's raw bytes (never through a symlink), or null. */
function readRaw(file: string): string | null {
  try {
    if (lstatSync(file).isSymbolicLink()) return null;
    return readFileSync(file, 'utf8');
  } catch {
    return null;
  }
}

// ── The card ──────────────────────────────────────────────────────────────

const TITLE_MAX = 80;
const DESCRIPTION_MAX = 256;

function clip(text: string, max: number): string {
  return text.length <= max ? text : `${text.slice(0, max - 1)}…`;
}

/**
 * The one owner card for a held call. The buttons' meaning is in the footer
 * line, which the card formatter never cuts: Approve runs the HELD call
 * once, now; Deny or no answer means nothing runs. `allow-always` is not
 * offered. The card's own lifetime is the hold window.
 */
export function buildHeldCardParams(input: {
  tool: string;
  actionId: string;
  windowMs: number;
  summary: ApprovalCardSummary;
}): Record<string, unknown> {
  const tool = /^[A-Za-z][A-Za-z0-9_.-]{0,31}$/.test(input.tool) ? input.tool : 'tool';
  const title = clip(`ShieldCortex: ${tool} is held, not run. Approve? [${input.actionId}]`, TITLE_MAX);
  const lines = formatApprovalCardLines(input.summary, {
    expiresInMs: input.windowMs,
    decisions: 'Approve runs it once now; deny or no answer: nothing runs',
    budget: DESCRIPTION_MAX,
  });
  return {
    pluginId: 'shieldcortex',
    title,
    description: clip(lines.join('\n'), DESCRIPTION_MAX),
    severity: 'warning',
    allowedDecisions: ['allow-once', 'deny'],
    timeoutMs: Math.max(1_000, Math.min(HOLD_SECONDS_MAX * 1000, Math.floor(input.windowMs))),
  };
}

// ── The wait ──────────────────────────────────────────────────────────────

export type HeldDecision =
  | { kind: 'approved' }
  | { kind: 'denied' }
  | { kind: 'expired' }
  | { kind: 'cancelled' }
  | { kind: 'card_failed'; reason: 'request-failed' | 'unparseable-response' | 'unrecognised-decision' | 'spawn-failed' };

export interface AwaitHeldDecisionOptions {
  openclawBin: string;
  params: Record<string, unknown>;
  windowMs: number;
  /** Aborted → the card request is killed and the result is `cancelled`. */
  signal?: AbortSignal;
  spawnImpl?: typeof spawn;
}

/**
 * Raise the card and wait for the owner, on ONE gateway connection owned by
 * this process. Resolves exactly once and never throws. Our own deadline is
 * the window, so a gateway that never answers ends as `expired`, and the
 * child is killed on every exit path.
 */
export function awaitHeldDecision(opts: AwaitHeldDecisionOptions): Promise<HeldDecision> {
  const spawnImpl = opts.spawnImpl ?? spawn;
  return new Promise<HeldDecision>((resolvePromise) => {
    let settled = false;
    let child: ChildProcess | null = null;
    let timer: NodeJS.Timeout | null = null;
    const finish = (d: HeldDecision) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      opts.signal?.removeEventListener('abort', onAbort);
      if (child && child.exitCode === null && child.signalCode === null) {
        try { child.kill('SIGKILL'); } catch { /* already gone */ }
      }
      resolvePromise(d);
    };
    const onAbort = () => finish({ kind: 'cancelled' });
    if (opts.signal?.aborted) { finish({ kind: 'cancelled' }); return; }
    opts.signal?.addEventListener('abort', onAbort, { once: true });

    try {
      child = spawnImpl(
        opts.openclawBin,
        [
          'gateway', 'call', 'plugin.approval.request',
          '--json', '--expect-final',
          '--params', JSON.stringify(opts.params),
          // The gateway's own call deadline sits a little past the card's
          // expiry so it can report it; ours (below) is the window itself.
          '--timeout', String(Math.floor(opts.windowMs) + 5_000),
        ],
        { stdio: ['ignore', 'pipe', 'ignore'] },
      );
    } catch {
      finish({ kind: 'card_failed', reason: 'spawn-failed' });
      return;
    }
    let out = '';
    child.stdout?.setEncoding('utf8');
    child.stdout?.on('data', (chunk: string) => {
      if (out.length < 256 * 1024) out += chunk;
    });
    child.on('error', () => finish({ kind: 'card_failed', reason: 'spawn-failed' }));
    child.on('close', (code) => {
      if (code !== 0) { finish({ kind: 'card_failed', reason: 'request-failed' }); return; }
      let decision: unknown;
      try { decision = (JSON.parse(out) as { decision?: unknown })?.decision; } catch {
        finish({ kind: 'card_failed', reason: 'unparseable-response' });
        return;
      }
      if (decision === 'allow-once') finish({ kind: 'approved' });
      else if (decision === 'deny') finish({ kind: 'denied' });
      else if (decision === null || decision === 'timeout' || decision === 'cancelled') finish({ kind: 'expired' });
      // 'allow-always' was never offered; honouring it would grant under a
      // label the owner never saw. Anything unknown runs nothing.
      else finish({ kind: 'card_failed', reason: 'unrecognised-decision' });
    });
    timer = setTimeout(() => finish({ kind: 'expired' }), Math.max(0, Math.floor(opts.windowMs)));
  });
}

// ── Copy ──────────────────────────────────────────────────────────────────

function seconds(ms: number): string {
  const s = Math.max(1, Math.round(ms / 1000));
  return s >= 120 ? `${Math.round(s / 60)} min` : `${s} s`;
}

/** What the agent is told when a held call ends without running. One
 *  sentence of fact, one of instruction. Never names a value from the input. */
export function heldRefusalReason(
  kind: 'denied' | 'expired' | 'cancelled' | 'card_failed' | 'open' | 'recently-denied' | 'recently-expired' | 'store-unavailable' | 'no-budget' | 'harness-unproven',
  ctx: { actionId: string; heldActionId?: string; windowMs?: number },
): string {
  const tail = 'Nothing ran. Do not work around this or retry it freehand; report it as not run (actionId '
    + `${ctx.heldActionId ?? ctx.actionId}).`;
  switch (kind) {
    case 'denied':
      return `HELD, then DENIED by the owner on the approval card. ${tail}`;
    case 'expired':
      return `HELD for ${seconds(ctx.windowMs ?? 0)} and the owner did not answer the approval card, so it expired. ${tail}`;
    case 'cancelled':
      // #853 review: a cancel can be the harness killing this hook on its
      // own timeout, after which the harness may have RUN the call (#884
      // C2). So never "Nothing ran" here.
      return 'HELD, then the hold was cancelled before the owner answered. ShieldCortex refused it, but if the harness '
        + 'ended this hook first the call may have run anyway: the outcome is UNKNOWN. Check before assuming it did not; '
        + `do not retry it freehand; report it as outcome unknown (actionId ${ctx.actionId}).`;
    case 'card_failed':
      return `HELD, but the approval card could not be raised or answered, so nobody could approve it. ${tail}`;
    case 'open':
      return `An identical call is already held under an open approval card (no second card is sent). ${tail}`;
    case 'recently-denied':
      return `The owner denied this exact call on its approval card in the last 10 minutes (no new card). ${tail}`;
    case 'recently-expired':
      return `The approval card for this exact call expired unanswered in the last 10 minutes (no new card). ${tail}`;
    case 'store-unavailable':
      return `It needed an approval card, but the held-action store could not be written, so it was not held. ${tail}`;
    case 'harness-unproven':
      return 'It needed an approval card, but this hook could not prove how long Claude Code lets it run (the Claude Code '
        + 'command line or a settings source could not be read), so it was not held: a hold the harness cuts short could run it. '
        + tail;
    case 'no-budget':
    default:
      return 'It needed an approval card, but this hook\'s timeout in settings.json is too short to hold it safely '
        + `(run \`shieldcortex setup\` or \`shieldcortex doctor\`). ${tail}`;
  }
}
