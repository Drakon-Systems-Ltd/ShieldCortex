/**
 * #331 — host-local DNP (denied_no_prompt_surface) digest.
 *
 * Volume control for loud terminal denials. Primary key is a time window on
 * THIS host. Payload / permission_mode never appear here — they must not
 * select silence (same class as #283/#287/#288).
 *
 * Contract:
 *  - Every DNP still writes denials.jsonl (caller responsibility).
 *  - At most one outbound notify per window (first event opens + notifies).
 *  - Later DNPs in the same window return `coalesced` so the hook skips send.
 *  - windowMs === 0 disables digest (legacy: every DNP notifies).
 *  - State lives under ~/.shieldcortex so concurrent hook processes share it.
 */
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { formatWorkLaneHintLines, suggestWorkLane, type WorkLaneHintInput } from './work-lane-hints.js';

export const DEFAULT_DNP_DIGEST_WINDOW_MS = 15 * 60 * 1000;
export const MIN_DNP_DIGEST_WINDOW_MS = 60 * 1000;
export const MAX_DNP_DIGEST_WINDOW_MS = 24 * 60 * 60 * 1000;
const MAX_ACTION_IDS = 5;
const MAX_SIGNAL_KEYS = 25;
const MAX_TOOL_KEYS = 15;

export interface DnpDigestEvent {
  actionId?: string;
  sessionId?: string;
  tool?: string;
  signals?: string[];
  severity?: string;
  atMs?: number;
}

export interface DnpDigestState {
  windowStartMs: number;
  windowMs: number;
  count: number;
  bySignal: Record<string, number>;
  byTool: Record<string, number>;
  lastActionIds: string[];
  lastSessionIds: string[];
  /** True once an outbound notify was attempted for this window. */
  notifiedForWindow: boolean;
}

export type DnpDigestDecision =
  | {
      action: 'notify';
      state: DnpDigestState;
      /** Human + structured summary for the outbound channel. */
      summary: DnpDigestSummary;
    }
  | {
      action: 'coalesce';
      state: DnpDigestState;
      summary: DnpDigestSummary;
    }
  | {
      /** Digest disabled (windowMs === 0) — caller sends per-event as before. */
      action: 'passthrough';
      state: null;
      summary: null;
    };

export interface DnpDigestSummary {
  count: number;
  windowMs: number;
  windowStartMs: number;
  bySignal: Record<string, number>;
  byTool: Record<string, number>;
  lastActionIds: string[];
  lastSessionIds: string[];
  coalescedAfterNotify: boolean;
}

export interface DnpDigestOptions {
  home?: string;
  windowMs?: number;
  nowMs?: number;
  /** Injected for tests. */
  statePath?: string;
}

function clampWindowMs(raw: unknown): number {
  if (raw === 0) return 0;
  if (typeof raw !== 'number' || !Number.isFinite(raw)) return DEFAULT_DNP_DIGEST_WINDOW_MS;
  if (raw < MIN_DNP_DIGEST_WINDOW_MS || raw > MAX_DNP_DIGEST_WINDOW_MS) {
    return DEFAULT_DNP_DIGEST_WINDOW_MS;
  }
  return Math.floor(raw);
}

export function normaliseDnpDigestWindowMs(raw: unknown): number {
  return clampWindowMs(raw);
}

function safeId(v: unknown, re: RegExp): string | undefined {
  const t = String(v ?? '').trim();
  return re.test(t) ? t : undefined;
}

function safeTool(v: unknown): string {
  const t = String(v ?? '').trim();
  if (!t || t.length > 64) return 'tool';
  if (!/^[A-Za-z][A-Za-z0-9._-]{0,63}$/.test(t)) return 'tool';
  return t;
}

function safeSignals(signals: unknown): string[] {
  if (!Array.isArray(signals)) return [];
  const out: string[] = [];
  for (const s of signals) {
    const t = String(s ?? '').trim();
    if (!t || t.length > 64) continue;
    if (!/^[a-z0-9][a-z0-9._-]{0,63}$/i.test(t)) continue;
    if (!out.includes(t)) out.push(t);
    if (out.length >= 10) break;
  }
  return out;
}

function emptyState(windowStartMs: number, windowMs: number): DnpDigestState {
  return {
    windowStartMs,
    windowMs,
    count: 0,
    bySignal: {},
    byTool: {},
    lastActionIds: [],
    lastSessionIds: [],
    notifiedForWindow: false,
  };
}

function bumpMap(map: Record<string, number>, key: string, maxKeys: number): void {
  if (map[key] !== undefined) {
    map[key] += 1;
    return;
  }
  if (Object.keys(map).length >= maxKeys) {
    map._other = (map._other ?? 0) + 1;
    return;
  }
  map[key] = 1;
}

function pushRing(list: string[], value: string | undefined, max: number): void {
  if (!value) return;
  if (list[list.length - 1] === value) return;
  list.push(value);
  while (list.length > max) list.shift();
}

export function defaultDnpDigestStatePath(home: string = os.homedir()): string {
  return path.join(home, '.shieldcortex', 'dnp-digest.json');
}

function readState(file: string): DnpDigestState | null {
  try {
    const raw = fs.readFileSync(file, 'utf8');
    const j = JSON.parse(raw) as Partial<DnpDigestState>;
    if (typeof j.windowStartMs !== 'number' || typeof j.windowMs !== 'number') return null;
    if (typeof j.count !== 'number' || j.count < 0) return null;
    return {
      windowStartMs: j.windowStartMs,
      windowMs: j.windowMs,
      count: j.count,
      bySignal: j.bySignal && typeof j.bySignal === 'object' ? j.bySignal as Record<string, number> : {},
      byTool: j.byTool && typeof j.byTool === 'object' ? j.byTool as Record<string, number> : {},
      lastActionIds: Array.isArray(j.lastActionIds) ? j.lastActionIds.map(String).slice(-MAX_ACTION_IDS) : [],
      lastSessionIds: Array.isArray(j.lastSessionIds) ? j.lastSessionIds.map(String).slice(-MAX_ACTION_IDS) : [],
      notifiedForWindow: j.notifiedForWindow === true,
    };
  } catch {
    return null;
  }
}

function writeStateAtomic(file: string, state: DnpDigestState): void {
  const dir = path.dirname(file);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const tmp = `${file}.${process.pid}.${Date.now()}.tmp`;
  fs.writeFileSync(tmp, `${JSON.stringify(state)}\n`, { encoding: 'utf8', mode: 0o600 });
  fs.renameSync(tmp, file);
}

function toSummary(state: DnpDigestState, coalescedAfterNotify: boolean): DnpDigestSummary {
  return {
    count: state.count,
    windowMs: state.windowMs,
    windowStartMs: state.windowStartMs,
    bySignal: { ...state.bySignal },
    byTool: { ...state.byTool },
    lastActionIds: [...state.lastActionIds],
    lastSessionIds: [...state.lastSessionIds],
    coalescedAfterNotify,
  };
}

/**
 * Record one DNP and decide whether the caller should send an outbound notify.
 * Synchronous + file-backed so one-shot hook processes share the window.
 */
export function recordDnpDigestEvent(
  event: DnpDigestEvent,
  opts: DnpDigestOptions = {},
): DnpDigestDecision {
  const windowMs = clampWindowMs(opts.windowMs ?? DEFAULT_DNP_DIGEST_WINDOW_MS);
  if (windowMs === 0) {
    return { action: 'passthrough', state: null, summary: null };
  }

  const nowMs = typeof opts.nowMs === 'number' && Number.isFinite(opts.nowMs) ? opts.nowMs : Date.now();
  const atMs = typeof event.atMs === 'number' && Number.isFinite(event.atMs) ? event.atMs : nowMs;
  const file = opts.statePath ?? defaultDnpDigestStatePath(opts.home);
  let state = readState(file);
  if (!state || state.windowMs !== windowMs || atMs - state.windowStartMs >= windowMs) {
    state = emptyState(atMs, windowMs);
  }

  state.count += 1;
  const tool = safeTool(event.tool);
  bumpMap(state.byTool, tool, MAX_TOOL_KEYS);
  for (const sig of safeSignals(event.signals)) {
    bumpMap(state.bySignal, sig, MAX_SIGNAL_KEYS);
  }
  pushRing(state.lastActionIds, safeId(event.actionId, /^(?:act|sc)-[a-f0-9]{16}$/), MAX_ACTION_IDS);
  pushRing(state.lastSessionIds, safeId(event.sessionId, /^sc-[a-f0-9]{16}$/), MAX_ACTION_IDS);

  if (!state.notifiedForWindow) {
    state.notifiedForWindow = true;
    writeStateAtomic(file, state);
    return { action: 'notify', state, summary: toSummary(state, false) };
  }

  writeStateAtomic(file, state);
  return { action: 'coalesce', state, summary: toSummary(state, true) };
}

/** Extra context for operator-facing digest copy (never raw command). */
export interface DnpDigestFormatOpts {
  /** Latest action id (for one-shot approve command). */
  actionId?: string;
  tool?: string;
  signals?: string[];
  cwd?: string | null;
  /** Whether a separate #310 Approve-once/Deny card was raised. */
  retryCardRaised?: boolean;
  /** Why the card was not raised (budget, no openclaw, off, …). */
  retryCardReason?: string;
  reviewedScriptPaths?: string[];
}

/** Operator-facing multi-line body. Never includes raw command. */
export function formatDnpDigestText(
  summary: DnpDigestSummary,
  opts: DnpDigestFormatOpts = {},
): string {
  const mins = Math.max(1, Math.round(summary.windowMs / 60_000));
  const topSignals = Object.entries(summary.bySignal)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6)
    .map(([k, v]) => `${k}×${v}`)
    .join(', ') || 'none';
  const topTools = Object.entries(summary.byTool)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 4)
    .map(([k, v]) => `${k}×${v}`)
    .join(', ') || 'none';
  const lastActs = summary.lastActionIds.slice(-3).join(', ') || 'none';
  const actionId = (opts.actionId && /^act-[0-9a-f]{8,}$/i.test(opts.actionId))
    ? opts.actionId
    : (summary.lastActionIds.filter((id) => /^act-[0-9a-f]/i.test(id)).slice(-1)[0] ?? '');

  const hintInput: WorkLaneHintInput = {
    signals: opts.signals ?? Object.keys(summary.bySignal),
    cwd: opts.cwd,
    tool: opts.tool,
    reviewedScriptPaths: opts.reviewedScriptPaths,
  };
  const lane = suggestWorkLane(hintInput);
  const laneLines = formatWorkLaneHintLines(lane);

  // Title: held + visibility — not "the product is broken"
  const lines = [
    'ShieldCortex — held (headless, no prompt)',
    '',
    `What:    ${summary.count} dangerous step(s) blocked in this ${mins}m window`,
    `Tools:   ${topTools}`,
    `Why:     ${topSignals}`,
    `Last:    ${lastActs}`,
  ];

  if (laneLines.length) {
    lines.push('', ...laneLines);
  }

  lines.push('');
  if (opts.retryCardRaised === true) {
    lines.push(
      'Retry:   A separate Approve once / Deny card was raised on OpenClaw.',
      '         Tap Approve once for a single scoped retry, or Deny to silence.',
    );
  } else if (opts.retryCardReason) {
    lines.push(
      `Retry:   No Approve card this time (${opts.retryCardReason}).`,
    );
  } else {
    lines.push('Retry:   No Approve card on this path — use the terminal command below.');
  }

  if (actionId) {
    lines.push(
      '',
      'One-shot from a real terminal on that host:',
      `  shieldcortex approve --denial ${actionId}`,
      'Then retry the same action once. Approve is not forever.',
    );
  } else {
    lines.push(
      '',
      'One-shot from a real terminal on that host:',
      '  shieldcortex approve --denial <actionId>',
    );
  }

  lines.push(
    '',
    summary.coalescedAfterNotify
      ? 'Note:    Coalesced into the open window (no extra page).'
      : 'Note:    First hold in this window; further holds are quiet (coalesced).',
    'Forensics: ~/.shieldcortex/denials.jsonl (command not included here).',
    'This message is visibility — not a tappable Approve surface.',
  );
  return lines.join('\n');
}
