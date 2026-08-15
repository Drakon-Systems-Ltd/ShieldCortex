/**
 * `shieldcortex allowlist` — the reviewed-script allowlist (#189).
 *
 * Usage:
 *   shieldcortex allowlist                       # list entries + drift status
 *   shieldcortex allowlist add <path> [--note "why"]
 *   shieldcortex allowlist remove <path>
 *   shieldcortex allowlist verify                # exit 1 if any entry drifted
 *   shieldcortex allowlist scan                  # #309 cron discovery + TTY batch review
 *
 * `add` pins a script by ABSOLUTE CANONICAL PATH + CONTENT HASH so the Action
 * Guard stops folding its source into the scan surface. This is the standing
 * trust the approval cards deliberately don't offer: a card's `allow-once`
 * spends itself, an allowlist entry survives until the FILE CHANGES — any
 * edit breaks the hash and the guard re-gates it silently.
 *
 * `add` and `remove` are TTY-gated exactly like `approve`/`deny` and for the
 * same #118 threat model: an agent shelling out must not be able to pin its
 * own payload as "reviewed". No env-var escape hatch. Listing and verifying
 * are harmless and stay scriptable.
 */

import { readFileSync, realpathSync, statSync } from 'node:fs';
import { isAbsolute, resolve as resolvePath } from 'node:path';
import { isInteractive } from './approve.js';
import {
  hashScriptSource,
  normaliseReviewedScripts,
  type ReviewedScriptEntry,
} from '../defence/iron-dome/reviewed-scripts.js';
import { getReviewedScriptsRaw, setReviewedScripts } from '../cloud/config.js';

const BOLD = '\x1b[1m';
const DIM = '\x1b[2m';
const GREEN = '\x1b[32m';
const YELLOW = '\x1b[33m';
const RED = '\x1b[31m';
const RESET = '\x1b[0m';

/** Matches the resolver's fold cap — a file the guard would refuse to fold
 *  cannot meaningfully be "exempt from folding". */
export const MAX_REVIEWABLE_BYTES = 262_144;

export interface AllowlistDeps {
  now?: number;
  interactive?: boolean;
  log?: (msg: string) => void;
  error?: (msg: string) => void;
  readEntries?: () => unknown[];
  writeEntries?: (entries: Array<Record<string, unknown>>) => void;
}

type DriftState = 'ok' | 'edited' | 'missing';

function driftOf(entry: ReviewedScriptEntry): DriftState {
  try {
    const content = readFileSync(entry.path, 'utf8');
    return hashScriptSource(content) === entry.sha256 ? 'ok' : 'edited';
  } catch {
    return 'missing';
  }
}

function renderDrift(state: DriftState): string {
  if (state === 'ok') return `${GREEN}ok${RESET}`;
  if (state === 'edited') return `${YELLOW}EDITED — re-gated, re-add after review${RESET}`;
  return `${RED}MISSING${RESET}`;
}

function renderList(entries: ReviewedScriptEntry[]): string {
  if (entries.length === 0) {
    return `${DIM}Reviewed-script allowlist is empty.\nPin a human-reviewed script with: shieldcortex allowlist add <path>${RESET}\n`;
  }
  const lines: string[] = [`${BOLD}Action Guard — reviewed scripts${RESET}\n`];
  for (const e of entries) {
    lines.push(`  ${BOLD}${e.path}${RESET}  ${renderDrift(driftOf(e))}`);
    lines.push(`     ${DIM}sha256 ${e.sha256.slice(0, 16)}…${e.addedAt ? ` · added ${new Date(e.addedAt).toISOString().slice(0, 10)}` : ''}${e.note ? ` · ${e.note}` : ''}${RESET}`);
    lines.push('');
  }
  lines.push(`${DIM}An edited file re-gates automatically; \`allowlist add\` it again once re-reviewed.${RESET}\n`);
  return lines.join('\n');
}

function requireHuman(deps: AllowlistDeps, err: (m: string) => void, verb: string): boolean {
  const interactive = deps.interactive ?? isInteractive();
  if (!interactive) {
    err(`shieldcortex allowlist ${verb} must be run by a human in an interactive terminal.`);
    err('Refusing: stdin/stdout are not TTYs, so this could be the agent pinning its own payload as "reviewed".');
    return false;
  }
  return true;
}

/** Serialise entries for config storage — plain records, no class baggage. */
function toRecords(entries: ReviewedScriptEntry[]): Array<Record<string, unknown>> {
  return entries.map((e) => ({
    path: e.path,
    sha256: e.sha256,
    ...(e.note ? { note: e.note } : {}),
    ...(e.addedAt ? { addedAt: e.addedAt } : {}),
  }));
}

export interface PinDeps {
  now?: number;
  readEntries?: () => unknown[];
  writeEntries?: (entries: Array<Record<string, unknown>>) => void;
}

export type PinResult = { ok: true; entry: ReviewedScriptEntry } | { ok: false; error: string };

/**
 * The ONE write path for pinning a script as reviewed — `allowlist add` and
 * the scan review flow (#309) both come through here, so canonicalisation,
 * the size cap, and replace-on-same-path can never drift apart. NOT TTY-gated
 * itself: every caller must gate on `isInteractive()` before invoking, the
 * same way `add` does.
 */
export function pinReviewedScript(target: string, note: string | undefined, deps: PinDeps = {}): PinResult {
  const now = deps.now ?? Date.now();
  const readEntries = deps.readEntries ?? getReviewedScriptsRaw;
  const writeEntries = deps.writeEntries ?? setReviewedScripts;

  let canonical: string;
  let content: string;
  try {
    canonical = realpathSync(isAbsolute(target) ? target : resolvePath(process.cwd(), target));
    const st = statSync(canonical);
    if (!st.isFile()) {
      return { ok: false, error: `Not a regular file: ${canonical}` };
    }
    if (st.size > MAX_REVIEWABLE_BYTES) {
      return { ok: false, error: `File exceeds the guard's 256KB fold cap — it is never folded, so there is nothing to exempt.` };
    }
    content = readFileSync(canonical, 'utf8');
  } catch (e) {
    return { ok: false, error: `Cannot read ${target}: ${e instanceof Error ? e.message : String(e)}` };
  }

  const sha256 = hashScriptSource(content);
  const entries = normaliseReviewedScripts(readEntries());
  const kept = entries.filter((e) => e.path !== canonical);
  const entry: ReviewedScriptEntry = { path: canonical, sha256, addedAt: now, ...(note ? { note } : {}) };
  try {
    writeEntries(toRecords([...kept, entry]));
  } catch (e) {
    return { ok: false, error: `Could not write the allowlist: ${e instanceof Error ? e.message : String(e)}` };
  }
  return { ok: true, entry };
}

export function runAllowlist(argv: string[], deps: AllowlistDeps = {}): number | Promise<number> {
  const now = deps.now ?? Date.now();
  const log = deps.log ?? ((m: string) => console.log(m));
  const err = deps.error ?? ((m: string) => console.error(m));
  const readEntries = deps.readEntries ?? getReviewedScriptsRaw;
  const writeEntries = deps.writeEntries ?? setReviewedScripts;

  const args = argv.filter((a) => a !== '--');
  const sub = args[0];

  // Scan (#309) dispatches before the entries read: it does its own read, and
  // the dynamic import keeps the module edge one-directional (scan imports
  // `pinReviewedScript` from here statically).
  if (sub === 'scan') {
    return import('./allowlist-scan.js').then((m) => m.runAllowlistScan(args.slice(1), deps));
  }

  const entries = normaliseReviewedScripts(readEntries());

  if (!sub || sub === 'list') {
    log(renderList(entries));
    return 0;
  }

  if (sub === 'verify') {
    let drifted = 0;
    for (const e of entries) {
      const state = driftOf(e);
      if (state !== 'ok') drifted += 1;
      log(`${state === 'ok' ? `${GREEN}✓${RESET}` : `${RED}✗${RESET}`} ${e.path}  ${renderDrift(state)}`);
    }
    if (entries.length === 0) log(`${DIM}Nothing to verify — allowlist is empty.${RESET}`);
    return drifted > 0 ? 1 : 0;
  }

  if (sub === 'add') {
    const noteIndex = args.findIndex((a) => a === '--note');
    let note: string | undefined;
    if (noteIndex >= 0) {
      note = args[noteIndex + 1];
      if (!note || note.startsWith('-')) {
        err('--note expects a short reason, e.g. --note "daily security sentry, reviewed 2026-08-09"');
        return 1;
      }
      args.splice(noteIndex, 2);
    }
    const target = args.slice(1).find((a) => !a.startsWith('-'));
    if (!target) {
      err('Usage: shieldcortex allowlist add <path> [--note "why this is trusted"]');
      return 1;
    }
    if (!requireHuman(deps, err, 'add')) return 1;

    const pin = pinReviewedScript(target, note, { now, readEntries, writeEntries });
    if (!pin.ok) {
      err(pin.error);
      return 1;
    }

    log(`${GREEN}✓${RESET} Pinned ${BOLD}${pin.entry.path}${RESET} as reviewed.`);
    log(`  sha256 ${pin.entry.sha256.slice(0, 16)}… — the guard stops folding this file's source.`);
    log(`${DIM}  You are vouching for this file's CONTENT. Any edit re-gates it; the command line`);
    log(`  that invokes it is still scanned in full. Remove with: shieldcortex allowlist remove <path>${RESET}`);
    return 0;
  }

  if (sub === 'remove') {
    const target = args.slice(1).find((a) => !a.startsWith('-'));
    if (!target) {
      err('Usage: shieldcortex allowlist remove <path>');
      return 1;
    }
    if (!requireHuman(deps, err, 'remove')) return 1;

    // Match by canonical path when the file still resolves; fall back to the
    // literal string so a MISSING entry can still be removed.
    let canonical = target;
    try {
      canonical = realpathSync(isAbsolute(target) ? target : resolvePath(process.cwd(), target));
    } catch {
      /* keep literal */
    }
    const kept = entries.filter((e) => e.path !== canonical && e.path !== target);
    if (kept.length === entries.length) {
      err(`No allowlist entry matches "${target}". Run \`shieldcortex allowlist\` to see what is pinned.`);
      return 1;
    }
    try {
      writeEntries(toRecords(kept));
    } catch (e) {
      err(`Could not write the allowlist: ${e instanceof Error ? e.message : String(e)}`);
      return 1;
    }
    log(`${GREEN}✓${RESET} Removed ${BOLD}${target}${RESET} — its source folds into the scan again.`);
    return 0;
  }

  err(`Unknown subcommand "${sub}". Usage: shieldcortex allowlist [list|add|remove|verify|scan]`);
  return 1;
}
