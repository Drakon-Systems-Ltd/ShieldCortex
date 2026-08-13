/**
 * `shieldcortex freeze|unfreeze|lease` — the operator side of the session
 * action lease (#227).
 *
 * freeze/unfreeze are TTY-GATED like `shieldcortex approve`, and for the same
 * reason with the same rule: THERE IS NO ENV-VAR ESCAPE HATCH — one would be
 * indistinguishable from the bypass this exists to prevent. The whole premise
 * of #227 is that an agent must not lift (or quietly pre-lift) a freeze that
 * binds it; the ledger is additionally guard-protected on the tool-call
 * surface (`touch-decisions-ledger`), so the only comfortable path to a lift
 * is a human at a real terminal.
 *
 * CAPABILITY HONESTY, stated not implied: a freeze binds tool calls on hosts
 * where an enforcement plane is actually in path. `freeze` prints exactly
 * which planes are live on THIS host and names what it cannot bind, because a
 * fleet-wide-looking freeze that silently doesn't bind a host is worse than
 * no freeze — the operator plans around protection they don't have.
 */

import fs from 'fs';
import os from 'os';
import path from 'path';

import {
  SCOPE_KEYWORDS,
  findFreeze,
  parseFreezeRecords,
  type LeaseScope,
} from '../defence/iron-dome/session-lease.js';
import {
  decisionsLedgerPath,
  listLeases,
  resolveStateDir,
} from '../defence/iron-dome/session-lease-store.js';

export interface FreezeStreams {
  stdin?: { isTTY?: boolean };
  stdout?: { isTTY?: boolean };
  log?: (line: string) => void;
  error?: (line: string) => void;
}

function isInteractive(streams?: FreezeStreams): boolean {
  const stdin = streams?.stdin ?? process.stdin;
  const stdout = streams?.stdout ?? process.stdout;
  return Boolean(stdin?.isTTY && stdout?.isTTY);
}

const SCOPES = Object.keys(SCOPE_KEYWORDS) as LeaseScope[];

function isLeaseScope(value: string): value is LeaseScope {
  return (SCOPES as string[]).includes(value);
}

/** Which enforcement planes are live on THIS host. Three-state per plane —
 *  present / absent / unreadable — never "unknown means fine" (#225). */
export function describeLocalPlanes(home: string = os.homedir()): string[] {
  const lines: string[] = [];

  // Claude Code plane: the PreToolUse hook entry in ~/.claude/settings.json.
  try {
    const settings = fs.readFileSync(path.join(home, '.claude', 'settings.json'), 'utf-8');
    lines.push(settings.includes('shieldcortex hook pre-tool')
      ? '  claude-code hook:      BOUND (PreToolUse wired in ~/.claude/settings.json)'
      : '  claude-code hook:      NOT BOUND — PreToolUse entry absent; run `shieldcortex setup`');
  } catch {
    lines.push('  claude-code hook:      UNKNOWN — cannot read ~/.claude/settings.json');
  }

  // OpenClaw plane: the realtime plugin registration.
  try {
    const installs = fs.readFileSync(path.join(home, '.openclaw', 'plugins', 'installs.json'), 'utf-8');
    lines.push(installs.includes('shieldcortex-realtime')
      ? '  openclaw interceptor:  BOUND (plugin registered; binds when the gateway loads it)'
      : '  openclaw interceptor:  NOT BOUND — plugin not registered on this host');
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    lines.push(code === 'ENOENT' || code === 'ENOTDIR'
      ? '  openclaw interceptor:  NOT BOUND — no OpenClaw plugin registry on this host'
      : '  openclaw interceptor:  UNKNOWN — plugin registry exists but cannot be read');
  }

  lines.push('  NOT bound anywhere:    direct shell outside tool calls; hosts without the guard;');
  lines.push('                         installs older than this feature. A freeze binds tool calls');
  lines.push('                         where a plane above says BOUND — nothing else. Verify other');
  lines.push('                         hosts with `shieldcortex lease status` on each.');
  return lines;
}

export interface FreezeCommandOptions {
  dir?: string;
  home?: string;
  streams?: FreezeStreams;
  user?: string;
}

export function runFreezeCommand(args: string[], opts: FreezeCommandOptions = {}): number {
  const log = opts.streams?.log ?? console.log;
  const error = opts.streams?.error ?? console.error;
  const dir = opts.dir ?? resolveStateDir();

  if (!isInteractive(opts.streams)) {
    error('freeze is operator-only: it needs a real terminal (TTY). There is no');
    error('env-var escape hatch — one would be indistinguishable from the bypass');
    error('this command exists to prevent.');
    return 1;
  }

  const scope = args[0];
  const reasonIdx = args.indexOf('--reason');
  const reason = reasonIdx >= 0 ? args.slice(reasonIdx + 1).join(' ').trim() : '';
  if (!scope || !isLeaseScope(scope)) {
    error(`Usage: shieldcortex freeze <${SCOPES.join('|')}> --reason "<why, and what lifts it>"`);
    return 1;
  }
  if (!reason) {
    error('A freeze without a stated reason gets routed around. --reason is required.');
    return 1;
  }

  const ledgerPath = decisionsLedgerPath(dir);
  const existing = (() => {
    try { return fs.readFileSync(ledgerPath, 'utf-8'); } catch { return ''; }
  })();
  if (findFreeze(existing, scope)) {
    error(`${scope} is already frozen. Lift it first (shieldcortex unfreeze ${scope}) if you want to re-word it.`);
    return 1;
  }

  const user = opts.user ?? process.env.USER ?? process.env.LOGNAME ?? 'operator';
  const record =
    `| FROZEN | ${scope} | ${new Date().toISOString()} | by ${user} | ${reason} ` +
    `| keywords: ${SCOPE_KEYWORDS[scope].join(', ')} |`;
  fs.mkdirSync(path.dirname(ledgerPath), { recursive: true, mode: 0o700 });
  fs.appendFileSync(ledgerPath, `${existing.length > 0 && !existing.endsWith('\n\n') ? '\n' : ''}${record}\n\n`, { mode: 0o600 });

  log(`FROZEN: ${scope}`);
  log(`  reason: ${reason}`);
  log('');
  log('This freeze binds, on THIS host:');
  for (const line of describeLocalPlanes(opts.home)) log(line);
  log('');
  log(`Lift with: shieldcortex unfreeze ${scope}   (TTY required)`);
  return 0;
}

export function runUnfreezeCommand(args: string[], opts: FreezeCommandOptions = {}): number {
  const log = opts.streams?.log ?? console.log;
  const error = opts.streams?.error ?? console.error;
  const dir = opts.dir ?? resolveStateDir();

  if (!isInteractive(opts.streams)) {
    error('unfreeze is operator-only: it needs a real terminal (TTY). An agent must');
    error('not lift a freeze that binds it — that is the entire point of the freeze.');
    return 1;
  }

  const scope = args[0];
  if (!scope || !isLeaseScope(scope)) {
    error(`Usage: shieldcortex unfreeze <${SCOPES.join('|')}>`);
    return 1;
  }

  const ledgerPath = decisionsLedgerPath(dir);
  let ledger: string;
  try {
    ledger = fs.readFileSync(ledgerPath, 'utf-8');
  } catch {
    error('No decisions ledger on this host — nothing is frozen here.');
    return 1;
  }

  const frozen = findFreeze(ledger, scope);
  if (!frozen) {
    error(`${scope} is not frozen on this host.`);
    return 1;
  }

  const user = opts.user ?? process.env.USER ?? process.env.LOGNAME ?? 'operator';
  // A lift is a REWRITE of the record (FROZEN marker → LIFTED marker), never a
  // deletion: the ledger keeps its history, and the parser's rule — a record
  // freezes iff it carries the `| FROZEN |` marker — makes the lift effective
  // exactly when the marker goes. The marker is matched WHITESPACE-TOLERANTLY
  // (`|  FROZEN  |`, tabs) because the ledger is hand-editable; a lift that
  // silently no-ops on a double-spaced marker while REPORTING success (the
  // old `block.replace('| FROZEN |', …)` on un-normalised text) is worse than
  // an error. We re-detect after rewriting and refuse to claim success unless
  // the freeze is genuinely gone.
  const FROZEN_MARKER = /\|\s*FROZEN\s*\|/i;
  const lifted = ledger
    .split(/\n\s*\n/)
    .map((block) => {
      const rejoined = block.split(/\s+/).join(' ').trim();
      if (rejoined === frozen && FROZEN_MARKER.test(block)) {
        return `${block.replace(FROZEN_MARKER, '| LIFTED |')} | lifted ${new Date().toISOString()} by ${user} |`;
      }
      return block;
    })
    .join('\n\n');

  if (findFreeze(lifted, scope)) {
    error(`Could not lift ${scope} — the record's FROZEN marker is malformed. Edit ${ledgerPath} by hand.`);
    return 1;
  }
  fs.writeFileSync(ledgerPath, lifted, { mode: 0o600 });

  log(`LIFTED: ${scope}`);
  log(`  was: ${frozen.slice(0, 160)}`);
  return 0;
}

export function runLeaseStatusCommand(opts: FreezeCommandOptions = {}): number {
  const log = opts.streams?.log ?? console.log;
  const dir = opts.dir ?? resolveStateDir();

  log('Session action lease — this host');
  log('');
  log('Freezes (DECISIONS.md):');
  let ledger: string | null = null;
  try {
    ledger = fs.readFileSync(decisionsLedgerPath(dir), 'utf-8');
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    ledger = code === 'ENOENT' || code === 'ENOTDIR' ? '' : null;
  }
  if (ledger == null) {
    log('  LEDGER UNREADABLE — scoped actions are refusing (fail closed). Fix the file permissions.');
  } else {
    const records = parseFreezeRecords(ledger);
    if (records.length === 0) log('  none');
    for (const r of records) log(`  ${r.slice(0, 160)}`);
  }

  log('');
  log('Leases:');
  const leases = listLeases(dir);
  const entries = Object.entries(leases).filter(([, v]) => v);
  if (entries.length === 0) log('  none held');
  for (const [scope, rec] of entries) {
    const expired = rec!.expiresAtMs != null && Date.now() > rec!.expiresAtMs;
    log(`  ${scope}: ${rec!.holder}${rec!.pid ? ` (pid ${rec!.pid})` : ''}${expired ? ' [EXPIRED]' : ''}`);
  }

  log('');
  log('Enforcement planes on this host:');
  for (const line of describeLocalPlanes(opts.home)) log(line);
  return 0;
}
