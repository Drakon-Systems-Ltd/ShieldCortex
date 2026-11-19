/**
 * The one place that builds — and guards — the `openclaw plugins install`
 * command for the realtime plugin.
 *
 * OpenClaw 2026.11.5 resolves a spec with no source prefix (`@scope/name`,
 * `@scope/name@1.2.3`, `@scope/name@latest`) on ClawHub and no longer falls
 * back to npm. ClawHub carries an old one-off listing of this package
 * (5.17.3), so a bare `@latest` install there silently put a stale plugin
 * behind a current CLI. `npm:<spec>` forces npm; an exact version means a
 * stale registry cannot swap in anything else. The plugin ships in lockstep
 * with the CLI, so the version is the one this CLI expects.
 *
 * The rules every automated install follows (#1109 review):
 *
 *  1. EXACT PIN ONLY. `realtimePluginInstallArgs` refuses anything that is not
 *     an exact semver version. There is no automated `@latest` install, and no
 *     floating bare retry. Only a printed hint for a human may say `@latest`,
 *     and only when this CLI cannot read its own version.
 *  2. ONE BARE RETRY PER OPERATION, ONLY ON THE LEGACY REFUSAL. OpenClaw hosts
 *     older than the `npm:` prefix (it landed in 2026.4.26) refuse it before
 *     installing anything, printing `unsupported npm spec: protocol specs are
 *     not allowed` on stderr. That exact line on stderr, with no other failure
 *     marker anywhere in the output, earns ONE retry with the bare spec at the
 *     same exact version — one per top-level operation (an `update` run, an
 *     `openclaw install`, a reconcile run across all its passes), tracked by a
 *     `BareRetryBudget`. Anything else (integrity, trust, policy, consent,
 *     secret reference, network, 404, or output that merely quotes the phrase)
 *     is surfaced as is. Nothing ever falls back to `clawhub:`.
 *  3. NEVER CLOBBER A DELIBERATE OR NEWER INSTALL. Before a forced install,
 *     `assessRealtimeReplacement` keeps a linked/path install and any install
 *     newer than the pin, and the caller prints the command instead.
 *  4. VERIFY AGAINST THE PIN. `landedVersionVerdict` compares what is on disk
 *     after the install with the pin captured BEFORE it; older and newer are
 *     both "not the pinned build".
 *
 * `--force` is always passed: since OpenClaw 2026.7 a non-ClawHub source
 * installed without a terminal is cancelled unless `--force` confirms it, and
 * `--force` also overwrites an existing npm/ClawHub install (rule 3 is what
 * keeps that from reaching a linked or newer one).
 */
import fs from 'fs';
import path from 'path';
import semver from 'semver';

export const REALTIME_PLUGIN_PACKAGE = '@drakon-systems/shieldcortex-realtime';
const REALTIME_PLUGIN_ID = 'shieldcortex-realtime';

/** `npm:` forces npm; `bare` is only for hosts that predate that prefix. */
export type RealtimePluginSpecSource = 'npm' | 'bare';

/** The exact version when `version` is one (valid semver, no range, no tag), else null. */
export function exactPluginPin(version: unknown): string | null {
  if (typeof version !== 'string') return null;
  return semver.valid(version.trim());
}

/** `npm:@drakon-systems/shieldcortex-realtime@<pin>` — `pin` must be exact. */
export function realtimePluginInstallSpec(pin: string, source: RealtimePluginSpecSource = 'npm'): string {
  const exact = exactPluginPin(pin);
  if (!exact) {
    // Fail closed: an automated install without an exact pin is the floating
    // install this module exists to prevent. Callers check first.
    throw new TypeError(`realtime plugin install needs an exact version, got ${JSON.stringify(pin)}`);
  }
  const spec = `${REALTIME_PLUGIN_PACKAGE}@${exact}`;
  return source === 'npm' ? `npm:${spec}` : spec;
}

/** argv for the `openclaw` binary. `pin` must be exact (throws otherwise). */
export function realtimePluginInstallArgs(pin: string, source: RealtimePluginSpecSource = 'npm'): string[] {
  return ['plugins', 'install', '--force', realtimePluginInstallSpec(pin, source)];
}

/**
 * The copy-paste command an operator runs. Exact when the version is known;
 * `npm:…@latest` only when it is not (a human runs it, and it is still npm).
 */
export function realtimePluginInstallCommand(
  version: string | null | undefined,
  source: RealtimePluginSpecSource = 'npm',
): string {
  const pin = exactPluginPin(version);
  if (pin) return `openclaw ${realtimePluginInstallArgs(pin, source).join(' ')}`;
  return `openclaw plugins install --force ${source === 'npm' ? 'npm:' : ''}${REALTIME_PLUGIN_PACKAGE}@latest`;
}

// ── The legacy-protocol refusal ─────────────────────────────────────────────

/** OpenClaw <= 2026.4.25, src/infra/npm-registry-spec.ts, for any spec containing `:`. */
export const LEGACY_NPM_PROTOCOL_REFUSAL = 'unsupported npm spec: protocol specs are not allowed';

// eslint-disable-next-line no-control-regex
const ANSI = /\u001b\[[0-9;]*[A-Za-z]/g;

/**
 * The line shapes that refusal takes on stderr: the plugin installer's own
 * line, optionally `Error:`-prefixed, and the hook-pack fallback's echo of the
 * same validator (`Also not a valid hook pack: <same text>`). Anchored: the
 * line is the refusal, nothing more.
 */
const REFUSAL_LINE = /^(?:error:\s*)?unsupported npm spec: protocol specs are not allowed\.?$/i;
const HOOK_PACK_ECHO_LINE = /^also not a valid hook pack:\s*unsupported npm spec: protocol specs are not allowed\.?$/i;

/**
 * Any of these anywhere in the child's output means something other than (or
 * as well as) the legacy refusal happened — a mixed or ambiguous failure,
 * which is surfaced, never retried.
 */
const OTHER_FAILURE_MARKER = new RegExp([
  'integrity', 'checksum', 'trust', 'provenance', 'signature',
  'polic(?:y|ies)', 'consent', 'cancell?ed', 'denied', 'forbidden', 'blocked', 'refus',
  'secret ?ref', 'secret reference', 'gateway\\.auth',
  'network', 'econn', 'enotfound', 'eai_again', 'etimedout', 'socket', 'fetch failed', 'timed? ?out',
  '\\b40[0-9]\\b', 'e404', 'not found', 'unauthori[sz]ed',
  'config is invalid', 'already exists', 'clawhub',
].join('|'), 'i');

function lines(text: string | null | undefined): string[] {
  return (text ?? '').replace(ANSI, '').split(/\r?\n/).map((l) => l.trim()).filter((l) => l.length > 0);
}

/**
 * True only when OpenClaw refused the `npm:` source itself because it predates
 * the prefix: the refusal is an anchored line on STDERR (never stdout, never a
 * report this process wrote), and no other line — on either stream — carries
 * a failure marker or a different `unsupported npm spec` reason.
 */
export function isLegacyNpmProtocolRefusal(output: { stderr?: string | null; stdout?: string | null }): boolean {
  const err = lines(output.stderr);
  if (!err.some((l) => REFUSAL_LINE.test(l))) return false;
  for (const l of err) {
    if (REFUSAL_LINE.test(l) || HOOK_PACK_ECHO_LINE.test(l)) continue;
    if (/unsupported npm spec/i.test(l) || OTHER_FAILURE_MARKER.test(l)) return false;
  }
  for (const l of lines(output.stdout)) {
    if (/unsupported npm spec/i.test(l) || OTHER_FAILURE_MARKER.test(l)) return false;
  }
  return true;
}

/**
 * At most ONE bare-spec run per top-level operation. Create one per `update`
 * run, per `openclaw install`, per reconcile run (shared by every pass), and
 * hand the same object to every install that operation makes.
 */
export class BareRetryBudget {
  private used = false;
  /** Spend the one bare run; false when it is already spent. */
  take(): boolean {
    if (this.used) return false;
    this.used = true;
    return true;
  }
  get spent(): boolean {
    return this.used;
  }
}

/**
 * The same install with the bare spec, for a host that rejected `npm:`; null
 * when `args` carry no `npm:` realtime spec at an exact version.
 */
export function bareFallbackArgs(args: readonly string[]): string[] | null {
  const prefix = `npm:${REALTIME_PLUGIN_PACKAGE}@`;
  const i = args.findIndex((a) => a.startsWith(prefix));
  if (i < 0) return null;
  if (!exactPluginPin(args[i].slice(prefix.length))) return null;
  const out = [...args];
  out[i] = args[i].slice('npm:'.length);
  return out;
}

/**
 * Run a synchronous install, retrying ONCE with the bare spec when — and only
 * when — the host refused the `npm:` source (see `isLegacyNpmProtocolRefusal`)
 * and the operation's budget still has its one bare run. `failureOf` returns
 * the failed child's stderr/stdout, or null when it succeeded.
 */
export function runWithNpmSourceFallbackSync<R>(
  args: readonly string[],
  run: (args: string[]) => R,
  failureOf: (r: R) => { stderr?: string | null; stdout?: string | null } | null,
  budget: BareRetryBudget,
): { result: R; args: string[]; fellBack: boolean } {
  const first = run([...args]);
  const failure = failureOf(first);
  const bare = failure !== null && isLegacyNpmProtocolRefusal(failure) ? bareFallbackArgs(args) : null;
  if (!bare || !budget.take()) return { result: first, args: [...args], fellBack: false };
  return { result: run(bare), args: bare, fellBack: true };
}

// ── Never clobber a deliberate or newer install ─────────────────────────────

/** What is installed now, as far as the replacement decision needs to know. */
export interface ExistingRealtimeInstall {
  /** The installed version, or null when none is installed / readable. */
  version: string | null;
  /** Where a linked/path install lives (load.paths entry or a `path` install record), else null. */
  linkedAt: string | null;
}

export type ReplacementDecision =
  | { replace: true }
  | { replace: false; why: 'linked'; summary: string }
  | { replace: false; why: 'newer'; summary: string };

/**
 * May a forced install of `pin` replace what is there? Not a linked/path
 * install (someone pointed OpenClaw at a checkout on purpose), and not an
 * install newer than the pin (that would be a downgrade).
 */
export function assessRealtimeReplacement(existing: ExistingRealtimeInstall, pin: string): ReplacementDecision {
  const at = existing.version ? ` (v${existing.version})` : '';
  if (existing.linkedAt) {
    return { replace: false, why: 'linked', summary: `left alone — the plugin is a linked install${at} at ${existing.linkedAt}` };
  }
  const v = exactPluginPin(existing.version);
  if (v && semver.gt(v, pin)) {
    return { replace: false, why: 'newer', summary: `left alone — the plugin is on v${v}, newer than this CLI (v${pin})` };
  }
  return { replace: true };
}

/**
 * Where a linked/path realtime install is registered, from OpenClaw's own
 * files under `home`: a `plugins.load.paths` entry naming the plugin, or an
 * install record whose source is a local path (`openclaw plugins install
 * --link` / `<dir>` record `source: "path"`). Null when neither exists or the
 * files cannot be read — an unreadable file is not evidence of a link.
 */
export function readLinkedRealtimeInstall(home: string): string | null {
  const readJson = (p: string): Record<string, unknown> | null => {
    try {
      const v = JSON.parse(fs.readFileSync(p, 'utf-8')) as unknown;
      return v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
    } catch {
      return null;
    }
  };
  const isPathRecord = (rec: unknown): string | null => {
    if (!rec || typeof rec !== 'object') return null;
    const r = rec as { source?: unknown; sourcePath?: unknown; installPath?: unknown };
    if (r.source !== 'path') return null;
    const where = typeof r.sourcePath === 'string' ? r.sourcePath : typeof r.installPath === 'string' ? r.installPath : 'a local path';
    return where;
  };
  const config = readJson(path.join(home, '.openclaw', 'openclaw.json'));
  const plugins = (config?.plugins ?? null) as { load?: { paths?: unknown }; installs?: Record<string, unknown> } | null;
  const loadPaths = Array.isArray(plugins?.load?.paths) ? plugins!.load!.paths as unknown[] : [];
  const linked = loadPaths.find((p) => typeof p === 'string' && p.includes(REALTIME_PLUGIN_ID));
  if (typeof linked === 'string') return linked;
  const legacyRecord = isPathRecord(plugins?.installs?.[REALTIME_PLUGIN_ID]);
  if (legacyRecord) return legacyRecord;
  const registry = readJson(path.join(home, '.openclaw', 'plugins', 'installs.json')) as
    { installRecords?: Record<string, unknown> } | null;
  return isPathRecord(registry?.installRecords?.[REALTIME_PLUGIN_ID]);
}

// ── Verify what landed ──────────────────────────────────────────────────────

export type LandedVerdict =
  | { ok: true; version: string }
  | { ok: false; version: string | null; summary: string };

/**
 * Compare what is on disk after an install with the pin captured BEFORE it.
 * Only the pinned build is success; older, newer and unreadable are not.
 */
export function landedVersionVerdict(landed: string | null | undefined, pin: string): LandedVerdict {
  const v = exactPluginPin(landed);
  if (!v) return { ok: false, version: null, summary: `installed version unreadable — expected v${pin}` };
  if (semver.eq(v, pin)) return { ok: true, version: v };
  return { ok: false, version: v, summary: `the plugin is on v${v}, CLI is v${pin}` };
}
