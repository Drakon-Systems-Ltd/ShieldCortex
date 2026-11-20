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
 *     not allowed` on stderr. The retry is an ALLOWLIST: the child exited on
 *     its own (no timeout, no signal) with a non-zero code, and every
 *     non-blank stderr line is one of that refusal's known forms. Any other
 *     line on stderr, or any stdout beyond the one `Downloading npm:…` line
 *     OpenClaw logs on that path, means no retry. That earns
 *     ONE retry with the bare spec at the same exact version — one per
 *     top-level operation (an `update` run, an `openclaw install`, a reconcile
 *     run across all its passes), tracked by a `BareRetryBudget`. Nothing ever
 *     falls back to `clawhub:`.
 *  3. NEVER CLOBBER A DELIBERATE OR NEWER INSTALL. Before a forced install,
 *     `assessRealtimeReplacement` keeps a linked/path install, any install
 *     newer than the pin, and — when OpenClaw's records could not be read —
 *     whatever is there; the caller prints the command instead.
 *  4. VERIFY AGAINST THE PIN. `landedVersionVerdict` compares the copy OpenClaw
 *     SELECTED (see `readSelectedRealtimeInstall`) with the pin captured
 *     BEFORE the install; older, newer and "could not tell which copy" are all
 *     "not the pinned build".
 *
 * `--force` is always passed: since OpenClaw 2026.7 a non-ClawHub source
 * installed without a terminal is cancelled unless `--force` confirms it, and
 * `--force` also overwrites an existing npm/ClawHub install (rule 3 is what
 * keeps that from reaching a linked or newer one).
 */
import semver from 'semver';

export const REALTIME_PLUGIN_PACKAGE = '@drakon-systems/shieldcortex-realtime';

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
 * The ONLY stderr lines a legacy refusal is made of (OpenClaw <= 2026.4.25,
 * src/cli/plugins-install-command.ts + plugins-command-helpers.ts at
 * cb9955dd5c~1): the npm installer's error through `defaultRuntime.error`
 * (console.error), followed — because the plugin installer failed — by
 * `formatPluginInstallWithHookFallbackError`'s second line, `Also not a valid
 * hook pack: <the hook-pack installer's error>`, which is the same validator's
 * text. An optional `Error:` prefix covers a runtime that prints the Error
 * object. Anchored: the line is the refusal and nothing more. OpenClaw's
 * banner is written to stdout and only on a TTY (src/cli/banner.ts), so there
 * is no banner line to allow on stderr.
 */
const ALLOWED_REFUSAL_LINES: readonly RegExp[] = [
  /^(?:error:\s*)?unsupported npm spec: protocol specs are not allowed\.?$/i,
  /^also not a valid hook pack:\s*unsupported npm spec: protocol specs are not allowed\.?$/i,
];

/**
 * The ONLY stdout a legacy refusal produces (#1109 round 3 — an allowlist,
 * not a list of failure words). At cb9955dd5c~1 the npm installer
 * (src/plugins/install.ts `installPluginFromNpmSpec`) validates the spec
 * BEFORE it logs, so it prints nothing; the hook-pack fallback that runs next
 * (src/cli/plugins-install-command.ts `tryInstallHookPackFromNpmSpec` →
 * src/hooks/install.ts:426 `installHooksFromNpmSpec`) logs
 * `Downloading ${spec.trim()}…` through `createHookPackInstallLogger`
 * (`defaultRuntime.log`, i.e. console.log — stdout) and only then fails the
 * same validation. Nothing else on that path writes to stdout. So stdout is
 * empty (a runtime that suppresses logs) or exactly that one line for this
 * package's `npm:` spec at an exact version; any other line means something
 * else happened, and there is no retry.
 */
const ALLOWED_REFUSAL_STDOUT_LINE = new RegExp(
  '^Downloading npm:' + REALTIME_PLUGIN_PACKAGE.replace(/[.*+?^$()|[\]{}\\/]/g, '\\$&') + '@' +
  '(?:0|[1-9]\\d*)\\.(?:0|[1-9]\\d*)\\.(?:0|[1-9]\\d*)(?:-[0-9A-Za-z.-]+)?(?:\\+[0-9A-Za-z.-]+)?\u2026$',
);

function lines(text: string | null | undefined): string[] {
  return (text ?? '').replace(ANSI, '').split(/\r?\n/).map((l) => l.trim()).filter((l) => l.length > 0);
}

/** How the install child ended, as far as the retry decision needs to know. */
export interface InstallChildOutcome {
  stderr?: string | null;
  stdout?: string | null;
  /** The child's own exit code; null when it did not exit normally. */
  exitCode: number | null;
  /** Killed by this process's deadline. */
  timedOut?: boolean;
  /** Killed by a signal. */
  signal?: string | null;
}

/**
 * True only when OpenClaw refused the `npm:` source itself because it predates
 * the prefix: the child exited normally with a non-zero code (not timed out,
 * not signalled), its stderr carries the anchored refusal line, EVERY
 * non-blank stderr line is one of the allowlisted refusal forms, and stdout
 * is empty or the one allowlisted `Downloading npm:…` line. Anything
 * unrecognised, on either stream, is not a legacy refusal.
 */
export function isLegacyNpmProtocolRefusal(outcome: InstallChildOutcome): boolean {
  if (outcome.timedOut || outcome.signal) return false;
  if (typeof outcome.exitCode !== 'number' || outcome.exitCode === 0) return false;
  const err = lines(outcome.stderr);
  if (!err.some((l) => ALLOWED_REFUSAL_LINES[0].test(l))) return false;
  if (!err.every((l) => ALLOWED_REFUSAL_LINES.some((re) => re.test(l)))) return false;
  const out = lines(outcome.stdout);
  return out.length === 0 || (out.length === 1 && ALLOWED_REFUSAL_STDOUT_LINE.test(out[0]));
}

/**
 * Why the `npm:` package install did not happen, for one decision only (#1109
 * round 2): may `shieldcortex openclaw install` fall back to its development
 * installs (`--link` to the checkout's plugins/openclaw, or a local copy)?
 *
 *  - `refused`: OpenClaw or npm said no on purpose — integrity, trust,
 *    provenance, signature, policy, consent, a cancelled install, a security
 *    scan, an invalid or missing config. Never worked around.
 *  - `unavailable`: the package could not be had here — offline/DNS/connection
 *    failures, 404/no matching version, or a host older than the `npm:` prefix
 *    (its refusal). The development fallbacks are for exactly this.
 *  - `other`: anything else, including a timeout (the child may still land,
 *    #604) or a signal. Treated like `refused`: nothing is worked around.
 *
 * A refusal word anywhere outranks an unavailability word.
 */
export type NpmInstallFailureClass = 'refused' | 'unavailable' | 'other';

const REFUSED_MARKER = new RegExp([
  'integrity', 'checksum', 'trust', 'provenance', 'signature', 'polic(?:y|ies)', 'consent',
  'cancell?ed', 'denied', 'forbidden', 'blocked', 'refus', 'security', 'dangerous', 'unsafe',
  'secret ?ref', 'gateway\\.auth', 'config is invalid', 'invalid config', 'no(?: openclaw)? config',
  'config(?:uration)?[^\\r\\n]{0,80}(?:not found|does not exist)', 'openclaw\\.json',
  'unauthori[sz]ed', '\\b40[13]\\b', 'eacces', 'eperm',
].join('|'), 'i');

const UNAVAILABLE_MARKER = new RegExp([
  'enotfound', 'eai_again', 'econnrefused', 'econnreset', 'enetunreach', 'ehostunreach', 'etimedout',
  'fetch failed', 'network', 'offline', 'getaddrinfo', 'socket hang up',
  'e404', '\\b404\\b', 'not found', 'notarget', 'no matching version', 'is not in this registry',
].join('|'), 'i');

export function classifyNpmInstallFailure(outcome: InstallChildOutcome): NpmInstallFailureClass {
  if (outcome.timedOut || outcome.signal || typeof outcome.exitCode !== 'number') return 'other';
  if (isLegacyNpmProtocolRefusal(outcome)) return 'unavailable';
  const all = [...lines(outcome.stderr), ...lines(outcome.stdout)];
  if (all.some((l) => REFUSED_MARKER.test(l))) return 'refused';
  if (all.some((l) => UNAVAILABLE_MARKER.test(l))) return 'unavailable';
  return 'other';
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
 * how the failed child ended (streams, exit code, timeout/signal), or null
 * when it succeeded.
 */
export function runWithNpmSourceFallbackSync<R>(
  args: readonly string[],
  run: (args: string[]) => R,
  failureOf: (r: R) => InstallChildOutcome | null,
  budget: BareRetryBudget,
): { result: R; args: string[]; fellBack: boolean } {
  const first = run([...args]);
  const failure = failureOf(first);
  const bare = failure !== null && isLegacyNpmProtocolRefusal(failure) ? bareFallbackArgs(args) : null;
  if (!bare || !budget.take()) return { result: first, args: [...args], fellBack: false };
  return { result: run(bare), args: bare, fellBack: true };
}

// ── Is the pin on npm? ─────────────────────────────────────────────────────

/**
 * Strictly parse `npm view <pkg>@<spec> version --json`: empty output (no such
 * version), one JSON string, or a JSON array of strings. Anything else —
 * including text around the JSON — is unparseable, never "published".
 */
export function parseNpmViewVersion(stdout: string): { state: 'versions'; versions: string[] } | { state: 'unparseable' } {
  const text = stdout.trim();
  if (text === '') return { state: 'versions', versions: [] };
  let v: unknown;
  try {
    v = JSON.parse(text);
  } catch {
    return { state: 'unparseable' };
  }
  if (typeof v === 'string') return { state: 'versions', versions: [v] };
  if (Array.isArray(v) && v.every((x) => typeof x === 'string')) return { state: 'versions', versions: v as string[] };
  return { state: 'unparseable' };
}

// ── Never clobber a deliberate or newer install ─────────────────────────────

/** What is installed now, as far as the replacement decision needs to know. */
export interface ExistingRealtimeInstall {
  /**
   * The copy OpenClaw SELECTED (`readSelectedRealtimeInstall`, #1109 round 3)
   * — never the highest version anywhere on disk: a stale npm project must not
   * hide a newer copy OpenClaw actually loads. `unknown` when the records
   * could not be read or disagree.
   */
  selected:
    | { state: 'selected'; version: string }
    | { state: 'none' }
    | { state: 'unknown'; why: string };
  /**
   * Whether it is a linked/path install (`readLinkedRealtimeInstall`):
   * `unknown` when OpenClaw's records could not be read.
   */
  linked:
    | { state: 'linked'; at: string }
    | { state: 'absent' }
    | { state: 'unknown'; why: string };
  /**
   * Every other copy the caller will DELETE before or as part of the install
   * (e.g. `update`'s legacy extensions purge, a duplicate repair's
   * candidates). A copy here that is newer than the pin, or whose version
   * cannot be read, stops the replacement just like the selected copy would.
   */
  deleting?: ReadonlyArray<
    | { dir: string; state: 'ok'; version: string }
    | { dir: string; state: 'unknown'; why: string }
  >;
}

export type ReplacementDecision =
  | { replace: true }
  | { replace: false; why: 'linked' | 'newer' | 'unknown'; summary: string };

/**
 * May a forced install of `pin` replace what is there? Not a linked/path
 * install (someone pointed OpenClaw at a checkout on purpose), not when the
 * selected copy — or any copy about to be deleted — is newer than the pin
 * (that would be a downgrade), and not when OpenClaw's records could not tell
 * which copy is selected, whether it is linked, or what a doomed copy holds.
 */
export function assessRealtimeReplacement(existing: ExistingRealtimeInstall, pin: string): ReplacementDecision {
  const sel = existing.selected;
  const at = sel.state === 'selected' ? ` (v${sel.version})` : '';
  if (existing.linked.state === 'linked') {
    return { replace: false, why: 'linked', summary: `left alone — the plugin is a linked install${at} at ${existing.linked.at}` };
  }
  if (sel.state === 'unknown') {
    return { replace: false, why: 'unknown', summary: `left alone — could not tell which copy OpenClaw selected (${sel.why})` };
  }
  const v = sel.state === 'selected' ? exactPluginPin(sel.version) : null;
  if (sel.state === 'selected' && !v) {
    return { replace: false, why: 'unknown', summary: `left alone — the selected copy's version is not exact (${JSON.stringify(sel.version)})` };
  }
  if (v && semver.gt(v, pin)) {
    return { replace: false, why: 'newer', summary: `left alone — the plugin is on v${v}, newer than this CLI (v${pin})` };
  }
  for (const copy of existing.deleting ?? []) {
    if (copy.state === 'unknown') {
      return { replace: false, why: 'unknown', summary: `left alone — could not read the copy at ${copy.dir} that the install would remove (${copy.why})` };
    }
    const cv = exactPluginPin(copy.version);
    if (!cv) {
      return { replace: false, why: 'unknown', summary: `left alone — the copy at ${copy.dir} that the install would remove has no exact version` };
    }
    if (semver.gt(cv, pin)) {
      return { replace: false, why: 'newer', summary: `left alone — ${copy.dir} holds v${cv}, newer than this CLI (v${pin})` };
    }
  }
  if (existing.linked.state === 'unknown') {
    return {
      replace: false,
      why: 'unknown',
      summary: `left alone — could not tell whether the plugin is a linked install (${existing.linked.why})`,
    };
  }
  return { replace: true };
}

// ── Verify what landed ──────────────────────────────────────────────────────

export type LandedVerdict =
  | { ok: true; version: string }
  | { ok: false; version: string | null; summary: string };

/**
 * Compare the copy OpenClaw selected after an install with the pin captured
 * BEFORE it. Only the pinned build is success; older, newer, unreadable and
 * "could not tell which copy" are not. `landed` is a version string, or the
 * `{ version, reason }` read of the selected copy.
 */
export function landedVersionVerdict(
  landed: string | null | undefined | { version: string | null; reason?: string },
  pin: string,
): LandedVerdict {
  if (landed && typeof landed === 'object') {
    if (landed.version === null) {
      return { ok: false, version: null, summary: `${landed.reason ?? 'installed version unreadable'} — expected v${pin}` };
    }
    return landedVersionVerdict(landed.version, pin);
  }
  const v = exactPluginPin(landed);
  if (!v) return { ok: false, version: null, summary: `installed version unreadable — expected v${pin}` };
  if (semver.eq(v, pin)) return { ok: true, version: v };
  return { ok: false, version: v, summary: `the plugin is on v${v}, CLI is v${pin}` };
}
