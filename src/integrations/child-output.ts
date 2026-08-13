/**
 * Turning a failed child process into something an operator can act on (#221).
 *
 * The field report behind #221: an operator followed `doctor`'s advice for five
 * days while every suggested command was a guaranteed no-op, because OpenClaw's
 * own config was invalid. OpenClaw said so clearly, every time. ShieldCortex
 * threw the message away and printed the command again:
 *
 *   } catch {
 *     return { status: 'warn', summary: 'update failed — run `openclaw plugins
 *              install --force …`' };   // the command that just failed
 *   }
 *
 * `runQuiet` had already captured stdout AND stderr and attached both to the
 * rejected error. The cause was in hand and discarded.
 *
 * Two details here are not obvious and are the reason this is a module rather
 * than a one-liner:
 *
 * SIGNAL-FIRST, NOT TAIL. The four existing `slice(-N)` call sites take the
 * LAST few lines. OpenClaw states its diagnosis first and signs off with
 * "Audit, status, health, logs, tasks list/audit, and doctor commands still run
 * with invalid config." A tail therefore returns the reassurance and drops the
 * cause — the precise failure this module exists to stop.
 *
 * REDACT WHAT WE OURSELVES HANDED OVER. `runQuiet` passes `{...process.env}` to
 * the child, so NPM_TOKEN and CLAWHUB_TOKEN are values WE supplied — and npm
 * echoes them back verbatim in a 401 body. This output is destined for a doctor
 * report an operator may paste into a GitHub issue. Env-value redaction runs
 * first and does not depend on a pattern matching the token's shape.
 */
import os from 'os';

import { redactCredentials } from '../defence/credential-leak/index.js';

/** A rejected `runQuiet` error, with the fields it attaches. */
export interface CapturedError extends Error {
  stdout?: string;
  stderr?: string;
  exitCode?: number | null;
  timedOut?: boolean;
  spawnFailed?: boolean;
  command?: string;
  /** Node's spawn errno (ENOENT, EACCES, …). */
  code?: string;
}

export interface RunFailureReport {
  /** ONE line, ≤120 chars — `step()` pads the summary on a single line. */
  reason: string;
  /** Redacted detail lines, most informative first. */
  detail: string[];
  /**
   * True when `reason` was derived from `detail[0]` — a caller printing both
   * should skip the first detail line or the headline appears twice.
   */
  reasonFromDetail: boolean;
  exitCode: number | null;
  timedOut: boolean;
  spawnFailed: boolean;
  truncated: boolean;
}

export interface SummariseOptions {
  maxLines?: number;
  maxChars?: number;
  /** Injected for tests; defaults to the real environment. */
  env?: NodeJS.ProcessEnv;
  /** Injected for tests; defaults to the real home directory. */
  home?: string;
  /**
   * `failure` (default) ranks signal-bearing lines and drops reassurance.
   * `plain` preserves source order — for the output of a command that
   * SUCCEEDED, where there is no failure to find and failure-biased ranking
   * picks the wrong line (it promoted "Removed 1 conflicting entry" over
   * "Installed …@4.47.39", because "conflict" reads as signal).
   */
  mode?: 'failure' | 'plain';
  /**
   * Drop `[plugins] …` lines as foreign chatter. Correct when summarising a
   * command that merely happened to load plugins; WRONG when the command IS a
   * `plugins` subcommand, where those lines are its own output — filtering
   * them there produced an empty summary, i.e. a failure with no stated
   * reason, which is the class of defect this module exists to remove.
   *
   * Keeping them does NOT promote them: a retained `[plugins] …` line ranks
   * below every non-plugin line in its band, so another plugin's TypeError
   * cannot outrank the real `npm error … EAI_AGAIN` that actually failed the
   * step. Last resort, not equal citizen.
   */
  dropPluginChatter?: boolean;
  /**
   * Guarantee a non-empty result whenever the raw output had ANY content, by
   * re-admitting noise lines when the filters would otherwise leave nothing.
   *
   * The caller's need is real — a failed step must never report a blank
   * reason. It must be served HERE rather than by the call site falling back
   * to `output.split('\n')[0]`, because every safety guarantee of this module
   * (env-value redaction, credential patterns, home scrubbing, line and char
   * caps) lives on this path and none of it exists on a raw string. A probe
   * with `NPM_TOKEN` set proved the call-site fallback emitted the token
   * verbatim, plus the absolute home path, whenever output was all `npm warn`.
   */
  neverEmpty?: boolean;
}

/** Read no more than this from either stream before doing regex work. */
const MAX_INPUT_BYTES = 32 * 1024;
const DEFAULT_MAX_LINES = 4;
const DEFAULT_MAX_CHARS = 400;
const MAX_LINE_CHARS = 160;
const MAX_REASON_CHARS = 120;

/** Env var names whose VALUES must never reach a pasted report. */
const SECRET_KEY_PATTERN = /(TOKEN|SECRET|KEY|PASSWORD|PASSWD|CREDENTIAL|AUTH|COOKIE|SESSION)/i;
/** Below this length a value is too short to be a real secret and too likely to
 *  appear as an ordinary substring (a 3-char value would redact half the text). */
const MIN_SECRET_VALUE_CHARS = 8;

/**
 * Lines worth surfacing. Deliberately broad: a missed signal line costs the
 * operator the cause, whereas a false positive costs one line of noise.
 */
const SIGNAL_PATTERN =
  /(error|invalid|refus|denied|missing|conflict|unknown command|EACCES|EPERM|ENOENT|EOVERRIDE|EEXIST|E40[134]|ETIMEDOUT|ENOTFOUND|not found|failed|cannot|could ?not|unable|✗|×)/i;

/**
 * Lines that name the failure ITSELF, as opposed to merely containing a word
 * like "failed". Ranked ahead of generic matches, because the first
 * signal-bearing line is not reliably the important one.
 *
 * Measured: on this fleet `openclaw <unknown-command>` emits two
 * `[plugins] codex failed during register …: TypeError …` lines from an
 * unrelated third-party plugin BEFORE its own "Could not start the CLI /
 * Reason: Unknown command". Taking the earliest match reported someone else's
 * TypeError as the cause — swapping one misleading headline for another.
 */
const STRONG_SIGNAL_PATTERN =
  /(config is invalid|unknown command|unknown option|too many arguments|refus|denied|EACCES|EPERM|ENOENT|EOVERRIDE|E40[134]|^\s*[×✗])/i;
// Note "could not start the CLI" is deliberately NOT strong: it is a header,
// and the `Reason: …` line beneath it carries the actual cause.

/**
 * Prose about what STILL WORKS. Never the cause of a failure, and actively
 * misleading directly under a blocking error.
 *
 * This exists because OpenClaw signs off an invalid-config report with
 * "Audit, status, health, logs, tasks list/audit, and doctor commands still run
 * with invalid config." — which contains the word "invalid" and so matches the
 * signal pattern on a keyword. Reassurance is not signal, however it is worded.
 */
const REASSURANCE_PATTERN = /\bstill (run|work|available)|\bunaffected\b|no action (is )?(required|needed)/i;

/**
 * Chatter that is never the cause: npm's own noise, and OTHER plugins'
 * registration failures. The `[plugins] …` prefix is a third party telling us
 * about itself — real, but never the answer to "why did OUR command fail".
 */
const NOISE_PATTERN =
  /^(npm notice|npm warn|npm WARN|added \d+ package|found \d+ vulnerabilit|up to date|audited \d+ package)/i;

/** Another plugin telling us about itself — see `dropPluginChatter`. */
const PLUGIN_CHATTER_PATTERN = /^\[plugins\]\s/i;

const ANSI_PATTERN = /\x1b\[[0-9;]*[A-Za-z]/g;

/** Escape a string for literal use inside a RegExp. */
function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Replace the literal values of secret-looking env vars.
 *
 * Runs BEFORE the pattern-based detector because it needs no pattern: the value
 * is known exactly. A token that our own credential patterns do not recognise
 * still gets caught here, provided we were the ones who put it in the child's
 * environment.
 */
function redactEnvValues(text: string, env: NodeJS.ProcessEnv): string {
  // LONGEST FIRST. When one secret is a prefix of another — two tokens minted
  // from the same base, say — replacing the short one first leaves the tail of
  // the long one in cleartext, and the second pass then finds nothing to do
  // because its value no longer appears intact.
  const secrets = Object.entries(env)
    .filter(([key, value]) =>
      typeof value === 'string' && value.length >= MIN_SECRET_VALUE_CHARS && SECRET_KEY_PATTERN.test(key))
    .sort((a, b) => (b[1] as string).length - (a[1] as string).length);

  let out = text;
  for (const [key, value] of secrets) {
    if (!out.includes(value as string)) continue;
    out = out.replace(new RegExp(escapeRegExp(value as string), 'g'), `[redacted:$${key}]`);
  }
  return out;
}

/**
 * Replace the operator's home directory with `~`.
 *
 * Every other path-printing site in doctor.ts already does this. This output is
 * bound for reports pasted into public issues, and OpenClaw's config errors
 * quote absolute plugin paths — which carry the OS username and, through
 * project directory names, client and vendor names. OpenClaw abbreviates on its
 * success path but not on its failure path.
 *
 * Runs AFTER redaction so it cannot split a secret mid-match.
 */
function scrubHome(text: string, home: string): string {
  if (!home || home === '/' || home.length < 2) return text;
  return text.split(home).join('~');
}

function cleanLines(raw: string, dropPluginChatter: boolean, keepNoise = false): string[] {
  return raw
    .replace(ANSI_PATTERN, '')
    .replace(/\r/g, '')
    .split('\n')
    .map(line => line.trimEnd())
    .filter(line => line.trim().length > 0)
    .filter(line => keepNoise || !NOISE_PATTERN.test(line.trim()))
    .filter(line => !(dropPluginChatter && PLUGIN_CHATTER_PATTERN.test(line.trim())));
}

/**
 * Plugin chatter last, source order preserved within each band.
 *
 * Only reachable when `dropPluginChatter` is false, i.e. when the command IS a
 * plugins subcommand. Its own `[plugins]` lines must remain available as a
 * reason of last resort without being allowed to outrank the actual failure.
 */
function pluginsLast(lines: string[], takeHead: boolean): string[] {
  const chatter = (line: string) => PLUGIN_CHATTER_PATTERN.test(line.trim());
  const own = lines.filter(l => !chatter(l));
  const theirs = lines.filter(chatter);
  // "Last resort" is a statement about the PICK, not about array order: the
  // head paths slice from the front, the no-signal failure path slices from the
  // tail. Demoting chatter therefore means pushing it to the opposite end from
  // wherever the slice is taken — sorting it to the back unconditionally would
  // hand the tail path nothing BUT chatter.
  return takeHead ? [...own, ...theirs] : [...theirs, ...own];
}

/**
 * Reduce raw child output to a few lines an operator can act on.
 *
 * Signal-bearing lines are taken from the FRONT (see the module note on why a
 * tail is wrong here); only when nothing matches does it fall back to the tail,
 * which is the right default for a generic stack trace.
 */
export function summariseCommandOutput(
  output: string,
  opts: SummariseOptions = {},
): { lines: string[]; truncated: boolean } {
  const maxLines = opts.maxLines ?? DEFAULT_MAX_LINES;
  const maxChars = opts.maxChars ?? DEFAULT_MAX_CHARS;
  const env = opts.env ?? process.env;
  const home = opts.home ?? os.homedir();

  if (!output || !output.trim()) return { lines: [], truncated: false };

  // Env-value redaction FIRST, on the UNCAPPED text. It is an exact-match
  // String.replace — cheap even on megabytes — and running it after the cap
  // let a secret split at the cap boundary escape the exact match entirely;
  // the surviving 40-hex prefix then read as a git SHA to the entropy
  // allowlist. Everything regex-shaped stays behind the cap below.
  const envRedacted = redactEnvValues(output, env);

  // Cap before any regex work — a failed `npm install -g` emits megabytes.
  // BOTH ENDS, not the tail: the diagnosis is printed first and the noise
  // follows, so a tail-only cap discards the cause before the signal filter
  // ever sees it — the very mistake this module exists to correct, moved one
  // stage earlier where nothing downstream can compensate.
  const half = Math.floor(MAX_INPUT_BYTES / 2);
  const capped = envRedacted.length > MAX_INPUT_BYTES
    ? `${envRedacted.slice(0, half)}\n…\n${envRedacted.slice(-half)}`
    : envRedacted;
  let truncated = envRedacted.length > MAX_INPUT_BYTES;

  // Same ordering as sanitiseForReport, for the same reasons: home-scrub
  // before token-shaped redaction (a legitimate `~/...` path must not read as
  // an entropy token because a temp home contains random bytes), then the
  // credential-FRAGMENT pass — child output quotes credential-shaped path
  // segments, and this sink previously lacked the pass while the hand-built-
  // string sink had it: the strongest redaction guarded the least dangerous
  // sink — then the whole-text pattern/entropy pass.
  const homeScrubbed = scrubHome(capped, home);
  const protectedPaths = protectReportPathLiterals(homeScrubbed);
  const fragmentRedacted = redactCredentialFragments(protectedPaths.text);
  const scrubbed = protectedPaths.restore(redactCredentials(fragmentRedacted, {
    // npm integrity hashes are high-entropy but not secrets; without this the
    // entropy pass eats them and the real message drowns in [REDACTED].
    allowlist: ['sha512-', 'sha1-', 'sha256-'],
  }));
  const dropPluginChatter = opts.dropPluginChatter ?? true;
  let all = cleanLines(scrubbed, dropPluginChatter);
  if (all.length === 0 && opts.neverEmpty) {
    // Everything was noise. Re-admit it rather than hand the caller nothing —
    // still redacted, scrubbed and capped, because it comes back through the
    // same path.
    all = cleanLines(scrubbed, dropPluginChatter, true);
    if (all.length > 0) truncated = true;
  }
  if (all.length === 0) return { lines: [], truncated };

  // `plain` skips ranking entirely: for output of a command that succeeded there
  // is no cause to hunt for, and the failure heuristics pick the wrong line.
  const signal = (opts.mode ?? 'failure') === 'plain'
    ? []
    : all.filter(line => SIGNAL_PATTERN.test(line) && !REASSURANCE_PATTERN.test(line));
  const usedSignal = signal.length > 0;
  // plain: keep the head (the primary outcome line comes first).
  // failure+signal: ranked head. failure+no-signal: tail, where a stack trace's
  // most specific frame sits.
  const takeHead = usedSignal || (opts.mode ?? 'failure') === 'plain';
  // Strongest cause first, original order preserved within each band — the
  // EARLIEST signal line is not reliably the most informative one. Retained
  // plugin chatter sinks away from the end being picked.
  const ranked = pluginsLast(
    usedSignal
      ? [...signal.filter(l => STRONG_SIGNAL_PATTERN.test(l)), ...signal.filter(l => !STRONG_SIGNAL_PATTERN.test(l))]
      : all,
    takeHead,
  );

  let picked = takeHead ? ranked.slice(0, maxLines) : ranked.slice(-maxLines);
  if (picked.length < all.length) truncated = true;

  picked = picked.map(line =>
    line.length > MAX_LINE_CHARS ? `${line.slice(0, MAX_LINE_CHARS - 1)}…` : line,
  );

  // Trim from the END on the signal path (lines are ranked, so the first is the
  // most important) and from the FRONT on the tail path (where the last line is
  // the most specific). Dropping from the front of a ranked list would delete
  // the very line that was selected as the cause.
  while (picked.length > 1 && picked.join('\n').length > maxChars) {
    if (usedSignal) picked.pop(); else picked.shift();
    truncated = true;
  }
  if (picked.length === 1 && picked[0].length > maxChars) {
    picked[0] = `${picked[0].slice(0, maxChars - 1)}…`;
    truncated = true;
  }

  return { lines: picked, truncated };
}

/**
 * Sanitise a string that was NOT produced by `summariseCommandOutput` — a
 * caller's own hand-built report string (an `err.message`, a path) — through
 * the same env-value redaction, credential-shape redaction, and home-scrubbing
 * every other reported string gets. Env-value redaction runs before home
 * scrubbing because it needs exact secret values; home scrubbing runs before
 * pattern redaction so a legitimate `~/.openclaw/...` path is not mistaken for
 * a high-entropy token just because the temp home directory contains random
 * bytes.
 */
const REPORT_PATH_SENTINELS: Array<[string, string]> = [
  ['~/.openclaw/extensions/shieldcortex-realtime', '__shieldcortex_report_path_ext__'],
  ['~/.openclaw/plugins/installs.json', '__shieldcortex_report_path_registry__'],
  ['~/plugins/installs.json', '__shieldcortex_report_path_plugins_registry__'],
];

function redactCredentialFragments(text: string): string {
  return text.replace(/[A-Za-z0-9\-_+=]{20,}/g, fragment =>
    redactCredentials(fragment, {
      allowlist: ['sha512-', 'sha1-', 'sha256-'],
    }));
}

function protectReportPathLiterals(text: string): { text: string; restore: (value: string) => string } {
  let protectedText = text;
  for (const [literal, sentinel] of REPORT_PATH_SENTINELS) {
    protectedText = protectedText.split(literal).join(sentinel);
  }
  return {
    text: protectedText,
    restore(value: string): string {
      let out = value;
      for (const [literal, sentinel] of REPORT_PATH_SENTINELS) {
        out = out.split(sentinel).join(literal);
      }
      return out;
    },
  };
}

export function sanitiseForReport(text: string, opts: SummariseOptions = {}): string {
  const envRedacted = redactEnvValues(text, opts.env ?? process.env);
  const homeScrubbed = scrubHome(envRedacted, opts.home ?? os.homedir());
  const protectedPaths = protectReportPathLiterals(homeScrubbed);
  const fragmentRedacted = redactCredentialFragments(protectedPaths.text);
  const credentialRedacted = redactCredentials(fragmentRedacted, {
    // Match summariseCommandOutput: npm integrity hashes are high-entropy but
    // not secrets, and otherwise bury the real failure in [REDACTED]. Do NOT
    // allowlist `~/.openclaw/` as a broad prefix: a credential-shaped child
    // path segment under that directory must still be redacted.
    allowlist: ['sha512-', 'sha1-', 'sha256-'],
  });
  return protectedPaths.restore(credentialRedacted);
}

function firstSentence(value: string, limit = MAX_REASON_CHARS): string {
  const single = value.replace(/\s+/g, ' ').trim();
  return single.length > limit ? `${single.slice(0, limit - 1)}…` : single;
}

/**
 * Describe a rejected child-process error without discarding what it captured.
 *
 * The empty-output ladder matters as much as the happy path: a bare "failed" is
 * what #221 is about. Even with no output at all, the caller gets the exit code
 * and the command, which is the minimum needed to reproduce it by hand.
 */
export function describeRunFailure(err: unknown, opts: SummariseOptions = {}): RunFailureReport {
  const e = (err ?? {}) as CapturedError;
  const exitCode = e.exitCode ?? null;
  const timedOut = e.timedOut === true;
  const spawnFailed = e.spawnFailed === true || e.code === 'ENOENT';
  const command = e.command ? ` (${e.command})` : '';

  // Invalid configs write to stderr, valid runs to stdout, npm to stderr — so
  // pick the stream carrying signal rather than concatenating both.
  const streams = [e.stderr ?? '', e.stdout ?? ''];
  const withSignal = streams.find(s => s.trim() && SIGNAL_PATTERN.test(s));
  const chosen = withSignal ?? streams.find(s => s.trim()) ?? '';

  const { lines, truncated } = summariseCommandOutput(chosen, opts);

  // How the process ENDED outranks whatever it managed to print. A step killed
  // at the 120s wall often has a plausible-looking network line in its buffer;
  // reporting that alone tells the operator to retry a transient blip when the
  // real fact is a half-applied install. Partial output is still surfaced, but
  // as detail behind the terminal condition, never in place of it.
  const sanitise = (text: string): string => sanitiseForReport(text, opts);

  let reason: string;
  let reasonFromDetail = false;
  if (spawnFailed) {
    reason = firstSentence(sanitise(`command not found${command}`));
  } else if (timedOut) {
    reason = firstSentence(sanitise(`timed out${command}`));
  } else if (lines.length > 0) {
    reason = firstSentence(lines[0]);
    reasonFromDetail = true;
  } else if (exitCode !== null) {
    reason = firstSentence(sanitise(`exited ${exitCode} with no output${command}`));
  } else {
    reason = firstSentence(sanitise(e.message || 'failed with no output'));
  }

  return { reason, detail: lines, reasonFromDetail, exitCode, timedOut, spawnFailed, truncated };
}
