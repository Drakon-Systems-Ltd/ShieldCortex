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
  /(error|invalid|refus|denied|missing|conflict|unknown command|EACCES|EPERM|ENOENT|EOVERRIDE|EEXIST|E40[134]|ETIMEDOUT|ENOTFOUND|not found|failed|cannot|unable|✗|×)/i;

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

/** npm chatter that is never the cause. */
const NOISE_PATTERN =
  /^(npm notice|npm warn|npm WARN|added \d+ package|found \d+ vulnerabilit|up to date|audited \d+ package)/i;

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
  let out = text;
  for (const [key, value] of Object.entries(env)) {
    if (!value || value.length < MIN_SECRET_VALUE_CHARS) continue;
    if (!SECRET_KEY_PATTERN.test(key)) continue;
    if (!out.includes(value)) continue;
    out = out.replace(new RegExp(escapeRegExp(value), 'g'), `[redacted:$${key}]`);
  }
  return out;
}

function cleanLines(raw: string): string[] {
  return raw
    .replace(ANSI_PATTERN, '')
    .replace(/\r/g, '')
    .split('\n')
    .map(line => line.trimEnd())
    .filter(line => line.trim().length > 0)
    .filter(line => !NOISE_PATTERN.test(line.trim()));
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

  if (!output || !output.trim()) return { lines: [], truncated: false };

  // Cap before any regex work — a failed `npm install -g` emits megabytes.
  const capped = output.length > MAX_INPUT_BYTES ? output.slice(-MAX_INPUT_BYTES) : output;
  let truncated = capped.length < output.length;

  const redacted = redactCredentials(redactEnvValues(capped, env), {
    // npm integrity hashes are high-entropy but not secrets; without this the
    // entropy pass eats them and the real message drowns in [REDACTED].
    allowlist: ['sha512-', 'sha1-', 'sha256-'],
  });

  const all = cleanLines(redacted);
  if (all.length === 0) return { lines: [], truncated };

  const signal = all.filter(line => SIGNAL_PATTERN.test(line) && !REASSURANCE_PATTERN.test(line));
  let picked = signal.length > 0 ? signal.slice(0, maxLines) : all.slice(-maxLines);
  if (picked.length < all.length) truncated = true;

  picked = picked.map(line =>
    line.length > MAX_LINE_CHARS ? `${line.slice(0, MAX_LINE_CHARS - 1)}…` : line,
  );

  // Drop from the front until the block fits — the last kept line is the most
  // specific one when the fallback tail is in play.
  while (picked.length > 1 && picked.join('\n').length > maxChars) {
    picked.shift();
    truncated = true;
  }
  if (picked.length === 1 && picked[0].length > maxChars) {
    picked[0] = `${picked[0].slice(0, maxChars - 1)}…`;
    truncated = true;
  }

  return { lines: picked, truncated };
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

  let reason: string;
  if (lines.length > 0) {
    reason = firstSentence(lines[0]);
  } else if (spawnFailed) {
    reason = firstSentence(`command not found${command}`);
  } else if (timedOut) {
    reason = firstSentence(`timed out${command}`);
  } else if (exitCode !== null) {
    reason = firstSentence(`exited ${exitCode} with no output${command}`);
  } else {
    reason = firstSentence(e.message || 'failed with no output');
  }

  return { reason, detail: lines, exitCode, timedOut, spawnFailed, truncated };
}
