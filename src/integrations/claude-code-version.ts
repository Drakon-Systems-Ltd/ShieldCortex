import { execFileSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';

/**
 * Detecting the installed Claude Code build, and whether it is new enough to
 * enforce the Action Guard's verdicts.
 *
 * Incident, 2026-07-30 (aiquant): under `--permission-mode bypassPermissions`,
 * Claude Code 2.1.76 converts a PreToolUse hook's `"ask"` decision into
 * `allow` and runs the command. The permission resolver preserves `"ask"` only
 * for `decisionReason.type === "rule"` or tools that require user interaction;
 * a hook-ask is type `"hook"`, so in a promptless mode it falls through to
 * mode-allow. `deny` is honoured unconditionally in every build we have
 * examined. A global `npm i -g` earned `require_approval` at 06:53:23Z, was
 * written to the audit log as gated, and installed anyway.
 *
 * The guard-side fix is to deny rather than ask when no prompt surface can be
 * confirmed. But the deeper condition is that the harness ShieldCortex depends
 * on for enforcement was 144 versions stale on one box and nobody knew: it is
 * distributed through two channels (npm global and the native installer),
 * neither of which anyone was tracking. A guard that silently depends on an
 * untracked version of something else is not a guard. So doctor reads the
 * version and says so.
 *
 * The floor is behavioural, not theoretical: 2.1.215 (native) and 2.1.220
 * (npm) were both observed honouring a hook-ask under `bypassPermissions` on
 * separate hosts; 2.1.76 was observed discarding it. We have not bisected the
 * range between, so the floor is the lowest build actually proven good.
 */

/**
 * Lowest Claude Code version observed to honour a hook `"ask"` in a promptless
 * mode. Below this, hook verdicts requiring approval may be silently discarded.
 */
export const CLAUDE_CODE_ENFORCEMENT_FLOOR = '2.1.215';

/** Where a Claude Code build came from — the two channels differ in upgrade path. */
export type ClaudeCodeChannel = 'native' | 'npm' | 'unknown';

export interface ClaudeCodeInstall {
  /** Parsed `major.minor.patch`, or null when the output could not be parsed. */
  version: string | null;
  /** Exactly what `claude --version` printed, for operator-facing evidence. */
  rawVersion: string | null;
  /** The `claude` that PATH resolves to. */
  binPath: string;
  /** `binPath` with symlinks followed, when resolvable — this is what names the channel. */
  realPath: string | null;
  channel: ClaudeCodeChannel;
  /** Set when the binary exists but `--version` could not be run or read. */
  error?: string;
}

export interface DetectClaudeCodeDeps {
  /** Resolve `claude` on PATH; return null when it is not installed. */
  which?: (cmd: string) => string | null;
  /** Follow symlinks; return null when the path cannot be resolved. */
  realpath?: (p: string) => string | null;
  /** Run `claude --version` and return stdout; throw when it cannot be run. */
  runVersion?: (bin: string) => string;
  homedir?: () => string;
}

/** Resolve a command through PATH without a shell. */
function defaultWhich(cmd: string): string | null {
  const pathEnv = process.env.PATH;
  if (!pathEnv) return null;
  for (const dir of pathEnv.split(path.delimiter)) {
    if (!dir) continue;
    const candidate = path.join(dir, cmd);
    try {
      fs.accessSync(candidate, fs.constants.X_OK);
      return candidate;
    } catch {
      /* not here — keep walking PATH */
    }
  }
  return null;
}

function defaultRealpath(p: string): string | null {
  try {
    return fs.realpathSync(p);
  } catch {
    return null;
  }
}

/**
 * `claude --version` is a fast local print, but doctor must never hang on a
 * wedged binary — hence the timeout and the empty-stdin redirect, which stops
 * a build that decides to read stdin from blocking forever.
 */
function defaultRunVersion(bin: string): string {
  return execFileSync(bin, ['--version'], {
    encoding: 'utf-8',
    timeout: 10_000,
    stdio: ['ignore', 'pipe', 'ignore'],
  });
}

/** First `x.y.z` in the output — builds print `2.1.220 (Claude Code)`. */
export function parseClaudeCodeVersion(output: string): string | null {
  const match = /(\d+\.\d+\.\d+)/.exec(output);
  return match ? match[1] : null;
}

/**
 * Name the distribution channel from the resolved binary path.
 *
 * Native installs live under `~/.local/share/claude/versions/<version>` with a
 * shim in `~/.local/bin`; npm globals resolve into a
 * `node_modules/@anthropic-ai/claude-code` directory. Anything else is
 * `unknown` — a channel we cannot name is reported as such rather than guessed,
 * because the upgrade instruction differs per channel and a wrong one wastes
 * an operator's time.
 */
export function classifyClaudeCodeChannel(realPath: string | null, homedir: string): ClaudeCodeChannel {
  if (!realPath) return 'unknown';
  const normalised = realPath.split(path.sep).join('/');
  if (normalised.includes('/node_modules/@anthropic-ai/claude-code')) return 'npm';
  const nativeRoot = path.join(homedir, '.local', 'share', 'claude').split(path.sep).join('/');
  if (normalised.startsWith(nativeRoot)) return 'native';
  return 'unknown';
}

/**
 * Locate Claude Code and read its version. Returns null when no `claude` is on
 * PATH at all — that is not a fault, it just means this box does not run the
 * Claude Code surface and the version floor does not apply to it.
 */
export function detectClaudeCode(deps: DetectClaudeCodeDeps = {}): ClaudeCodeInstall | null {
  const which = deps.which ?? defaultWhich;
  const realpath = deps.realpath ?? defaultRealpath;
  const runVersion = deps.runVersion ?? defaultRunVersion;
  const homedir = deps.homedir ?? os.homedir;

  const binPath = which('claude');
  if (!binPath) return null;

  const realPath = realpath(binPath);
  const channel = classifyClaudeCodeChannel(realPath, homedir());

  let rawVersion: string | null = null;
  let error: string | undefined;
  try {
    rawVersion = runVersion(binPath).trim();
  } catch (err) {
    error = err instanceof Error ? err.message : String(err);
  }

  return {
    version: rawVersion ? parseClaudeCodeVersion(rawVersion) : null,
    rawVersion,
    binPath,
    realPath,
    channel,
    ...(error ? { error } : {}),
  };
}

/** Per-channel upgrade instruction, so the fix text is actionable as printed. */
export function upgradeCommandFor(channel: ClaudeCodeChannel): string {
  switch (channel) {
    case 'npm':
      return `npm i -g @anthropic-ai/claude-code@latest`;
    case 'native':
      return `claude update`;
    default:
      return `re-run the Claude Code installer for whichever channel this box uses (\`claude update\` for the native installer, \`npm i -g @anthropic-ai/claude-code@latest\` for the npm global)`;
  }
}
