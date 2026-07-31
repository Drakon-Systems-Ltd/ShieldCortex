/**
 * ShieldCortex — the Claude Code CLI judge transport (#143).
 *
 * Design: docs/design/2026-07-31-ai-approval-broker.md
 *
 * The broker needs a model. It is not allowed to bring one: no API key of its
 * own, no login, no SDK, no second bill. On a box where the operator already
 * runs Claude Code, the model is *already there and already authenticated* — so
 * this shells out to it, once, as a classifier.
 *
 * Everything in here follows from one sentence in the design: **same
 * credentials, never same context.**
 *
 *   - **Tools disabled** (`--tools ""`). The judge answers a question; it does
 *     not act. A judge with tools is an agent holding the operator's
 *     credentials, invoked by the very thing it was asked to distrust.
 *   - **No context** (`--safe-mode`, `--strict-mcp-config`,
 *     `--no-session-persistence`, and a scratch cwd). No CLAUDE.md, no skills,
 *     no plugins, no MCP servers, no hooks, no transcript, no project settings.
 *     A poisoned session must not be able to hand the judge its own argument for
 *     approval — and the judge's own process must not re-enter ShieldCortex's
 *     hooks and gate itself.
 *   - **The prompt is stdin, never argv.** The untrusted half of the prompt
 *     never becomes a command-line argument, where it would land in `ps` output,
 *     shell history and the audit of every process on the box.
 *   - **A hard deadline that kills.** An operator is waiting behind this call. A
 *     judge that overruns is terminated, not abandoned — an abandoned child is
 *     still spending the operator's rate limit.
 *   - **Every failure rejects.** Non-zero exit, spawn error, timeout, empty
 *     reply: all of them reach `runJudge`, which returns null, which the broker
 *     reads as "hold for a human". There is no error path that yields a verdict.
 */
import { spawn as nodeSpawn } from 'node:child_process';
import { tmpdir } from 'node:os';
import { normaliseBrokerModel } from './broker-config.js';
import type { ModelInvoker } from './approval-judge.js';

/** The slice of a child process this module uses. Narrow on purpose: it is the
 *  test seam, and a narrow seam is one a fake can honestly satisfy. */
export interface ChildLike {
  stdin: { write(chunk: string): unknown; end(): unknown; on(event: string, cb: (err: unknown) => void): unknown } | null;
  stdout: { on(event: 'data', cb: (chunk: unknown) => void): unknown } | null;
  stderr: { on(event: 'data', cb: (chunk: unknown) => void): unknown } | null;
  on(event: 'error' | 'close', cb: (...args: never[]) => void): unknown;
  kill(signal?: string): boolean;
  killed?: boolean;
}

export type SpawnLike = (
  command: string,
  args: readonly string[],
  options: { cwd?: string; env?: NodeJS.ProcessEnv; stdio?: unknown },
) => ChildLike;

export interface CliInvokerOptions {
  /** Injected for tests; defaults to node:child_process.spawn. */
  spawn?: SpawnLike;
  /** The CLI binary. Default `claude` — resolved from PATH. */
  command?: string;
  /** Judge model override. Re-validated here; a hostile value is dropped. */
  model?: string;
  /** Hard deadline for the whole call. */
  timeoutMs?: number;
  /** Environment to derive the child's allowlisted env from. */
  env?: NodeJS.ProcessEnv;
}

const DEFAULT_COMMAND = 'claude';
const DEFAULT_TIMEOUT_MS = 8_000;
/** Grace between "please stop" and "stop". */
const KILL_GRACE_MS = 100;
/** A judge reply is one small JSON object. Anything beyond this is noise, and
 *  unbounded accumulation from a child process is a memory bug waiting to be
 *  triggered deliberately. */
const MAX_OUTPUT_BYTES = 65_536;

/**
 * The judge's environment, allowlisted.
 *
 * The agent's process environment is where a working box keeps its secrets:
 * repo tokens, cloud keys, database URLs. None of that is needed to classify a
 * shell command, so none of it is forwarded. What IS forwarded is the operator's
 * own Claude auth and the minimum a process needs to run — because riding the
 * existing login is the entire point.
 *
 * Bedrock/Vertex-hosted CLIs authenticate through cloud SDK variables that are
 * deliberately NOT on this list; those hosts fall back to no judge, which the
 * broker reads as hold-for-a-human. Failing closed beats forwarding a cloud
 * credential the operator never pointed at this feature.
 */
const JUDGE_ENV_ALLOWLIST = [
  'PATH', 'HOME', 'USERPROFILE', 'LANG', 'LC_ALL', 'TMPDIR', 'TEMP', 'TMP',
  // Proxy/TLS plumbing — without these the call simply fails on some networks.
  'HTTP_PROXY', 'HTTPS_PROXY', 'NO_PROXY', 'http_proxy', 'https_proxy', 'no_proxy',
  'NODE_EXTRA_CA_CERTS',
  // The host's existing Claude login. Not new credentials — the same ones the
  // operator already runs their agent on.
  'ANTHROPIC_API_KEY', 'ANTHROPIC_AUTH_TOKEN', 'ANTHROPIC_BASE_URL',
  'CLAUDE_CONFIG_DIR',
] as const;

export function buildJudgeEnv(source: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = Object.create(null) as NodeJS.ProcessEnv;
  for (const key of JUDGE_ENV_ALLOWLIST) {
    const value = source[key];
    // Absent stays absent: defining a variable as empty is not the same as not
    // defining it, and some CLIs treat the empty string as a real setting.
    if (typeof value === 'string') env[key] = value;
  }
  return env;
}

/**
 * The argument vector. Trusted content only — the system prompt is ShieldCortex's
 * own constant and the model is re-validated. The untrusted request goes on stdin.
 */
export function buildCliArgs(system: string, model?: string): string[] {
  const args = [
    '--print',
    // Disable every built-in tool. `""` is the CLI's documented "no tools".
    '--tools', '',
    // No MCP servers from any other config source.
    '--strict-mcp-config',
    // No CLAUDE.md, skills, plugins, hooks, custom agents or settings. This is
    // both the "no session context" guarantee and the recursion guard.
    '--safe-mode',
    '--no-session-persistence',
    '--system-prompt', system,
  ];
  // Re-validated rather than trusted: broker-config already rejects a hostile
  // model, but this is the function that turns a string into argv, so it is the
  // right place to refuse a leading dash one last time.
  const safeModel = normaliseBrokerModel(model);
  if (safeModel) args.push('--model', safeModel);
  return args;
}

function text(chunk: unknown): string {
  return typeof chunk === 'string' ? chunk : String(chunk);
}

/**
 * One judge call through the already-logged-in CLI.
 *
 * Resolves with the model's raw stdout; rejects on every failure. `runJudge`
 * turns a rejection into null and the broker turns null into "hold", so a
 * rejection here is the fail-closed direction, not an outage.
 */
export function createCliInvoker(opts: CliInvokerOptions = {}): ModelInvoker {
  const spawnFn: SpawnLike = opts.spawn ?? (nodeSpawn as unknown as SpawnLike);
  const command = opts.command ?? DEFAULT_COMMAND;
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;

  return (system: string, user: string): Promise<string> =>
    new Promise<string>((resolve, reject) => {
      let settled = false;
      let stdout = '';
      let stderr = '';
      let deadline: ReturnType<typeof setTimeout> | undefined;
      let grace: ReturnType<typeof setTimeout> | undefined;
      let child: ChildLike;

      const finish = (fn: () => void): void => {
        if (settled) return;
        settled = true;
        if (deadline) clearTimeout(deadline);
        fn();
      };

      try {
        child = spawnFn(command, buildCliArgs(system, opts.model), {
          // A scratch directory, deliberately. The agent's cwd is where the
          // .env, the credentials file and the project settings live; the judge
          // has no business resolving anything relative to it.
          cwd: tmpdir(),
          env: buildJudgeEnv(opts.env),
          stdio: ['pipe', 'pipe', 'pipe'],
        });
      } catch (err) {
        reject(new Error(`judge CLI could not be spawned: ${err instanceof Error ? err.message : String(err)}`));
        return;
      }

      deadline = setTimeout(() => {
        finish(() => {
          // Ask, then insist. A judge still running is still spending the
          // operator's rate limit on an answer nobody will read.
          try { child.kill('SIGTERM'); } catch { /* already gone */ }
          grace = setTimeout(() => {
            try { child.kill('SIGKILL'); } catch { /* already gone */ }
          }, KILL_GRACE_MS);
          if (typeof (grace as { unref?: () => void }).unref === 'function') (grace as { unref: () => void }).unref();
          reject(new Error(`judge CLI timed out after ${timeoutMs}ms`));
        });
      }, timeoutMs);

      child.stdout?.on('data', chunk => {
        if (stdout.length >= MAX_OUTPUT_BYTES) return;
        stdout += text(chunk);
        if (stdout.length > MAX_OUTPUT_BYTES) stdout = stdout.slice(0, MAX_OUTPUT_BYTES);
      });
      child.stderr?.on('data', chunk => {
        if (stderr.length < 2_000) stderr += text(chunk);
      });

      child.on('error', ((err: Error) => {
        finish(() => reject(new Error(`judge CLI failed to start: ${err?.message ?? err}`)));
      }) as (...args: never[]) => void);

      child.on('close', ((code: number | null) => {
        finish(() => {
          if (code !== 0) {
            reject(new Error(`judge CLI exited ${code}${stderr ? `: ${stderr.slice(0, 200)}` : ''}`));
            return;
          }
          if (!stdout.trim()) {
            // A clean exit with no output is not a verdict. Say so rather than
            // handing the parser an empty string to be confused by.
            reject(new Error('judge CLI produced empty output'));
            return;
          }
          resolve(stdout);
        });
      }) as (...args: never[]) => void);

      try {
        child.stdin?.on('error', () => { /* EPIPE if the child died first — the close handler owns the outcome */ });
        child.stdin?.write(user);
        child.stdin?.end();
      } catch {
        finish(() => reject(new Error('judge CLI stdin was not writable')));
      }
    });
}
