/**
 * `shieldcortex update` — animated, captured-output release flow.
 *
 * Replaces the v4.14.x wall-of-text update output with:
 *   - a header banner showing the version delta
 *   - one stage per concern (npm package, plugin, hooks, skill)
 *   - per-stage spinner + ✓/⚠/✗ + duration + condensed summary
 *   - npm and openclaw stdout/stderr captured; printed only on error
 *   - graceful fallback to plain text when not on a TTY (CI, piped output)
 *
 * Behaviour-preserving — every step does what the old inline flow did.
 */

import { spawn } from 'child_process';
import fs from 'fs';
import path from 'path';
import { homedir } from 'os';
import { fileURLToPath } from 'url';
import { resolveRealtimePluginInstallPath, readInstalledRealtimePluginVersion } from '../integrations/openclaw-plugin-state.js';
import { describeRunFailure, sanitiseForReport } from '../integrations/child-output.js';
import type { CapturedError } from '../integrations/child-output.js';

// ── ANSI ────────────────────────────────────────────────────

const ANSI = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  cyan: '\x1b[36m',
  magenta: '\x1b[35m',
  gray: '\x1b[90m',
};

const isTTY = Boolean(process.stdout.isTTY);

function paint(color: keyof typeof ANSI, s: string): string {
  return isTTY ? `${ANSI[color]}${s}${ANSI.reset}` : s;
}

// ── Progress runner ─────────────────────────────────────────

const SPINNER_FRAMES = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
const LABEL_WIDTH = 24;

interface StepResult {
  status: 'ok' | 'warn' | 'skip';
  summary?: string;
  /**
   * What the failing child process actually said (#221). `summary` is padded
   * onto a single line, so anything multi-line has to live here or it destroys
   * the layout — and a cause that does not fit on one line is exactly the kind
   * that was previously thrown away.
   */
  detail?: string[];
  /** True when `detail` is a reduction of longer output (#221). */
  truncated?: boolean;
}

export async function step(
  label: string,
  fn: () => Promise<StepResult | string | void>,
): Promise<StepResult> {
  const start = Date.now();
  const padded = label.padEnd(LABEL_WIDTH);
  let frame = 0;
  let timer: NodeJS.Timeout | null = null;

  if (isTTY) {
    process.stdout.write(`  ${paint('cyan', SPINNER_FRAMES[0])}  ${padded}`);
    timer = setInterval(() => {
      frame = (frame + 1) % SPINNER_FRAMES.length;
      process.stdout.write(`\r  ${paint('cyan', SPINNER_FRAMES[frame])}  ${padded}`);
    }, 80);
    timer.unref();
  } else {
    process.stdout.write(`  ◦  ${label}…\n`);
  }

  try {
    const raw = await fn();
    if (timer) clearInterval(timer);
    const result: StepResult =
      typeof raw === 'string' ? { status: 'ok', summary: raw } :
      raw && typeof raw === 'object' ? raw :
      { status: 'ok' };
    const elapsed = ((Date.now() - start) / 1000).toFixed(1) + 's';
    const icon =
      result.status === 'ok' ? paint('green', '✓') :
      result.status === 'warn' ? paint('yellow', '⚠') :
      paint('gray', '·');
    const summary = result.summary
      ? paint('gray', result.summary).padEnd(LABEL_WIDTH + 9)
      : ''.padEnd(LABEL_WIDTH);
    if (isTTY) {
      process.stdout.write(`\r  ${icon}  ${padded}  ${summary}  ${paint('gray', elapsed)}\n`);
    } else {
      process.stdout.write(
        `  ${result.status === 'ok' ? '✓' : result.status === 'warn' ? '⚠' : '·'}  ${label}: ${result.summary ?? 'done'} (${elapsed})\n`,
      );
    }
    // #221: print what the child actually said, indented under its step. This
    // is the difference between "update failed — run <the command that just
    // failed>" and a message naming the config key to fix.
    for (const line of result.detail ?? []) {
      process.stdout.write(`     ${paint('gray', line)}\n`);
    }
    if (result.truncated) {
      process.stdout.write(`     ${paint('gray', '… output truncated — run the command directly for the full text')}\n`);
    }
    return result;
  } catch (err) {
    if (timer) clearInterval(timer);
    const elapsed = ((Date.now() - start) / 1000).toFixed(1) + 's';
    const icon = paint('red', '✗');
    if (isTTY) {
      process.stdout.write(`\r  ${icon}  ${padded}  ${paint('red', 'failed')}                          ${paint('gray', elapsed)}\n`);
    } else {
      process.stdout.write(`  ✗  ${label}: failed (${elapsed})\n`);
    }
    // #248: this used to write `(e.stderr || '') + (e.stdout || '')` straight
    // to the terminal. `runQuiet` hands the child `{...process.env}`, so
    // NPM_TOKEN / CLAWHUB_TOKEN are values WE supplied — and npm echoes them
    // back verbatim in a 401 body. Route through the same redaction #221
    // built for the OpenClaw steps so a credential never reaches output that
    // gets pasted into an issue or support thread.
    // `neverEmpty` because a step that failed on noise-only output (or an
    // ENOENT/timeout with nothing captured) must still show SOMETHING — the
    // regression #248 was reopened against: `detail` alone is `[]` in exactly
    // those cases, but `reason` is never empty.
    const report = describeRunFailure(err, { neverEmpty: true });
    process.stderr.write('\n' + paint('gray', '── output ─────────────────────────────────────────') + '\n');
    process.stderr.write(report.reason + '\n');
    // When the reason was derived from detail[0], printing both duplicates the
    // headline on the common failure path — skip the line the reason already is.
    const detailLines = report.reasonFromDetail ? report.detail.slice(1) : report.detail;
    for (const line of detailLines) process.stderr.write(line + '\n');
    if (report.truncated) {
      process.stderr.write(paint('gray', '… output truncated — run the command directly for the full text') + '\n');
    }
    process.stderr.write(paint('gray', '───────────────────────────────────────────────────') + '\n');
    throw err;
  }
}

// ── Captured subprocess ─────────────────────────────────────

interface RunOpts {
  timeout?: number;
  env?: NodeJS.ProcessEnv;
}

function runQuiet(cmd: string, args: string[], opts: RunOpts = {}): Promise<{ stdout: string; stderr: string }> {
  // Async on purpose: spawnSync blocks the event loop, which froze the spinner
  // for the full duration of `npm install` (30–60s). Using `spawn` lets the
  // setInterval-driven braille animation keep ticking while the child runs.
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, {
      stdio: ['ignore', 'pipe', 'pipe'],
      env: opts.env ?? process.env,
      shell: false,
    });
    let stdout = '';
    let stderr = '';
    let timedOut = false;
    let timer: NodeJS.Timeout | null = null;

    child.stdout?.setEncoding('utf-8');
    child.stderr?.setEncoding('utf-8');
    child.stdout?.on('data', (chunk: string) => { stdout += chunk; });
    child.stderr?.on('data', (chunk: string) => { stderr += chunk; });

    if (opts.timeout) {
      timer = setTimeout(() => {
        timedOut = true;
        child.kill('SIGTERM');
        // Grace period before SIGKILL — long npm tarball extracts can take
        // a few seconds to wind down even after SIGTERM.
        setTimeout(() => { try { child.kill('SIGKILL'); } catch { /* already dead */ } }, 5000).unref();
      }, opts.timeout);
      timer.unref();
    }

    child.on('error', (err) => {
      if (timer) clearTimeout(timer);
      // #221: a spawn failure is a DIFFERENT thing from a non-zero exit, and
      // reporting them identically is how "openclaw is not installed" reads as
      // "openclaw rejected the command".
      const e = err as CapturedError;
      e.spawnFailed = true;
      e.exitCode = null;
      e.command = `${cmd} ${args.join(' ')}`;
      reject(e);
    });

    child.on('close', (code) => {
      if (timer) clearTimeout(timer);
      if (timedOut) {
        const err = new Error(`timeout: ${cmd} ${args.join(' ')}`) as CapturedError;
        err.stdout = stdout;
        err.stderr = stderr;
        err.timedOut = true;
        err.exitCode = null;
        err.command = `${cmd} ${args.join(' ')}`;
        return reject(err);
      }
      if (typeof code === 'number' && code !== 0) {
        const err = new Error(`exit ${code}: ${cmd} ${args.join(' ')}`) as CapturedError;
        err.stdout = stdout;
        err.stderr = stderr;
        err.exitCode = code;
        err.command = `${cmd} ${args.join(' ')}`;
        return reject(err);
      }
      resolve({ stdout, stderr });
    });
  });
}

// ── Header / footer ─────────────────────────────────────────

function header(currentVersion: string, latestVersion: string | null): void {
  process.stdout.write('\n');
  process.stdout.write(`  ${paint('magenta', '◆')} ${paint('bold', 'ShieldCortex')}\n`);
  if (latestVersion && latestVersion !== currentVersion) {
    process.stdout.write(
      `    ${paint('gray', `v${currentVersion}`)}  ${paint('cyan', '→')}  ${paint('green', `v${latestVersion}`)}\n\n`,
    );
  } else if (latestVersion) {
    process.stdout.write(`    ${paint('green', `v${currentVersion}`)} ${paint('gray', '· already on latest')}\n\n`);
  } else {
    process.stdout.write(`    ${paint('green', `v${currentVersion}`)}\n\n`);
  }
}

export function footer(totalMs: number, mainUpdated: boolean, latest: LatestVersionResult): void {
  const elapsed = (totalMs / 1000).toFixed(1) + 's';
  process.stdout.write(
    `\n  ${paint('gray', '──────────────────────────────────────────────────────────────')}\n`,
  );
  if (mainUpdated) {
    process.stdout.write(
      `  ${paint('green', '✓')}  ${paint('bold', 'done')}  ${paint('gray', `in ${elapsed}`)}  ${paint('cyan', '·')}  ${paint('yellow', 'restart Claude Code / OpenClaw gateway')}\n\n`,
    );
  } else if (latest.version === null) {
    // #248: `mainUpdated` is false both when we ARE current AND when the
    // registry lookup never resolved (E401, ENOTFOUND, timeout) — `header()`
    // already tells the two apart; the footer must not close an E401/ENOTFOUND
    // run with the same reassuring "already on latest" line as a real check.
    const reason = latest.reason ? ` — ${latest.reason}` : '';
    process.stdout.write(`  ${paint('yellow', '⚠')}  ${paint('bold', 'done')}  ${paint('gray', `in ${elapsed} · latest version unknown${reason}`)}\n\n`);
  } else {
    process.stdout.write(`  ${paint('green', '✓')}  ${paint('bold', 'done')}  ${paint('gray', `in ${elapsed} · already on latest`)}\n\n`);
  }
}

// ── Steps ───────────────────────────────────────────────────

function readPackageVersion(): string {
  const __filename = fileURLToPath(import.meta.url);
  const pkgPath = path.resolve(path.dirname(__filename), '..', '..', 'package.json');
  return JSON.parse(fs.readFileSync(pkgPath, 'utf-8')).version ?? 'unknown';
}

export interface LatestVersionResult {
  version: string | null;
  /**
   * Why the lookup failed (#248). E401 (bad/expired token), ENOTFOUND
   * (offline/DNS) and a proxy failure all used to collapse to a bare `null`,
   * which the caller reported as "registry unreachable" — true for
   * ENOTFOUND, actively wrong for a rejected token, and downstream a bare
   * `null` reads as "already up to date".
   */
  reason?: string;
}

/** `run` is injectable so the failure path can be tested without a real spawn. */
export async function fetchLatestVersion(deps: { run?: typeof runQuiet } = {}): Promise<LatestVersionResult> {
  const run = deps.run ?? runQuiet;
  try {
    const { stdout } = await run('npm', ['view', 'shieldcortex', 'version'], { timeout: 10000 });
    return { version: stdout.trim() || null };
  } catch (err) {
    return { version: null, reason: describeRunFailure(err).reason };
  }
}

async function stepNpmPackage(
  currentVersion: string,
  latest: LatestVersionResult,
  force: boolean,
): Promise<{ updated: boolean; result: StepResult }> {
  const latestVersion = latest.version;
  if (!latestVersion) {
    const summary = latest.reason ? `registry check failed — ${latest.reason}` : 'registry unreachable';
    const result = await step('npm package', async () => ({ status: 'warn' as const, summary }));
    return { updated: false, result };
  }
  if (latestVersion === currentVersion && !force) {
    const result = await step('npm package', async () => `v${currentVersion} (current)`);
    return { updated: false, result };
  }
  if (latestVersion === currentVersion && force) {
    const result = await step('npm package', async () => {
      await runQuiet('npm', ['install', '-g', 'shieldcortex@latest', '--silent', '--no-audit', '--no-fund'], { timeout: 180000 });
      return `v${currentVersion} (reinstalled)`;
    });
    return { updated: true, result };
  }
  const result = await step('npm package', async () => {
    await runQuiet('npm', ['install', '-g', 'shieldcortex@latest', '--silent', '--no-audit', '--no-fund'], { timeout: 180000 });
    return `v${currentVersion} → v${latestVersion}`;
  });
  return { updated: true, result };
}

/**
 * Verify the better-sqlite3 native binding loads and self-heal it if not.
 *
 * `npm install -g` reports success on its exit code even when the native
 * binding never built for this platform/ABI (common on arm64 / a Node newer
 * than the prebuilds) — leaving the package installed-but-broken. This step
 * runs AFTER the install completes (not nested inside it), rebuilds the binding
 * in the correct install dir if it's missing, and reports honestly.
 */
async function stepVerifyEngine(): Promise<{ remediation: string | null }> {
  let remediation: string | null = null;
  await step('Database engine', async () => {
    const { ensureNativeBinding } = await import('../setup/native-binding.js');
    const r = await ensureNativeBinding();
    if (r.status === 'ok') return 'native binding OK';
    if (r.status === 'healed') return 'rebuilt native binding';
    remediation = r.remediation ?? null;
    return { status: 'warn' as const, summary: 'binding failed — run `shieldcortex repair`' };
  });
  return { remediation };
}

/**
 * Is the realtime plugin registered with OpenClaw's plugin registry?
 *
 * OpenClaw's modern `openclaw plugins install` stores the package under
 * `~/.openclaw/npm/projects/<name>-<hash>/node_modules/` and records it in
 * `~/.openclaw/plugins/installs.json`. The old detection only checked
 * `~/.openclaw/extensions/` (the legacy file-copy layout) and a non-existent
 * `~/.openclaw/npm/node_modules/...` path, so a registry-managed install was
 * invisible — `update` reported "not installed" and silently SKIPPED it,
 * leaving the plugin stale while the npm package moved on. Read the registry
 * (the authoritative source `doctor` also trusts) instead.
 */
export interface RegistryReadResult {
  registered: boolean;
  /**
   * True when `installs.json` exists but could not be read or parsed (#248).
   * A permission-denied or truncated registry is NOT evidence the plugin is
   * absent — it means the host's install state is unknown. Callers that
   * would otherwise report "not installed" on `registered: false` must check
   * this first, or an unreadable registry renders a false-green skip on a
   * host that update never actually touched.
   */
  unreadable: boolean;
  detail?: string;
}

/**
 * Read whether the realtime plugin is registered with OpenClaw, distinguishing
 * "genuinely not installed" from "installs.json exists but could not be
 * confirmed" (#248). `isRealtimePluginRegistered` collapses both into `false`
 * for callers that only need a yes/no; `stepOpenClawPlugin` needs the
 * distinction so it never reports "not installed" on a registry it could not
 * actually read.
 */
export function readRealtimePluginRegistration(home: string): RegistryReadResult {
  // An on-disk install resolves even on boxes whose authoritative plugin state
  // is SQLite-only (no legacy installs.json) — check that first.
  if (resolveRealtimePluginInstallPath(home)) return { registered: true, unreadable: false };

  const installsPath = path.join(home, '.openclaw', 'plugins', 'installs.json');

  // No existsSync pre-check: it swallows a traversal EACCES on the plugins
  // DIRECTORY into a plain `false`, rendering the exact false-green "not
  // installed" skip #248 exists to kill — at directory level instead of file
  // level (sudo-damaged perms under user dirs are a documented fleet failure
  // mode). Read directly and branch on the errno; this also removes the
  // exists→read TOCTOU.
  let raw: string;
  try {
    raw = fs.readFileSync(installsPath, 'utf-8');
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === 'ENOENT' || code === 'ENOTDIR') return { registered: false, unreadable: false };
    return {
      registered: false,
      unreadable: true,
      detail: sanitiseForReport(
        `could not read installs.json: ${err instanceof Error ? err.message : String(err)}`,
        { home },
      ),
    };
  }

  let json: unknown;
  try {
    json = JSON.parse(raw);
  } catch {
    // #248: V8 embeds up to ~30 chars of the raw file in one of its two
    // parse-error forms, so including `err.message` here would echo a
    // corrupt registry's own head bytes to the terminal. The parse offset
    // tells an operator nothing they cannot get by opening the file — drop
    // it entirely rather than try to sanitise it.
    return {
      registered: false,
      unreadable: true,
      detail: 'installs.json is malformed JSON',
    };
  }

  if (!json || typeof json !== 'object' || Array.isArray(json)) {
    return {
      registered: false,
      unreadable: true,
      detail: 'installs.json has invalid registry shape',
    };
  }
  const registry = json as { installRecords?: Record<string, unknown>; plugins?: Array<{ pluginId?: string }> };

  if (registry.installRecords && Object.prototype.hasOwnProperty.call(registry.installRecords, 'shieldcortex-realtime')) {
    return { registered: true, unreadable: false };
  }
  const registered = Array.isArray(registry.plugins) && registry.plugins.some((p) => p?.pluginId === 'shieldcortex-realtime');
  return { registered, unreadable: false };
}

export function isRealtimePluginRegistered(home: string): boolean {
  return readRealtimePluginRegistration(home).registered;
}

/** `run`/`rm` are injectable so the failure paths can be tested without a real spawn or a root-owned dir. */
export async function stepOpenClawPlugin(
  home: string,
  deps: { run?: typeof runQuiet; rm?: typeof fs.rmSync } = {},
): Promise<StepResult> {
  const run = deps.run ?? runQuiet;
  const rm = deps.rm ?? fs.rmSync;
  const extDir = path.join(home, '.openclaw', 'extensions', 'shieldcortex-realtime');
  const legacy = fs.existsSync(extDir);
  const registration = readRealtimePluginRegistration(home);
  // #248: an unreadable/malformed registry is not evidence the plugin is
  // absent — reporting "not installed" here is a false-green skip on a host
  // whose actual state we could not confirm.
  if (!legacy && registration.unreadable) {
    return await step('OpenClaw plugin', async () => ({
      status: 'warn' as const,
      summary: `plugin registry unreadable — ${registration.detail ?? 'could not confirm install state'}`,
    }));
  }
  if (!legacy && !registration.registered) {
    return await step('OpenClaw plugin', async () => ({ status: 'skip' as const, summary: 'not installed' }));
  }
  return await step('OpenClaw plugin', async () => {
    // Drop any legacy file-copied extension so OpenClaw's registry copy is the
    // single source of truth (prevents the dup-install state doctor flags).
    let purgeFailure: string | null = null;
    if (legacy) {
      try {
        rm(extDir, { recursive: true, force: true });
      } catch (err) {
        // #248: this used to be `catch { /* ignore */ }`. A denied purge
        // (root-owned dir, EPERM) left the duplicate in place with no hint it
        // was even attempted — the next `doctor` run reported a dup install
        // as if nothing had tried to fix it.
        purgeFailure = err instanceof Error ? err.message : String(err);
      }
    }
    const before = readInstalledRealtimePluginVersion(home);
    try {
      // `openclaw plugins update` no-ops when OpenClaw recorded an exact-pinned
      // spec (observed 2026-06-09: the index pinned @4.30.2 → "up to date" while
      // npm had 4.31.0). A forced @latest install reliably advances the plugin
      // AND rewrites the tracked spec to @latest so future updates work.
      await run('openclaw', ['plugins', 'install', '--force', '@drakon-systems/shieldcortex-realtime@latest'],
        { timeout: 120000, env: { ...process.env, HOME: home } });
      // Report the ACTUAL on-disk transition, not just command success — the old
      // "updated via openclaw" was printed even when the version never moved.
      const after = readInstalledRealtimePluginVersion(home);
      const transition =
        before && after && before !== after ? `${before} → ${after}` :
        after ? `up to date (v${after})` :
        'reinstalled';
      if (purgeFailure) {
        return {
          status: 'warn' as const,
          summary: `${transition} — legacy copy left behind`,
          detail: [sanitiseForReport(`could not remove legacy extension at ${extDir}: ${purgeFailure}`, { home })],
        };
      }
      return transition;
    } catch (err) {
      // Don't propagate — surface as warn instead of failing the whole flow.
      //
      // #221: this used to restate the command that had just failed and throw
      // the reason away. When OpenClaw's config is invalid it says so exactly,
      // names the offending key and gives the repair — and an operator chased
      // this line for five days because that message was discarded here while
      // `runQuiet` had it in hand the whole time.
      const report = describeRunFailure(err);
      return {
        status: 'warn' as const,
        summary: `update failed — ${report.reason}`,
        detail: purgeFailure
          ? [...report.detail, sanitiseForReport(`also: could not remove legacy extension at ${extDir}: ${purgeFailure}`, { home })]
          : report.detail,
        truncated: report.truncated,
      };
    }
  });
}

async function stepOpenClawSkill(home: string): Promise<StepResult> {
  // #179: this step used to be four stacked failures — it spawned a bare
  // `openclaw` (invisible to non-interactive PATH on two of five fleet hosts),
  // omitted the acknowledge flag ClawHub now requires (so even a resolvable
  // binary cancelled), skipped silently when no copy existed, and reported
  // "@latest installed" off the exit code without reading what landed. The
  // measured result: a box carrying a skill 21 releases stale with every
  // surface green. Now: resolved binary, acknowledge flag, verify-by-reading,
  // and the skip names the command that installs.
  const { resolveOpenClawBinary, findInstalledSkillDirs, readInstalledSkillVersion } =
    await import('../setup/openclaw.js');
  if (findInstalledSkillDirs(home).length === 0) {
    return await step('OpenClaw skill', async () => ({
      status: 'skip' as const,
      summary: 'not installed — `shieldcortex openclaw skill install` adds it',
    }));
  }
  return await step('OpenClaw skill', async () => {
    const bin = resolveOpenClawBinary(home);
    if (!bin) return { status: 'warn' as const, summary: 'openclaw binary not found — run `shieldcortex openclaw skill install`' };
    try {
      await runQuiet(bin, ['skills', 'install', 'shieldcortex', '--force', '--acknowledge-clawhub-risk'], {
        timeout: 120000,
        env: { ...process.env, HOME: home },
      });
      const dirs = findInstalledSkillDirs(home);
      const v = dirs.length > 0 ? readInstalledSkillVersion(dirs[0]) : null;
      return v ? `v${v} installed` : { status: 'warn' as const, summary: 'installed but version unreadable' };
    } catch (err) {
      // #221: same defect as the plugin step, and worse here — ClawHub skill
      // installs fail for several distinct reasons (moderation lag, the
      // acknowledge flag, an invalid OpenClaw config) and all of them read
      // identically once the reason is dropped.
      const report = describeRunFailure(err);
      return {
        status: 'warn' as const,
        summary: `reinstall failed — ${report.reason}`,
        detail: report.detail,
        truncated: report.truncated,
      };
    }
  });
}

async function stepClaudeHooks(): Promise<StepResult> {
  return await step('Claude Code hooks', async () => {
    // setupHooks logs its own progress; capture it so we can summarise.
    const logBuffer: string[] = [];
    const origLog = console.log;
    const origWarn = console.warn;
    console.log = (...args: unknown[]) => { logBuffer.push(args.map(String).join(' ')); };
    console.warn = (...args: unknown[]) => { logBuffer.push(args.map(String).join(' ')); };
    try {
      const { setupHooks } = await import('../setup/settings-hooks.js');
      setupHooks();
    } finally {
      console.log = origLog;
      console.warn = origWarn;
    }
    const added = logBuffer.filter((l) => l.includes('+ Hook:')).length;
    const migrated = logBuffer.filter((l) => l.includes('migrated from npx')).length;
    const timeoutsUpdated = logBuffer.filter((l) => l.includes('timeout')).length;
    if (added === 0 && migrated === 0 && timeoutsUpdated === 0) {
      return 'all canonical';
    }
    const parts: string[] = [];
    if (added > 0) parts.push(`${added} added`);
    if (migrated > 0) parts.push(`${migrated} migrated`);
    if (timeoutsUpdated > 0) parts.push(`${timeoutsUpdated} timeout fix`);
    return parts.join(', ');
  });
}

// ── Dashboard discovery hint ────────────────────────────────

/**
 * After a successful update, surface the dashboard command on non-headless
 * systems where it isn't already running. The dashboard never auto-starts;
 * this is purely a "did you know?" line.
 */
async function maybePrintDashboardHint(): Promise<void> {
  try {
    const { getDashboardHint } =
      // @ts-expect-error — importing a .mjs hook util that has no .d.ts
      await import('../../scripts/lib/dashboard-hint.mjs');
    const hint = (await getDashboardHint()) as
      | {
          title: string;
          command: string;
          url: string;
          detail: string;
          alwaysOnCommand?: string;
          alwaysOnDetail?: string;
        }
      | null;
    if (!hint) return;

    process.stdout.write(`  ${paint('cyan', hint.title)}:\n`);
    process.stdout.write(`     ${paint('yellow', hint.command)}  ${paint('gray', `→ ${hint.url}`)}\n`);
    process.stdout.write(`     ${paint('gray', hint.detail)}\n`);
    if (hint.alwaysOnCommand) {
      process.stdout.write(`     ${paint('yellow', hint.alwaysOnCommand)}  ${paint('gray', hint.alwaysOnDetail ?? '')}\n`);
    }
    process.stdout.write('\n');
  } catch { /* hint is best-effort */ }
}

// ── 4.11.0 boundary notice (preserved from old flow) ────────

function maybePrint411Notice(currentVersion: string, mainUpdated: boolean): void {
  if (!mainUpdated || !/^\d+\.\d+\.\d+/.test(currentVersion)) return;
  const [maj, min] = currentVersion.split('.').map(Number);
  if (!(maj < 4 || (maj === 4 && min < 11))) return;

  process.stdout.write('\n');
  process.stdout.write(`  ${paint('yellow', '!')}  ${paint('bold', 'v4.11.0 default behaviour changes')}\n`);
  process.stdout.write('     • Proactive recall on prompt submit is now OFF by default.\n');
  process.stdout.write('     • Tool-call interceptor no longer blocks critical/high writes with approval prompts.\n');
  process.stdout.write('     • SessionStart preamble OFF; memory cap reduced 15 → 5.\n');
  process.stdout.write('     • PreCompact thresholds raised; auto-memories cap 5 → 2.\n');
  process.stdout.write(`     ${paint('gray', 'restore pre-4.11 with: ')}${paint('cyan', 'shieldcortex config --restore-4.10-defaults')}\n`);
  process.stdout.write(`     ${paint('gray', 'changelog: ')}${paint('cyan', 'https://github.com/Drakon-Systems-Ltd/ShieldCortex/blob/main/CHANGELOG.md')}\n\n`);
}

// ── #171: the two install-path fixes update was missing ─────

/**
 * Harden state permissions — the #163 fix, which `update` silently skipped.
 *
 * The audit hardening runs in `setupClaudeMd()` step 5, and `install` reaches
 * it. `update` calls `setupHooks()` DIRECTLY, so every box that upgraded via
 * `shieldcortex update` rather than the full install command kept its
 * world-readable memories.db. The recurring codebase defect, again: a fix that
 * lands on one of two call sites. Both surfaces now run the same helper.
 */
async function stepStatePermissions(): Promise<StepResult> {
  return await step('State permissions', async () => {
    const { secureStatePermissions } = await import('../setup/state-permissions.js');
    const { getConfigDir } = await import('../cloud/config.js');
    const findings = secureStatePermissions(getConfigDir());
    const fixed = findings.filter((f) => f.fixed).length;
    const failed = findings.length - fixed;
    if (failed > 0) return { status: 'warn' as const, summary: `${failed} path(s) could not be tightened` };
    return fixed > 0 ? `tightened ${fixed} path(s) to owner-only` : 'owner-only';
  });
}

/**
 * Finish by proving the update actually PROTECTS the box (#156/#171).
 *
 * Before this, `update` force-installed the plugin, printed the on-disk
 * version transition, and left the gateway running the OLD build with one gray
 * "restart …" hint in the footer. That gap — on-disk current, gateway stale —
 * is the exact state three fleet boxes spent this week stuck in, and the state
 * an operator explicitly cannot diagnose from our own output (doctor reads the
 * disk; the gateway enforces from memory).
 *
 * So update now ends the same way repair does: reconcile → restart → wait for
 * the gateway to prove it is the new process → self-check → one plain-English
 * verdict line. Consent follows #156 exactly — an interactive terminal IS the
 * consent (you typed `update`; a plugin update that leaves the old build
 * enforcing is not an update), while headless runs still require the explicit
 * envs and degrade to today's hint rather than restarting a gateway out from
 * under an agent.
 *
 * The dynamic import is deliberate: npm has just replaced this package on
 * disk, so importing here loads the FRESHLY INSTALLED reconcile/self-check —
 * the new version verifies itself with its own logic, not last release's.
 */
export async function stepVerifyProtection(home: string): Promise<void> {
  // #248: `isRealtimePluginRegistered` collapses "genuinely not installed"
  // and "installs.json exists but could not be confirmed" into the same
  // `false`, which made an unreadable registry return here silently — the
  // protection self-check never ran, and the run still ended green with no
  // hint it had been skipped. Read the split result so "unreadable" gets
  // its own branch instead of falling through the same gate as "absent".
  const registration = readRealtimePluginRegistration(home);
  if (registration.unreadable) {
    process.stdout.write('\n');
    process.stdout.write(
      `  ${paint('yellow', '!')}  ${paint('gray', `protection check skipped — plugin registry unreadable: ${registration.detail ?? 'could not confirm install state'}`)}\n`,
    );
    return;
  }
  if (!registration.registered) return;
  process.stdout.write('\n');
  try {
    const { reconcileOpenClawPluginState, formatReconcileReport } = await import('../setup/openclaw-reconcile.js');
    // Expected version read fresh from disk — after the npm step this is the
    // NEW build, and pinning expectations to the in-process (old) version
    // would certify the very staleness this step exists to end.
    const result = await reconcileOpenClawPluginState({ home, expectedVersion: readPackageVersion() });
    for (const line of formatReconcileReport(result)) {
      process.stdout.write(`  ${line}\n`);
    }
    if (result.applied && !result.ok) process.exitCode = 1;
  } catch (err) {
    const msg = sanitiseForReport(err instanceof Error ? err.message : String(err), { home });
    process.stdout.write(`  ${paint('gray', `protection check skipped — ${msg}`)}\n`);
  }
}

// ── Public entry ────────────────────────────────────────────

export async function runUpdate(): Promise<void> {
  const home = homedir();
  const currentVersion = readPackageVersion();
  const flowStart = Date.now();
  const force = process.argv.includes('--force') || process.argv.includes('-f');

  // Header — show current version immediately, then update with latest once we know it.
  // (We resolve `latest` before drawing the arrow so the banner is correct.)
  const latest = await fetchLatestVersion();
  header(currentVersion, latest.version);
  if (force) {
    process.stdout.write(`  ${paint('yellow', '!')}  ${paint('gray', '--force: reinstall everything regardless of version')}\n\n`);
  }

  let mainUpdated = false;
  try {
    const npmStep = await stepNpmPackage(currentVersion, latest, force);
    mainUpdated = npmStep.updated;
  } catch {
    // npm failure already surfaced by step(); continue with reconcile.
  }

  // Verify (and self-heal) the native DB binding after the install completes.
  // Runs unconditionally: a pre-existing broken binding heals on any update.
  const engineResult = await stepVerifyEngine();

  await stepOpenClawPlugin(home);
  await stepOpenClawSkill(home);
  await stepClaudeHooks();
  await stepStatePermissions();

  footer(Date.now() - flowStart, mainUpdated, latest);

  // The verdict comes AFTER the footer so the last thing on screen is the one
  // line that answers "am I protected?" — not a spinner summary.
  await stepVerifyProtection(home);

  // If the binding couldn't be auto-healed, print the exact copy-paste fix.
  if (engineResult.remediation) {
    process.stdout.write(`\n  ${paint('yellow', '⚠')}  ${paint('bold', 'Database engine could not be rebuilt automatically.')}\n`);
    for (const line of engineResult.remediation.split('\n')) {
      process.stdout.write(`     ${paint('gray', line)}\n`);
    }
    process.stdout.write('\n');
  }

  // #309 — after the package is current, surface new/changed cron-referenced
  // scripts for TTY batch review. Headless updates only print a pointer line;
  // never auto-pin and never fail the update if discovery is weird.
  try {
    const { maybeReviewAllowlistAfterUpdate } = await import('./allowlist-scan.js');
    await maybeReviewAllowlistAfterUpdate({
      log: (m: string) => process.stdout.write(`  ${paint('gray', m)}\n`),
    });
  } catch {
    /* update must not fail on allowlist scan */
  }

  maybePrint411Notice(currentVersion, mainUpdated);
  await maybePrintDashboardHint();
}
