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
import { describeRunFailure } from '../integrations/child-output.js';
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
}

async function step(
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
    const e = err as Error & { stdout?: string; stderr?: string };
    const captured = (e.stderr || '') + (e.stdout || '');
    if (captured.trim()) {
      process.stderr.write('\n' + paint('gray', '── output ─────────────────────────────────────────') + '\n');
      process.stderr.write(captured.trim() + '\n');
      process.stderr.write(paint('gray', '───────────────────────────────────────────────────') + '\n');
    }
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

function footer(totalMs: number, mainUpdated: boolean): void {
  const elapsed = (totalMs / 1000).toFixed(1) + 's';
  process.stdout.write(
    `\n  ${paint('gray', '──────────────────────────────────────────────────────────────')}\n`,
  );
  if (mainUpdated) {
    process.stdout.write(
      `  ${paint('green', '✓')}  ${paint('bold', 'done')}  ${paint('gray', `in ${elapsed}`)}  ${paint('cyan', '·')}  ${paint('yellow', 'restart Claude Code / OpenClaw gateway')}\n\n`,
    );
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

async function fetchLatestVersion(): Promise<string | null> {
  try {
    const { stdout } = await runQuiet('npm', ['view', 'shieldcortex', 'version'], { timeout: 10000 });
    return stdout.trim() || null;
  } catch {
    return null;
  }
}

async function stepNpmPackage(
  currentVersion: string,
  latestVersion: string | null,
  force: boolean,
): Promise<{ updated: boolean; result: StepResult }> {
  if (!latestVersion) {
    const result = await step('npm package', async () => ({ status: 'warn' as const, summary: 'registry unreachable' }));
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
export function isRealtimePluginRegistered(home: string): boolean {
  // An on-disk install resolves even on boxes whose authoritative plugin state
  // is SQLite-only (no legacy installs.json) — check that first.
  if (resolveRealtimePluginInstallPath(home)) return true;
  try {
    const installsPath = path.join(home, '.openclaw', 'plugins', 'installs.json');
    if (!fs.existsSync(installsPath)) return false;
    const json = JSON.parse(fs.readFileSync(installsPath, 'utf-8')) as {
      installRecords?: Record<string, unknown>;
      plugins?: Array<{ pluginId?: string }>;
    };
    if (json.installRecords && Object.prototype.hasOwnProperty.call(json.installRecords, 'shieldcortex-realtime')) {
      return true;
    }
    return Array.isArray(json.plugins) && json.plugins.some((p) => p?.pluginId === 'shieldcortex-realtime');
  } catch {
    return false; // unreadable registry → treat as not installed
  }
}

/** `run` is injectable so the failure path can be tested without a real spawn. */
export async function stepOpenClawPlugin(
  home: string,
  deps: { run?: typeof runQuiet } = {},
): Promise<StepResult> {
  const run = deps.run ?? runQuiet;
  const extDir = path.join(home, '.openclaw', 'extensions', 'shieldcortex-realtime');
  const legacy = fs.existsSync(extDir);
  const registered = isRealtimePluginRegistered(home);
  if (!legacy && !registered) {
    return await step('OpenClaw plugin', async () => ({ status: 'skip' as const, summary: 'not installed' }));
  }
  return await step('OpenClaw plugin', async () => {
    // Drop any legacy file-copied extension so OpenClaw's registry copy is the
    // single source of truth (prevents the dup-install state doctor flags).
    if (legacy) {
      try { fs.rmSync(extDir, { recursive: true, force: true }); } catch { /* ignore */ }
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
      if (before && after && before !== after) return `${before} → ${after}`;
      if (after) return `up to date (v${after})`;
      return 'reinstalled';
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
        detail: report.detail,
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
async function stepVerifyProtection(home: string): Promise<void> {
  if (!isRealtimePluginRegistered(home)) return;
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
    const msg = err instanceof Error ? err.message : String(err);
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
  const latestVersion = await fetchLatestVersion();
  header(currentVersion, latestVersion);
  if (force) {
    process.stdout.write(`  ${paint('yellow', '!')}  ${paint('gray', '--force: reinstall everything regardless of version')}\n\n`);
  }

  let mainUpdated = false;
  try {
    const npmStep = await stepNpmPackage(currentVersion, latestVersion, force);
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

  footer(Date.now() - flowStart, mainUpdated);

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
  maybePrint411Notice(currentVersion, mainUpdated);
  await maybePrintDashboardHint();
}
