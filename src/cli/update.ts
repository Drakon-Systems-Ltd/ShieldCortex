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
      reject(err);
    });

    child.on('close', (code) => {
      if (timer) clearTimeout(timer);
      if (timedOut) {
        const err = new Error(`timeout: ${cmd} ${args.join(' ')}`) as Error & { stdout?: string; stderr?: string };
        err.stdout = stdout;
        err.stderr = stderr;
        return reject(err);
      }
      if (typeof code === 'number' && code !== 0) {
        const err = new Error(`exit ${code}: ${cmd} ${args.join(' ')}`) as Error & { stdout?: string; stderr?: string };
        err.stdout = stdout;
        err.stderr = stderr;
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

async function stepOpenClawPlugin(home: string): Promise<StepResult> {
  const extDir = path.join(home, '.openclaw', 'extensions', 'shieldcortex-realtime');
  const npmDir = path.join(home, '.openclaw', 'npm', 'node_modules', '@drakon-systems', 'shieldcortex-realtime');
  if (!fs.existsSync(extDir) && !fs.existsSync(npmDir)) {
    return await step('OpenClaw plugin', async () => ({ status: 'skip' as const, summary: 'not installed' }));
  }
  return await step('OpenClaw plugin', async () => {
    try { fs.rmSync(extDir, { recursive: true, force: true }); } catch { /* ignore */ }
    try {
      await runQuiet(
        'openclaw',
        ['plugins', 'install', '--force', '@drakon-systems/shieldcortex-realtime@latest'],
        { timeout: 60000, env: { ...process.env, HOME: home } },
      );
      return '@latest installed';
    } catch {
      // Don't propagate — surface as warn instead of failing the whole flow.
      return { status: 'warn' as const, summary: 'reinstall failed (run manually)' };
    }
  });
}

async function stepOpenClawSkill(home: string): Promise<StepResult> {
  const skillDirs = [
    path.join(home, '.openclaw', 'workspace', 'skills', 'shieldcortex'),
    path.join(home, '.openclaw', 'skills', 'shieldcortex'),
    path.join(home, 'clawd', 'skills', 'shieldcortex'),
    path.join(home, 'friday', 'skills', 'shieldcortex'),
  ];
  if (!skillDirs.find((d) => fs.existsSync(d))) {
    return await step('OpenClaw skill', async () => ({ status: 'skip' as const, summary: 'not installed' }));
  }
  return await step('OpenClaw skill', async () => {
    try {
      await runQuiet('openclaw', ['skills', 'install', 'shieldcortex', '--force'], {
        timeout: 60000,
        env: { ...process.env, HOME: home },
      });
      return '@latest installed';
    } catch {
      return { status: 'warn' as const, summary: 'reinstall failed (run manually)' };
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

  await stepOpenClawPlugin(home);
  await stepOpenClawSkill(home);
  await stepClaudeHooks();

  footer(Date.now() - flowStart, mainUpdated);
  maybePrint411Notice(currentVersion, mainUpdated);
}
