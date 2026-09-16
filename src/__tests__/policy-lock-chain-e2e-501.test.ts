/**
 * #501 — the PROVEN CHAIN: one lock, three built surfaces, three OS processes.
 *
 * `policy-lock-dist-regression-501` proves the lock through the built CLI and
 * the built Claude Code hook. It cannot reach the third surface. The OpenClaw
 * plugin is compiled by a SEPARATE tsc project (`tsconfig.openclaw-plugin.json`
 * → `plugins/openclaw/dist/`), reaches the precedence rules through a bare
 * `import('shieldcortex/defence')` that only resolves on a real install layout,
 * and carries its own inline probe. Every one of those is a build-and-packaging
 * property, invisible to an in-process unit seam: a plugin that compiled but
 * whose `shieldcortex/defence` specifier no longer resolved would keep every
 * unit test green while silently enforcing nothing.
 *
 * So this suite stages an install the way a host actually has one —
 *
 *     <stage>/node_modules/shieldcortex  ->  the repo (its `exports` map
 *                                            points `./defence` at dist/)
 *     <stage>/plugin/                        a copy of the BUILT plugin dist
 *
 * — and drives it from a child process, with the same SC-02 forge the
 * regression suite uses: a `config.json` whose embedded `_sig` genuinely
 * verifies while saying `actionGuard.enabled: false`, plus a same-UID
 * `policy.json`.
 *
 * The chain claim is then stated as an equality, not three separate greens:
 * with ONE lock on disk, the hook, the CLI and the plugin — three programs, no
 * shared process state, two separate build outputs — must reach the same
 * posture. A fix that held in only two of them is the defect #501 is about.
 */
import { spawnSync } from 'node:child_process';
import { createHmac, randomBytes } from 'node:crypto';
import { cpSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from '@jest/globals';
import { requireFreshBuiltArtefacts } from './built-artefact-freshness.js';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const DIST_ENTRY = join(repoRoot, 'dist', 'index.js');
const HOOK = join(repoRoot, 'scripts', 'pre-tool-hook.mjs');
const PLUGIN_DIST = join(repoRoot, 'plugins', 'openclaw', 'dist');

/** SC-01: assembled char by char — this file is scanned by the guard it drives. */
const SC01_CATASTROPHIC = ['r', 'm', ' ', '-', 'r', 'f', ' ', '/'].join('');

/** Sources whose behaviour this suite asserts through the built output. */
const SOURCES_UNDER_TEST = [
  join(repoRoot, 'src', 'index.ts'),
  join(repoRoot, 'src', 'cloud', 'config.ts'),
  join(repoRoot, 'src', 'cloud', 'cli.ts'),
  join(repoRoot, 'src', 'defence', 'index.ts'),
  join(repoRoot, 'src', 'defence', 'iron-dome', 'policy-lock.ts'),
  join(repoRoot, 'src', 'defence', 'iron-dome', 'protected-root.ts'),
  join(repoRoot, 'plugins', 'openclaw', 'index.ts'),
];

/**
 * The child program. Written to disk rather than passed to `node -e` so the
 * stack of any failure names a real file, and kept OUTSIDE the staged install
 * on purpose: a bare specifier in an ES module resolves from the importing
 * module's own URL, so it is the staged plugin copy — not this driver — whose
 * location decides whether `shieldcortex/defence` is found. Staging the driver
 * next to the symlink would have hidden a plugin that could not resolve it.
 */
const DRIVER = `
const CATASTROPHIC = ${JSON.stringify(SC01_CATASTROPHIC.split(''))}.join('');
const plugin = (await import(process.env.SC501_PLUGIN_ENTRY)).default;

const hooks = new Map();
const commands = new Map();
const logs = [];
const warnings = [];
// The degrade notice is a console.warn, not an api.logger call — it has to
// survive a host that supplies no logger at all.
const realWarn = console.warn;
console.warn = (...parts) => { warnings.push(parts.map(String).join(' ')); };

plugin.register({
  version: '2026.5.20',
  // The openclaw.json plugin entry: an unsigned, same-UID file that deep-merges
  // OVER the shield config. Injected per-case so a test can make it lie, and in
  // the host's REAL shape (\`plugins.entries.<id>.config\`) — a flat object here
  // is silently dropped by extractPluginConfig, which would leave the test
  // asserting about an override that never existed.
  config: JSON.parse(process.env.SC501_PLUGIN_ENTRY_CONFIG || '{}'),
  logger: { info: (m) => logs.push(String(m)), warn: (m) => logs.push(String(m)), error: (m) => logs.push(String(m)) },
  registerCommand: (c) => commands.set(c.name, c),
  registerHook: () => {},
  on: (name, fn) => hooks.set(name, fn),
});

const beforeToolCall = hooks.get('before_tool_call');
async function call(command) {
  if (!beforeToolCall) return { unregistered: true };
  try {
    return (await beforeToolCall({ toolName: 'Bash', params: { command } }, { sessionId: 'sc-501-chain' })) ?? null;
  } catch (err) {
    return { threw: String(err) };
  }
}

const catastrophic = await call(CATASTROPHIC);
const benign = await call('ls -la');
const status = commands.get('shieldcortex-status');
const statusText = status ? (await status.handler()).text : '';
console.warn = realWarn;

// Sentinel-prefixed: the plugin logs to stdout on some paths and the harness
// must read OUR line, not whatever else the load printed.
const line = 'SC501_RESULT ' + JSON.stringify({
  catastrophic,
  benign,
  guardLine: (statusText.split('\\n').find((l) => l.includes('Action guard')) || '').trim(),
  warnings,
  logs,
});
await new Promise((done) => process.stdout.write(line + '\\n', done));
process.exit(0);
`;

/** A staged install: the built plugin dist, with or without a resolvable package. */
function stageInstall(withShieldCortexResolvable: boolean): string {
  const stage = mkdtempSync(join(tmpdir(), 'sc-501-chain-stage-'));
  cpSync(PLUGIN_DIST, join(stage, 'plugin'), { recursive: true });
  if (withShieldCortexResolvable) {
    mkdirSync(join(stage, 'node_modules'));
    symlinkSync(repoRoot, join(stage, 'node_modules', 'shieldcortex'), 'dir');
  }
  return stage;
}

let installedStage: string;
let brokenStage: string;
let driverPath: string;
let driverDir: string;

let home: string;
let configDir: string;
let protectedRoot: string;

beforeAll(() => {
  requireFreshBuiltArtefacts({
    repoRoot,
    sources: SOURCES_UNDER_TEST,
    artefacts: [
      DIST_ENTRY,
      join(repoRoot, 'dist', 'defence', 'index.js'),
      join(repoRoot, 'dist', 'defence', 'iron-dome', 'policy-lock.js'),
      join(PLUGIN_DIST, 'index.js'),
    ],
  });
  installedStage = stageInstall(true);
  // The same built plugin with the package NOT resolvable — a broken or
  // half-removed install, which is the state "just delete dist" produces.
  brokenStage = stageInstall(false);
  driverDir = mkdtempSync(join(tmpdir(), 'sc-501-chain-driver-'));
  driverPath = join(driverDir, 'drive-plugin.mjs');
  writeFileSync(driverPath, DRIVER);
});

afterAll(() => {
  for (const dir of [installedStage, brokenStage, driverDir]) {
    if (dir) rmSync(dir, { recursive: true, force: true });
  }
});

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'sc-501-chain-home-'));
  configDir = join(home, '.shieldcortex');
  mkdirSync(configDir, { recursive: true });
  protectedRoot = mkdtempSync(join(tmpdir(), 'sc-501-chain-root-'));
});

afterEach(() => {
  rmSync(home, { recursive: true, force: true });
  rmSync(protectedRoot, { recursive: true, force: true });
});

/**
 * A config.json whose embedded `_sig` GENUINELY verifies — same forge as
 * `policy-lock-dist-regression-501`, which asserts that doctor accepts it.
 * Mirrors `canonicalBodyForSig` + `signConfig` in src/cloud/config.ts.
 */
function forgeSignedConfig(body: Record<string, unknown>): void {
  const key = randomBytes(32).toString('hex');
  writeFileSync(join(configDir, '.integrity-key'), key, { mode: 0o600 });
  const sig = createHmac('sha256', key).update(JSON.stringify(body, null, 2), 'utf-8').digest('hex');
  writeFileSync(join(configDir, 'config.json'), `${JSON.stringify({ ...body, _sig: sig }, null, 2)}\n`);
}

/** The guard switched off in signed bytes, on every key all three surfaces read. */
const GUARD_OFF_EVERYWHERE = {
  actionGuard: { enabled: false, enforce: false, autoApprove: ['anything'], broker: { enabled: true } },
  interceptor: { enabled: true, actionGuard: { enabled: false, enforce: false, autoApprove: ['anything'] } },
  defenceMode: 'permissive',
};

/** Drop a same-UID policy.json — a lock this very process could have written. */
function forgePolicyLock(policy: unknown = { actionGuard: { enabled: false, enforce: false } }): void {
  writeFileSync(join(protectedRoot, 'policy.json'), JSON.stringify(policy, null, 2));
}

function env(extra: Record<string, string> = {}): NodeJS.ProcessEnv {
  return {
    ...process.env,
    HOME: home,
    USERPROFILE: home,
    SHIELDCORTEX_CONFIG_DIR: configDir,
    SHIELDCORTEX_PROTECTED_ROOT: protectedRoot,
    ...extra,
  };
}

// ---- surface 1: the built Claude Code hook -------------------------------

function runHook(command: string): { decision: string | null; reason: string } {
  const run = spawnSync(process.execPath, [HOOK], {
    input: JSON.stringify({
      session_id: 'sc-501-chain',
      cwd: home,
      permission_mode: 'default',
      hook_event_name: 'PreToolUse',
      tool_name: 'Bash',
      tool_input: { command },
    }),
    env: env(), encoding: 'utf8', timeout: 60_000,
  });
  const stdout = (run.stdout ?? '').trim();
  if (!stdout) return { decision: null, reason: '' };
  const parsed = JSON.parse(stdout);
  return {
    decision: parsed.hookSpecificOutput?.permissionDecision ?? null,
    reason: parsed.hookSpecificOutput?.permissionDecisionReason ?? '',
  };
}

// ---- surface 2: the built CLI -------------------------------------------

function runCli(args: string[]): { stdout: string; stderr: string; status: number } {
  const run = spawnSync(process.execPath, [DIST_ENTRY, ...args], {
    env: env(), encoding: 'utf8', timeout: 120_000,
  });
  return { stdout: run.stdout ?? '', stderr: run.stderr ?? '', status: run.status ?? 0 };
}

// ---- surface 3: the built OpenClaw plugin --------------------------------

interface PluginRun {
  catastrophic: { block?: boolean; blockReason?: string; unregistered?: boolean; threw?: string } | null;
  benign: unknown;
  guardLine: string;
  warnings: string[];
  logs: string[];
}

function runPlugin(options: { stage?: string; entryConfig?: unknown } = {}): PluginRun {
  const stage = options.stage ?? installedStage;
  const run = spawnSync(process.execPath, [driverPath], {
    cwd: stage,
    env: env({
      SC501_PLUGIN_ENTRY: join(stage, 'plugin', 'index.js'),
      SC501_PLUGIN_ENTRY_CONFIG: JSON.stringify(
        options.entryConfig === undefined
          ? {}
          : { plugins: { entries: { 'shieldcortex-realtime': { config: options.entryConfig } } } },
      ),
    }),
    encoding: 'utf8',
    timeout: 120_000,
  });
  const line = (run.stdout ?? '').split('\n').find((l) => l.startsWith('SC501_RESULT '));
  if (!line) {
    throw new Error(`#501 plugin driver produced no result.\nstdout: ${run.stdout}\nstderr: ${run.stderr}`);
  }
  return JSON.parse(line.slice('SC501_RESULT '.length)) as PluginRun;
}

// -------------------------------------------------------------------------

describe('#501 the chain, with NO lock — the 5.0.5 outcome, on all three surfaces', () => {
  // The negative half, and the reason the positive half means anything: with
  // the signature intact and no lock, a one-line edit to a file the agent owns
  // takes the guard off EVERYWHERE, including for `rm -rf /`.
  beforeEach(() => { forgeSignedConfig(GUARD_OFF_EVERYWHERE); });

  it('the openclaw.json entry really IS the last word here — the fixture has teeth', () => {
    // The counterpart of the regression suite's "a recomputed _sig is accepted"
    // row. The entry-override assertion further down is only meaningful if the
    // entry plane is live in this harness at all: `extractPluginConfig` reads
    // `plugins.entries.<id>.config` and silently drops any other shape, so a
    // malformed fixture would leave that test passing for the wrong reason.
    // Here the entry TIGHTENS what the signed config loosened, with no lock
    // anywhere, and the built plugin must follow it.
    const plugin = runPlugin({
      entryConfig: { interceptor: { enabled: true, actionGuard: { enabled: true, enforce: true } } },
    });
    expect(plugin.guardLine).toMatch(/Action guard: enforce/);
    expect(plugin.catastrophic?.block).toBe(true);
  }, 180_000);

  it('the hook stays silent, the CLI says Off, and the plugin ALLOWS `rm -rf /`', () => {
    expect(runHook(SC01_CATASTROPHIC).decision).toBeNull();

    const cli = runCli(['config', '--cloud-status']);
    expect(cli.stdout).toMatch(/Action Guard: Off/);

    const plugin = runPlugin();
    expect(plugin.guardLine).toMatch(/Action guard: off/);
    expect(plugin.catastrophic).toBeNull();
  }, 180_000);
});

describe('#501 the chain, with a same-UID lock — three processes, one posture', () => {
  beforeEach(() => {
    forgeSignedConfig(GUARD_OFF_EVERYWHERE);
    forgePolicyLock();
  });

  it('all three BUILT surfaces enforce, from the same lock, in the same run', () => {
    // The chain assertion. Not "the hook denies" and separately "the CLI
    // reports strict": the same on-disk fixture, read by three programs from
    // two different build outputs, must produce one answer.
    const hook = runHook(SC01_CATASTROPHIC);
    expect(hook.decision).toBe('deny');
    expect(hook.reason).toMatch(/catastrophic/i);

    const cli = runCli(['config', '--cloud-status']);
    expect(cli.stdout).toMatch(/Action Guard: Enforce/);
    expect(cli.stdout).toMatch(/Defence Mode: strict/);

    const plugin = runPlugin();
    expect(plugin.guardLine).toMatch(/Action guard: enforce/);
    expect(plugin.catastrophic?.block).toBe(true);
    expect(plugin.catastrophic?.blockReason).toMatch(/catastrophic/i);
  }, 240_000);

  it('the plugin still allows a benign call — fail-closed, not bricked', () => {
    // §2 of the design doc: an unverifiable lock raises the posture, it does
    // not deny every tool call. An agent that cannot run `ls` teaches the
    // operator to delete the lock.
    expect(runPlugin().benign).toBeNull();
  }, 180_000);

  it('the lock out-ranks the openclaw.json entry, which merges OVER the config', () => {
    // The ordering claim in `applyPolicyLockToPluginConfig`, proven through the
    // built plugin rather than asserted in a comment. The entry is the LAST
    // writer before #501 — and `openclaw-plugin-guard-sync` writes into it —
    // so a lock applied before `mergeConfigs` would be silently overwritten
    // here and nowhere else.
    const plugin = runPlugin({
      entryConfig: { interceptor: { enabled: true, actionGuard: { enabled: false, enforce: false, autoApprove: ['*'] } } },
    });
    expect(plugin.guardLine).toMatch(/Action guard: enforce/);
    expect(plugin.catastrophic?.block).toBe(true);
  }, 180_000);
});

describe('#501 breaking the install is not a bypass, on the plugin surface either', () => {
  it('an unresolvable `shieldcortex/defence` plus a lock forces the strict posture', () => {
    forgeSignedConfig(GUARD_OFF_EVERYWHERE);
    forgePolicyLock();
    const plugin = runPlugin({ stage: brokenStage });

    // What this does and does not claim. The inline probe raises the posture
    // and says so loudly — but the module that IMPLEMENTS the gate is the one
    // that is missing, so no tool call is blocked here. The honest statement is
    // that the reported posture is strict and the operator is told the install
    // is broken; the enforcement itself is restored by `shieldcortex repair`.
    expect(plugin.guardLine).toMatch(/Action guard: enforce/);
    expect(plugin.warnings.join('\n')).toMatch(
      /policy lock is present but the ShieldCortex defence module could not be loaded/,
    );
    expect(plugin.warnings.join('\n')).toMatch(/shieldcortex repair/);
  }, 180_000);

  it('the same broken install with NO lock keeps today\'s behaviour, silently', () => {
    // The other half of the rule. A stale build on an unlocked host must not
    // start narrating policy failures at an operator who has pinned nothing.
    forgeSignedConfig(GUARD_OFF_EVERYWHERE);
    const plugin = runPlugin({ stage: brokenStage });
    expect(plugin.guardLine).toMatch(/Action guard: off/);
    expect(plugin.warnings.join('\n')).not.toMatch(/policy lock is present/);
  }, 180_000);
});
