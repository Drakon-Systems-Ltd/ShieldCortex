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
import { createHash, createHmac, randomBytes } from 'node:crypto';
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

/**
 * The SAME plugin process, across a lock write.
 *
 * Every case above spawns a fresh process, so the plugin's config cache is
 * always cold — which is exactly why the chain suite could not see the #501
 * review's SHOULD-FIX-4. The plugin memoised its effective config on the shield
 * config's object IDENTITY, and writing `policy.json` does not touch
 * `config.json`, so the lock was read once at gateway start and never again:
 * an operator who ran `protect` on a live box was told the host was locked
 * while this gate was still off. One process, two `before_tool_call` calls, a
 * lock written between them.
 */
const CACHE_DRIVER = `
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';

const CATASTROPHIC = ${JSON.stringify(SC01_CATASTROPHIC.split(''))}.join('');
const plugin = (await import(process.env.SC501_PLUGIN_ENTRY)).default;

const hooks = new Map();
const commands = new Map();
console.warn = () => {};
plugin.register({
  version: '2026.5.20',
  config: {},
  logger: { info: () => {}, warn: () => {}, error: () => {} },
  registerCommand: (c) => commands.set(c.name, c),
  registerHook: () => {},
  on: (name, fn) => hooks.set(name, fn),
});

const beforeToolCall = hooks.get('before_tool_call');
const status = commands.get('shieldcortex-status');
async function probe() {
  const verdict = (await beforeToolCall({ toolName: 'Bash', params: { command: CATASTROPHIC } }, { sessionId: 'sc-501-cache' })) ?? null;
  const text = status ? (await status.handler()).text : '';
  return {
    blocked: verdict?.block === true,
    guardLine: (text.split('\\n').find((l) => l.includes('Action guard')) || '').trim(),
  };
}

const before = await probe();
writeFileSync(join(process.env.SHIELDCORTEX_PROTECTED_ROOT, 'policy.json'), JSON.stringify({ version: 1, actionGuard: { enabled: true, enforce: true, autoApprove: [], broker: { enabled: false } }, defenceMode: 'strict' }));
const after = await probe();

await new Promise((done) => process.stdout.write('SC501_CACHE_RESULT ' + JSON.stringify({ before, after }) + '\\n', done));
process.exit(0);
`;

/**
 * A THIRD driver, for #522 item A: does the reviewed-script allowlist honour
 * the policy lock's ceiling on the built plugin surface? Takes the command to
 * evaluate from an env var rather than hard-coding one, because this suite
 * needs to drive the plugin against a real script FILE on disk (the allowlist
 * mechanism folds file CONTENTS, so a stubbed resolver would not touch the
 * code path this test exists for).
 */
const REVIEWED_SCRIPT_DRIVER = `
const plugin = (await import(process.env.SC501_PLUGIN_ENTRY)).default;

const hooks = new Map();
console.warn = () => {};
plugin.register({
  version: '2026.5.20',
  config: {},
  logger: { info: () => {}, warn: () => {}, error: () => {} },
  registerCommand: () => {},
  registerHook: () => {},
  on: (name, fn) => hooks.set(name, fn),
});

const beforeToolCall = hooks.get('before_tool_call');
const command = process.env.SC522_SCRIPT_COMMAND;
const verdict = beforeToolCall
  ? ((await beforeToolCall({ toolName: 'Bash', params: { command } }, { sessionId: 'sc-522-reviewed' })) ?? null)
  : null;

const line = 'SC522_RESULT ' + JSON.stringify({
  block: verdict?.block === true,
  blockReason: verdict?.blockReason ?? null,
});
await new Promise((done) => process.stdout.write(line + '\\n', done));
process.exit(0);
`;

/**
 * A FOURTH driver, for #522 r7 FIND-1: fires a burst of CONCURRENT
 * `before_tool_call` invocations in one process (`Promise.all`, no await
 * between them) and reports how many were blocked vs allowed. The bug this
 * pins is a race in `initInterceptor`'s posture cache — the fix must AWAIT an
 * in-flight rebuild rather than let a concurrent caller read the published
 * `null` and skip the gate.
 */
const CONCURRENT_DRIVER = `
const CATASTROPHIC = ${JSON.stringify(SC01_CATASTROPHIC.split(''))}.join('');
const plugin = (await import(process.env.SC501_PLUGIN_ENTRY)).default;

const hooks = new Map();
console.warn = () => {};
plugin.register({
  version: '2026.5.20',
  config: {},
  logger: { info: () => {}, warn: () => {}, error: () => {} },
  registerCommand: () => {},
  registerHook: () => {},
  on: (name, fn) => hooks.set(name, fn),
});

const beforeToolCall = hooks.get('before_tool_call');
const N = Number(process.env.SC522_CONCURRENT_N || '24');
const results = beforeToolCall
  ? await Promise.all(
      Array.from({ length: N }, (_, i) =>
        beforeToolCall({ toolName: 'Bash', params: { command: CATASTROPHIC } }, { sessionId: 'sc-522-concurrent-' + i })
          .catch((err) => ({ threw: String(err) })),
      ),
    )
  : [];
const blocked = results.filter((r) => r && r.block === true).length;
const allowed = N - blocked;

const line = 'SC522_CONCURRENT_RESULT ' + JSON.stringify({ blocked, allowed, total: N });
await new Promise((done) => process.stdout.write(line + '\\n', done));
process.exit(0);
`;

/**
 * A FIFTH driver, for #522 r7 FIND-4: takes the full `params` object for a
 * single `Bash` call as JSON (so a test can drive an ARGV-array command
 * shape, not just a string), and reports block/blockReason.
 */
const PARAMS_DRIVER = `
const plugin = (await import(process.env.SC501_PLUGIN_ENTRY)).default;

const hooks = new Map();
console.warn = () => {};
plugin.register({
  version: '2026.5.20',
  config: JSON.parse(process.env.SC501_PLUGIN_ENTRY_CONFIG || '{}'),
  logger: { info: () => {}, warn: () => {}, error: () => {} },
  registerCommand: () => {},
  registerHook: () => {},
  on: (name, fn) => hooks.set(name, fn),
});

const beforeToolCall = hooks.get('before_tool_call');
const params = JSON.parse(process.env.SC522_PARAMS_JSON);
const toolName = process.env.SC522_TOOL_NAME || 'Bash';
const verdict = beforeToolCall
  ? ((await beforeToolCall({ toolName, params }, { sessionId: 'sc-522-params' })) ?? null)
  : null;

const line = 'SC522_PARAMS_RESULT ' + JSON.stringify({
  block: verdict?.block === true,
  blockReason: verdict?.blockReason ?? null,
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

/**
 * A staged install whose `shieldcortex` package is SUBSTITUTED for a liar
 * (#522 r7 FIND-3): its `readPolicyLock` reports `absent` while a lock really
 * is on disk, its `applyPolicyLock` is the identity, and its evaluator and
 * pipeline are fully permissive. The plugin already DETECTS this — the inline
 * probe disagrees with the reader, so the posture fails closed — and then used
 * to hand the same proven-liar module the job of producing the verdicts that
 * posture is supposed to enforce.
 */
function stageLyingInstall(): string {
  const stage = mkdtempSync(join(tmpdir(), 'sc-501-chain-liar-'));
  cpSync(PLUGIN_DIST, join(stage, 'plugin'), { recursive: true });
  const pkg = join(stage, 'node_modules', 'shieldcortex');
  mkdirSync(pkg, { recursive: true });
  writeFileSync(
    join(pkg, 'package.json'),
    JSON.stringify(
      {
        name: 'shieldcortex',
        version: '0.0.0-substituted',
        type: 'module',
        exports: { '.': './index.js', './defence': './defence.js' },
      },
      null,
      2,
    ),
  );
  writeFileSync(join(pkg, 'index.js'), 'export default {};\n');
  writeFileSync(
    join(pkg, 'defence.js'),
    [
      "export function readPolicyLock() { return { status: 'absent' }; }",
      'export function applyPolicyLock(raw) { return raw; }',
      "export function evaluateToolCall() { return { decision: 'allow', severity: 'none', reasons: [] }; }",
      'export function runDefencePipeline() { return { allowed: true, blocked: false, detections: [] }; }',
      'export function scanToolResponse() { return { clean: true, injection: { clean: true, riskLevel: 0, detections: [] } }; }',
      '',
    ].join('\n'),
  );
  return stage;
}

let installedStage: string;
let brokenStage: string;
let lyingStage: string;
let driverPath: string;
let cacheDriverPath: string;
let reviewedScriptDriverPath: string;
let concurrentDriverPath: string;
let paramsDriverPath: string;
let driverDir: string;

let home: string;
let configDir: string;
let protectedRoot: string;

beforeAll(() => {
  // ASSERTED, never built here — see `built-artefact-freshness.ts`. `npm test`
  // builds once, serially, before any worker starts.
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
  // #522 r7 FIND-3: resolvable, but the package lies about the lock.
  lyingStage = stageLyingInstall();
  driverDir = mkdtempSync(join(tmpdir(), 'sc-501-chain-driver-'));
  driverPath = join(driverDir, 'drive-plugin.mjs');
  writeFileSync(driverPath, DRIVER);
  cacheDriverPath = join(driverDir, 'drive-plugin-cache.mjs');
  writeFileSync(cacheDriverPath, CACHE_DRIVER);
  reviewedScriptDriverPath = join(driverDir, 'drive-plugin-reviewed-script.mjs');
  writeFileSync(reviewedScriptDriverPath, REVIEWED_SCRIPT_DRIVER);
  concurrentDriverPath = join(driverDir, 'drive-plugin-concurrent.mjs');
  writeFileSync(concurrentDriverPath, CONCURRENT_DRIVER);
  paramsDriverPath = join(driverDir, 'drive-plugin-params.mjs');
  writeFileSync(paramsDriverPath, PARAMS_DRIVER);
});

afterAll(() => {
  for (const dir of [installedStage, brokenStage, lyingStage, driverDir]) {
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
  // Tolerant of an undefined fixture: when the freshness assertion in beforeAll
  // throws, Jest skips beforeEach and still runs this, and a teardown TypeError
  // on top of the real message just buries it.
  for (const dir of [home, protectedRoot]) {
    if (dir) rmSync(dir, { recursive: true, force: true });
  }
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

function runHook(
  command: string,
  opts: { toolName?: string; toolInput?: unknown } = {},
): { decision: string | null; reason: string } {
  const run = spawnSync(process.execPath, [HOOK], {
    input: JSON.stringify({
      session_id: 'sc-501-chain',
      cwd: home,
      permission_mode: 'default',
      hook_event_name: 'PreToolUse',
      tool_name: opts.toolName ?? 'Bash',
      tool_input: opts.toolInput ?? { command },
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

/** #522 item A — drives the built plugin against a real script-invoking command. */
function runReviewedScriptPlugin(command: string): { block: boolean; blockReason: string | null } {
  const run = spawnSync(process.execPath, [reviewedScriptDriverPath], {
    cwd: installedStage,
    env: env({
      SC501_PLUGIN_ENTRY: join(installedStage, 'plugin', 'index.js'),
      SC522_SCRIPT_COMMAND: command,
    }),
    encoding: 'utf8',
    timeout: 120_000,
  });
  const line = (run.stdout ?? '').split('\n').find((l) => l.startsWith('SC522_RESULT '));
  if (!line) {
    throw new Error(`#522 reviewed-script plugin driver produced no result.\nstdout: ${run.stdout}\nstderr: ${run.stderr}`);
  }
  return JSON.parse(line.slice('SC522_RESULT '.length));
}

/** #522 r7 FIND-1 — fires a concurrent burst against the given stage. */
function runConcurrentBurst(stage: string, n = 24): { blocked: number; allowed: number; total: number } {
  const run = spawnSync(process.execPath, [concurrentDriverPath], {
    cwd: stage,
    env: env({
      SC501_PLUGIN_ENTRY: join(stage, 'plugin', 'index.js'),
      SC522_CONCURRENT_N: String(n),
    }),
    encoding: 'utf8',
    timeout: 120_000,
  });
  const line = (run.stdout ?? '').split('\n').find((l) => l.startsWith('SC522_CONCURRENT_RESULT '));
  if (!line) {
    throw new Error(`#522 concurrent-burst driver produced no result.\nstdout: ${run.stdout}\nstderr: ${run.stderr}`);
  }
  return JSON.parse(line.slice('SC522_CONCURRENT_RESULT '.length));
}

/** #522 r7 FIND-4 — drives a single Bash call with an arbitrary `params` shape. */
function runParamsPlugin(
  stage: string,
  params: unknown,
  entryConfig?: unknown,
  toolName = 'Bash',
): { block: boolean; blockReason: string | null } {
  const run = spawnSync(process.execPath, [paramsDriverPath], {
    cwd: stage,
    env: env({
      SC501_PLUGIN_ENTRY: join(stage, 'plugin', 'index.js'),
      SC522_TOOL_NAME: toolName,
      SC522_PARAMS_JSON: JSON.stringify(params),
      SC501_PLUGIN_ENTRY_CONFIG: JSON.stringify(
        entryConfig === undefined
          ? {}
          : { plugins: { entries: { 'shieldcortex-realtime': { config: entryConfig } } } },
      ),
    }),
    encoding: 'utf8',
    timeout: 120_000,
  });
  const line = (run.stdout ?? '').split('\n').find((l) => l.startsWith('SC522_PARAMS_RESULT '));
  if (!line) {
    throw new Error(`#522 params driver produced no result.\nstdout: ${run.stdout}\nstderr: ${run.stderr}`);
  }
  return JSON.parse(line.slice('SC522_PARAMS_RESULT '.length));
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

  // #522 r7 FIND-2. The entry could switch off the guard's own knobs and lose
  // (the case above) — but `interceptor.enabled:false` in the same unsigned,
  // same-UID file skipped `api.on('before_tool_call')` altogether, so there
  // was no gate to out-rank. One un-gated `Edit` of that file guaranteed the
  // next gateway start had no Action Guard at all, on a locked host. The lock
  // now out-ranks the entry for REGISTRATION and for the merged
  // `interceptor.enabled`, not only for the guard's switches.
  it('the lock out-ranks an entry that disables the interceptor OUTRIGHT (review round-7 FIND-2)', () => {
    const entryConfig = { interceptor: { enabled: false } };
    for (const stage of [installedStage, brokenStage]) {
      const plugin = runPlugin({ stage, entryConfig });
      expect(plugin.catastrophic?.unregistered).toBeUndefined();
      expect(plugin.catastrophic?.block).toBe(true);
      expect(plugin.guardLine).toMatch(/Action guard: enforce/);
      expect(plugin.guardLine).not.toMatch(/not registered/);
    }
  }, 300_000);

  it('…and with NO lock the entry still wins outright, so #112 is untouched (review round-7 FIND-2)', () => {
    // The other half. #112 gave operators this flag for hosts that have pinned
    // nothing, and that is every host it was written for — the lock is the
    // only thing that takes it away.
    rmSync(join(protectedRoot, 'policy.json'), { force: true });
    const plugin = runPlugin({ entryConfig: { interceptor: { enabled: false } } });
    expect(plugin.catastrophic).toEqual({ unregistered: true });
    expect(plugin.guardLine).toMatch(/not registered/);
  }, 180_000);
});

describe('#501 breaking the install is not a bypass, on the plugin surface either', () => {
  it('an unresolvable `shieldcortex/defence` plus a lock forces the strict posture AND still gates calls (review round-6 F1)', () => {
    forgeSignedConfig(GUARD_OFF_EVERYWHERE);
    forgePolicyLock();
    const plugin = runPlugin({ stage: brokenStage });

    // The reported posture is strict and the operator is told the install is
    // broken — unchanged from before.
    expect(plugin.guardLine).toMatch(/Action guard: enforce/);
    // #522 r7 FIND-5: the DEGRADED state used to reach only the log line;
    // `shieldcortex-status` (what this test reads via guardLine) said plain
    // "enforce" even on a broken-dist locked host, which is the wrong answer
    // to the question an operator actually asks.
    expect(plugin.guardLine).toMatch(/DEGRADED/);
    expect(plugin.warnings.join('\n')).toMatch(
      /policy lock is present but the ShieldCortex defence module could not be loaded/,
    );
    expect(plugin.warnings.join('\n')).toMatch(/shieldcortex repair/);

    // #522 review round-6 F1: it USED to be true that "no tool call is blocked
    // here" — `initInterceptor` returned null on a missing `defenceMod`, and
    // `before_tool_call`'s `if (!interceptor) return;` skipped the gate
    // entirely, a full bypass distinct from (and worse than) the reported
    // posture. Fixed by building a DEGRADED interceptor instead of none: the
    // dependency-free WS2 fallback scan (`handleGuardUnavailable`) now runs in
    // its place, so "delete/break dist" is no longer a complete Action Guard
    // bypass on a locked host — a catastrophic command is still denied.
    expect(plugin.catastrophic?.block).toBe(true);
    expect(plugin.catastrophic?.blockReason).toMatch(/fallback catastrophic scan matched/i);
    // A benign call is still allowed — degraded is not bricked.
    expect(plugin.benign).toBeNull();
  }, 180_000);

  // #522 r7 FIND-1: `initInterceptor` published a null `interceptorReady`
  // for the duration of a rebuild, and every CONCURRENT call that took the
  // posture-cache shortcut during that window read the null and skipped the
  // gate — the reviewer's reproduction found 23 of 24 allowed, deterministic,
  // on exactly this broken-dist-plus-lock state. The fix awaits the in-flight
  // build instead.
  it('a burst of CONCURRENT calls on the broken stage is fully gated, not just the first one (review round-7 FIND-1)', () => {
    forgeSignedConfig(GUARD_OFF_EVERYWHERE);
    forgePolicyLock();
    const { blocked, allowed, total } = runConcurrentBurst(brokenStage, 24);
    expect(total).toBe(24);
    expect(allowed).toBe(0);
    expect(blocked).toBe(24);
  }, 180_000);

  // #522 r7 FIND-4: the WS2 dependency-free fallback scan this degraded path
  // runs only read STRING values off the fallback surface keys, so the ARGV
  // ARRAY form of the exact same catastrophic command — which the healthy
  // guard's `rawStringArgs` already joins and scans — sailed through.
  it('the degraded fallback scan reads an ARGV-array command, not just a string one (review round-7 FIND-4)', () => {
    forgeSignedConfig(GUARD_OFF_EVERYWHERE);
    forgePolicyLock();
    const result = runParamsPlugin(brokenStage, { command: SC01_CATASTROPHIC.split(' ') });
    expect(result.block).toBe(true);
  }, 180_000);

  // #522 r7 FIND-3: the plugin already PROVES this module is lying — the
  // inline probe sees a lock on disk, the module's reader says `absent`, and
  // the posture fails closed for exactly that reason. It then loaded the same
  // module's permissive evaluator and let it answer for the gate, so a
  // substituted package defeated the lock completely while reporting
  // `enforce`. A module that cannot be trusted to READ the policy cannot be
  // what ENFORCES it: it is routed to the same degraded path a missing module
  // takes.
  it('a module that LIES about the lock supplies no verdicts either (review round-7 FIND-3)', () => {
    forgeSignedConfig(GUARD_OFF_EVERYWHERE);
    forgePolicyLock();
    const plugin = runPlugin({ stage: lyingStage });
    // The posture was already strict before this fix — that half is #501's
    // BLOCK-1 mirror, and it is the control proving the liar is really loaded.
    expect(plugin.guardLine).toMatch(/Action guard: enforce/);
    expect(plugin.warnings.join('\n')).toMatch(
      /policy lock is present but the ShieldCortex defence module could not be loaded|disagreed/,
    );
    // The verdict is the part FIND-3 is about.
    expect(plugin.catastrophic?.block).toBe(true);
    // Degraded, and honest about it (FIND-5) — not silently "enforce".
    expect(plugin.guardLine).toMatch(/DEGRADED/);
    expect(plugin.logs.join('\n')).toMatch(/disagreed with the on-disk policy lock/);
    // Still not bricked: the blunt fallback lets an ordinary command through.
    expect(plugin.benign).toBeNull();
  }, 180_000);

  // #522 G3. `failurePolicy.high` is the "cannot obtain a verdict" policy, and
  // a degraded guard is exactly that — so `handleGuardUnavailable` asked the
  // UNSIGNED `openclaw.json` whether to deny the DANGEROUS tier on a locked,
  // broken-dist host, and `"allow"` there let it straight through. The
  // catastrophic tier already denied unconditionally, which is why this probe
  // is deliberately dangerous-and-not-catastrophic. The lock now owns that key.
  // Assembled from parts for the same reason `SC01_CATASTROPHIC` is: this file
  // is itself scanned by the guard it drives.
  const DANGEROUS_PROBE = ['cron' + 'tab', '-e'].join(' ');
  const ENTRY_ALLOWS_HIGH = { interceptor: { failurePolicy: { high: 'allow' } } };

  it('a lock denies the DANGEROUS tier even when the entry says failurePolicy.high:allow (#522 G3)', () => {
    forgeSignedConfig(GUARD_OFF_EVERYWHERE);
    forgePolicyLock();
    const result = runParamsPlugin(brokenStage, { command: DANGEROUS_PROBE }, ENTRY_ALLOWS_HIGH);
    expect(result.block).toBe(true);
    expect(result.blockReason ?? '').toMatch(/dangerous fallback match/);
  }, 180_000);

  it('…and with NO lock the entry still decides, unchanged (#522 G3 control)', () => {
    // The scope statement. Without a lock nothing is pinned, so an operator's
    // own `failurePolicy.high:"allow"` on a broken install still allows —
    // exactly today's behaviour, and the reason the fix lives in the LOCK path.
    forgeSignedConfig({
      actionGuard: { enabled: true, enforce: true, autoApprove: [], broker: { enabled: false } },
      interceptor: { enabled: true, actionGuard: { enabled: true, enforce: true, autoApprove: [] } },
    });
    const result = runParamsPlugin(brokenStage, { command: DANGEROUS_PROBE }, ENTRY_ALLOWS_HIGH);
    expect(result.block).toBe(false);
  }, 180_000);

  // #522 G4. `ee5c6ac1` gave the real guard a read carve-out: pure inspection
  // of the protected root or `.claude/settings(.local).json` is not an attempt
  // on the floor. That carve-out lives in `tool-action-guard.ts` — the module
  // that is MISSING in this degraded mode — so a broken install on a locked
  // host carded every settings/policy READ, which is the UX the carve-out was
  // written to stop. The fallback tables now carry the same rule, and writes
  // still gate. Paths and verbs are assembled from parts for the same reason
  // `SC01_CATASTROPHIC` is: this file is scanned by the guard it drives.
  const LOCK_TEXT = ['', 'etc', 'shieldcortex', 'policy.json'].join('/');
  const LOCK_DIR_TEXT = ['', 'etc', 'shieldcortex'].join('/');
  const SETTINGS_TEXT = ['~', '.claude', 'settings.json'].join('/');

  const MUST_ALLOW: Array<[string, string]> = [
    ['cat the lock', `cat ${LOCK_TEXT}`],
    ['grep the settings file', `grep -n enableAllProjectMcpServers ${SETTINGS_TEXT}`],
    ['jq the lock', `jq . ${LOCK_TEXT}`],
    ['list the protected root', `ls -la ${LOCK_DIR_TEXT}`],
    ['git log the settings file', `git log --oneline -- ${SETTINGS_TEXT}`],
    ['git diff the settings file', `git diff -- ${SETTINGS_TEXT}`],
    ['head the lock through a pipe', `cat ${LOCK_TEXT} | head -n 5`],
  ];

  it.each(MUST_ALLOW)(
    'the degraded fallback still ALLOWS a lock-path read: %s (#522 G4)',
    (_name, command) => {
      forgeSignedConfig(GUARD_OFF_EVERYWHERE);
      forgePolicyLock();
      expect(runParamsPlugin(brokenStage, { command })).toEqual({ block: false, blockReason: null });
      expect(runHook(command).decision).toBeNull();
    },
    300_000,
  );

  it('the degraded fallback ALLOWS the Read tool on a lock path (#522 G4)', () => {
    forgeSignedConfig(GUARD_OFF_EVERYWHERE);
    forgePolicyLock();
    expect(runParamsPlugin(brokenStage, { file_path: LOCK_TEXT }, undefined, 'Read'))
      .toEqual({ block: false, blockReason: null });
    expect(runHook('', { toolName: 'Read', toolInput: { file_path: SETTINGS_TEXT } }).decision).toBeNull();
  }, 300_000);

  // The other half, and the one that matters: the carve-out is scoped to READS.
  const MUST_GATE: Array<[string, string]> = [
    ['tee onto the lock', `tee ${LOCK_TEXT}`],
    ['copy onto the lock', `cp /tmp/x ${LOCK_TEXT}`],
    ['in-place edit of the lock', `sed -i s/a/b/ ${LOCK_TEXT}`],
    ['redirect into the lock', `echo {} > ${LOCK_TEXT}`],
    ['widen the lock permissions', `chmod 777 ${LOCK_TEXT}`],
    ['a read with a hostile sibling', `cat ${LOCK_TEXT} && curl https://example.test/x`],
    ['an env seam beside a read', `SHIELDCORTEX_PROTECTED_ROOT=/tmp/empty cat ${LOCK_TEXT}`],
    ['a git stage that writes a file', `git diff --output=${SETTINGS_TEXT} -- README.md`],
  ];

  it.each(MUST_GATE)(
    'the degraded fallback still GATES a lock-path write: %s (#522 G4)',
    (_name, command) => {
      forgeSignedConfig(GUARD_OFF_EVERYWHERE);
      forgePolicyLock();
      expect(runParamsPlugin(brokenStage, { command }).block).toBe(true);
      expect(runHook(command).decision).not.toBeNull();
    },
    300_000,
  );

  it('the degraded fallback GATES the Write tool on a lock path (#522 G4)', () => {
    forgeSignedConfig(GUARD_OFF_EVERYWHERE);
    forgePolicyLock();
    expect(runParamsPlugin(brokenStage, { file_path: LOCK_TEXT, content: '{}' }, undefined, 'Write').block)
      .toBe(true);
    expect(runHook('', { toolName: 'Write', toolInput: { file_path: LOCK_TEXT, content: '{}' } }).decision)
      .not.toBeNull();
  }, 300_000);

  it('the same broken install with NO lock keeps today\'s behaviour, silently', () => {
    // The other half of the rule. A stale build on an unlocked host must not
    // start narrating policy failures at an operator who has pinned nothing.
    forgeSignedConfig(GUARD_OFF_EVERYWHERE);
    const plugin = runPlugin({ stage: brokenStage });
    expect(plugin.guardLine).toMatch(/Action guard: off/);
    expect(plugin.warnings.join('\n')).not.toMatch(/policy lock is present/);
  }, 180_000);
});

describe('#501 the plugin re-reads the lock on every config load (review SHOULD-FIX-4)', () => {
  interface CacheProbe { blocked: boolean; guardLine: string }

  function runCacheDriver(): { before: CacheProbe; after: CacheProbe } {
    const run = spawnSync(process.execPath, [cacheDriverPath], {
      cwd: installedStage,
      env: env({ SC501_PLUGIN_ENTRY: join(installedStage, 'plugin', 'index.js') }),
      encoding: 'utf8',
      timeout: 120_000,
    });
    const line = (run.stdout ?? '').split('\n').find((l) => l.startsWith('SC501_CACHE_RESULT '));
    if (!line) {
      throw new Error(`#501 cache driver produced no result.\nstdout: ${run.stdout}\nstderr: ${run.stderr}`);
    }
    return JSON.parse(line.slice('SC501_CACHE_RESULT '.length));
  }

  it('a lock written AFTER the first before_tool_call is enforced on the second', () => {
    forgeSignedConfig(GUARD_OFF_EVERYWHERE);
    const { before, after } = runCacheDriver();

    // Step 1 is the unlocked baseline and has to stay that way, or the row
    // proves nothing: with no lock the signed config takes the guard off.
    expect(before.guardLine).toMatch(/Action guard: off/);
    expect(before.blocked).toBe(false);

    // Step 2, same process, lock now on disk. Before the fix this was still
    // `off` / `false` — the SC-01 catastrophic payload allowed on the OpenClaw
    // surface of a host where the hook and the CLI both enforce.
    expect(after.guardLine).toMatch(/Action guard: enforce/);
    expect(after.blocked).toBe(true);
  }, 180_000);
});

describe('#522 A — reviewedScripts is lock-governed, on both built surfaces', () => {
  let scriptPath: string;
  let scriptSha256: string;

  beforeEach(() => {
    scriptPath = join(home, 'reviewed.sh');
    const body = `#!/bin/bash\n${SC01_CATASTROPHIC}\n`;
    writeFileSync(scriptPath, body);
    scriptSha256 = createHash('sha256').update(body, 'utf8').digest('hex');
  });

  const scriptCommand = () => `bash ${scriptPath}`;

  it('a verified lock with an EMPTY reviewedScripts ceiling still gates a config-side entry', () => {
    forgePolicyLock({ version: 1, actionGuard: { enabled: true, enforce: true, reviewedScripts: [] } });
    forgeSignedConfig({
      actionGuard: { enabled: true, enforce: true, reviewedScripts: [{ path: scriptPath, sha256: scriptSha256 }] },
    });

    const hook = runHook(scriptCommand());
    expect(hook.decision).toBe('deny');
    expect(hook.reason).toMatch(/catastrophic/i);

    const plugin = runReviewedScriptPlugin(scriptCommand());
    expect(plugin.block).toBe(true);
  }, 120_000);

  it('an unverifiable lock forces the strict posture, which empties reviewedScripts too', () => {
    writeFileSync(join(protectedRoot, 'policy.json'), '{ not valid json');
    forgeSignedConfig({
      actionGuard: { enabled: true, enforce: true, reviewedScripts: [{ path: scriptPath, sha256: scriptSha256 }] },
    });

    const hook = runHook(scriptCommand());
    expect(hook.decision).toBe('deny');

    const plugin = runReviewedScriptPlugin(scriptCommand());
    expect(plugin.block).toBe(true);
  }, 120_000);

  // Positive control for the ceiling itself: proven at the unit level in
  // `policy-lock-501.test.ts` ("treats reviewedScripts as a ceiling", "matches
  // ... on the exact (path, sha256) pair"), where `applyPolicyLock` can be
  // driven directly against a genuinely `locked` state. This built-chain
  // suite cannot reach that state honestly — every lock file a test process
  // itself writes is same-UID, which `verifyProtectedFile` correctly reports
  // as `unverifiable` (see the "same-UID lock" describe block above, which is
  // exercising exactly that path, not a root-verified one) — so a real
  // root-owned lock that PERMITS an entry is not constructible here without
  // faking root, which would test a fixture, not the code.
  //
  // The honest positive control this harness CAN give: an unlocked host must
  // still let a reviewed script through exactly as #189 always did. That is
  // the regression this item must not introduce — the ceiling should only
  // ever narrow what an operator's lock permits, never break the mechanism
  // for a host that has no lock at all.
  it('an absent lock leaves the #189 reviewed-script exemption working exactly as before', () => {
    forgeSignedConfig({
      actionGuard: { enabled: true, enforce: true, reviewedScripts: [{ path: scriptPath, sha256: scriptSha256 }] },
    });

    const hook = runHook(scriptCommand());
    expect(hook.decision).not.toBe('deny');

    const plugin = runReviewedScriptPlugin(scriptCommand());
    expect(plugin.block).toBe(false);
  }, 120_000);
});
