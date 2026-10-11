/**
 * #634 — a relative invoked script resolves against the directory the command
 * actually runs in, not the directory the guard process happens to sit in.
 *
 * The Claude Code hook folded `bash scripts/run.sh` against its OWN process
 * cwd. The harness reports the session's working directory per call as payload
 * `cwd`; the hook process is spawned wherever the harness likes. When the two
 * differ the hook read an unrelated same-named file (or none, and went opaque),
 * and the reviewed-script pin was checked against that wrong file's bytes.
 *
 * Every existing cross-plane harness spawns the hook with payload `cwd: '/tmp'`
 * and an unrelated process cwd, using command-only inputs, so none of them can
 * see this. Here the two directories are deliberately different and each holds
 * a DIFFERENT file under the same relative name — the verdict says which one
 * was read.
 *
 * The OpenClaw half is NOT changed by this fix: the published `before_tool_call`
 * tool context carries no workspace or cwd (see the CHANGELOG entry), so there
 * is no host-reported default to thread. The bridge block below only pins the
 * precedence that already exists — an explicit absolute `workdir` outranks the
 * gateway's own process cwd — through the real registered hook.
 */
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { cpSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from '@jest/globals';
import { requireFreshBuiltArtefacts } from './built-artefact-freshness.js';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const HOOK = join(repoRoot, 'scripts', 'pre-tool-hook.mjs');
const PLUGIN_DIST = join(repoRoot, 'plugins', 'openclaw', 'dist');

const BENIGN_SCRIPT = '#!/bin/bash\necho hello\n';
// The parity suite's existing dangerous (approval-tier, not catastrophic) line.
const DANGEROUS_SCRIPT = '#!/bin/bash\nsudo modprobe softdog\n';
// Same signal, different bytes — so a pin on one cannot match the other.
const DANGEROUS_DECOY_SCRIPT = '#!/bin/bash\n# decoy\nsudo modprobe softdog\n';

const sha256 = (text: string): string => createHash('sha256').update(text, 'utf8').digest('hex');

let home: string;
let configDir: string;
let protectedRoot: string;
/** Where the command runs: the harness-reported per-call cwd. */
let workspace: string;
/** Where the guard process runs. Must never be what gets folded when the host reports a cwd. */
let decoy: string;

// Every block drives the built evaluator through the hook or the plugin;
// asserted, never built here (see built-artefact-freshness.ts).
beforeAll(() => {
  requireFreshBuiltArtefacts({
    repoRoot,
    sources: [
      join(repoRoot, 'src', 'defence', 'iron-dome', 'script-source-resolver.ts'),
      join(repoRoot, 'src', 'defence', 'iron-dome', 'reviewed-scripts.ts'),
      join(repoRoot, 'src', 'defence', 'iron-dome', 'tool-action-guard.ts'),
    ],
    artefacts: [
      join(repoRoot, 'dist', 'defence', 'iron-dome', 'script-source-resolver.js'),
      join(repoRoot, 'dist', 'defence', 'iron-dome', 'reviewed-scripts.js'),
      join(repoRoot, 'dist', 'defence', 'iron-dome', 'tool-action-guard.js'),
    ],
  });
});

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'sc-634-home-'));
  configDir = join(home, '.shieldcortex');
  mkdirSync(configDir, { recursive: true });
  protectedRoot = mkdtempSync(join(tmpdir(), 'sc-634-root-'));
  workspace = mkdtempSync(join(tmpdir(), 'sc-634-workspace-'));
  decoy = mkdtempSync(join(tmpdir(), 'sc-634-decoy-'));
  mkdirSync(join(workspace, 'scripts'));
  mkdirSync(join(decoy, 'scripts'));
});

afterEach(() => {
  for (const dir of [home, protectedRoot, workspace, decoy]) {
    if (dir) rmSync(dir, { recursive: true, force: true });
  }
});

function writeConfig(actionGuard: Record<string, unknown> = {}): void {
  writeFileSync(
    join(configDir, 'config.json'),
    JSON.stringify({ actionGuard: { enabled: true, enforce: true, ...actionGuard } }),
  );
}

function childEnv(): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    HOME: home,
    USERPROFILE: home,
    SHIELDCORTEX_CONFIG_DIR: configDir,
    SHIELDCORTEX_AUDIT_DIR: join(configDir, 'audit'),
    SHIELDCORTEX_PROTECTED_ROOT: protectedRoot,
  };
  // The hook must load the real built evaluator, not an inherited substitute.
  delete env.SHIELDCORTEX_DIST_ROOT;
  return env;
}

// ---- the spawned Claude Code hook ----------------------------------------

type HookOutcome = 'allow' | 'ask' | 'deny';

/**
 * Spawn the real hook with its PROCESS cwd set to `decoy`. `payloadCwd` is
 * what the harness reports; `undefined` omits the key entirely.
 */
function runHook(command: string, payloadCwd: unknown): HookOutcome {
  const payload: Record<string, unknown> = {
    session_id: 'sc-634-hook',
    permission_mode: 'default',
    hook_event_name: 'PreToolUse',
    tool_name: 'Bash',
    tool_input: { command },
  };
  if (payloadCwd !== undefined) payload.cwd = payloadCwd;
  const run = spawnSync(process.execPath, [HOOK], {
    cwd: decoy,
    input: JSON.stringify(payload),
    env: childEnv(),
    encoding: 'utf8',
    timeout: 60_000,
  });
  if (run.status !== 0) throw new Error(`hook exited ${run.status}: ${run.stderr}`);
  const stdout = (run.stdout ?? '').trim();
  if (!stdout) return 'allow';
  const decision = JSON.parse(stdout).hookSpecificOutput?.permissionDecision;
  if (decision === 'ask' || decision === 'deny') return decision;
  throw new Error(`unexpected hook output: ${stdout}`);
}

/** Every signal on the hook's local audit rows (fresh HOME per test). */
function auditedSignals(): string[] {
  const dir = join(home, '.shieldcortex', 'audit');
  if (!existsSync(dir)) return [];
  const signals: string[] = [];
  for (const f of readdirSync(dir)) {
    if (!f.startsWith('realtime-') || !f.endsWith('.jsonl')) continue;
    for (const line of readFileSync(join(dir, f), 'utf8').split('\n')) {
      if (!line.trim()) continue;
      const row = JSON.parse(line) as { threats?: unknown };
      if (Array.isArray(row.threats)) signals.push(...row.threats.map(String));
    }
  }
  return signals;
}

describe('#634 hook — relative scripts resolve against the reported cwd, not the hook process cwd', () => {
  beforeEach(() => writeConfig());

  it('controls: a benign and a dangerous recognised command are unaffected by either directory', () => {
    expect(runHook('ls -la', workspace)).toBe('allow');
    expect(runHook('sudo modprobe softdog', workspace)).toBe('ask');
  }, 120_000);

  it('folds the WORKSPACE script: benign there, dangerous same-name decoy in the process cwd → allow', () => {
    writeFileSync(join(workspace, 'scripts', 'run.sh'), BENIGN_SCRIPT);
    writeFileSync(join(decoy, 'scripts', 'run.sh'), DANGEROUS_SCRIPT);

    expect(runHook('bash scripts/run.sh', workspace)).toBe('allow');
    expect(auditedSignals()).not.toContain('opaque-script-invocation');
  }, 120_000);

  it('folds the WORKSPACE script: dangerous there, benign same-name decoy in the process cwd → ask', () => {
    writeFileSync(join(workspace, 'scripts', 'run.sh'), DANGEROUS_SCRIPT);
    writeFileSync(join(decoy, 'scripts', 'run.sh'), BENIGN_SCRIPT);

    expect(runHook('bash scripts/run.sh', workspace)).toBe('ask');
  }, 120_000);

  it('a script missing from the workspace stays opaque even when the process cwd has one', () => {
    writeFileSync(join(decoy, 'scripts', 'run.sh'), BENIGN_SCRIPT);

    expect(runHook('bash scripts/run.sh', workspace)).toBe('allow');
    expect(auditedSignals()).toContain('opaque-script-invocation');
  }, 120_000);

  it('a missing or unusable reported cwd keeps the established fallback: the hook process cwd', () => {
    writeFileSync(join(workspace, 'scripts', 'run.sh'), BENIGN_SCRIPT);
    writeFileSync(join(decoy, 'scripts', 'run.sh'), DANGEROUS_SCRIPT);

    // Absent, relative, empty and non-string all fall back — and the fallback
    // is observable because only the process-cwd copy is dangerous.
    expect(runHook('bash scripts/run.sh', undefined)).toBe('ask');
    expect(runHook('bash scripts/run.sh', 'scripts')).toBe('ask');
    expect(runHook('bash scripts/run.sh', '')).toBe('ask');
    expect(runHook('bash scripts/run.sh', 42)).toBe('ask');
  }, 240_000);

  it('an absolute script path is base-independent', () => {
    writeFileSync(join(workspace, 'scripts', 'run.sh'), DANGEROUS_SCRIPT);
    writeFileSync(join(decoy, 'scripts', 'run.sh'), BENIGN_SCRIPT);
    const absolute = `bash ${join(workspace, 'scripts', 'run.sh')}`;

    expect(runHook(absolute, workspace)).toBe('ask');
    expect(runHook(absolute, decoy)).toBe('ask');
    expect(runHook(absolute, undefined)).toBe('ask');
  }, 180_000);
});

describe('#634 hook — the reviewed-script pin binds the workspace file and its exact bytes', () => {
  let pinned: string;

  beforeEach(() => {
    pinned = join(workspace, 'scripts', 'run.sh');
    writeFileSync(pinned, DANGEROUS_SCRIPT);
    // A dangerous decoy whose bytes the pin does NOT cover: folding it instead
    // of the pinned file would gate.
    writeFileSync(join(decoy, 'scripts', 'run.sh'), DANGEROUS_DECOY_SCRIPT);
    writeConfig({ reviewedScripts: [{ path: pinned, sha256: sha256(DANGEROUS_SCRIPT) }] });
  });

  it('a relative call to the pinned workspace script matches the pin', () => {
    expect(runHook('bash scripts/run.sh', workspace)).toBe('allow');
  }, 120_000);

  it('one changed byte in the pinned file re-gates it', () => {
    writeFileSync(pinned, DANGEROUS_SCRIPT.replace('softdog', 'softdoh'));
    expect(runHook('bash scripts/run.sh', workspace)).toBe('ask');
  }, 120_000);

  it('the fallback still checks the pin against the file it actually folded', () => {
    // No reported cwd → the decoy is folded, and its bytes are not pinned.
    expect(runHook('bash scripts/run.sh', undefined)).toBe('ask');
  }, 120_000);

  it('a same-UID policy lock with an empty reviewedScripts ceiling still ignores the pin', () => {
    writeFileSync(
      join(protectedRoot, 'policy.json'),
      JSON.stringify({ version: 1, actionGuard: { enabled: true, enforce: true, reviewedScripts: [] } }, null, 2),
    );
    // The claim is only that the pin no longer exempts it; ask vs deny under
    // the lock's posture is that suite's business, not this one's.
    expect(runHook('bash scripts/run.sh', workspace)).not.toBe('allow');
  }, 120_000);
});

// ---- the real registered OpenClaw bridge (unchanged; precedence pinned) ----

const BRIDGE_DRIVER = `
const plugin = (await import(process.env.SC634_PLUGIN_ENTRY)).default;
const hooks = new Map();
console.warn = () => {};
plugin.register({
  version: '2026.9.6',
  config: {},
  logger: { info: () => {}, warn: () => {}, error: () => {} },
  registerCommand: () => {},
  registerHook: () => {},
  on: (name, fn) => hooks.set(name, fn),
});
const beforeToolCall = hooks.get('before_tool_call');
const params = JSON.parse(process.env.SC634_PARAMS_JSON);
let outcome = 'unregistered';
if (beforeToolCall) {
  const r = (await beforeToolCall({ toolName: 'exec', params }, { sessionId: 'sc-634-bridge' })) ?? null;
  outcome = r && r.block === true ? 'block' : r && r.requireApproval ? 'ask' : 'allow';
}
await new Promise((done) => process.stdout.write('SC634_RESULT ' + JSON.stringify({ outcome }) + '\\n', done));
process.exit(0);
`;

describe('#634 OpenClaw bridge — an explicit absolute workdir outranks the gateway process cwd', () => {
  let stage: string;
  let driverPath: string;

  beforeAll(() => {
    requireFreshBuiltArtefacts({
      repoRoot,
      sources: [
        join(repoRoot, 'plugins', 'openclaw', 'index.ts'),
        join(repoRoot, 'plugins', 'openclaw', 'interceptor.ts'),
        join(repoRoot, 'src', 'defence', 'iron-dome', 'script-source-resolver.ts'),
        join(repoRoot, 'src', 'defence', 'iron-dome', 'tool-action-guard.ts'),
      ],
      artefacts: [
        join(PLUGIN_DIST, 'index.js'),
        join(repoRoot, 'dist', 'defence', 'index.js'),
      ],
    });
    // The install layout a host has: the built plugin, and a resolvable
    // `shieldcortex` package for its bare `shieldcortex/defence` import.
    stage = mkdtempSync(join(tmpdir(), 'sc-634-stage-'));
    cpSync(PLUGIN_DIST, join(stage, 'plugin'), { recursive: true });
    mkdirSync(join(stage, 'node_modules'));
    symlinkSync(repoRoot, join(stage, 'node_modules', 'shieldcortex'), 'dir');
    // Outside the stage on purpose, as in policy-lock-chain-e2e-501: the
    // plugin copy's own location must decide the bare-specifier resolution.
    const driverDir = mkdtempSync(join(tmpdir(), 'sc-634-driver-'));
    driverPath = join(driverDir, 'drive-bridge.mjs');
    writeFileSync(driverPath, BRIDGE_DRIVER);
  });

  afterAll(() => {
    if (stage) rmSync(stage, { recursive: true, force: true });
    if (driverPath) rmSync(dirname(driverPath), { recursive: true, force: true });
  });

  beforeEach(() => writeConfig());

  function runBridge(params: Record<string, unknown>): string {
    const run = spawnSync(process.execPath, [driverPath], {
      // The gateway's own process cwd is the decoy.
      cwd: decoy,
      env: {
        ...childEnv(),
        SC634_PLUGIN_ENTRY: join(stage, 'plugin', 'index.js'),
        SC634_PARAMS_JSON: JSON.stringify(params),
      },
      encoding: 'utf8',
      timeout: 60_000,
    });
    const line = (run.stdout ?? '').split('\n').find((l) => l.startsWith('SC634_RESULT '));
    if (!line) throw new Error(`bridge driver produced no result (status ${run.status}): ${run.stderr}`);
    return JSON.parse(line.slice('SC634_RESULT '.length)).outcome;
  }

  it('benign workdir script, dangerous same-name decoy in the gateway cwd → allow', () => {
    writeFileSync(join(workspace, 'scripts', 'run.sh'), BENIGN_SCRIPT);
    writeFileSync(join(decoy, 'scripts', 'run.sh'), DANGEROUS_SCRIPT);
    expect(runBridge({ command: 'bash scripts/run.sh', workdir: workspace })).toBe('allow');
  }, 120_000);

  it('dangerous workdir script, benign same-name decoy in the gateway cwd → ask', () => {
    writeFileSync(join(workspace, 'scripts', 'run.sh'), DANGEROUS_SCRIPT);
    writeFileSync(join(decoy, 'scripts', 'run.sh'), BENIGN_SCRIPT);
    expect(runBridge({ command: 'bash scripts/run.sh', workdir: workspace })).toBe('ask');
  }, 120_000);
});
