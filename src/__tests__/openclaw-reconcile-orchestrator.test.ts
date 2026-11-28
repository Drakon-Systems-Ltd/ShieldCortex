import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';
import Database from 'better-sqlite3';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { reconcileOpenClawPluginState } from '../setup/openclaw-reconcile.js';
import type { SelfCheckRunResult } from '../setup/openclaw-selfcheck.js';

/**
 * The reconciler orchestrator: gather → classify → plan → (execute behind
 * guards) → honest-state self-check. Tested end-to-end with an INJECTED openclaw
 * executor + self-check so nothing touches a live gateway (#74 zeroth law).
 */
const PLUGIN = 'shieldcortex-realtime';
const PKG_SUBPATH = path.join('node_modules', '@drakon-systems', 'shieldcortex-realtime');
let home: string;

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-orch-'));
});
afterEach(() => {
  fs.rmSync(home, { recursive: true, force: true });
});

function setup(opts: { roster: Array<{ pluginId: string; enabled: boolean }>; onDisk: string }): void {
  const oc = path.join(home, '.openclaw');
  fs.mkdirSync(path.join(oc, 'plugins'), { recursive: true });
  fs.mkdirSync(path.join(oc, 'state'), { recursive: true });
  const pkgDir = path.join(oc, 'npm', 'projects', 'drakon-systems-shieldcortex-realtime-abc', PKG_SUBPATH);
  // A real npm build (#260: a package.json alone is leftover metadata, not an
  // install): the manifest naming the plugin and the `main` entry point.
  fs.mkdirSync(path.join(pkgDir, 'dist'), { recursive: true });
  fs.writeFileSync(path.join(pkgDir, 'package.json'), JSON.stringify({ version: opts.onDisk, main: './dist/index.js' }));
  fs.writeFileSync(path.join(pkgDir, 'openclaw.plugin.json'), JSON.stringify({ id: PLUGIN, version: opts.onDisk }));
  fs.writeFileSync(path.join(pkgDir, 'dist', 'index.js'), '');
  fs.writeFileSync(path.join(oc, 'openclaw.json'), JSON.stringify({ plugins: { entries: { [PLUGIN]: { enabled: true } }, allow: [PLUGIN] } }));
  fs.writeFileSync(path.join(oc, 'plugins', 'installs.json'), JSON.stringify({ installRecords: { [PLUGIN]: { version: opts.onDisk, installPath: pkgDir } } }));
  const db = new Database(path.join(oc, 'state', 'openclaw.sqlite'));
  db.exec(`CREATE TABLE installed_plugin_index (index_key TEXT NOT NULL PRIMARY KEY, version INTEGER NOT NULL, host_contract_version TEXT NOT NULL, compat_registry_version TEXT NOT NULL, migration_version INTEGER NOT NULL, policy_hash TEXT NOT NULL, generated_at_ms INTEGER NOT NULL, refresh_reason TEXT, install_records_json TEXT NOT NULL, plugins_json TEXT NOT NULL, diagnostics_json TEXT NOT NULL, warning TEXT, updated_at_ms INTEGER NOT NULL);`);
  db.prepare(`INSERT INTO installed_plugin_index VALUES ('k',1,'v','x',1,'h',1,'r',@ir,@pj,'[]',NULL,1)`).run({
    ir: JSON.stringify({ [PLUGIN]: { source: 'npm', version: opts.onDisk, installPath: pkgDir } }),
    // Every OpenClaw that writes this table (2026.6–2026.10) requires a string
    // rootDir on each entry; ours is the recorded install (#260).
    pj: JSON.stringify(opts.roster.map((e) => ({ rootDir: e.pluginId === PLUGIN ? pkgDir : path.join(oc, 'extensions', e.pluginId), ...e }))),
  });
  db.close();
}

const passingSelfCheck: SelfCheckRunResult = {
  ok: true, rosterProof: true, rosterState: 'loaded', canaryProof: true, versionProof: true, reasons: ['ok'],
  index: null, liveRoster: [PLUGIN], canary: { ran: true, denied: true, auditEntryFound: true },
};

describe('reconcileOpenClawPluginState', () => {
  it('dry-run (apply:false) computes verdict + plan without executing any command', async () => {
    setup({ roster: [{ pluginId: 'brave', enabled: true }], onDisk: '4.47.2' });
    const calls: string[][] = [];
    const res = await reconcileOpenClawPluginState({
      home, expectedVersion: '4.47.2', apply: false,
      runCommand: (argv) => { calls.push(argv); return { status: 0, output: '' }; },
      selfCheck: async () => passingSelfCheck,
    });
    // An index-only omission is attention, not proof of a live unload.
    expect(res.verdict.state).toBe('load-unproven');
    expect(res.verdict.severity).toBe('warn');
    expect(res.plan.some((s) => s.kind === 'openclaw-install-pinned')).toBe(true);
    expect(res.plan.some((s) => s.kind === 'openclaw-update')).toBe(false);
    expect(res.applied).toBe(false);
    expect(calls).toHaveLength(0);
  });

  it('apply: executes the silent-drop remediation via the pinned npm install (never `plugins update`), then self-checks', async () => {
    setup({ roster: [{ pluginId: 'brave', enabled: true }], onDisk: '4.47.2' });
    const calls: string[][] = [];
    let reloaded = false;
    const res = await reconcileOpenClawPluginState({
      home, expectedVersion: '4.47.2', apply: true,
      runCommand: (argv) => { calls.push(argv); return { status: 0, output: '' }; },
      reloadGateway: async () => { reloaded = true; return { restarted: true }; },
      // #260 Sol r2: success needs the restart PROVEN back up after the install.
      waitForGateway: async () => ({ ready: true, waitedMs: 1 }),
      selfCheck: async () => passingSelfCheck,
    });
    expect(calls).toContainEqual(['plugins', 'install', '--force', 'npm:@drakon-systems/shieldcortex-realtime@4.47.2']);
    expect(calls.some((a) => a[1] === 'update')).toBe(false);
    expect(reloaded).toBe(true);
    expect(res.applied).toBe(true);
    expect(res.ok).toBe(true);
    expect(res.selfCheck?.ok).toBe(true);
  });

  it('HARD FAILS when the self-check does not pass after remediation', async () => {
    setup({ roster: [{ pluginId: 'brave', enabled: true }], onDisk: '4.47.2' });
    const res = await reconcileOpenClawPluginState({
      home, expectedVersion: '4.47.2', apply: true,
      runCommand: () => ({ status: 0, output: '' }),
      reloadGateway: async () => ({ restarted: true }),
      selfCheck: async () => ({ ...passingSelfCheck, ok: false, canaryProof: false, reasons: ['canary not run'] }),
    });
    expect(res.ok).toBe(false);
    expect(res.messages.join(' ')).toMatch(/self-check|not.*(load|enforc|confirm)/i);
  });

  it('version regression executes a PINNED reinstall, never @latest', async () => {
    setup({ roster: [{ pluginId: PLUGIN, enabled: true }], onDisk: '4.25.4' });
    const calls: string[][] = [];
    await reconcileOpenClawPluginState({
      home, expectedVersion: '4.47.2', apply: true,
      runCommand: (argv) => { calls.push(argv); return { status: 0, output: '' }; },
      reloadGateway: async () => ({ restarted: true }),
      selfCheck: async () => passingSelfCheck,
    });
    const install = calls.find((a) => a.includes('install'));
    expect(install).toEqual(['plugins', 'install', '--force', 'npm:@drakon-systems/shieldcortex-realtime@4.47.2']);
    expect(install!.join(' ')).not.toMatch(/@latest/);
  });

  it('#1109 round 2: an install step that exits 0 but leaves the selected copy off the pin FAILS on its own step', async () => {
    setup({ roster: [{ pluginId: PLUGIN, enabled: true }], onDisk: '4.25.4' });
    const res = await reconcileOpenClawPluginState({
      home, expectedVersion: '4.47.2', apply: true,
      runCommand: () => ({ status: 0, output: '' }), // "succeeds", lands nothing
      reloadGateway: async () => ({ restarted: true }),
      selfCheck: async () => passingSelfCheck, // even a self-check that says yes does not rescue it
    });
    const step = res.stepResults.find((r) => r.kind === 'openclaw-install-pinned');
    expect(step).toMatchObject({ ok: false, detail: expect.stringContaining('install exited 0, but the plugin is on v4.25.4, CLI is v4.47.2') });
    expect(res.messages.join('\n')).toMatch(/plugin install not finished: .*npm:@drakon-systems\/shieldcortex-realtime@4\.47\.2/);
    expect(res.ok).toBe(false);
  });

  it('#1109 round 2: an install step whose selected copy cannot be told FAILS on its own step', async () => {
    setup({ roster: [{ pluginId: PLUGIN, enabled: true }], onDisk: '4.25.4' });
    const res = await reconcileOpenClawPluginState({
      home, expectedVersion: '4.47.2', apply: true,
      runCommand: () => ({ status: 0, output: '' }),
      readLandedVersion: () => ({ version: null, reason: 'could not tell which copy OpenClaw selected — two copies' }),
      reloadGateway: async () => ({ restarted: true }),
      selfCheck: async () => passingSelfCheck,
    });
    expect(res.stepResults.find((r) => r.kind === 'openclaw-install-pinned')).toMatchObject({ ok: false });
    expect(res.ok).toBe(false);
  });

  it('#1109 round 2: an install step that lands the pin in the selected copy is ok', async () => {
    setup({ roster: [{ pluginId: PLUGIN, enabled: true }], onDisk: '4.25.4' });
    const pkg = path.join(home, '.openclaw', 'npm', 'projects', 'drakon-systems-shieldcortex-realtime-abc', PKG_SUBPATH, 'package.json');
    const res = await reconcileOpenClawPluginState({
      home, expectedVersion: '4.47.2', apply: true,
      runCommand: (argv) => {
        if (argv[1] === 'install') fs.writeFileSync(pkg, JSON.stringify({ version: '4.47.2' }));
        return { status: 0, output: '' };
      },
      readLandedVersion: () => ({ version: JSON.parse(fs.readFileSync(pkg, 'utf-8')).version }),
      reloadGateway: async () => ({ restarted: true }),
      selfCheck: async () => passingSelfCheck,
    });
    expect(res.stepResults.find((r) => r.kind === 'openclaw-install-pinned')).toMatchObject({ ok: true });
  });

  const NPM_4472 = ['plugins', 'install', '--force', 'npm:@drakon-systems/shieldcortex-realtime@4.47.2'];
  const BARE_4472 = ['plugins', 'install', '--force', '@drakon-systems/shieldcortex-realtime@4.47.2'];
  const PRE_NPM = 'unsupported npm spec: protocol specs are not allowed';

  it.each([
    ['an OpenClaw that predates `npm:` (refusal on stderr)', { stderr: PRE_NPM, stdout: '' }, true],
    ['the refusal mixed with an integrity failure', { stderr: `${PRE_NPM}\nnpm error code EINTEGRITY`, stdout: '' }, false],
    ['the refusal phrase on stdout only', { stderr: 'install failed', stdout: PRE_NPM }, false],
    ['an executor that reports combined output only', { stderr: undefined, stdout: undefined }, false],
    ['an integrity failure', { stderr: 'npm error code EINTEGRITY', stdout: '' }, false],
    ['a consent refusal', { stderr: 'Install cancelled; rerun with --force after reviewing the source.', stdout: '' }, false],
  ] as const)('pinned reinstall: %s — at most ONE bare exact retry for the WHOLE reconcile run, across every pass', async (_label, streams, retried) => {
    setup({ roster: [{ pluginId: PLUGIN, enabled: true }], onDisk: '4.25.4' });
    const calls: string[][] = [];
    const res = await reconcileOpenClawPluginState({
      home, expectedVersion: '4.47.2', apply: true,
      runCommand: (argv) => {
        calls.push(argv);
        return { status: 1, output: `${streams.stdout ?? ''}${streams.stderr ?? PRE_NPM}`, ...(streams.stderr === undefined ? {} : { stderr: streams.stderr, stdout: streams.stdout }) };
      },
      reloadGateway: async () => ({ restarted: true }),
      selfCheck: async () => passingSelfCheck,
    });
    const installs = calls.filter((a) => a.includes('install'));
    // The converge loop really did run the plan more than once…
    expect(res.passes ?? 1).toBeGreaterThan(1);
    expect(installs.filter((a) => a[3].startsWith('npm:')).length).toBe(res.passes);
    // …and the operation as a whole spent at most one bare run.
    expect(installs.filter((a) => !a[3].startsWith('npm:'))).toEqual(retried ? [BARE_4472] : []);
    expect(installs[0]).toEqual(NPM_4472);
    if (retried) expect(installs[1]).toEqual(BARE_4472);
    expect(installs.flat().join(' ')).not.toMatch(/clawhub:|@latest/);
  });

  it('a ClawHub-origin install record is refreshed from npm at the pin — never `plugins update`', async () => {
    setup({ roster: [{ pluginId: 'brave', enabled: true }], onDisk: '4.47.2' });
    const db = new Database(path.join(home, '.openclaw', 'state', 'openclaw.sqlite'));
    db.prepare('UPDATE installed_plugin_index SET install_records_json = ?').run(
      JSON.stringify({ [PLUGIN]: { source: 'clawhub', spec: 'clawhub:@drakon-systems/shieldcortex-realtime@5.17.3', version: '4.47.2' } }),
    );
    db.close();
    const calls: string[][] = [];
    await reconcileOpenClawPluginState({
      home, expectedVersion: '4.47.2', apply: true,
      runCommand: (argv) => { calls.push(argv); return { status: 0, output: '' }; },
      reloadGateway: async () => ({ restarted: true }),
      selfCheck: async () => passingSelfCheck,
    });
    expect(calls.filter((a) => a[1] === 'update')).toEqual([]);
    expect(calls.filter((a) => a[1] === 'install')[0]).toEqual(NPM_4472);
  });

  it('a NEWER on-disk plugin is never downgraded by a reconcile install — the step is refused with the command', async () => {
    setup({ roster: [{ pluginId: 'brave', enabled: true }], onDisk: '4.48.0' });
    const calls: string[][] = [];
    const res = await reconcileOpenClawPluginState({
      home, expectedVersion: '4.47.2', apply: true,
      runCommand: (argv) => { calls.push(argv); return { status: 0, output: '' }; },
      reloadGateway: async () => ({ restarted: true }),
      selfCheck: async () => passingSelfCheck,
    });
    expect(calls.filter((a) => a[1] === 'install')).toEqual([]);
    expect(res.ok).toBe(false);
    expect(res.messages.join('\n')).toMatch(/left alone — the plugin is on v4\.48\.0, newer than this CLI \(v4\.47\.2\).*npm:@drakon-systems\/shieldcortex-realtime@4\.47\.2/);
  });

  it('a linked install (plugins.load.paths) is never replaced by a reconcile install', async () => {
    setup({ roster: [{ pluginId: PLUGIN, enabled: true }], onDisk: '4.25.4' });
    const cfgPath = path.join(home, '.openclaw', 'openclaw.json');
    const cfg = JSON.parse(fs.readFileSync(cfgPath, 'utf-8'));
    // #1109 round 2: identified by what is AT the path — a checkout's plugins/openclaw.
    const checkout = path.join(home, 'src', 'ShieldCortex', 'plugins', 'openclaw');
    fs.mkdirSync(checkout, { recursive: true });
    fs.writeFileSync(path.join(checkout, 'package.json'), JSON.stringify({ name: '@drakon-systems/shieldcortex-realtime', version: '4.25.4' }));
    cfg.plugins.load = { paths: [checkout] };
    fs.writeFileSync(cfgPath, JSON.stringify(cfg));
    const calls: string[][] = [];
    const res = await reconcileOpenClawPluginState({
      home, expectedVersion: '4.47.2', apply: true,
      runCommand: (argv) => { calls.push(argv); return { status: 0, output: '' }; },
      reloadGateway: async () => ({ restarted: true }),
      selfCheck: async () => passingSelfCheck,
    });
    expect(calls.filter((a) => a[1] === 'install')).toEqual([]);
    expect(res.ok).toBe(false);
    expect(res.messages.join('\n')).toMatch(/linked install/);
  });

  it('a non-exact expected version runs NO install — refused, with the human command', async () => {
    // Index omission → the tracked-refresh route, which needs an install.
    setup({ roster: [{ pluginId: 'brave', enabled: true }], onDisk: '4.25.4' });
    const calls: string[][] = [];
    const res = await reconcileOpenClawPluginState({
      home, expectedVersion: 'unknown', apply: true,
      runCommand: (argv) => { calls.push(argv); return { status: 0, output: '' }; },
      reloadGateway: async () => ({ restarted: true }),
      selfCheck: async () => passingSelfCheck,
    });
    expect(calls.filter((a) => a[1] === 'install')).toEqual([]);
    expect(calls.some((a) => a.length === 0)).toBe(false);
    expect(res.stepResults.find((r) => r.kind === 'openclaw-install-pinned')).toMatchObject({ ok: false });
    expect(res.messages.join('\n')).toMatch(/no exact plugin version to pin to.*npm:@drakon-systems\/shieldcortex-realtime@latest/);
    expect(res.ok).toBe(false);
  });

  it('healthy state runs only the self-check, executes no openclaw command', async () => {
    setup({ roster: [{ pluginId: PLUGIN, enabled: true }], onDisk: '4.47.2' });
    const calls: string[][] = [];
    const res = await reconcileOpenClawPluginState({
      home, expectedVersion: '4.47.2', apply: true,
      runCommand: (argv) => { calls.push(argv); return { status: 0, output: '' }; },
      reloadGateway: async () => ({ restarted: true }),
      selfCheck: async () => passingSelfCheck,
    });
    expect(res.verdict.state).toBe('healthy');
    expect(calls.length).toBe(0);
    expect(res.ok).toBe(true);
  });

  /** The copy OpenClaw's index (and installs.json) record names, deleted from disk. */
  const recordedCopy = (): string => path.join(home, '.openclaw', 'npm', 'projects', 'drakon-systems-shieldcortex-realtime-abc', PKG_SUBPATH);

  it('#1109 round 4 (CASE blocking 1): a DANGLING record — the copy it names was deleted — gets the pinned install, not "could not tell"', async () => {
    setup({ roster: [{ pluginId: PLUGIN, enabled: true }], onDisk: '4.25.4' });
    fs.rmSync(recordedCopy(), { recursive: true, force: true });
    const calls: string[][] = [];
    const res = await reconcileOpenClawPluginState({
      home, expectedVersion: '4.47.2', apply: true,
      runCommand: (argv) => {
        calls.push(argv);
        if (argv[1] === 'install') {
          // OpenClaw writes the copy and rewrites its index row in the same install.
          fs.mkdirSync(recordedCopy(), { recursive: true });
          fs.writeFileSync(path.join(recordedCopy(), 'package.json'), JSON.stringify({ version: '4.47.2' }));
          const db = new Database(path.join(home, '.openclaw', 'state', 'openclaw.sqlite'));
          db.prepare('UPDATE installed_plugin_index SET install_records_json = ?').run(
            JSON.stringify({ [PLUGIN]: { source: 'npm', version: '4.47.2', installPath: recordedCopy() } }),
          );
          db.close();
        }
        return { status: 0, output: '' };
      },
      reloadGateway: async () => ({ restarted: true }),
      selfCheck: async () => passingSelfCheck,
    });
    expect(calls.filter((a) => a[1] === 'install')[0]).toEqual(['plugins', 'install', '--force', 'npm:@drakon-systems/shieldcortex-realtime@4.47.2']);
    expect(res.messages.join('\n')).not.toMatch(/could not tell which copy OpenClaw selected/);
    const step = res.stepResults.find((r) => r.kind === 'openclaw-install-pinned' || r.kind === 'openclaw-install');
    expect(step).toMatchObject({ ok: true });
  });

  it('#1109 round 4: a recorded copy that EXISTS but cannot be parsed still refuses the install', async () => {
    setup({ roster: [{ pluginId: PLUGIN, enabled: true }], onDisk: '4.25.4' });
    fs.writeFileSync(path.join(recordedCopy(), 'package.json'), '{ nope');
    const calls: string[][] = [];
    const res = await reconcileOpenClawPluginState({
      home, expectedVersion: '4.47.2', apply: true,
      runCommand: (argv) => { calls.push(argv); return { status: 0, output: '' }; },
      reloadGateway: async () => ({ restarted: true }),
      selfCheck: async () => passingSelfCheck,
    });
    expect(calls.filter((a) => a[1] === 'install')).toEqual([]);
    expect(res.ok).toBe(false);
  });
});

describe('reconcile executor — gateway-safety guard', () => {
  it('the default openclaw executor is guarded by a consent env before spawning', () => {
    const thisFile = fileURLToPath(import.meta.url);
    const repoRoot = path.resolve(path.dirname(thisFile), '..', '..');
    const src = fs.readFileSync(path.join(repoRoot, 'src', 'setup', 'openclaw-reconcile.ts'), 'utf-8');
    expect(src).toMatch(/JEST_WORKER_ID/);
    expect(src).toMatch(/SHIELDCORTEX_ALLOW_GATEWAY_(RESTART|CANARY|RECONCILE)/);
  });
});
