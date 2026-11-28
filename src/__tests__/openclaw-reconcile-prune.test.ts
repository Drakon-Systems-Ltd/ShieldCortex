import fs from 'fs';
import os from 'os';
import path from 'path';
import Database from 'better-sqlite3';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { reconcileOpenClawPluginState, formatReconcileReport } from '../setup/openclaw-reconcile.js';
import type { SelfCheckRunResult } from '../setup/openclaw-selfcheck.js';

/**
 * #74 finding 4 (HOST-SAFETY BLOCKER): duplicate-dir pruning must NEVER delete a
 * directory the authoritative roster/index resolves into — pruning the live
 * install would `rm -rf` the running plugin. And finding 5: the aiquant silent
 * drop shipped WITH a leftover duplicate dir that the old code never pruned.
 *
 * These are DISK-LEVEL tests of the orchestrator's prune targeting, in a fully
 * isolated temp HOME (never `~/.openclaw`; all live execs injected). They fail
 * against the old `scanDuplicateDirs` logic, which kept the installs.json /
 * shortest-name dir and could drop the live `__openclaw-generation__` one.
 */
const PLUGIN = 'shieldcortex-realtime';
const PKG_SUBPATH = path.join('node_modules', '@drakon-systems', 'shieldcortex-realtime');
const BASE_DIR = 'drakon-systems-shieldcortex-realtime-6e7e2e7717';
const GEN_DIR = 'drakon-systems-shieldcortex-realtime-6e7e2e7717__openclaw-generation__1752230000-4.47.2-abc';

let home: string;
beforeEach(() => { home = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-prune-')); });
afterEach(() => { fs.rmSync(home, { recursive: true, force: true }); });

const passingSelfCheck: SelfCheckRunResult = {
  ok: true, rosterProof: true, rosterState: 'loaded', canaryProof: true, versionProof: true, reasons: ['ok'],
  index: null, liveRoster: [PLUGIN], canary: { ran: true, denied: true, auditEntryFound: true },
};

function projectsDir(): string {
  return path.join(home, '.openclaw', 'npm', 'projects');
}

/**
 * Create an on-disk project dir holding the plugin package at `version`. By
 * default a REAL build (#260: manifest naming the plugin + the `main` entry
 * point); `build: false` leaves only the package.json an uninstall leaves
 * behind — leftover metadata, not an intact copy.
 */
function mkProjectDir(dirName: string, version: string, opts: { build?: boolean } = {}): string {
  const pkgDir = path.join(projectsDir(), dirName, PKG_SUBPATH);
  fs.mkdirSync(pkgDir, { recursive: true });
  if (opts.build === false) {
    fs.writeFileSync(path.join(pkgDir, 'package.json'), JSON.stringify({ version }));
    return pkgDir;
  }
  fs.mkdirSync(path.join(pkgDir, 'dist'), { recursive: true });
  fs.writeFileSync(path.join(pkgDir, 'package.json'), JSON.stringify({ version, main: './dist/index.js' }));
  fs.writeFileSync(path.join(pkgDir, 'openclaw.plugin.json'), JSON.stringify({ id: PLUGIN, version }));
  fs.writeFileSync(path.join(pkgDir, 'dist', 'index.js'), '');
  return pkgDir;
}

/**
 * Build a host with two project dirs on disk. `indexInstallPath` is what the
 * AUTHORITATIVE SQLite index records as the install path (the live dir), and
 * `rosterEntries` is the loaded plugins_json roster.
 */
function setupTwoDirHost(opts: {
  dirs: Array<{ name: string; version: string; build?: boolean }>;
  installsJsonPath: string;
  indexInstallPath: string;
  rosterEntries: Array<Record<string, unknown>>;
}): void {
  const oc = path.join(home, '.openclaw');
  fs.mkdirSync(path.join(oc, 'plugins'), { recursive: true });
  fs.mkdirSync(path.join(oc, 'state'), { recursive: true });
  for (const d of opts.dirs) mkProjectDir(d.name, d.version, { build: d.build });

  fs.writeFileSync(
    path.join(oc, 'openclaw.json'),
    JSON.stringify({ plugins: { entries: { [PLUGIN]: { enabled: true } }, allow: [PLUGIN] } }),
  );
  fs.writeFileSync(
    path.join(oc, 'plugins', 'installs.json'),
    JSON.stringify({ installRecords: { [PLUGIN]: { version: '4.47.2', installPath: opts.installsJsonPath } } }),
  );

  const db = new Database(path.join(oc, 'state', 'openclaw.sqlite'));
  db.exec(`CREATE TABLE installed_plugin_index (index_key TEXT NOT NULL PRIMARY KEY, version INTEGER NOT NULL, host_contract_version TEXT NOT NULL, compat_registry_version TEXT NOT NULL, migration_version INTEGER NOT NULL, policy_hash TEXT NOT NULL, generated_at_ms INTEGER NOT NULL, refresh_reason TEXT, install_records_json TEXT NOT NULL, plugins_json TEXT NOT NULL, diagnostics_json TEXT NOT NULL, warning TEXT, updated_at_ms INTEGER NOT NULL);`);
  db.prepare(`INSERT INTO installed_plugin_index VALUES ('k',1,'v','x',1,'h',1,'r',@ir,@pj,'[]',NULL,1)`).run({
    ir: JSON.stringify({ [PLUGIN]: { source: 'npm', version: '4.47.2', resolvedVersion: '4.47.2', installPath: opts.indexInstallPath } }),
    pj: JSON.stringify(opts.rosterEntries),
  });
  db.close();
}

/** Run the orchestrator with all live execs injected; record which dirs were pruned. */
async function runReconcile(): Promise<{ pruned: string[]; messages: string[]; state: string }> {
  const pruned: string[] = [];
  const res = await reconcileOpenClawPluginState({
    home, expectedVersion: '4.47.2', apply: true,
    runCommand: () => ({ status: 0, output: '' }),
    reloadGateway: async () => ({ restarted: true }),
    selfCheck: async () => passingSelfCheck,
    // Record AND actually remove, so we can assert both intent and disk state.
    pruneDir: (h, d) => { pruned.push(d); fs.rmSync(path.join(h, '.openclaw', 'npm', 'projects', d), { recursive: true, force: true }); },
  });
  return { pruned, messages: res.messages, state: res.verdict.state };
}

describe('duplicate-dir prune — never deletes the live install (#74 finding 4/5)', () => {
  it('aiquant enabled-not-loaded + two dirs: prunes ONLY the stale dir, keeps the index/live dir', async () => {
    // The exact aiquant shape: config enabled, roster OMITS the plugin (the drop),
    // index install record points at the base dir → base is live, __openclaw-generation__ is stale.
    setupTwoDirHost({
      dirs: [{ name: BASE_DIR, version: '4.47.2' }, { name: GEN_DIR, version: '4.47.2' }],
      installsJsonPath: path.join(projectsDir(), BASE_DIR, PKG_SUBPATH),
      indexInstallPath: path.join(projectsDir(), BASE_DIR, PKG_SUBPATH),
      rosterEntries: [{ pluginId: 'brave', enabled: true }, { pluginId: 'codex', enabled: true }],
    });

    const { pruned } = await runReconcile();

    expect(pruned).toEqual([GEN_DIR]);
    expect(pruned).not.toContain(BASE_DIR);
    // The live dir is still on disk; the stale one is gone.
    expect(fs.existsSync(path.join(projectsDir(), BASE_DIR))).toBe(true);
    expect(fs.existsSync(path.join(projectsDir(), GEN_DIR))).toBe(false);
  });

  it('conflicted-metadata: keeps the dir the INDEX resolves into, prunes the installs.json-only dir', async () => {
    // installs.json points at BASE_DIR, but the authoritative index + loaded
    // roster resolve into GEN_DIR. The old code kept the installs.json dir and
    // would have pruned the LIVE (index) dir — this asserts the opposite.
    setupTwoDirHost({
      dirs: [{ name: BASE_DIR, version: '4.47.2' }, { name: GEN_DIR, version: '4.47.2' }],
      installsJsonPath: path.join(projectsDir(), BASE_DIR, PKG_SUBPATH),
      indexInstallPath: path.join(projectsDir(), GEN_DIR, PKG_SUBPATH),
      rosterEntries: [{ pluginId: PLUGIN, enabled: true, rootDir: path.join(projectsDir(), GEN_DIR, PKG_SUBPATH) }],
    });

    const { pruned } = await runReconcile();

    expect(pruned).toEqual([BASE_DIR]);
    expect(pruned).not.toContain(GEN_DIR);
    expect(fs.existsSync(path.join(projectsDir(), GEN_DIR))).toBe(true);
    expect(fs.existsSync(path.join(projectsDir(), BASE_DIR))).toBe(false);
  });

  it('REFUSES to prune (deletes nothing) when the index cannot name a live dir — never guesses', async () => {
    // enabled-not-loaded + two dirs, but the index install record has no usable
    // installPath and the roster omits the plugin → the live dir is ambiguous.
    setupTwoDirHost({
      dirs: [{ name: BASE_DIR, version: '4.47.2' }, { name: GEN_DIR, version: '4.47.2' }],
      installsJsonPath: path.join(projectsDir(), BASE_DIR, PKG_SUBPATH),
      indexInstallPath: '', // unusable → canonicalProjectDirFromIndex returns null
      rosterEntries: [{ pluginId: 'brave', enabled: true }],
    });

    const { pruned, messages } = await runReconcile();

    expect(pruned).toEqual([]);
    expect(fs.existsSync(path.join(projectsDir(), BASE_DIR))).toBe(true);
    expect(fs.existsSync(path.join(projectsDir(), GEN_DIR))).toBe(true);
    expect(messages.join(' ')).toMatch(/refus/i);
  });
});

/**
 * #260 Sol r2 — never prune (or advise removing) the only intact copy. The
 * index NAMING a dir is not enough: the kept copy must be a verified build,
 * named unambiguously, and every removed dir must be safe to lose (no copy,
 * or an older/equal one whose version reads). Otherwise nothing is pruned.
 */
describe('duplicate-dir prune — only a true duplicate of a verified, unambiguous kept build (#260 Sol r2)', () => {
  const pkg = (dir: string): string => path.join(projectsDir(), dir, PKG_SUBPATH);
  const entry = (dir: string) => ({ pluginId: PLUGIN, enabled: true, rootDir: pkg(dir) });
  const bothKept = (dirs: Array<{ name: string; version: string; build?: boolean }>, keep: string) =>
    setupTwoDirHost({ dirs, installsJsonPath: pkg(keep), indexInstallPath: pkg(keep), rosterEntries: [entry(keep)] });
  const untouched = (...dirs: string[]): void => {
    for (const d of dirs) expect(fs.existsSync(path.join(projectsDir(), d))).toBe(true);
  };

  it('STALE selection: the dir the index names holds no build, the other holds the only intact copy ⇒ nothing pruned', async () => {
    bothKept([{ name: BASE_DIR, version: '4.47.2', build: false }, { name: GEN_DIR, version: '4.47.2' }], BASE_DIR);
    const { pruned, messages, state } = await runReconcile();
    expect(state).toBe('duplicate-install');
    expect(pruned).toEqual([]);
    untouched(BASE_DIR, GEN_DIR);
    expect(messages.join(' ')).toMatch(/refusing to prune .*not a verified plugin build/);
  });

  it('ALTERNATE selection: rootDir and the install record name different dirs ⇒ ambiguous, nothing pruned', async () => {
    setupTwoDirHost({
      dirs: [{ name: BASE_DIR, version: '4.47.2' }, { name: GEN_DIR, version: '4.47.2' }],
      installsJsonPath: pkg(BASE_DIR),
      indexInstallPath: pkg(BASE_DIR),
      rosterEntries: [entry(GEN_DIR)],
    });
    const { pruned, messages } = await runReconcile();
    expect(pruned).toEqual([]);
    untouched(BASE_DIR, GEN_DIR);
    expect(messages.join(' ')).toMatch(/refusing to prune .*ambiguous/);
  });

  it('a NEWER copy in the other dir is never pruned', async () => {
    bothKept([{ name: BASE_DIR, version: '5.0.0' }, { name: GEN_DIR, version: '4.47.2' }], GEN_DIR);
    const { pruned, messages } = await runReconcile();
    expect(pruned).toEqual([]);
    untouched(BASE_DIR, GEN_DIR);
    expect(messages.join(' ')).toMatch(/holds v5\.0\.0, newer than the kept v4\.47\.2/);
  });

  it('a copy whose version cannot be read is never pruned', async () => {
    bothKept([{ name: BASE_DIR, version: '4.47.2' }, { name: GEN_DIR, version: '4.47.2' }], GEN_DIR);
    fs.writeFileSync(path.join(pkg(BASE_DIR), 'package.json'), '{ nope');
    const { pruned, messages } = await runReconcile();
    expect(pruned).toEqual([]);
    untouched(BASE_DIR, GEN_DIR);
    expect(messages.join(' ')).toMatch(/cannot be read/);
  });

  it('the kept build\'s own version cannot be read ⇒ nothing can be shown older, nothing pruned', async () => {
    bothKept([{ name: BASE_DIR, version: '4.40.0' }, { name: GEN_DIR, version: '4.47.2' }], GEN_DIR);
    fs.writeFileSync(path.join(pkg(GEN_DIR), 'package.json'), JSON.stringify({ main: './dist/index.js' }));
    fs.writeFileSync(path.join(pkg(GEN_DIR), 'openclaw.plugin.json'), JSON.stringify({ id: PLUGIN }));
    const { pruned } = await runReconcile();
    expect(pruned).toEqual([]);
    untouched(BASE_DIR, GEN_DIR);
  });

  it('positive control — a TRUE duplicate (older copy) beside the verified selected build is pruned', async () => {
    bothKept([{ name: BASE_DIR, version: '4.40.0' }, { name: GEN_DIR, version: '4.47.2' }], GEN_DIR);
    const { pruned, messages } = await runReconcile();
    expect(pruned).toEqual([BASE_DIR]);
    untouched(GEN_DIR);
    expect(fs.existsSync(path.join(projectsDir(), BASE_DIR))).toBe(false);
    expect(messages.join(' ')).not.toMatch(/refus/i);
  });

  it('positive control — an empty leftover project dir (no copy of the package) is pruned', async () => {
    bothKept([{ name: GEN_DIR, version: '4.47.2' }], GEN_DIR);
    fs.mkdirSync(path.join(projectsDir(), BASE_DIR), { recursive: true });
    fs.writeFileSync(path.join(projectsDir(), BASE_DIR, 'package.json'), JSON.stringify({ name: 'managed-project' }));
    const { pruned } = await runReconcile();
    expect(pruned).toEqual([BASE_DIR]);
    untouched(GEN_DIR);
  });

  // Sol r2: report the prune that HAPPENED, not the one planned.
  it('a PARTIAL prune is reported as such and fails the repair, even with a passing self-check', async () => {
    const OTHER = 'drakon-systems-shieldcortex-realtime-0ld';
    bothKept([{ name: BASE_DIR, version: '4.40.0' }, { name: OTHER, version: '4.30.0' }, { name: GEN_DIR, version: '4.47.2' }], GEN_DIR);
    const res = await reconcileOpenClawPluginState({
      home, expectedVersion: '4.47.2', apply: true,
      runCommand: () => ({ status: 0, output: '' }),
      reloadGateway: async () => ({ restarted: true }),
      waitForGateway: async () => ({ ready: true, waitedMs: 1 }),
      selfCheck: async () => passingSelfCheck,
      pruneDir: (h, d) => {
        if (d === OTHER) throw new Error('EBUSY: resource busy');
        fs.rmSync(path.join(h, '.openclaw', 'npm', 'projects', d), { recursive: true, force: true });
      },
    });
    const step = res.stepResults.find((s) => s.kind === 'prune-duplicate-dirs');
    expect(step).toMatchObject({ ok: false });
    expect(step!.detail).toBe(`pruned 1 of 2 dir(s); still on disk: ${OTHER}`);
    expect(res.ok).toBe(false);
    expect(res.messages.join(' ')).toMatch(/prune incomplete: removed 1 of 2/);
    expect(formatReconcileReport(res, { compact: true }).join(' ')).toMatch(/prune incomplete/);
    expect(formatReconcileReport(res, { compact: true }).join(' ')).not.toMatch(/pruned dups/);
    untouched(GEN_DIR, OTHER);
  });

  it('positive control — a complete prune reports the count removed and does not fail the repair', async () => {
    bothKept([{ name: BASE_DIR, version: '4.40.0' }, { name: GEN_DIR, version: '4.47.2' }], GEN_DIR);
    const res = await reconcileOpenClawPluginState({
      home, expectedVersion: '4.47.2', apply: true,
      runCommand: () => ({ status: 0, output: '' }),
      reloadGateway: async () => ({ restarted: true }),
      waitForGateway: async () => ({ ready: true, waitedMs: 1 }),
      selfCheck: async () => passingSelfCheck,
      pruneDir: (h, d) => { fs.rmSync(path.join(h, '.openclaw', 'npm', 'projects', d), { recursive: true, force: true }); },
    });
    expect(res.stepResults.find((s) => s.kind === 'prune-duplicate-dirs')).toMatchObject({ ok: true, detail: 'pruned 1 dir(s)' });
    expect(res.ok).toBe(true);
  });

  it('dry-run plans the same (no prune step) on the stale-selection host', async () => {
    bothKept([{ name: BASE_DIR, version: '4.47.2', build: false }, { name: GEN_DIR, version: '4.47.2' }], BASE_DIR);
    const res = await reconcileOpenClawPluginState({ home, expectedVersion: '4.47.2', apply: false });
    expect(res.plan.some((s) => s.kind === 'prune-duplicate-dirs')).toBe(false);
    untouched(BASE_DIR, GEN_DIR);
  });
});
