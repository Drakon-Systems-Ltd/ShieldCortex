/**
 * PR #928 round 1 (review at 51eaaa11): blockers 1-3 and the four nits.
 * Temp HOME/project dirs only, placeholder commands, no network. Every test
 * fails on 51eaaa11 and passes on the repair. Only APIs that exist on both
 * heads are imported, so the file also compiles against the old head.
 */
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath, pathToFileURL } from 'url';
import {
  WATCHED_FILES,
  agentConfigStatePath,
  snapshotFile,
  runAgentConfigWatch,
  type AgentConfigLedgerRow,
  type AgentConfigNotification,
} from '../audit/agent-config-watch.js';
import { withOwnConfigWrite } from '../audit/agent-config-watch-own-write.js';
import { checkAgentConfigWatch } from '../cli/doctor.js';
import { cleanResidue, type ResidueReport } from '../setup/deep-clean.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, '..', '..');
const tsxLoader = pathToFileURL(path.join(repoRoot, 'node_modules', 'tsx', 'dist', 'loader.mjs')).href;

const UNTRUSTED = 'watch baseline untrusted';

let home: string;
let project: string;
let notes: AgentConfigNotification[];
let rows: AgentConfigLedgerRow[];

const settings = () => path.join(home, '.claude', 'settings.json');
const toml = () => path.join(home, '.codex', 'config.toml');
const ocConfig = () => path.join(home, '.openclaw', 'openclaw.json');
const statePath = () => agentConfigStatePath(home);
const keyPath = () => path.join(home, '.shieldcortex', 'keys', 'agent-config-watch.key');
const put = (p: string, s: string): string => { fs.mkdirSync(path.dirname(p), { recursive: true }); fs.writeFileSync(p, s); return s; };
const putJson = (p: string, v: unknown) => put(p, JSON.stringify(v, null, 2));
const hookSettings = (cmd: string) => ({ hooks: { SessionStart: [{ hooks: [{ type: 'command', command: cmd }] }] } });
const spec = (id: string) => WATCHED_FILES.find((s) => s.id === id)!;

const run = (over: Partial<Parameters<typeof runAgentConfigWatch>[0]> = {}) =>
  runAgentConfigWatch({
    home,
    projectRoots: [project],
    notify: async (n) => { notes.push(n); },
    ledger: (r) => { rows.push(r); return true; },
    ...over,
  });

/**
 * The attack the review reproduced: edit a watched file, then rewrite the
 * baseline JSON so it already contains the edit. The writer does not know the
 * key, so any signature field is left as it was.
 */
function launderBaseline(file: string, specId: string): void {
  const st = JSON.parse(fs.readFileSync(statePath(), 'utf-8'));
  st.files[file] = snapshotFile(file, spec(specId));
  fs.writeFileSync(statePath(), JSON.stringify(st));
}

const untrustedNotes = () => notes.filter((n) => n.changes.some((c) => c.label === UNTRUSTED));

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-928r1-home-'));
  project = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-928r1-proj-'));
  notes = [];
  rows = [];
});

afterEach(() => {
  fs.rmSync(home, { recursive: true, force: true });
  fs.rmSync(project, { recursive: true, force: true });
});

describe('blocker 1: the baseline is signed', () => {
  it('a laundered baseline raises an untrusted-baseline alert instead of hiding the change', async () => {
    putJson(settings(), hookSettings('echo fixture-ok'));
    await run();
    putJson(settings(), hookSettings('echo fixture-injected'));
    launderBaseline(settings(), 'claude-settings.json');
    await run();
    expect(untrustedNotes()).toHaveLength(1);
    expect(untrustedNotes()[0].changes[0].name).toBe('review all agent configs');
    expect(rows.some((r) => r.kind === 'baseline-untrusted')).toBe(true);
    // Re-baselined after notifying: the next run is quiet.
    notes = [];
    await run();
    expect(notes).toHaveLength(0);
  });

  it('an undelivered untrusted alert saves nothing and is retried next run', async () => {
    putJson(settings(), hookSettings('echo fixture-ok'));
    await run();
    putJson(settings(), hookSettings('echo fixture-injected'));
    launderBaseline(settings(), 'claude-settings.json');
    const tampered = fs.readFileSync(statePath(), 'utf-8');
    await run({ notify: async () => { throw Object.assign(new Error('down'), { code: 'ECONNREFUSED' }); } });
    expect(fs.readFileSync(statePath(), 'utf-8')).toBe(tampered);
    expect(rows.some((r) => r.kind === 'notify-error')).toBe(true);
    await run();
    expect(untrustedNotes()).toHaveLength(1);
  });

  it('deleting the state while its key remains alerts (not a silent first run)', async () => {
    putJson(settings(), hookSettings('echo fixture-ok'));
    await run();
    fs.unlinkSync(statePath());
    putJson(settings(), hookSettings('echo fixture-injected'));
    await run();
    expect(untrustedNotes()).toHaveLength(1);
  });

  it('the key is 0600 in a 0700 directory and the state carries a 64-hex mac', async () => {
    putJson(settings(), hookSettings('echo fixture-ok'));
    await run();
    expect(fs.statSync(keyPath()).mode & 0o777).toBe(0o600);
    expect(fs.statSync(path.dirname(keyPath())).mode & 0o777).toBe(0o700);
    expect(JSON.parse(fs.readFileSync(statePath(), 'utf-8')).mac).toMatch(/^[0-9a-f]{64}$/);
  });

  it('doctor warns on a tampered baseline', async () => {
    putJson(settings(), hookSettings('echo fixture-ok'));
    await run();
    putJson(settings(), hookSettings('echo fixture-injected'));
    launderBaseline(settings(), 'claude-settings.json');
    const r = await checkAgentConfigWatch(home);
    expect(r.status).toBe('warn');
    expect(r.message).toMatch(/integrity/);
  });

  it('an own write never re-signs a tampered baseline', async () => {
    putJson(settings(), hookSettings('echo fixture-ok'));
    await run();
    putJson(settings(), hookSettings('echo fixture-injected'));
    launderBaseline(settings(), 'claude-settings.json');
    const tampered = fs.readFileSync(statePath(), 'utf-8');
    withOwnConfigWrite(settings(), () => putJson(settings(), { ...hookSettings('echo fixture-injected'), env: { FIXTURE: '1' } }), home);
    expect(fs.readFileSync(statePath(), 'utf-8')).toBe(tampered);
    await run();
    expect(untrustedNotes()).toHaveLength(1);
  });
});

describe('blocker 2: state writes never follow a planted path', () => {
  it('a symlink at the old predictable .tmp-<pid> path does not overwrite settings.json', async () => {
    const original = putJson(settings(), hookSettings('echo fixture-ok'));
    await run();
    fs.symlinkSync(settings(), `${statePath()}.tmp-${process.pid}`);
    await run();
    expect(fs.readFileSync(settings(), 'utf-8')).toBe(original);
    expect(fs.lstatSync(statePath()).isFile()).toBe(true);
  });

  it('a symlinked state file is refused (EUNSAFEPATH) and left a symlink', async () => {
    putJson(settings(), hookSettings('echo fixture-ok'));
    const decoy = put(path.join(home, 'decoy.json'), 'decoy-content');
    fs.mkdirSync(path.dirname(statePath()), { recursive: true });
    fs.symlinkSync(path.join(home, 'decoy.json'), statePath());
    await run();
    expect(fs.lstatSync(statePath()).isSymbolicLink()).toBe(true);
    expect(fs.readFileSync(path.join(home, 'decoy.json'), 'utf-8')).toBe(decoy);
    expect(rows.some((r) => r.detail.includes('EUNSAFEPATH'))).toBe(true);
  });

  it('a symlinked state directory is refused and nothing is written through it', async () => {
    putJson(settings(), hookSettings('echo fixture-ok'));
    const elsewhere = path.join(home, 'elsewhere');
    fs.mkdirSync(elsewhere);
    fs.mkdirSync(path.join(home, '.shieldcortex'), { recursive: true });
    fs.symlinkSync(elsewhere, path.join(home, '.shieldcortex', 'state'));
    await run();
    expect(fs.readdirSync(elsewhere)).toEqual([]);
    expect(rows.some((r) => r.detail.includes('EUNSAFEPATH'))).toBe(true);
  });
});

describe('blocker 3: special files never pin the detached child', () => {
  const CHILD_DEADLINE = 8_000;
  const KILL_AFTER = 20_000;

  function runChild(): { status: number | null; signal: NodeJS.Signals | null; out: string; ms: number } {
    const script = path.join(project, 'watch-child.mts');
    fs.writeFileSync(script, `
import { runAgentConfigWatch } from ${JSON.stringify(path.join(repoRoot, 'src', 'audit', 'agent-config-watch.ts'))};
import { armChildDeadline } from ${JSON.stringify(path.join(repoRoot, 'src', 'audit', 'agent-config-watch-runner.ts'))};
const [home, project] = process.argv.slice(2);
armChildDeadline(${CHILD_DEADLINE}, () => { process.stdout.write('DEADLINE\\n'); process.exit(3); });
const rows: unknown[] = [];
const r = await runAgentConfigWatch({ home, projectRoots: [project], notify: async () => {}, ledger: (row) => { rows.push(row); return true; }, totalBudgetMs: 2000 });
process.stdout.write(JSON.stringify({ r, rows }) + '\\n');
process.exit(0);
`);
    const t0 = Date.now();
    const res = spawnSync(process.execPath, ['--import', tsxLoader, script, home, project], {
      cwd: repoRoot, encoding: 'utf-8', timeout: KILL_AFTER, env: { ...process.env, HOME: home },
    });
    return { status: res.status, signal: res.signal, out: res.stdout ?? '', ms: Date.now() - t0 };
  }

  function expectFinishedWithReadError(res: ReturnType<typeof runChild>, category: string): void {
    // Exit 0 = the child returned on its own, before its deadline (which exits 3)
    // and before the parent's kill timer.
    expect({ status: res.status, signal: res.signal }).toEqual({ status: 0, signal: null });
    const parsed = JSON.parse(res.out.trim().split('\n').pop()!);
    expect(parsed.rows).toEqual(expect.arrayContaining([expect.objectContaining({ kind: 'health-error', detail: `read-error (${category})` })]));
  }

  it('a FIFO at a watched path is a read error and the child finishes within its deadline', () => {
    fs.mkdirSync(path.dirname(settings()), { recursive: true });
    expect(spawnSync('mkfifo', [settings()]).status).toBe(0);
    expectFinishedWithReadError(runChild(), 'ENOTREG');
  }, 40_000);

  it('a symlink to /dev/zero is a read error and the child finishes within its deadline', () => {
    fs.mkdirSync(path.dirname(settings()), { recursive: true });
    fs.symlinkSync('/dev/zero', settings());
    expectFinishedWithReadError(runChild(), 'ENOTREG');
  }, 40_000);

  it('an oversize file is a read error (EFBIG), not parsed', async () => {
    put(settings(), `{"pad":"${'a'.repeat(1024 * 1024)}"}`);
    await run();
    expect(rows).toEqual(expect.arrayContaining([expect.objectContaining({ kind: 'health-error', detail: 'read-error (EFBIG)' })]));
  });
});

describe('nits', () => {
  it('deep-clean cleanResidue is an own write: no alert', async () => {
    const spy = jest.spyOn(os, 'homedir').mockReturnValue(home);
    try {
      putJson(ocConfig(), { hooks: { shieldcortex: { enabled: true }, other: { enabled: true } } });
      await run();
      const report: ResidueReport = {
        paths: [{ description: 'fixture hook', removal: { kind: 'delete-config-key', file: ocConfig(), keyPath: ['hooks', 'shieldcortex'] }, present: true, category: 'hook-config' }],
        dirtyCount: 1,
        cleanCount: 0,
      };
      const res = cleanResidue(report);
      expect(res.errors).toEqual([]);
      expect(JSON.parse(fs.readFileSync(ocConfig(), 'utf-8')).hooks.shieldcortex).toBeUndefined();
      await run();
      expect(notes).toHaveLength(0);
    } finally {
      spy.mockRestore();
    }
  });

  it('a writer racing in after the own write still alerts (baseline from the written bytes)', async () => {
    putJson(settings(), hookSettings('echo fixture-ok'));
    await run();
    withOwnConfigWrite(settings(), () => {
      const ours = putJson(settings(), hookSettings('echo fixture-ours'));
      putJson(settings(), hookSettings('echo fixture-racer'));
      return ours;
    }, home);
    await run();
    expect(notes).toHaveLength(1);
    expect(notes[0].changes[0].label).toMatch(/^hook /);
  });

  it('a TOML [[hooks]] edit or addition alerts', async () => {
    put(toml(), '[[hooks]]\ncommand = "echo fixture-one"\n');
    await run();
    put(toml(), '[[hooks]]\ncommand = "echo fixture-two"\n');
    await run();
    expect(notes).toHaveLength(1);
    put(toml(), '[[hooks]]\ncommand = "echo fixture-two"\n\n[[hooks]]\ncommand = "echo fixture-three"\n');
    await run();
    expect(notes).toHaveLength(2);
    expect(notes.every((n) => n.changes[0].label.startsWith('hook '))).toBe(true);
  });

  it('an own write through a symlinked OPENCLAW_HOME rebaselines the runner state: no alert', async () => {
    const alt = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-928r1-alt-'));
    const spy = jest.spyOn(os, 'homedir').mockReturnValue(home);
    const prev = process.env.OPENCLAW_HOME;
    try {
      putJson(ocConfig(), { plugins: { entries: {} } });
      fs.symlinkSync(path.join(home, '.openclaw'), path.join(alt, '.openclaw'));
      await run();
      process.env.OPENCLAW_HOME = alt;
      const { trustLocalPlugin } = await import('../setup/openclaw.js');
      expect(trustLocalPlugin('/fixture/install', '0.0.0-fixture')).toBe(true);
      expect(JSON.parse(fs.readFileSync(ocConfig(), 'utf-8')).plugins.entries).not.toEqual({});
      await run();
      expect(notes).toHaveLength(0);
    } finally {
      if (prev === undefined) delete process.env.OPENCLAW_HOME; else process.env.OPENCLAW_HOME = prev;
      spy.mockRestore();
      fs.rmSync(alt, { recursive: true, force: true });
    }
  });
});
