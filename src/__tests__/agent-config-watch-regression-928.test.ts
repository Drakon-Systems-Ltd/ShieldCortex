/**
 * PR #928 panel findings 1-8 (+ ledger-failure, doctor wording): synthetic
 * regressions. Temp HOME/project dirs only, placeholder commands, no network.
 * Each test fails on f7d49cab and passes on the repair.
 */
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import fs from 'fs';
import os from 'os';
import path from 'path';
import {
  loadAgentConfigState,
  runAgentConfigWatch,
  stripJsonc,
  type AgentConfigLedgerRow,
  type AgentConfigNotification,
} from '../audit/agent-config-watch.js';
import { withOwnConfigWrite } from '../audit/agent-config-watch-own-write.js';
import { parseToml } from '../audit/toml-lite.js';
import { armChildDeadline, makeAgentConfigLedger, projectRootFromArgv } from '../audit/agent-config-watch-runner.js';
import { resolveProjectRoots } from '../audit/agent-config-watch.js';
// @ts-expect-error plain .mjs launcher
import { maybeSpawnAgentConfigWatch } from '../../scripts/lib/agent-config-watch-spawn.mjs';
import { checkAgentConfigWatch } from '../cli/doctor.js';

const TOKEN = 'https://hooks.example.invalid/x?token=SYNTH-TOKEN-7c1e';

let home: string;
let project: string;
let notes: AgentConfigNotification[];
let rows: AgentConfigLedgerRow[];

const settings = () => path.join(home, '.claude', 'settings.json');
const toml = () => path.join(home, '.codex', 'config.toml');
const tasks = () => path.join(project, '.vscode', 'tasks.json');
const put = (p: string, s: string): string => { fs.mkdirSync(path.dirname(p), { recursive: true }); fs.writeFileSync(p, s); return s; };
const putJson = (p: string, v: unknown) => put(p, JSON.stringify(v, null, 2));
const readJson = (p: string) => JSON.parse(fs.readFileSync(p, 'utf-8'));

const run = (over: Partial<Parameters<typeof runAgentConfigWatch>[0]> = {}) =>
  runAgentConfigWatch({
    home,
    projectRoots: [project],
    // Never the default drop directories: those include the real /tmp.
    dropzoneDirs: [],
    notify: async (n) => { notes.push(n); },
    ledger: (r) => { rows.push(r); return true; },
    ...over,
  });

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-928-home-'));
  project = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-928-proj-'));
  notes = [];
  rows = [];
});

afterEach(() => {
  fs.rmSync(home, { recursive: true, force: true });
  fs.rmSync(project, { recursive: true, force: true });
});

describe('finding 1: TOML is parsed, not line-hashed', () => {
  it('a commented table header adding an MCP server alerts', async () => {
    put(toml(), 'model = "fixture"\n');
    await run();
    put(toml(), 'model = "fixture"\n[mcp_servers.fixture] # valid comment\ncommand = "echo"\n');
    await run();
    expect(notes).toHaveLength(1);
    expect(notes[0].changes[0]).toMatchObject({ label: 'MCP server added', name: 'fixture' });
  });

  it('dotted keys and inline tables register a server', async () => {
    put(toml(), 'model = "fixture"\n');
    await run();
    put(toml(), 'model = "fixture"\nmcp_servers.dotted.command = "echo"\nmcp_servers.inl = { command = "echo" }\n');
    await run();
    expect(notes).toHaveLength(1);
    expect(notes[0].changes.map((c) => c.name).sort()).toEqual(['dotted', 'inl']);
  });

  it('a multiline string containing a fake [table] neither hides nor fakes a server', async () => {
    put(toml(), 'note = """\n[mcp_servers.fake]\ncommand = "x"\n"""\n');
    await run();
    // fake header lives inside a string: not a server, and editing the text is not a server change
    put(toml(), 'note = """\n[mcp_servers.fake]\ncommand = "y"\n"""\n');
    await run();
    expect(notes).toHaveLength(0);
    // a real server added after the string still alerts
    put(toml(), 'note = """\n[mcp_servers.fake]\ncommand = "y"\n"""\n[mcp_servers.real]\ncommand = "echo"\n');
    await run();
    expect(notes).toHaveLength(1);
    expect(notes[0].changes[0].name).toBe('real');
  });

  it('key reorder and comment edits do NOT alert; a value change does', async () => {
    put(toml(), '[mcp_servers.s]\ncommand = "echo"\nargs = ["a"]\n');
    await run();
    put(toml(), '[mcp_servers.s] # now commented\nargs = ["a"]  # c\ncommand = "echo"\n');
    await run();
    expect(notes).toHaveLength(0);
    put(toml(), '[mcp_servers.s]\nargs = ["b"]\ncommand = "echo"\n');
    await run();
    expect(notes).toHaveLength(1);
    expect(notes[0].changes[0]).toMatchObject({ label: 'MCP server changed', name: 's' });
  });

  it('malformed TOML throws a parse error and is reported, not an empty snapshot', async () => {
    expect(() => parseToml('[mcp_servers.s\ncommand = ')).toThrow();
    put(toml(), 'model = "fixture"\n');
    await run();
    put(toml(), '[mcp_servers.s\ncommand = "echo"\n');
    const r = await run();
    expect(r.errors).toBe(1);
    expect(rows[0]).toMatchObject({ kind: 'health-error', detail: 'parse-error' });
  });
});

describe('finding 2: JSONC comma stripping is string-aware', () => {
  it('stripJsonc keeps `echo ,]` verbatim', () => {
    expect(JSON.parse(stripJsonc('{"c": "echo ,]", }'))).toEqual({ c: 'echo ,]' });
  });

  it('`echo ,]` -> `echo ]` alerts', async () => {
    putJson(tasks(), { tasks: [{ label: 't', command: 'echo ,]' }] });
    await run();
    putJson(tasks(), { tasks: [{ label: 't', command: 'echo ]' }] });
    await run();
    expect(notes).toHaveLength(1);
    expect(notes[0].changes[0]).toMatchObject({ label: 'task changed', name: 't' });
  });
});

describe('finding 3: one unreadable file does not blind the rest', () => {
  it('EISDIR on settings.json: tasks change still alerts, baseline kept, health error recorded', async () => {
    putJson(settings(), { hooks: { Stop: [{ hooks: [{ type: 'command', command: 'echo a' }] }] } });
    putJson(tasks(), { tasks: [{ label: 'a', command: 'echo a' }] });
    await run();
    const baseline = loadAgentConfigState(home).files[settings()];
    expect(baseline).toBeDefined();
    fs.rmSync(settings());
    fs.mkdirSync(settings());
    putJson(tasks(), { tasks: [{ label: 'a', command: 'echo a' }, { label: 'b', command: 'echo b' }] });
    const r = await run();
    expect(notes).toHaveLength(1);
    expect(notes[0].changes[0]).toMatchObject({ label: 'task added', name: 'b' });
    expect(r.errors).toBe(1);
    expect(rows.find((x) => x.kind === 'health-error')).toMatchObject({ detail: 'read-error (EISDIR)', outcome: 'error' });
    expect(loadAgentConfigState(home).files[settings()]).toEqual(baseline);
    expect(loadAgentConfigState(home).fileErrors).toBeDefined();
  });
});

describe('finding 4: own-write equality is semantic', () => {
  it('a hook-event reorder then a withOwnConfigWrite addition gives no alert', async () => {
    putJson(settings(), { hooks: { SessionStart: [{ hooks: [{ type: 'command', command: 'echo s' }] }], Stop: [{ hooks: [{ type: 'command', command: 'echo t' }] }] } });
    await run();
    const s = readJson(settings());
    putJson(settings(), { hooks: { Stop: s.hooks.Stop, SessionStart: s.hooks.SessionStart } }); // reorder only
    expect((await run()).notified).toBe(0);
    withOwnConfigWrite(settings(), () => {
      const t = readJson(settings());
      t.hooks.PreToolUse = [{ hooks: [{ type: 'command', command: 'shieldcortex hook pre-tool' }] }];
      return putJson(settings(), t);
    }, home);
    await run();
    expect(notes).toHaveLength(0);
  });

  it('the Codex installer write (src/setup/codex.ts) is suppressed', async () => {
    jest.resetModules();
    const spy = jest.spyOn(os, 'homedir').mockReturnValue(home);
    const log = jest.spyOn(console, 'log').mockImplementation(() => undefined);
    // Under ts-jest the compiled MCP entry (src/index.js) does not exist; pretend it does.
    const realExists = fs.existsSync;
    const exists = jest.spyOn(fs, 'existsSync').mockImplementation(((p: fs.PathLike) => /[\\/]index\.js$/.test(String(p)) || realExists(p)) as never);
    try {
      put(toml(), 'model = "fixture"\n');
      await run();
      const { installCodex, uninstallCodex } = await import('../setup/codex.js');
      await installCodex();
      expect(fs.readFileSync(toml(), 'utf-8')).toContain('mcp_servers');
      await run();
      expect(notes).toHaveLength(0);
      await uninstallCodex();
      await run();
      expect(notes).toHaveLength(0);
    } finally {
      exists.mockRestore();
      log.mockRestore();
      spy.mockRestore();
    }
  });
});

describe('finding 5: malformed first-run file', () => {
  it('is a health error with no change notification and no contents logged', async () => {
    put(settings(), '{ malformed SECRET-CONTENT-31d2');
    const r = await run();
    expect(r.baselined).toBe(true);
    expect(r.errors).toBe(1);
    expect(notes).toHaveLength(0);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ kind: 'health-error', detail: 'parse-error', outcome: 'error' });
    expect(JSON.stringify([rows, loadAgentConfigState(home)])).not.toContain('SECRET-CONTENT');
    // unchanged next run: no repeat ledger row
    await run();
    expect(rows).toHaveLength(1);
  });
});

describe('finding 6: hook payload cwd reaches the watcher', () => {
  it('the launcher passes --project-root and the runner turns it into a scanned root', () => {
    const dist = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-928-dist-'));
    fs.mkdirSync(path.join(dist, 'audit'), { recursive: true });
    fs.writeFileSync(path.join(dist, 'audit', 'agent-config-watch-runner.js'), '');
    const calls: Array<{ args: string[] }> = [];
    const spawnImpl = ((_c: string, args: string[]) => { calls.push({ args }); return { on() {}, unref() {} }; }) as never;
    const payloadCwd = path.join(project, 'payload-root');
    expect(maybeSpawnAgentConfigWatch({}, { distRoot: dist, spawnImpl, cwd: payloadCwd })).toBe(true);
    const i = calls[0].args.indexOf('--project-root');
    expect(i).toBeGreaterThan(0);
    expect(calls[0].args[i + 1]).toBe(payloadCwd);
    const root = projectRootFromArgv(calls[0].args);
    expect(root).toBe(payloadCwd);
    expect(root).not.toBe(process.cwd());
    expect(resolveProjectRoots({}, root)).toContain(payloadCwd);
    expect(projectRootFromArgv(['x', '--project-root', 'relative/path'])).toBeUndefined();
    fs.rmSync(dist, { recursive: true, force: true });
  });

  it('a payload-cwd project differing from process cwd is actually scanned', async () => {
    const other = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-928-payload-'));
    putJson(path.join(other, '.vscode', 'tasks.json'), { tasks: [{ label: 'a', command: 'echo a' }] });
    await run({ projectRoots: resolveProjectRoots({}, other) });
    putJson(path.join(other, '.vscode', 'tasks.json'), { tasks: [{ label: 'a', command: 'echo a' }, { label: 'b', command: 'echo b' }] });
    await run({ projectRoots: resolveProjectRoots({}, other) });
    expect(notes).toHaveLength(1);
    expect(notes[0].changes[0].name).toBe('b');
    fs.rmSync(other, { recursive: true, force: true });
  });

  it('the child gets a whole-process deadline', () => {
    const exit = jest.fn();
    jest.useFakeTimers();
    try {
      armChildDeadline(50, exit);
      jest.advanceTimersByTime(60);
      expect(exit).toHaveBeenCalledTimes(1);
    } finally {
      jest.useRealTimers();
    }
  });
});

describe('finding 7: ledger stores fixed categories, never error text', () => {
  it('a notify error carrying a synthetic token is not persisted', async () => {
    putJson(tasks(), { tasks: [{ label: 'a', command: 'echo a' }] });
    await run();
    putJson(tasks(), { tasks: [{ label: 'a', command: 'echo a' }, { label: 'b', command: 'echo b' }] });
    await run({ notify: async () => { throw new Error(`POST ${TOKEN} failed`); } });
    const err = rows.find((r) => r.kind === 'notify-error');
    expect(err).toBeDefined();
    expect(err!.detail).toBe('notification not delivered (unclassified)');
    expect(JSON.stringify(rows)).not.toContain('SYNTH-TOKEN');
  });

  it('a whole-check failure stores only the category', async () => {
    putJson(tasks(), { tasks: [{ label: 'a', command: 'echo a' }] });
    await run();
    const boom = Object.assign(new Error(`read ${TOKEN}`), { code: 'EFIXTURE' });
    await run({ ledger: (r) => { rows.push(r); return true; }, now: () => { throw boom; } });
    expect(JSON.stringify(rows)).not.toContain('SYNTH-TOKEN');
    expect(rows.some((r) => r.kind === 'error' && /EFIXTURE/.test(r.detail))).toBe(true);
  });
});

describe('finding 8: nothing commits after the deadline', () => {
  it('a snapshot delayed past the budget saves no state, notifies and logs nothing afterwards', async () => {
    let first = true;
    const r = await run({
      totalBudgetMs: 20,
      // only the first read is slow; once it resolves the abandoned body would race to the end
      snapshot: () => {
        if (!first) return {};
        first = false;
        return new Promise((res) => setTimeout(() => res({}), 120));
      },
    });
    expect(r.errors).toBe(1);
    const rowsAtReturn = rows.length;
    await new Promise((res) => setTimeout(res, 300));
    expect(fs.existsSync(path.join(home, '.shieldcortex', 'state', 'agent-config-watch.json'))).toBe(false);
    expect(notes).toHaveLength(0);
    expect(rows).toHaveLength(rowsAtReturn);
  });
});

describe('ledger failure does not advance the baseline', () => {
  const change = async () => {
    putJson(tasks(), { tasks: [{ label: 'a', command: 'echo a' }] });
    await run();
    putJson(tasks(), { tasks: [{ label: 'a', command: 'echo a' }, { label: 'b', command: 'echo b' }] });
  };

  it.each([['returns false', () => false], ['throws', () => { throw new Error('db down'); }]])('ledger %s: change is retried', async (_n, bad) => {
    await change();
    const r = await run({ ledger: bad as never });
    expect(r.notified).toBe(1);
    expect(loadAgentConfigState(home).pendingChanges).toBe(1);
    await run(); // healthy ledger: re-reported and recorded
    expect(notes).toHaveLength(2);
    expect(rows.filter((x) => x.outcome === 'change')).toHaveLength(1);
    expect(loadAgentConfigState(home).pendingChanges).toBe(0);
  });

  it('makeAgentConfigLedger returns false when the audit log throws', () => {
    const ledger = makeAgentConfigLedger((() => { throw new Error('x'); }) as never);
    expect(ledger({ file: 'f', keyPath: '', kind: 'k', detail: 'd', outcome: 'error' })).toBe(false);
  });
});

describe('doctor wording: detected vs reported', () => {
  it('a detected-but-undelivered change shows as detected and pending, with a warn status', async () => {
    putJson(tasks(), { tasks: [{ label: 'a', command: 'echo a' }] });
    await run({ });
    putJson(tasks(), { tasks: [{ label: 'a', command: 'echo a' }, { label: 'b', command: 'echo b' }] });
    await run({ notify: async () => { throw new Error('no channel'); } });
    const c = await checkAgentConfigWatch(home);
    expect(c.status).toBe('warn');
    expect(c.message).toMatch(/last unexpected change detected \d{4}-/);
    expect(c.message).not.toMatch(/no unexpected change detected/);
    expect(c.message).toMatch(/1 detected change\(s\) not yet reported/);
  });

  it('a parse-failing file warns', async () => {
    put(settings(), '{ malformed');
    await run();
    const c = await checkAgentConfigWatch(home);
    expect(c.status).toBe('warn');
    expect(c.message).toMatch(/could not be read or parsed/);
  });
});
