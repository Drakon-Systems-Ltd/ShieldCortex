/**
 * #916 agent configuration watch. Synthetic and inert: plain JSON edits in an
 * isolated temp HOME, harmless placeholder commands, no network, no shell.
 */
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import fs from 'fs';
import os from 'os';
import path from 'path';
import {
  agentConfigWatchEnabled,
  loadAgentConfigState,
  runAgentConfigWatch,
  type AgentConfigLedgerRow,
  type AgentConfigNotification,
} from '../audit/agent-config-watch.js';
import { withOwnConfigWrite } from '../audit/agent-config-watch-own-write.js';
import {
  buildAgentConfigChangeNotification,
  formatOperatorNotification,
} from '../defence/iron-dome/operator-notify.js';

const SECRET_CMD = 'echo fixture-injected-command-9f3a';

let home: string;
let project: string;
let notes: AgentConfigNotification[];
let rows: AgentConfigLedgerRow[];

const settings = () => path.join(home, '.claude', 'settings.json');
const tasks = () => path.join(project, '.vscode', 'tasks.json');
const writeJson = (p: string, v: unknown) => { fs.mkdirSync(path.dirname(p), { recursive: true }); fs.writeFileSync(p, JSON.stringify(v, null, 2)); };
const readJson = (p: string) => JSON.parse(fs.readFileSync(p, 'utf-8'));

const run = (over: Partial<Parameters<typeof runAgentConfigWatch>[0]> = {}) =>
  runAgentConfigWatch({
    home,
    projectRoots: [project],
    notify: async (n) => { notes.push(n); },
    ledger: (r) => { rows.push(r); return true; },
    ...over,
  });

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-916-home-'));
  project = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-916-proj-'));
  notes = [];
  rows = [];
  writeJson(settings(), { theme: 'dark', hooks: { SessionStart: [{ hooks: [{ type: 'command', command: 'echo baseline' }] }] } });
  writeJson(tasks(), { version: '2.0.0', tasks: [{ label: 'build', type: 'shell', command: 'echo build' }] });
});

describe('agent config watch (#916)', () => {
  it('(a) first run records a baseline silently', async () => {
    const r = await run();
    expect(r.baselined).toBe(true);
    expect(notes).toHaveLength(0);
    expect(rows).toHaveLength(0);
    expect(loadAgentConfigState(home).initialised).toBe(true);
    expect((await run()).notified).toBe(0);
  });

  it('(b) a non-SC hook added to settings.json = one notification, one ledger row, no raw command', async () => {
    await run();
    const s = readJson(settings());
    s.hooks.SessionStart.push({ hooks: [{ type: 'command', command: SECRET_CMD }] });
    writeJson(settings(), s);
    await run();
    expect(notes).toHaveLength(1);
    expect(notes[0].file).toBe('~/.claude/settings.json');
    expect(notes[0].changes[0]).toMatchObject({ label: 'hook added', name: 'SessionStart' });
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ file: '~/.claude/settings.json', keyPath: 'hooks', kind: 'hook added', outcome: 'change' });
    const text = formatOperatorNotification(buildAgentConfigChangeNotification(notes[0]));
    expect(JSON.stringify([notes, rows, text])).not.toContain('fixture-injected');
    expect(text).toMatch(/hook added \(SessionStart\)/);
    expect(loadAgentConfigState(home).lastChangeAt).toBeDefined();
    // acknowledged: the same state does not re-alert
    await run();
    expect(notes).toHaveLength(1);
  });

  it('(c) a new .vscode/tasks.json task = one notification', async () => {
    await run();
    const t = readJson(tasks());
    t.tasks.push({ label: 'persist', type: 'shell', command: SECRET_CMD });
    writeJson(tasks(), t);
    await run();
    expect(notes).toHaveLength(1);
    expect(notes[0].changes[0]).toMatchObject({ label: 'task added', name: 'persist' });
    expect(JSON.stringify(notes)).not.toContain('fixture-injected');
  });

  it('(c2) JSONC comments in tasks.json parse', async () => {
    fs.writeFileSync(tasks(), '// c\n{ "tasks": [ { "label": "a", "command": "echo a" /* x */ }, ], }');
    await run();
    fs.writeFileSync(tasks(), '// c\n{ "tasks": [ { "label": "a", "command": "echo a" }, { "label": "b", "command": "echo b" } ] }');
    await run();
    expect(notes[0].changes[0]).toMatchObject({ label: 'task added', name: 'b' });
  });

  it('(d) a new mcpServers entry = one notification', async () => {
    const mcp = path.join(home, '.claude.json');
    writeJson(mcp, { mcpServers: { files: { command: 'echo files' } } });
    await run();
    writeJson(mcp, { mcpServers: { files: { command: 'echo files' }, extra: { command: SECRET_CMD } } });
    await run();
    expect(notes).toHaveLength(1);
    expect(notes[0].file).toBe('~/.claude.json');
    expect(notes[0].changes[0]).toMatchObject({ label: 'MCP server added', name: 'extra' });
    writeJson(mcp, { mcpServers: { files: { command: 'echo changed' }, extra: { command: SECRET_CMD } } });
    await run();
    expect(notes[1].changes[0]).toMatchObject({ label: 'MCP server changed', name: 'files' });
  });

  it('(d2) Codex TOML mcp_servers and removal kinds', async () => {
    const toml = path.join(home, '.codex', 'config.toml');
    fs.mkdirSync(path.dirname(toml), { recursive: true });
    fs.writeFileSync(toml, 'model = "x"\n[mcp_servers.one]\ncommand = "echo one"\n');
    await run();
    fs.writeFileSync(toml, 'model = "y"\n[mcp_servers.one]\ncommand = "echo one"\n[mcp_servers.two]\ncommand = "echo two"\n');
    await run();
    expect(notes).toHaveLength(1);
    expect(notes[0].changes[0]).toMatchObject({ label: 'MCP server added', name: 'two' });
    fs.writeFileSync(toml, 'model = "y"\n[mcp_servers.two]\ncommand = "echo two"\n');
    await run();
    expect(notes[1].changes[0]).toMatchObject({ label: 'MCP server removed', name: 'one' });
  });

  it('(e) a ShieldCortex rewrite of its own hooks = no notification', async () => {
    await run();
    withOwnConfigWrite(settings(), () => {
      const s = readJson(settings());
      s.hooks.PreToolUse = [{ matcher: '*', hooks: [{ type: 'command', command: 'shieldcortex hook pre-tool' }] }];
      writeJson(settings(), s);
    }, home);
    await run();
    expect(notes).toHaveLength(0);
    // and the baseline moved: a later foreign hook still alerts exactly once
    const s = readJson(settings());
    s.hooks.PreToolUse.push({ hooks: [{ type: 'command', command: SECRET_CMD }] });
    writeJson(settings(), s);
    await run();
    expect(notes).toHaveLength(1);
  });

  it('(e2) own write does not launder an earlier foreign edit', async () => {
    await run();
    const s = readJson(settings());
    s.hooks.Stop = [{ hooks: [{ type: 'command', command: SECRET_CMD }] }];
    writeJson(settings(), s);
    withOwnConfigWrite(settings(), () => {
      const t = readJson(settings());
      t.hooks.PreToolUse = [{ hooks: [{ type: 'command', command: 'shieldcortex hook pre-tool' }] }];
      writeJson(settings(), t);
    }, home);
    await run();
    expect(notes).toHaveLength(1);
    expect(notes[0].changes.map((c) => c.name)).toContain('Stop');
  });

  it('(e3) the real installer write path (writeJsonConfigWithBackup) does not alert', async () => {
    jest.resetModules();
    const spy = jest.spyOn(os, 'homedir').mockReturnValue(home);
    try {
      await run();
      const { writeJsonConfigWithBackup } = await import('../setup/json-config.js');
      const s = readJson(settings());
      s.hooks.SessionStart.push({ hooks: [{ type: 'command', command: 'shieldcortex hook session-start' }] });
      writeJsonConfigWithBackup(settings(), s);
      await run();
      expect(notes).toHaveLength(0);
    } finally {
      spy.mockRestore();
    }
  });

  it('(f) a non-security edit (theme) = no notification', async () => {
    await run();
    const s = readJson(settings());
    s.theme = 'light';
    s.hooks.SessionStart[0].hooks[0].command = 'echo baseline'; // identical
    writeJson(settings(), s);
    await run();
    expect(notes).toHaveLength(0);
    expect(rows).toHaveLength(0);
  });

  it('(g) timeout = fail open with one ledger row and no notification', async () => {
    await run();
    const r = await run({ totalBudgetMs: 30, snapshot: () => new Promise(() => {}) });
    expect(r.errors).toBe(1);
    expect(notes).toHaveLength(0);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ kind: 'error', outcome: 'error' });
    expect(rows[0].detail).toMatch(/timed out/);
  });

  it('(g2) a thrown read error is a per-file health error, never raw error text', async () => {
    await run();
    const before = loadAgentConfigState(home).files;
    const r = await run({ snapshot: () => { throw new Error('EACCES fixture'); } });
    // every watched path failed: one health error per file, baselines kept
    expect(r.errors).toBeGreaterThan(1);
    expect(rows.length).toBe(r.errors);
    expect(rows.every((x) => x.kind === 'health-error' && x.detail === 'read-error (unclassified)')).toBe(true);
    expect(JSON.stringify(rows)).not.toContain('fixture');
    expect(notes).toHaveLength(0);
    expect(loadAgentConfigState(home).files).toEqual(before);
  });

  it('(g3) undelivered notification keeps the change pending and re-sends next run', async () => {
    await run();
    const s = readJson(settings());
    s.hooks.Stop = [{ hooks: [{ type: 'command', command: SECRET_CMD }] }];
    writeJson(settings(), s);
    await run({ notify: async () => { throw new Error('no channel'); } });
    expect(rows.filter((r) => r.outcome === 'error')).toHaveLength(1);
    await run();
    expect(notes).toHaveLength(1);
  });

  it('(h) opt-out disables the watch', () => {
    expect(agentConfigWatchEnabled({})).toBe(true);
    expect(agentConfigWatchEnabled({ sessionStart: { agentConfigWatch: false } })).toBe(false);
  });

  it('a first-seen project root baselines silently; a new file in a known root alerts', async () => {
    await run();
    const other = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-916-proj2-'));
    writeJson(path.join(other, '.vscode', 'tasks.json'), { tasks: [{ label: 'x', command: 'echo x' }] });
    await run({ projectRoots: [project, other] });
    expect(notes).toHaveLength(0);
    writeJson(path.join(project, '.cursor', 'mcp.json'), { mcpServers: { s: { command: 'echo s' } } });
    await run({ projectRoots: [project, other] });
    expect(notes).toHaveLength(1);
    expect(notes[0].changes[0].label).toBe('MCP server added');
  });
});
