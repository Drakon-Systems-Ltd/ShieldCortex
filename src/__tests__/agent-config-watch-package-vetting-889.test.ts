/**
 * #889 phase 1 — the #916 agent-config watch vets a NEWLY ADDED MCP server
 * that launches a package (npx/uvx). Report-only: the finding rides on the
 * notification and never changes what is baselined or delivered. Synthetic:
 * temp HOME, inert placeholder commands, vetting stubbed (no network).
 */
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import fs from 'fs';
import os from 'os';
import path from 'path';
import {
  runAgentConfigWatch,
  addedServerEntries,
  specForPath,
  snapshotFile,
  agentConfigStatePath,
  PACKAGE_CHECK_UNFINISHED,
  type AgentConfigNotification,
  type AgentConfigLedgerRow,
} from '../audit/agent-config-watch.js';
import { buildAgentConfigChangeNotification, formatOperatorNotification } from '../defence/iron-dome/operator-notify.js';
import { vetMcpServers, type FetchLike } from '../defence/iron-dome/package-vetting.js';

let home: string;
let project: string;
let notes: AgentConfigNotification[];
let rows: AgentConfigLedgerRow[];
const mcpFile = () => path.join(project, '.mcp.json');
const write = (v: unknown) => fs.writeFileSync(mcpFile(), JSON.stringify(v, null, 2));

const run = (over: Partial<Parameters<typeof runAgentConfigWatch>[0]> = {}) =>
  runAgentConfigWatch({
    home, projectRoots: [project], dropzoneDirs: [],
    notify: async (n) => { notes.push(n); },
    ledger: (r) => { rows.push(r); return true; },
    ...over,
  });

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-889w-home-'));
  project = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-889w-proj-'));
  notes = []; rows = [];
  write({ mcpServers: { existing: { command: 'node', args: ['server.js'] } } });
});
afterEach(() => {
  fs.rmSync(home, { recursive: true, force: true });
  fs.rmSync(project, { recursive: true, force: true });
});

describe('agent config watch — package vetting of added MCP servers (#889)', () => {
  it('passes only the ADDED server entry to the vetting callback and puts the result on the notification', async () => {
    await run(); // baseline
    write({ mcpServers: { existing: { command: 'node', args: ['server.js'] }, docs: { command: 'npx', args: ['-y', 'some-mcp@1.0.0'] } } });
    let seen: Array<{ name: string; entry: unknown }> = [];
    await run({
      vetServers: async (servers) => {
        seen = servers;
        return [{ name: 'docs', malicious: true, reasons: ['OSV lists some-mcp@1.0.0 as known malicious (MAL-2026-18603)'] }];
      },
    });
    expect(seen).toEqual([{ name: 'docs', entry: { command: 'npx', args: ['-y', 'some-mcp@1.0.0'] } }]);
    expect(notes).toHaveLength(1);
    expect(notes[0].packageChecks).toEqual([{ name: 'docs', malicious: true, reasons: ['OSV lists some-mcp@1.0.0 as known malicious (MAL-2026-18603)'] }]);
    const text = formatOperatorNotification(buildAgentConfigChangeNotification(notes[0]));
    expect(text).toContain('KNOWN MALICIOUS PACKAGE for MCP server docs');
    expect(text).toContain('MAL-2026-18603');
  });

  it('is report-only: a throwing check still delivers the ordinary notification, says the check failed, and advances the baseline', async () => {
    await run();
    write({ mcpServers: { existing: { command: 'node', args: ['server.js'] }, docs: { command: 'npx', args: ['some-mcp'] } } });
    await run({ vetServers: async () => { throw new Error('boom'); } });
    expect(notes).toHaveLength(1);
    expect(notes[0].packageChecks).toEqual([{ name: 'docs', malicious: false, reasons: [PACKAGE_CHECK_UNFINISHED.failed] }]);
    expect(notes[0].changes[0]).toMatchObject({ label: 'MCP server added', name: 'docs' });
    expect((await run()).notified).toBe(0); // acknowledged
  });

  it('is report-only: a hanging check still delivers the ordinary notification, says the check did not finish, and advances the baseline', async () => {
    await run();
    write({ mcpServers: { existing: { command: 'node', args: ['server.js'] }, docs: { command: 'npx', args: ['some-mcp'] } } });
    const t0 = Date.now();
    const res = await run({ totalBudgetMs: 800, vetServers: () => new Promise(() => undefined) });
    expect(Date.now() - t0).toBeLessThan(800);
    expect(res).toMatchObject({ notified: 1, errors: 0 });
    expect(notes[0].packageChecks).toEqual([{ name: 'docs', malicious: false, reasons: [PACKAGE_CHECK_UNFINISHED.timedOut] }]);
    expect((await run()).notified).toBe(1 - 1); // acknowledged
  });

  it('does not call the callback for a change that adds no MCP server', async () => {
    await run();
    fs.writeFileSync(mcpFile(), JSON.stringify({ mcpServers: {} }));
    let called = false;
    await run({ vetServers: async () => { called = true; return []; } });
    expect(called).toBe(false);
  });

  it('addedServerEntries reads raw entries back from the file (snapshots only hold hashes)', () => {
    write({ mcpServers: { a: { command: 'uvx', args: ['tool'] } } });
    const spec = specForPath(mcpFile(), home, [project])!;
    const entries = addedServerEntries(mcpFile(), spec, [{ keyPath: 'mcpServers', section: 'mcpServers', kind: 'added', name: 'a' }]);
    expect(entries).toEqual([{ name: 'a', entry: { command: 'uvx', args: ['tool'] } }]);
    expect(addedServerEntries('/nonexistent/.mcp.json', spec, [{ keyPath: 'mcpServers', section: 'mcpServers', kind: 'added', name: 'a' }])).toEqual([]);
  });

  it('vetMcpServers shares one budget and ignores servers that launch no package', async () => {
    const fetchImpl: FetchLike = async () => { throw Object.assign(new Error('x'), { code: 'ENOTFOUND' }); };
    const out = await vetMcpServers([
      { name: 'local', entry: { command: 'node', args: ['x.js'] } },
      { name: 'remote', entry: { command: 'npx', args: ['-y', 'some-mcp'] } },
    ], { fetchImpl, stateDir: path.join(home, 'state') });
    expect(out).toEqual([{ name: 'remote', malicious: false, reasons: [expect.stringMatching(/^unchecked: network error/)] }]);
  });
});

// Release review (v5.20.0, Astra B3): each changed file awaited its own package
// check (up to 2.5 s) before notifying, serially, inside the watch's 5 s total
// budget, with no deadline check after that await. Three changed files with a
// slow check: two delivered, the run timed out, a third notification fired
// AFTER the run returned, and no baseline advanced, so every change re-alerted
// next session. The check now runs once for all files, concurrently, inside a
// window that closes by half the watch budget; delivery and baselining keep the
// other half.
describe('release review B3 — the package check is subordinate to the watch deadline', () => {
  let projects: string[];
  const ADDED = { mcpServers: { existing: { command: 'node', args: ['server.js'] }, docs: { command: 'npx', args: ['-y', 'some-mcp@1.0.0'] } } };
  const BASE = { mcpServers: { existing: { command: 'node', args: ['server.js'] } } };
  const runMany = (over: Partial<Parameters<typeof runAgentConfigWatch>[0]> = {}) =>
    runAgentConfigWatch({
      home, projectRoots: projects, dropzoneDirs: [],
      notify: async (n) => { notes.push(n); },
      ledger: (r) => { rows.push(r); return true; },
      ...over,
    });
  const setup = async (n: number) => {
    projects = Array.from({ length: n }, () => fs.mkdtempSync(path.join(os.tmpdir(), 'sc-889w-multi-')));
    for (const p of projects) fs.writeFileSync(path.join(p, '.mcp.json'), JSON.stringify(BASE));
    await runMany(); // baseline
    for (const p of projects) fs.writeFileSync(path.join(p, '.mcp.json'), JSON.stringify(ADDED));
    notes = []; rows = [];
  };
  const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
  afterEach(() => { for (const p of projects ?? []) fs.rmSync(p, { recursive: true, force: true }); projects = []; });

  it('three changed files and a check that never answers: all three delivered and baselined in time, nothing after return', async () => {
    await setup(3);
    const t0 = Date.now();
    const res = await runMany({ totalBudgetMs: 1200, vetServers: () => new Promise(() => undefined) });
    const returnedAfter = Date.now() - t0;
    expect(returnedAfter).toBeLessThan(1200);
    expect(res).toEqual({ baselined: false, notified: 3, errors: 0 });
    expect(rows.filter((r) => r.kind === 'error')).toEqual([]); // no timeout row
    expect(rows.filter((r) => r.outcome === 'change')).toHaveLength(3);
    for (const n of notes) expect(n.packageChecks).toEqual([{ name: 'docs', malicious: false, reasons: [PACKAGE_CHECK_UNFINISHED.timedOut] }]);
    // Nothing is delivered or recorded after the run has returned.
    const counts = [notes.length, rows.length];
    await sleep(400);
    expect([notes.length, rows.length]).toEqual(counts);
    // Every baseline advanced: the next run (no check) re-alerts nothing.
    notes = [];
    expect((await runMany()).notified).toBe(0);
    expect(notes).toEqual([]);
  });

  it('three changed files and a slow check that does answer: one shared window, every file gets its answer', async () => {
    await setup(3);
    let calls = 0;
    const t0 = Date.now();
    const res = await runMany({
      totalBudgetMs: 3000,
      vetServers: async (servers) => {
        calls++;
        await sleep(300);
        return servers.map((s) => ({ name: s.name, malicious: false, reasons: ['unchecked: timed out'] }));
      },
    });
    expect(calls).toBe(3);
    expect(Date.now() - t0).toBeLessThan(1500); // concurrent, not 3 x 300 ms serially plus slack
    expect(res).toEqual({ baselined: false, notified: 3, errors: 0 });
    for (const n of notes) expect(n.packageChecks).toEqual([{ name: 'docs', malicious: false, reasons: ['unchecked: timed out'] }]);
    expect((await runMany()).notified).toBe(0);
  });

  it('hands the check a budget that ends inside its window, never past half the watch budget', async () => {
    await setup(1);
    const seen: Array<number | undefined> = [];
    await runMany({ totalBudgetMs: 2000, vetServers: async (_s, o) => { seen.push(o?.budgetMs); return []; } });
    expect(seen).toHaveLength(1);
    expect(seen[0]).toBeGreaterThan(0);
    expect(seen[0]!).toBeLessThanOrEqual(1000 - 250);
  });

  it('no time left for the check (slow reads used half the budget): skipped, said so, and the notification still goes out', async () => {
    await setup(1);
    let called = false;
    let first = true; // one slow read (of many watched paths) uses up the first half of the budget
    const slowTake = async (file: string, spec: Parameters<typeof snapshotFile>[1]) => { if (first) { first = false; await sleep(650); } return snapshotFile(file, spec); };
    const res = await runMany({ totalBudgetMs: 1200, snapshot: slowTake, vetServers: async () => { called = true; return []; } });
    expect(called).toBe(false);
    expect(res).toMatchObject({ notified: 1, errors: 0 });
    expect(notes[0].packageChecks).toEqual([{ name: 'docs', malicious: false, reasons: [PACKAGE_CHECK_UNFINISHED.noTime] }]);
  });

  it('checks at most five changed files per run and says so for the rest', async () => {
    await setup(6);
    let calls = 0;
    const res = await runMany({ vetServers: async (servers) => { calls++; return servers.map((s) => ({ name: s.name, malicious: false, reasons: ['ok'] })); } });
    expect(calls).toBe(5);
    expect(res.notified).toBe(6);
    expect(notes.filter((n) => n.packageChecks?.[0]?.reasons[0] === PACKAGE_CHECK_UNFINISHED.tooMany)).toHaveLength(1);
  });

  it('an unfinished check lists only servers that have a command (a remote url server launches no package)', async () => {
    await setup(1);
    fs.writeFileSync(path.join(projects[0], '.mcp.json'), JSON.stringify({ mcpServers: { ...ADDED.mcpServers, remote: { url: 'https://mcp.example/x' } } }));
    await runMany({ vetServers: async () => { throw new Error('boom'); } });
    expect(notes[0].packageChecks).toEqual([{ name: 'docs', malicious: false, reasons: [PACKAGE_CHECK_UNFINISHED.failed] }]);
  });

  it('control: without a check the three files deliver and baseline as before, and the state file is written', async () => {
    await setup(3);
    const res = await runMany();
    expect(res).toEqual({ baselined: false, notified: 3, errors: 0 });
    expect(notes.every((n) => n.packageChecks === undefined)).toBe(true);
    expect(fs.existsSync(agentConfigStatePath(home))).toBe(true);
  });
});
