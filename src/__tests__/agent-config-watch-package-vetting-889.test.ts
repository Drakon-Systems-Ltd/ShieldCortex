/**
 * #889 phase 1 — the #916 agent-config watch vets a NEWLY ADDED MCP server
 * that launches a package (npx/uvx). Report-only: the finding follows the
 * change notice out as a follow-up and never changes what is baselined or
 * delivered. Synthetic:
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
import { createWebhookNotifyChannel } from '../defence/iron-dome/webhook-notify-channel.js';
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
  it('passes only the ADDED server entry to the vetting callback and sends the result as a follow-up to the change notice', async () => {
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
    expect(notes).toHaveLength(2);
    // The change notice is exactly what it is without the check...
    expect(notes[0]).toEqual({ file: expect.any(String), changes: [{ label: 'MCP server added', name: 'docs' }], changeCount: 1 });
    // ...and the answer follows it, naming the notice it follows.
    expect(notes[1]).toMatchObject({ file: notes[0].file, changes: notes[0].changes, packageCheckFollowUp: true, severity: 'high' });
    expect(notes[1].packageChecks).toEqual([{ name: 'docs', malicious: true, reasons: ['OSV lists some-mcp@1.0.0 as known malicious (MAL-2026-18603)'] }]);
    const text = formatOperatorNotification(buildAgentConfigChangeNotification(notes[1]));
    expect(text).toMatch(/^ShieldCortex HIGH SEVERITY: package check, follow-up to the .*\.mcp\.json change notice \(MCP server added \(docs\)\)\./);
    expect(text).toContain('KNOWN MALICIOUS PACKAGE for MCP server docs');
    expect(text).toContain('MAL-2026-18603');
    expect(text).toContain('Remove that MCP server before starting an agent.');
    expect(text).not.toContain('changed outside ShieldCortex');
    const webhookShape = buildAgentConfigChangeNotification(notes[1]);
    expect(webhookShape.packageCheckFollowUp).toBe(true);
    expect(buildAgentConfigChangeNotification(notes[0]).packageCheckFollowUp).toBeUndefined();
  });

  it('is report-only: a throwing check still delivers the ordinary notification, says the check failed, and advances the baseline', async () => {
    await run();
    write({ mcpServers: { existing: { command: 'node', args: ['server.js'] }, docs: { command: 'npx', args: ['some-mcp'] } } });
    await run({ vetServers: async () => { throw new Error('boom'); } });
    expect(notes).toHaveLength(2);
    expect(notes[0].packageChecks).toBeUndefined();
    expect(notes[0].changes[0]).toMatchObject({ label: 'MCP server added', name: 'docs' });
    expect(notes[1]).toMatchObject({ packageCheckFollowUp: true, packageChecks: [{ name: 'docs', malicious: false, reasons: [PACKAGE_CHECK_UNFINISHED.failed] }] });
    expect(notes[1].severity).toBeUndefined();
    expect((await run()).notified).toBe(0); // acknowledged
  });

  it('is report-only: a hanging check still delivers the ordinary notification, says the check did not finish, and advances the baseline', async () => {
    await run();
    write({ mcpServers: { existing: { command: 'node', args: ['server.js'] }, docs: { command: 'npx', args: ['some-mcp'] } } });
    const t0 = Date.now();
    const res = await run({ totalBudgetMs: 800, vetServers: () => new Promise(() => undefined) });
    expect(Date.now() - t0).toBeLessThan(800);
    expect(res).toMatchObject({ notified: 1, errors: 0 });
    expect(notes[0].packageChecks).toBeUndefined();
    expect(notes[1]).toMatchObject({ packageCheckFollowUp: true, packageChecks: [{ name: 'docs', malicious: false, reasons: [PACKAGE_CHECK_UNFINISHED.timedOut] }] });
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
// next session. Round 1 ran the check once for all files inside a window that
// closed by half the budget, but delivery still waited for that window: with
// 1100 ms deliveries (3 x 1100 > the 2500 ms left) round 2 reproduced the same
// loss. The check now starts beside delivery and nothing before the save waits
// for it; its answer goes out afterwards as a follow-up, only while time lasts.
describe('release review B3 — the package check is off the delivery and baseline path', () => {
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
  const changeNotes = () => notes.filter((n) => !n.packageCheckFollowUp);
  const followUps = () => notes.filter((n) => n.packageCheckFollowUp);
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
    expect(changeNotes()).toHaveLength(3);
    for (const n of changeNotes()) expect(n.packageChecks).toBeUndefined();
    expect(followUps()).toHaveLength(3);
    for (const n of followUps()) expect(n.packageChecks).toEqual([{ name: 'docs', malicious: false, reasons: [PACKAGE_CHECK_UNFINISHED.timedOut] }]);
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
    expect(followUps()).toHaveLength(3);
    for (const n of followUps()) expect(n.packageChecks).toEqual([{ name: 'docs', malicious: false, reasons: ['unchecked: timed out'] }]);
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
    expect(changeNotes()[0].packageChecks).toBeUndefined();
    expect(followUps().map((n) => n.packageChecks)).toEqual([[{ name: 'docs', malicious: false, reasons: [PACKAGE_CHECK_UNFINISHED.noTime] }]]);
  });

  it('checks at most five changed files per run and says so for the rest', async () => {
    await setup(6);
    let calls = 0;
    const res = await runMany({ vetServers: async (servers) => { calls++; return servers.map((s) => ({ name: s.name, malicious: false, reasons: ['ok'] })); } });
    expect(calls).toBe(5);
    expect(res.notified).toBe(6);
    expect(changeNotes()).toHaveLength(6);
    expect(followUps()).toHaveLength(6);
    expect(followUps().filter((n) => n.packageChecks?.[0]?.reasons[0] === PACKAGE_CHECK_UNFINISHED.tooMany)).toHaveLength(1);
  });

  it('an unfinished check lists only servers that have a command (a remote url server launches no package)', async () => {
    await setup(1);
    fs.writeFileSync(path.join(projects[0], '.mcp.json'), JSON.stringify({ mcpServers: { ...ADDED.mcpServers, remote: { url: 'https://mcp.example/x' } } }));
    await runMany({ vetServers: async () => { throw new Error('boom'); } });
    expect(followUps()[0].packageChecks).toEqual([{ name: 'docs', malicious: false, reasons: [PACKAGE_CHECK_UNFINISHED.failed] }]);
  });

  it('control: without a check the three files deliver and baseline as before, and the state file is written', async () => {
    await setup(3);
    const res = await runMany();
    expect(res).toEqual({ baselined: false, notified: 3, errors: 0 });
    expect(notes.every((n) => n.packageChecks === undefined)).toBe(true);
    expect(fs.existsSync(agentConfigStatePath(home))).toBe(true);
  });

  // Round 2's reproduction, at the DEFAULT 5 s budget: three changed files,
  // each change notice taking 1100 ms to deliver (under the transport's 10 s
  // default) and each package check answering after 1900 ms (under the
  // runner's 2 s cap). Before: {baselined:false, notified:2, errors:1}, no
  // baseline advanced, the third notice landed after return, and a repeat run
  // re-alerted all three.
  const slowNotify = (ms: number) => async (n: AgentConfigNotification) => {
    events.push({ at: Date.now(), what: n.packageCheckFollowUp ? 'follow-up start' : 'notice start' });
    await sleep(ms);
    notes.push(n);
  };
  let events: Array<{ at: number; what: string }> = [];
  beforeEach(() => { events = []; });

  it('three files, 1100 ms deliveries, 1900 ms checks, default budget: all delivered, every baseline advanced, a repeat run notifies 0', async () => {
    await setup(3);
    const baseline = fs.readFileSync(agentConfigStatePath(home), 'utf-8');
    const malicious = [{ name: 'docs', malicious: true, reasons: ['OSV lists some-mcp@1.0.0 as known malicious (MAL-2026-18603)'] }];
    const t0 = Date.now();
    const res = await runMany({ notify: slowNotify(1100), vetServers: async () => { await sleep(1900); return malicious; } });
    const returnedAfter = Date.now() - t0;
    expect(res).toEqual({ baselined: false, notified: 3, errors: 0 });
    expect(returnedAfter).toBeLessThan(5000);
    // Exactly as without the check: three plain change notices, three change rows, no timeout row.
    expect(changeNotes()).toHaveLength(3);
    for (const n of changeNotes()) expect(n.packageChecks).toBeUndefined();
    expect(rows.filter((r) => r.outcome === 'change')).toHaveLength(3);
    expect(rows.filter((r) => r.kind === 'error')).toEqual([]);
    expect(fs.readFileSync(agentConfigStatePath(home), 'utf-8')).not.toBe(baseline); // saved (the repeat run below proves every file advanced)
    // Every follow-up started after the last change notice had been delivered.
    const firstFollowUp = events.findIndex((e) => e.what === 'follow-up start');
    expect(events.slice(0, 3).map((e) => e.what)).toEqual(['notice start', 'notice start', 'notice start']);
    expect(firstFollowUp).toBe(3);
    expect(events[firstFollowUp].at - events[2].at).toBeGreaterThanOrEqual(1050);
    // The answer goes out while time lasts (one fits: 3300 + 1100 < 5000), and
    // the rest are recorded as not delivered instead of overrunning the deadline.
    expect(followUps()).toHaveLength(1);
    expect(followUps()[0]).toMatchObject({ packageCheckFollowUp: true, severity: 'high', packageChecks: malicious });
    expect(rows.filter((r) => r.kind === 'notify-error').map((r) => r.detail)).toEqual([
      'package check follow-up not delivered (no time left)',
      'package check follow-up not delivered (no time left)',
    ]);
    // Nothing is delivered or recorded after the run has returned.
    const counts = [notes.length, rows.length, events.length];
    await sleep(1300);
    expect([notes.length, rows.length, events.length]).toEqual(counts);
    // Every baseline advanced: a repeat run, with the same slow check, notifies nothing.
    notes = []; rows = [];
    let vetted = 0;
    expect(await runMany({ notify: slowNotify(1100), vetServers: async () => { vetted++; await sleep(1900); return malicious; } })).toEqual({ baselined: false, notified: 0, errors: 0 });
    expect(notes).toEqual([]);
    expect(vetted).toBe(0);
  }, 20_000);

  it('control: the same three 1100 ms deliveries with no check at all give the same result and baselines', async () => {
    await setup(3);
    const res = await runMany({ notify: slowNotify(1100) });
    expect(res).toEqual({ baselined: false, notified: 3, errors: 0 });
    expect(changeNotes()).toHaveLength(3);
    expect(rows.filter((r) => r.outcome === 'change')).toHaveLength(3);
    notes = [];
    expect((await runMany({ notify: slowNotify(1100) })).notified).toBe(0);
  }, 20_000);

  it('three 1100 ms deliveries and a check that never answers: the same, with the answer unchecked', async () => {
    await setup(3);
    const res = await runMany({ notify: slowNotify(1100), vetServers: () => new Promise(() => undefined) });
    expect(res).toEqual({ baselined: false, notified: 3, errors: 0 });
    expect(rows.filter((r) => r.kind === 'error')).toEqual([]);
    expect(followUps().map((n) => n.packageChecks)).toEqual([[{ name: 'docs', malicious: false, reasons: [PACKAGE_CHECK_UNFINISHED.timedOut] }]]);
    notes = [];
    expect((await runMany({ notify: slowNotify(1100) })).notified).toBe(0);
  }, 20_000);

  it('a follow-up still in flight at the deadline is cut off: the run returns on time and its result and baseline are untouched', async () => {
    await setup(1);
    let release!: () => void;
    const held = new Promise<void>((r) => { release = r; });
    const t0 = Date.now();
    const res = await runMany({
      totalBudgetMs: 1500,
      notify: async (n) => { if (n.packageCheckFollowUp) { await held; return; } notes.push(n); },
      vetServers: async () => [{ name: 'docs', malicious: false, reasons: ['published 2 days ago'] }],
    });
    expect(Date.now() - t0).toBeLessThan(1500 + 400);
    expect(res).toEqual({ baselined: false, notified: 1, errors: 0 });
    expect(changeNotes()).toHaveLength(1);
    expect(rows.filter((r) => r.outcome === 'change')).toHaveLength(1);
    expect(rows.filter((r) => r.kind === 'error')).toEqual([]);
    expect(rows.filter((r) => r.kind === 'notify-error').map((r) => r.detail)).toEqual(['package check follow-up did not finish (timed out after 1500ms)']);
    const rowsAtReturn = rows.length;
    release(); // the cut-off send settling late records nothing more
    await sleep(20);
    expect(rows.length).toBe(rowsAtReturn);
    notes = []; rows = [];
    expect((await runMany()).notified).toBe(0);
  }, 20_000);

  it('a follow-up that fails to send is recorded, and the change notice it follows still counts and baselines', async () => {
    await setup(1);
    const res = await runMany({
      notify: async (n) => { if (n.packageCheckFollowUp) throw Object.assign(new Error('x'), { code: 'ECONNRESET' }); notes.push(n); },
      vetServers: async () => [{ name: 'docs', malicious: false, reasons: ['published 2 days ago'] }],
    });
    expect(res).toEqual({ baselined: false, notified: 1, errors: 0 });
    expect(rows.filter((r) => r.kind === 'notify-error')).toEqual([expect.objectContaining({ keyPath: 'mcpServers', detail: 'package check follow-up not delivered (ECONNRESET)', outcome: 'error' })]);
    expect((await runMany()).notified).toBe(0);
  });

  it('an undelivered change notice gets no follow-up (it re-alerts, and is re-checked, next run)', async () => {
    await setup(1);
    let calls = 0;
    const res = await runMany({
      notify: async () => { throw new Error('down'); },
      vetServers: async () => { calls++; return [{ name: 'docs', malicious: false, reasons: ['published 2 days ago'] }]; },
    });
    expect(res).toMatchObject({ notified: 0, errors: 1 });
    expect(calls).toBe(1);
    expect(rows.filter((r) => r.kind === 'notify-error').map((r) => r.detail)).toEqual([expect.stringMatching(/^notification not delivered/)]);
    notes = [];
    expect((await runMany()).notified).toBe(1);
  });
});

// #1054 (P2 source-head panel, Sol 4): `collect()` armed its window timer only
// when it was called, after delivery and saving. With a delivery that outlasts
// the package-check window, an answer that settled AFTER the window had closed
// (but before `collect()` ran) was still taken from the settled slot and sent
// as the check's answer. The window now closes when it ends, whenever
// `collect()` is called: a late answer is dropped and reported as not finished.
describe('#1054 — an answer that settles after the package-check window closed is not used', () => {
  let project2: string;
  const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
  const LATE = [{ name: 'docs', malicious: true, reasons: ['OSV lists some-mcp@1.0.0 as known malicious (MAL-2026-18603)'] }];
  const start = async () => {
    project2 = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-889w-late-'));
    const file = path.join(project2, '.mcp.json');
    fs.writeFileSync(file, JSON.stringify({ mcpServers: { existing: { command: 'node', args: ['server.js'] } } }));
    const go = (over: Partial<Parameters<typeof runAgentConfigWatch>[0]> = {}) => runAgentConfigWatch({
      home, projectRoots: [project2], dropzoneDirs: [],
      // Only the change notice is slow; the follow-up is delivered at once.
      notify: async (n) => { if (!n.packageCheckFollowUp) await sleep(3000); notes.push(n); },
      ledger: (r) => { rows.push(r); return true; },
      totalBudgetMs: 8000, // window: the 2500 ms ceiling
      ...over,
    });
    await runAgentConfigWatch({ home, projectRoots: [project2], dropzoneDirs: [], notify: async () => undefined, ledger: () => true });
    fs.writeFileSync(file, JSON.stringify({ mcpServers: { existing: { command: 'node', args: ['server.js'] }, docs: { command: 'npx', args: ['-y', 'some-mcp@1.0.0'] } } }));
    notes = []; rows = [];
    return go;
  };
  afterEach(() => { if (project2) fs.rmSync(project2, { recursive: true, force: true }); });

  it('delivery outlasts the window and the check answers after the cutoff but before collection: reported as not finished', async () => {
    const go = await start();
    let answeredAt = 0;
    const t0 = Date.now();
    const res = await go({ vetServers: async () => { await sleep(2750); answeredAt = Date.now() - t0; return LATE; } });
    expect(res).toMatchObject({ notified: 1, errors: 0 });
    // The fixture did what it says: the answer came after the 2500 ms window and before the 3000 ms delivery ended.
    expect(answeredAt).toBeGreaterThanOrEqual(2700);
    expect(answeredAt).toBeLessThan(3000);
    const follow = notes.filter((n) => n.packageCheckFollowUp);
    expect(follow).toHaveLength(1);
    expect(follow[0].packageChecks).toEqual([{ name: 'docs', malicious: false, reasons: [PACKAGE_CHECK_UNFINISHED.timedOut] }]);
    expect(follow[0].severity).toBeUndefined();
  }, 20_000);

  it('control: an answer inside the window is used even when collection comes after the window', async () => {
    const go = await start();
    await go({ vetServers: async () => { await sleep(1000); return LATE; } });
    const follow = notes.filter((n) => n.packageCheckFollowUp);
    expect(follow).toHaveLength(1);
    expect(follow[0]).toMatchObject({ severity: 'high', packageChecks: LATE });
  }, 20_000);

  it('a check that throws after the cutoff is reported as not finished, not as failed', async () => {
    const go = await start();
    await go({ vetServers: async () => { await sleep(2750); throw new Error('late'); } });
    const follow = notes.filter((n) => n.packageCheckFollowUp);
    expect(follow[0].packageChecks).toEqual([{ name: 'docs', malicious: false, reasons: [PACKAGE_CHECK_UNFINISHED.timedOut] }]);
  }, 20_000);
});

// #1054 (CASE N4 on the source PR): the follow-up's webhook payload carried
// `packageCheckFollowUp` and `text` only, so a receiver that reads fields had
// to parse the sentence to learn which server was flagged. The follow-up
// payload now carries the same sanitised `packageChecks` the notification
// holds. The change notice's payload is unchanged.
describe('#1054 — the webhook payload of a package-check follow-up carries the findings', () => {
  const post = async (n: Parameters<typeof buildAgentConfigChangeNotification>[0]) => {
    let body: Record<string, unknown> = {};
    const fetchImpl = (async (_url: string, init: RequestInit) => { body = JSON.parse(String(init.body)); return { ok: true, status: 200, text: async () => '' } as unknown as Response; }) as unknown as typeof fetch;
    const channel = createWebhookNotifyChannel({ url: 'https://ops.example.com/hook', fetchImpl });
    expect(await channel.send(buildAgentConfigChangeNotification(n), { timeoutMs: 5_000 })).toEqual({ delivered: true });
    return body;
  };
  const CHANGE = { file: '~/.mcp.json', changes: [{ label: 'MCP server added', name: 'docs' }], changeCount: 1 };

  it('follow-up: packageChecks is present, bounded and sanitised, beside text', async () => {
    const body = await post({ ...CHANGE, severity: 'high', packageCheckFollowUp: true, packageChecks: [{ name: 'docs\u001b[31m', malicious: true, reasons: ['OSV lists some-mcp@1.0.0 as known malicious (MAL-2026-18603)', 'b', 'c', 'd'] }] });
    expect(body).toMatchObject({ event: 'agent_config_change', packageCheckFollowUp: true, severity: 'high' });
    expect(body.packageChecks).toEqual([{ name: 'docs??31m', malicious: true, reasons: ['OSV lists some-mcp@1.0.0 as known malicious ?MAL-2026-18603?', 'b', 'c'] }]);
    expect(String(body.text)).toContain('KNOWN MALICIOUS PACKAGE for MCP server docs');
  });

  it('the change notice itself never carries packageChecks, and a follow-up without findings has no empty array', async () => {
    expect(await post(CHANGE)).not.toHaveProperty('packageChecks');
    expect(await post({ ...CHANGE, packageChecks: [{ name: 'docs', malicious: true, reasons: ['x'] }] })).not.toHaveProperty('packageChecks');
    const empty = await post({ ...CHANGE, packageCheckFollowUp: true });
    expect(empty).toMatchObject({ packageCheckFollowUp: true });
    expect(empty).not.toHaveProperty('packageChecks');
  });
});

// #1054 (P2 source-head panel, Daybreak 5 / Grok 4): the text said the watch
// checks MCP servers it reports as "added"; the code has always checked the
// ones it reports as added OR changed. The text now says so; this pins the code.
describe('#1054 — the watch checks an MCP server entry it reports as changed, not only added', () => {
  it('an existing entry edited to launch a package is handed to the check, and its finding follows the change notice', async () => {
    await run(); // baseline: `existing` runs `node server.js`
    write({ mcpServers: { existing: { command: 'npx', args: ['-y', 'some-mcp@1.0.0'] } } });
    let seen: Array<{ name: string; entry: unknown }> = [];
    await run({ vetServers: async (servers) => { seen = servers; return [{ name: 'existing', malicious: false, reasons: ['published 2 days ago'] }]; } });
    expect(seen).toEqual([{ name: 'existing', entry: { command: 'npx', args: ['-y', 'some-mcp@1.0.0'] } }]);
    expect(notes[0].changes).toEqual([{ label: 'MCP server changed', name: 'existing' }]);
    expect(notes[1]).toMatchObject({ packageCheckFollowUp: true, packageChecks: [{ name: 'existing', malicious: false, reasons: ['published 2 days ago'] }] });
  });

  it('addedServerEntries returns entries for both kinds and none for a removal', () => {
    write({ mcpServers: { a: { command: 'uvx', args: ['tool'] }, b: { command: 'npx', args: ['pkg'] } } });
    const spec = specForPath(mcpFile(), home, [project])!;
    const change = (kind: 'added' | 'changed' | 'removed', name: string) => ({ keyPath: 'mcpServers', section: 'mcpServers' as const, kind, name });
    expect(addedServerEntries(mcpFile(), spec, [change('added', 'a'), change('changed', 'b')]).map((e) => e.name)).toEqual(['a', 'b']);
    expect(addedServerEntries(mcpFile(), spec, [change('removed', 'a')])).toEqual([]);
  });
});
