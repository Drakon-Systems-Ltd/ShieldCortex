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

  it('is report-only: a throwing or hanging check still delivers the ordinary notification and advances the baseline', async () => {
    await run();
    write({ mcpServers: { existing: { command: 'node', args: ['server.js'] }, docs: { command: 'npx', args: ['some-mcp'] } } });
    await run({ vetServers: async () => { throw new Error('boom'); } });
    expect(notes).toHaveLength(1);
    expect(notes[0].packageChecks).toBeUndefined();
    expect(notes[0].changes[0]).toMatchObject({ label: 'MCP server added', name: 'docs' });
    expect((await run()).notified).toBe(0); // acknowledged
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
