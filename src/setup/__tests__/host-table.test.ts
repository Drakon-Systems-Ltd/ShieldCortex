import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from '@jest/globals';
import {
  formatHostTable,
  presentUnwired,
  repairJobsFor,
  scanHostTable,
  writeRepairAgentBrief,
} from '../host-table.js';

describe('host table', () => {
  const homes: string[] = [];
  const previousHome = process.env.HOME;
  const previousOpenClawHome = process.env.OPENCLAW_HOME;
  afterEach(() => {
    for (const home of homes) rmSync(home, { recursive: true, force: true });
    homes.length = 0;
    process.env.HOME = previousHome;
    if (previousOpenClawHome === undefined) delete process.env.OPENCLAW_HOME;
    else process.env.OPENCLAW_HOME = previousOpenClawHome;
  });

  function home(): string {
    const h = mkdtempSync(join(tmpdir(), 'sc-hosts-'));
    homes.push(h);
    return h;
  }

  it('marks absent hosts not present and not wired', () => {
    const table = scanHostTable(home());
    expect(table.rows).toHaveLength(5);
    expect(table.rows.every((r) => !r.present && !r.wired)).toBe(true);
    expect(presentUnwired(table)).toHaveLength(0);
  });

  function fakeOpenClawBin(h: string): void {
    const binDir = join(h, '.npm-global', 'bin');
    mkdirSync(binDir, { recursive: true });
    writeFileSync(join(binDir, 'openclaw'), '#!/bin/sh\nexit 0\n', { mode: 0o755 });
  }

  function enableOpenClaw(h: string): void {
    writeFileSync(
      join(h, '.openclaw', 'openclaw.json'),
      JSON.stringify({
        plugins: {
          allow: ['shieldcortex-realtime'],
          entries: { 'shieldcortex-realtime': { enabled: true } },
        },
      }),
    );
  }

  function validLocalPlugin(h: string): void {
    const plugin = join(h, '.openclaw', 'extensions', 'shieldcortex-realtime');
    mkdirSync(plugin, { recursive: true });
    writeFileSync(join(plugin, 'index.js'), 'export default {};\n');
    writeFileSync(join(plugin, 'openclaw.plugin.json'), '{}\n');
  }

  it('sees Hermes present but not wired, and OpenClaw wired from a valid local plugin', () => {
    const h = home();
    mkdirSync(join(h, '.hermes'), { recursive: true });
    writeFileSync(join(h, '.hermes', 'config.yaml'), 'model: test\n');
    validLocalPlugin(h);
    enableOpenClaw(h);
    fakeOpenClawBin(h);
    const table = scanHostTable(h);
    const hermes = table.rows.find((r) => r.id === 'hermes')!;
    const oc = table.rows.find((r) => r.id === 'openclaw')!;
    expect(hermes.present).toBe(true);
    expect(hermes.wired).toBe(false);
    expect(oc.present).toBe(true);
    expect(oc.wired).toBe(true);
    expect(hermes.kind).toBe('bound');
    expect(table.rows.find((r) => r.id === 'codex')!.kind).toBe('memory-only');
  });

  it('prints Guard off and does not prescribe enable', () => {
    const h = home();
    mkdirSync(join(h, '.claude'), { recursive: true });
    const text = formatHostTable(scanHostTable(h), '5.0.4').join('\n');
    expect(text).toContain('Guard off');
    expect(text).toContain('Claude Code');
    expect(text).toContain('Hermes');
    expect(text).not.toMatch(/action-guard-enable|iron-dome activate/i);
    expect(presentUnwired(scanHostTable(h)).map((r) => r.id)).toEqual(['claude']);
  });

  it('repair brief names only the jobs and forbids Guard / conversation / import', () => {
    const h = home();
    mkdirSync(join(h, '.hermes'), { recursive: true });
    writeFileSync(join(h, '.hermes', 'config.yaml'), 'model: test\n');
    const jobs = repairJobsFor(scanHostTable(h));
    expect(jobs).toEqual(['wire-hermes']);
    const dest = join(h, '.shieldcortex', 'repair-brief.md');
    writeRepairAgentBrief(jobs, dest);
    const brief = readFileSync(dest, 'utf8');
    expect(brief).toContain('wire-hermes');
    expect(brief).toMatch(/Action Guard stays off/i);
    expect(brief).toMatch(/Do not grant conversation access/);
    expect(brief).toMatch(/Do not import native memory/);
  });

  it('Codex is wired only when the MCP block exists', () => {
    const h = home();
    mkdirSync(join(h, '.codex'), { recursive: true });
    expect(scanHostTable(h).rows.find((r) => r.id === 'codex')).toMatchObject({ present: true, wired: false });
    writeFileSync(join(h, '.codex', 'config.toml'), '[mcp_servers.shieldcortex-memory]\ncommand = "shieldcortex"\n');
    expect(scanHostTable(h).rows.find((r) => r.id === 'codex')).toMatchObject({ present: true, wired: true });
  });

  it('Claude is present-unwired without PreToolUse, wired only with a shieldcortex pre-tool hook', () => {
    const h = home();
    mkdirSync(join(h, '.claude'), { recursive: true });
    writeFileSync(join(h, '.claude', 'settings.json'), '{"hooks":{}}\n');
    expect(scanHostTable(h).rows.find((r) => r.id === 'claude')).toMatchObject({ present: true, wired: false });
    writeFileSync(
      join(h, '.claude', 'settings.json'),
      JSON.stringify({ hooks: { PreToolUse: [{ hooks: [{ command: 'shieldcortex hook pre-tool' }] }] } }),
    );
    expect(scanHostTable(h).rows.find((r) => r.id === 'claude')).toMatchObject({ present: true, wired: true });
  });

  it('does not treat stray shieldcortex text plus empty PreToolUse as wired', () => {
    const h = home();
    mkdirSync(join(h, '.claude'), { recursive: true });
    writeFileSync(
      join(h, '.claude', 'settings.json'),
      JSON.stringify({
        permissions: { allow: ['Bash(shieldcortex *)'] },
        hooks: { PreToolUse: [] },
      }),
    );
    expect(scanHostTable(h).rows.find((r) => r.id === 'claude')).toMatchObject({ present: true, wired: false });
  });

  it('does not treat leftover ~/.hermes/ekho-state as Hermes present', () => {
    const h = home();
    mkdirSync(join(h, '.hermes', 'ekho-state'), { recursive: true });
    expect(scanHostTable(h).rows.find((r) => r.id === 'hermes')).toMatchObject({ present: false, wired: false });
    expect(presentUnwired(scanHostTable(h)).map((r) => r.id)).not.toContain('hermes');
  });

  it('does not treat leftover ~/.openclaw without a binary as OpenClaw present', () => {
    const h = home();
    const noBinary = { openclawBinaryPresent: () => false };
    mkdirSync(join(h, '.openclaw', 'hooks', 'cortex-memory'), { recursive: true });
    writeFileSync(join(h, '.openclaw', 'openclaw.json'), '{"plugins":{"entries":{}}}\n');
    const table = scanHostTable(h, noBinary);
    const oc = table.rows.find((r) => r.id === 'openclaw')!;
    expect(oc).toMatchObject({ present: false, wired: false });
    const text = formatHostTable(table, '5.0.5').join('\n');
    expect(text).not.toMatch(/openclaw install/i);
    expect(presentUnwired(table).map((r) => r.id)).not.toContain('openclaw');
  });

  it('does not treat leftover cortex-memory hook as OpenClaw wired', () => {
    const h = home();
    mkdirSync(join(h, '.openclaw', 'hooks', 'cortex-memory'), { recursive: true });
    writeFileSync(join(h, '.openclaw', 'openclaw.json'), '{"plugins":{"entries":{}}}\n');
    fakeOpenClawBin(h);
    const oc = scanHostTable(h).rows.find((r) => r.id === 'openclaw')!;
    expect(oc).toMatchObject({ present: true, wired: false });
    expect(presentUnwired(scanHostTable(h)).map((r) => r.id)).toContain('openclaw');
  });

  it('wires OpenClaw from shieldcortex-realtime in openclaw.json, not from cortex-memory', () => {
    const h = home();
    mkdirSync(join(h, '.openclaw', 'hooks', 'cortex-memory'), { recursive: true });
    validLocalPlugin(h);
    enableOpenClaw(h);
    fakeOpenClawBin(h);
    expect(scanHostTable(h).rows.find((r) => r.id === 'openclaw')).toMatchObject({ present: true, wired: true });
    expect(presentUnwired(scanHostTable(h)).map((r) => r.id)).not.toContain('openclaw');
  });

  it('recognises the npm-managed OpenClaw plugin layout', () => {
    const h = home();
    const plugin = join(
      h,
      '.openclaw',
      'npm',
      'projects',
      'drakon-systems-shieldcortex-realtime-a__openclaw-generation__g-b',
      'node_modules',
      '@drakon-systems',
      'shieldcortex-realtime',
    );
    mkdirSync(plugin, { recursive: true });
    writeFileSync(join(plugin, 'package.json'), '{"name":"@drakon-systems/shieldcortex-realtime"}\n');
    enableOpenClaw(h);
    fakeOpenClawBin(h);

    expect(scanHostTable(h).rows.find((r) => r.id === 'openclaw')).toMatchObject({
      present: true,
      wired: true,
    });
  });

  it.each([
    ['disabled entry', { plugins: { allow: ['shieldcortex-realtime'], entries: { 'shieldcortex-realtime': { enabled: false } } } }],
    ['missing allow entry', { plugins: { allow: [], entries: { 'shieldcortex-realtime': { enabled: true } } } }],
    ['mere plugin-id text', { note: 'shieldcortex-realtime' }],
  ])('does not call OpenClaw wired from %s', (_label, config) => {
    const h = home();
    validLocalPlugin(h);
    writeFileSync(join(h, '.openclaw', 'openclaw.json'), JSON.stringify(config));
    fakeOpenClawBin(h);
    expect(scanHostTable(h).rows.find((r) => r.id === 'openclaw')).toMatchObject({ present: true, wired: false });
  });

  it('does not call a bare stale extension directory wired', () => {
    const h = home();
    mkdirSync(join(h, '.openclaw', 'extensions', 'shieldcortex-realtime'), { recursive: true });
    enableOpenClaw(h);
    fakeOpenClawBin(h);
    expect(scanHostTable(h).rows.find((r) => r.id === 'openclaw')).toMatchObject({ present: true, wired: false });
  });

  it('uses an absolute OPENCLAW_HOME as the operator home for config and binary probes', () => {
    const tableHome = home();
    const openclawHome = home();
    process.env.OPENCLAW_HOME = openclawHome;
    validLocalPlugin(openclawHome);
    enableOpenClaw(openclawHome);
    fakeOpenClawBin(openclawHome);

    expect(scanHostTable(tableHome).rows.find((r) => r.id === 'openclaw')).toMatchObject({
      present: true,
      wired: true,
    });
  });

  it('expands ~/… OPENCLAW_HOME once against an absolute HOME', () => {
    const tableHome = home();
    const operatorHome = home();
    const openclawHome = join(operatorHome, 'isolated');
    process.env.HOME = operatorHome;
    process.env.OPENCLAW_HOME = '~/isolated';
    mkdirSync(join(openclawHome, '.openclaw'), { recursive: true });
    writeFileSync(join(openclawHome, '.openclaw', 'openclaw.json'), '{}\n');
    fakeOpenClawBin(openclawHome);

    expect(scanHostTable(tableHome).rows.find((r) => r.id === 'openclaw')).toMatchObject({
      present: true,
      wired: false,
    });
  });
});
