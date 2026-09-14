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
  afterEach(() => {
    for (const home of homes) rmSync(home, { recursive: true, force: true });
    homes.length = 0;
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

  it('sees Hermes present but not wired, and OpenClaw wired from a plugin dir', () => {
    const h = home();
    mkdirSync(join(h, '.hermes'), { recursive: true });
    writeFileSync(join(h, '.hermes', 'config.yaml'), 'model: test\n');
    mkdirSync(join(h, '.openclaw', 'extensions', 'shieldcortex-realtime'), { recursive: true });
    writeFileSync(join(h, '.openclaw', 'openclaw.json'), '{}\n');
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
    const prevPath = process.env.PATH;
    process.env.PATH = '/nonexistent-sc-openclaw-path';
    try {
      mkdirSync(join(h, '.openclaw', 'hooks', 'cortex-memory'), { recursive: true });
      writeFileSync(join(h, '.openclaw', 'openclaw.json'), '{"plugins":{"entries":{}}}\n');
      const oc = scanHostTable(h).rows.find((r) => r.id === 'openclaw')!;
      expect(oc).toMatchObject({ present: false, wired: false });
      const text = formatHostTable(scanHostTable(h), '5.0.5').join('\n');
      expect(text).not.toMatch(/openclaw install/i);
      expect(presentUnwired(scanHostTable(h)).map((r) => r.id)).not.toContain('openclaw');
    } finally {
      process.env.PATH = prevPath;
    }
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
    writeFileSync(
      join(h, '.openclaw', 'openclaw.json'),
      '{"plugins":{"entries":{"shieldcortex-realtime":{"enabled":true}}}}\n',
    );
    fakeOpenClawBin(h);
    expect(scanHostTable(h).rows.find((r) => r.id === 'openclaw')).toMatchObject({ present: true, wired: true });
    expect(presentUnwired(scanHostTable(h)).map((r) => r.id)).not.toContain('openclaw');
  });
});
