import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { checkRuntimePosture, RUNTIME_POSTURE_LABEL } from '../doctor.js';
import { formatHostTable, scanHostTable } from '../../setup/host-table.js';
import { resolveHermesEvidence } from '../../memory/host-contract.js';
import { SELF_REPORT_SCHEMA, SELF_REPORT_VERSION } from '../../posture/posture-record.js';
import { postureSelfReportDir } from '../../posture/collect.js';

/**
 * #613 — doctor's posture lines read the typed posture module. The existing
 * `bound` surfaces (HOSTS table, host-contract evidence) are pinned
 * byte-for-byte against output captured from origin/main 8bd1ca20 before
 * this change.
 */

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(__dirname, '..', '..', '..');
const NOW = Date.parse('2026-09-29T12:00:00.000Z');
const hostDeps = { openclawBinaryPresent: () => false };
let root: string;
let home: string;
let configDir: string;

beforeEach(() => {
  root = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-doctor-posture-613-'));
  home = path.join(root, 'fx');
  configDir = path.join(home, '.shieldcortex');
  fs.mkdirSync(path.join(home, '.hermes', 'plugins', 'shieldcortex'), { recursive: true });
  fs.mkdirSync(path.join(home, '.codex'), { recursive: true });
  fs.writeFileSync(path.join(home, '.hermes', 'config.yaml'), 'x: 1\n');
  fs.writeFileSync(path.join(home, '.hermes', 'plugins', 'shieldcortex', 'plugin.yaml'), 'name: shieldcortex\n');
});

afterEach(() => {
  fs.rmSync(root, { recursive: true, force: true });
});

function hermesReport(over: Record<string, unknown> = {}): void {
  fs.mkdirSync(postureSelfReportDir(configDir), { recursive: true });
  fs.writeFileSync(path.join(postureSelfReportDir(configDir), 'hermes--default.json'), JSON.stringify({
    schema: SELF_REPORT_SCHEMA,
    version: SELF_REPORT_VERSION,
    runtime: 'hermes',
    profile: 'default',
    plane: 'tool-gate',
    loaded: true,
    configured_posture: 'enforce',
    scanner: 'available',
    policy_hash: null,
    runtime_version: null,
    plugin_id: 'shieldcortex',
    plugin_version: '0.1.0',
    plugin_hash: null,
    instance_id: 'pid:1',
    written_at: new Date(NOW - 1000).toISOString(),
    last_denial_at: null,
    degraded_intervals: [],
    ...over,
  }));
}

describe('#613 doctor posture rows read the posture module', () => {
  it('Hermes installed but not loaded: its row and the host summary are not pass', async () => {
    const rows = await checkRuntimePosture({ home, configDir, nowMs: NOW, hostDeps });
    const hermes = rows.find((r) => r.label.startsWith(`${RUNTIME_POSTURE_LABEL}: Hermes`))!;
    expect(hermes).toBeDefined();
    expect(hermes.status).not.toBe('pass');
    expect(hermes.message).toMatch(/installed yes/);
    expect(hermes.message).toMatch(/unobserved/);
    const summary = rows.find((r) => r.label === `${RUNTIME_POSTURE_LABEL} (host)`)!;
    expect(summary.status).not.toBe('pass');
  });

  it('memory-only Codex row says it is not a tool gate', async () => {
    const rows = await checkRuntimePosture({ home, configDir, nowMs: NOW, hostDeps });
    const codex = rows.find((r) => r.label.startsWith(`${RUNTIME_POSTURE_LABEL}: Codex`))!;
    expect(codex.message).toMatch(/not a tool gate/);
    expect(codex.status).not.toBe('pass');
  });

  it('a fresh loaded-enforce self-report is the only pass, and still no "enforced" wording', async () => {
    fs.rmSync(path.join(home, '.codex'), { recursive: true });
    hermesReport();
    const rows = await checkRuntimePosture({ home, configDir, nowMs: NOW, hostDeps });
    const hermes = rows.find((r) => r.label.startsWith(`${RUNTIME_POSTURE_LABEL}: Hermes`))!;
    expect(hermes.status).toBe('pass');
    for (const r of rows) expect(`${r.message} ${r.fix ?? ''}`).not.toMatch(/enforced|protected|proves/i);
  });

  it('stale report row is not pass', async () => {
    hermesReport({ written_at: new Date(NOW - 3 * 24 * 3600_000).toISOString() });
    const rows = await checkRuntimePosture({ home, configDir, nowMs: NOW, hostDeps });
    const hermes = rows.find((r) => r.label.startsWith(`${RUNTIME_POSTURE_LABEL}: Hermes`))!;
    expect(hermes.status).not.toBe('pass');
    expect(hermes.message).toMatch(/stale/);
  });

  it('no row is ever warn or fail — posture rows cannot change the doctor exit code', async () => {
    hermesReport({ configured_posture: 'advisory' });
    const rows = await checkRuntimePosture({ home, configDir, nowMs: NOW, hostDeps });
    for (const r of rows) expect(['pass', 'info']).toContain(r.status);
  });

  it('runDoctor includes the posture check', () => {
    const src = fs.readFileSync(path.join(REPO, 'src', 'cli', 'doctor.ts'), 'utf8');
    const list = src.slice(src.indexOf('const checks: Array<'), src.indexOf('for (const check of checks)'));
    expect(list).toMatch(/\bcheckRuntimePosture\b/);
  });
});

describe('#613 existing `bound` output is unchanged', () => {
  it('HOSTS table is byte-identical to the pre-change capture', () => {
    const lines = formatHostTable(scanHostTable(home, hostDeps), '5.2.1', {
      signedEnabled: false, signedEnforce: false, claudeWired: false, openclaw: 'unknown',
    });
    expect(lines).toEqual([
      'ShieldCortex  5.2.1    Guard off',
      '',
      '  Claude Code       absent   —  memory + tool gate',
      '  OpenClaw          absent   —  memory + tool gate',
      '  Hermes            present  wired     memory + tool gate',
      '  Codex             present  not wired  memory only — not a gate',
      '  Cursor / VS Code  absent   —  memory only — not a gate',
      '',
      'Unwired hosts on this box:',
      '  shieldcortex codex install',
    ]);
  });

  it('host-contract bound / boundReason for an installed Hermes plugin is unchanged', () => {
    const ev = resolveHermesEvidence(
      { config: { kind: 'absent' }, profiles: [], profileScanComplete: true, scPluginInstalled: true, nativeArtifacts: [], declared: false },
      { contract: '', plane: 'shieldcortex', nowMs: 0 } as never,
    );
    expect({ bound: ev.bound, boundReason: ev.boundReason }).toEqual({ bound: true, boundReason: 'SC Hermes plugin installed' });
  });
});
