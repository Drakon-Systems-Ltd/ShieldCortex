import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { checkRuntimePosture, RUNTIME_POSTURE_LABEL } from '../doctor.js';
import { formatHostTable, scanHostTable } from '../../setup/host-table.js';
import { resolveHermesEvidence } from '../../memory/host-contract.js';
import { LIVE, NOW as FIXTURE_NOW, hermesPluginArtefacts, iso, reportBody, writeReport } from '../../posture/__tests__/self-report-fixture.js';

/**
 * #613 — doctor's posture lines read the typed posture module. The existing
 * `bound` surfaces (HOSTS table, host-contract evidence) are pinned
 * byte-for-byte against output captured from origin/main 8bd1ca20 before
 * this change.
 */

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(__dirname, '..', '..', '..');
const NOW = FIXTURE_NOW;
const hostDeps = { openclawBinaryPresent: () => false };
const deps = LIVE;
let root: string;
let home: string;
let configDir: string;

beforeEach(() => {
  root = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-doctor-posture-613-'));
  home = path.join(root, 'fx');
  configDir = path.join(home, '.shieldcortex');
  fs.mkdirSync(path.join(home, '.hermes'), { recursive: true });
  fs.mkdirSync(path.join(home, '.codex'), { recursive: true });
  fs.writeFileSync(path.join(home, '.hermes', 'config.yaml'), 'x: 1\n');
  hermesPluginArtefacts(home);
});

afterEach(() => {
  fs.rmSync(root, { recursive: true, force: true });
});

function hermesReport(over: Record<string, unknown> = {}): void {
  writeReport(configDir, reportBody({ policy_hash: null, heartbeat_at: iso(NOW - 1000), ...over }));
}

describe('#613 doctor posture rows read the posture module', () => {
  it('Hermes installed but not loaded: its row and the host summary are not pass', async () => {
    const rows = await checkRuntimePosture({ home, configDir, nowMs: NOW, hostDeps, deps });
    const hermes = rows.find((r) => r.label.startsWith(`${RUNTIME_POSTURE_LABEL}: Hermes`))!;
    expect(hermes).toBeDefined();
    expect(hermes.status).not.toBe('pass');
    expect(hermes.message).toMatch(/installed yes/);
    expect(hermes.message).toMatch(/unobserved/);
    const summary = rows.find((r) => r.label === `${RUNTIME_POSTURE_LABEL} (host)`)!;
    expect(summary.status).not.toBe('pass');
    expect(summary.message).toMatch(/records found only/);
    expect(summary.message).toMatch(/not attestation/);
  });

  it('one row per reporting instance: the row label names the instance', async () => {
    hermesReport();
    const rows = await checkRuntimePosture({ home, configDir, nowMs: NOW, hostDeps, deps });
    const hermes = rows.filter((r) => r.label.startsWith(`${RUNTIME_POSTURE_LABEL}: Hermes`));
    expect(hermes).toHaveLength(1);
    expect(hermes[0].label).toMatch(/p4242-s100/);
  });

  it('memory-only Codex row says it is not a tool gate', async () => {
    const rows = await checkRuntimePosture({ home, configDir, nowMs: NOW, hostDeps, deps });
    const codex = rows.find((r) => r.label.startsWith(`${RUNTIME_POSTURE_LABEL}: Codex`))!;
    expect(codex.message).toMatch(/not a tool gate/);
    expect(codex.status).not.toBe('pass');
  });

  it('a fresh loaded-enforce self-report is the only pass, and still no "enforced" wording', async () => {
    fs.rmSync(path.join(home, '.codex'), { recursive: true });
    hermesReport();
    const rows = await checkRuntimePosture({ home, configDir, nowMs: NOW, hostDeps, deps });
    const hermes = rows.find((r) => r.label.startsWith(`${RUNTIME_POSTURE_LABEL}: Hermes`))!;
    expect(hermes.status).toBe('pass');
    for (const r of rows) expect(`${r.message} ${r.fix ?? ''}`).not.toMatch(/enforced|protected|proves/i);
  });

  it('stale report row is not pass', async () => {
    hermesReport({ heartbeat_at: new Date(NOW - 3 * 24 * 3600_000).toISOString() });
    const rows = await checkRuntimePosture({ home, configDir, nowMs: NOW, hostDeps, deps });
    const hermes = rows.find((r) => r.label.startsWith(`${RUNTIME_POSTURE_LABEL}: Hermes`))!;
    expect(hermes.status).not.toBe('pass');
    expect(hermes.message).toMatch(/stale/);
  });

  it('no row is ever warn or fail — posture rows cannot change the doctor exit code', async () => {
    hermesReport({ configured_posture: 'advisory' });
    const rows = await checkRuntimePosture({ home, configDir, nowMs: NOW, hostDeps, deps });
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
