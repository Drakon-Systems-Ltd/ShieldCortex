import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { buildPolicyEvidence, runPolicyEvidence } from '../policy-evidence.js';
import { SELF_REPORT_SCHEMA, SELF_REPORT_VERSION } from '../../posture/posture-record.js';
import { postureSelfReportDir } from '../../posture/collect.js';

/**
 * #613 — `shieldcortex policy-evidence`: the posture records as JSON, each
 * item carrying `source: "sc://..."` provenance, read from the same typed
 * module doctor reads. It never exports `bound`, and never says "enforced".
 */

const NOW = Date.parse('2026-09-29T12:00:00.000Z');
let root: string;
let home: string;
let configDir: string;
const hostDeps = { openclawBinaryPresent: () => false };

beforeEach(() => {
  root = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-evidence-613-'));
  home = path.join(root, 'home');
  configDir = path.join(home, '.shieldcortex');
  fs.mkdirSync(path.join(home, '.hermes', 'plugins', 'shieldcortex'), { recursive: true });
  fs.writeFileSync(path.join(home, '.hermes', 'config.yaml'), 'x: 1\n');
  fs.writeFileSync(path.join(home, '.hermes', 'plugins', 'shieldcortex', 'plugin.yaml'), 'name: shieldcortex\n');
  fs.mkdirSync(path.join(home, '.codex'), { recursive: true });
  fs.mkdirSync(path.join(home, '.claude'), { recursive: true });
  fs.mkdirSync(postureSelfReportDir(configDir), { recursive: true });
  fs.writeFileSync(path.join(postureSelfReportDir(configDir), 'claude_code--default.json'), JSON.stringify({
    schema: SELF_REPORT_SCHEMA,
    version: SELF_REPORT_VERSION,
    runtime: 'claude_code',
    profile: 'default',
    plane: 'tool-gate',
    loaded: true,
    configured_posture: 'enforce',
    scanner: 'available',
    policy_hash: `sha256:${'d'.repeat(64)}`,
    runtime_version: null,
    plugin_id: 'shieldcortex-pre-tool-hook',
    plugin_version: '5.2.1',
    plugin_hash: `sha256:${'e'.repeat(64)}`,
    instance_id: 'pid:9',
    written_at: new Date(NOW - 1000).toISOString(),
    last_denial_at: new Date(NOW - 500).toISOString(),
    degraded_intervals: [],
  }));
});

afterEach(() => {
  fs.rmSync(root, { recursive: true, force: true });
});

describe('#613 policy-evidence export', () => {
  it('is versioned JSON with one record per (runtime, profile, plane)', () => {
    const ev = buildPolicyEvidence({ home, configDir, nowMs: NOW, hostDeps });
    expect(ev.schema).toBe('shieldcortex.policy-evidence');
    expect(ev.version).toBe(1);
    const keys = ev.records.map((r) => `${r.runtime}/${r.profile}/${r.plane}`);
    expect(new Set(keys).size).toBe(keys.length);
    expect(keys).toEqual(expect.arrayContaining(['claude_code/default/tool-gate', 'hermes/default/tool-gate', 'codex/default/memory']));
  });

  it('every item, and every probe inside it, carries sc:// provenance', () => {
    const ev = buildPolicyEvidence({ home, configDir, nowMs: NOW, hostDeps });
    expect(ev.source).toMatch(/^sc:\/\//);
    for (const r of ev.records) {
      expect(r.source).toMatch(/^sc:\/\/posture\//);
      expect(r.probe.source).toMatch(/^sc:\/\//);
      for (const s of Object.values(r.field_sources)) expect(s).toMatch(/^sc:\/\//);
    }
    expect(ev.summary.weakest).toMatch(/^sc:\/\//);
  });

  it('never exports bound, and never uses the words enforced / protected / proves', () => {
    const text = JSON.stringify(buildPolicyEvidence({ home, configDir, nowMs: NOW, hostDeps }));
    expect(text).not.toMatch(/"bound"/);
    expect(text).not.toMatch(/enforced|protected|proves/i);
  });

  it('summary is the weakest record: a loaded Claude Code gate does not lift an unobserved Hermes', () => {
    const ev = buildPolicyEvidence({ home, configDir, nowMs: NOW, hostDeps });
    const claude = ev.records.find((r) => r.runtime === 'claude_code')!;
    expect(claude.runtime_loaded).toBe('yes');
    expect(claude.observed_denial).toBe('observed');
    expect(ev.summary.green).toBe(false);
    expect(['unobserved', 'not-a-gate']).toContain(ev.summary.level);
  });

  it('runPolicyEvidence prints parseable JSON and exits 0', () => {
    const out = runPolicyEvidence([], { home, configDir, nowMs: NOW, hostDeps });
    expect(out.code).toBe(0);
    const parsed = JSON.parse(out.output) as { records: unknown[] };
    expect(Array.isArray(parsed.records)).toBe(true);
  });

  it('rejects unknown flags rather than ignoring them', () => {
    const out = runPolicyEvidence(['--fix'], { home, configDir, nowMs: NOW, hostDeps });
    expect(out.code).toBe(2);
  });
});
