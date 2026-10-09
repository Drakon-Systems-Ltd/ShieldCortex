import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { buildPolicyEvidence, runPolicyEvidence } from '../policy-evidence.js';
import { LIVE, H, NOW as FIXTURE_NOW, denial, hermesPluginArtefacts, iso, reportBody, writeReport } from '../../posture/__tests__/self-report-fixture.js';

/**
 * #613 — `shieldcortex policy-evidence`: the posture records as JSON, each
 * item carrying `source: "sc://..."` provenance, read from the same typed
 * module doctor reads. It never exports `bound`, and never says "enforced".
 */

const NOW = FIXTURE_NOW;
let root: string;
let home: string;
let configDir: string;
const hostDeps = { openclawBinaryPresent: () => false };
const deps = LIVE;

beforeEach(() => {
  root = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-evidence-613-'));
  home = path.join(root, 'home');
  configDir = path.join(home, '.shieldcortex');
  fs.mkdirSync(path.join(home, '.hermes'), { recursive: true });
  fs.writeFileSync(path.join(home, '.hermes', 'config.yaml'), 'x: 1\n');
  hermesPluginArtefacts(home);
  fs.mkdirSync(path.join(home, '.codex'), { recursive: true });
  fs.mkdirSync(path.join(home, '.claude'), { recursive: true });
  // Claude Code: a per-call hook report with a fresh blocked action.
  writeReport(configDir, reportBody({
    runtime: 'claude_code',
    instance: { key: 'c0123456789abcdef01234567', pid: null, process_start: null, started_at: iso(NOW - 60_000), liveness: 'per-call' },
    plugin: { id: 'shieldcortex-pre-tool-hook', version: '5.2.1', hash: H('e') },
    policy_hash: H('d'),
    heartbeat_at: iso(NOW - 1000),
    denials: {
      blocked_action: denial({ at: iso(NOW - 500), instance: 'c0123456789abcdef01234567', plugin_hash: H('e'), policy_hash: H('d'), tested_path: 'PreToolUse:Bash' }),
      synthetic_probe: null,
      blocked_action_count: 1,
    },
  }));
});

afterEach(() => {
  fs.rmSync(root, { recursive: true, force: true });
});

describe('#613 policy-evidence export', () => {
  it('is versioned JSON with one record per (runtime, profile, plane, instance)', () => {
    const ev = buildPolicyEvidence({ home, configDir, nowMs: NOW, hostDeps, deps });
    expect(ev.schema).toBe('shieldcortex.policy-evidence');
    expect(ev.version).toBe(1);
    const keys = ev.records.map((r) => `${r.runtime}/${r.profile}/${r.plane}/${r.key.instance ?? 'none'}`);
    expect(new Set(keys).size).toBe(keys.length);
    expect(keys).toEqual(expect.arrayContaining([
      'claude_code/default/tool-gate/c0123456789abcdef01234567',
      'hermes/default/tool-gate/none',
      'codex/default/memory/none',
    ]));
  });

  it('states the host-integrity limitation and makes no completeness claim', () => {
    const ev = buildPolicyEvidence({ home, configDir, nowMs: NOW, hostDeps, deps });
    expect(ev.limitations.join(' ')).toMatch(/not attestation/);
    expect(ev.limitations.join(' ')).toMatch(/Nothing here claims there are no others/);
    expect(ev.summary.completeness).toBe('not-claimed');
  });

  it('every item, and every field evidence inside it, carries sc:// provenance', () => {
    const ev = buildPolicyEvidence({ home, configDir, nowMs: NOW, hostDeps, deps });
    expect(ev.source).toMatch(/^sc:\/\//);
    for (const r of ev.records) {
      expect(r.source).toMatch(/^sc:\/\/posture\//);
      const fields = [r.liveness, r.capability, r.installed, r.runtime_loaded, r.configured_posture, r.scanner,
        r.effective_policy_hash, r.observed_denial, r.incidents, r.denials.blocked_action, r.denials.synthetic_probe];
      for (const f of fields) if (f) expect(f.source).toMatch(/^sc:\/\//);
    }
    expect(ev.summary.weakest).toMatch(/^sc:\/\//);
  });

  it('never exports bound, and never uses the words enforced / protected / proves', () => {
    const text = JSON.stringify(buildPolicyEvidence({ home, configDir, nowMs: NOW, hostDeps, deps }));
    expect(text).not.toMatch(/"bound"/);
    expect(text).not.toMatch(/enforced|protected|proves/i);
  });

  it('summary is the weakest record: a loaded Claude Code gate does not lift an unobserved Hermes', () => {
    const ev = buildPolicyEvidence({ home, configDir, nowMs: NOW, hostDeps, deps });
    const claude = ev.records.find((r) => r.runtime === 'claude_code')!;
    expect(claude.runtime_loaded.value).toBe('yes');
    expect(claude.liveness.value).toBe('per-call');
    expect(claude.observed_denial.value).toBe('observed');
    expect(claude.observed_denial.kind).toBe('blocked-action');
    expect(claude.observed_denial.tested_path).toBe('PreToolUse:Bash');
    expect(ev.summary.green).toBe(false);
    expect(['unobserved', 'not-a-gate']).toContain(ev.summary.level);
  });

  it('runPolicyEvidence prints parseable JSON and exits 0', () => {
    const out = runPolicyEvidence([], { home, configDir, nowMs: NOW, hostDeps, deps });
    expect(out.code).toBe(0);
    const parsed = JSON.parse(out.output) as { records: unknown[] };
    expect(Array.isArray(parsed.records)).toBe(true);
  });

  it('rejects unknown flags rather than ignoring them', () => {
    const out = runPolicyEvidence(['--fix'], { home, configDir, nowMs: NOW, hostDeps, deps });
    expect(out.code).toBe(2);
  });
});
