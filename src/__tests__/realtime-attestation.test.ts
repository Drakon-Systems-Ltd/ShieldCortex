import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { closeDatabase, getDatabase, initDatabase } from '../database/init.js';
import { projectRealtimeLedger } from '../threat-graph/realtime-ledger.js';
import { PROJECTOR_VERSION } from '../threat-graph/projector.js';
import { runRiskSweep } from '../threat-graph/risk.js';

const __dirname = path.join(fileURLToPath(import.meta.url), '..');
const repoRoot = path.join(__dirname, '..', '..');

/**
 * Phase 4 of the attestation gap: the OpenClaw realtime plane — RECORD-ONLY.
 *
 * The gateway's writers stamp a literal `attested: true` on their threat rows
 * (the identity is a hardcoded hook literal; no conversation content can reach
 * the field), and the reader surfaces it into event-node attrs. What it must
 * NEVER do is feed accrual: the JSONL transport has no integrity — any
 * same-user process can append forged rows — so `attrs.attested` is a
 * writer-side claim for attribution/display, structurally firewalled from
 * `source_risk.attested` (sweep-derived from defence_audit, a different fact).
 */
describe('phase 4 — realtime attestation is record-only', () => {
  let dir: string;

  beforeEach(() => {
    initDatabase(':memory:');
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-rt-attest-'));
  });

  afterEach(() => {
    closeDatabase();
    fs.rmSync(dir, { recursive: true, force: true });
  });

  function writeRows(rows: Array<Record<string, unknown>>): void {
    fs.writeFileSync(
      path.join(dir, 'realtime-2026-08-16.jsonl'),
      rows.map(r => JSON.stringify(r)).join('\n') + '\n',
    );
  }

  function eventAttrs(line: number): Record<string, unknown> {
    const row = getDatabase()
      .prepare("SELECT attrs FROM threat_nodes WHERE kind = 'event' AND key = ?")
      .get(`rt:realtime-2026-08-16.jsonl:${line}`) as { attrs: string } | undefined;
    expect(row).toBeDefined();
    return JSON.parse(row!.attrs) as Record<string, unknown>;
  }

  const base = {
    type: 'threat', hook: 'llm_input', sessionId: 's1', model: 'm',
    reason: 'detector tripped', chars: 10, ts: '2026-08-16T10:00:00.000Z',
  };

  it('surfaces attested: true into event attrs (strict === true only)', () => {
    writeRows([
      { ...base, attested: true },        // line 1 → surfaced
      { ...base, attested: 'true' },      // line 2 → hostile-influenceable file: string is NOT true
      { ...base, attested: 1 },           // line 3 → not true
      { ...base, attested: false },       // line 4 → not surfaced
      { ...base },                        // line 5 → old row, absent
    ]);
    const result = projectRealtimeLedger({ dir });
    expect(result.eventNodes).toBe(5);

    expect(eventAttrs(1).attested).toBe(true);
    expect(eventAttrs(2).attested).toBeUndefined();
    expect(eventAttrs(3).attested).toBeUndefined();
    expect(eventAttrs(4).attested).toBeUndefined();
    expect(eventAttrs(5).attested).toBeUndefined();
  });

  it('an attested realtime row NEVER accrues risk (record-only firewall)', () => {
    // A forged `attested: true` in the JSONL must buy an attacker nothing on
    // the risk model: realtime rows are not accrual inputs, and the sweep's
    // attestation is derived from defence_audit only.
    writeRows([{ ...base, attested: true }]);
    projectRealtimeLedger({ dir });
    runRiskSweep({ nowMs: Date.parse('2026-08-16T11:00:00.000Z') });

    const risk = getDatabase()
      .prepare("SELECT risk, attested FROM source_risk WHERE source_key = 'conversation:llm_input'")
      .get() as { risk: number; attested: number } | undefined;
    if (risk) {
      expect(risk.risk).toBe(0);
      expect(risk.attested).not.toBe(1);
    }
  });

  it('the risk model never reads event-attr attestation (source pin)', () => {
    // attrs.attested (row-level writer claim on event nodes) and
    // source_risk.attested (sweep-derived from defence_audit) are DIFFERENT
    // facts. The sweep/model must never conflate them.
    for (const rel of ['src/threat-graph/risk.ts', 'src/threat-graph/projector.ts']) {
      const src = fs.readFileSync(path.join(repoRoot, rel), 'utf8');
      expect(src).not.toContain('attrs.attested');
    }
  });

  it('PROJECTOR_VERSION is bumped to 6 (attrs are in the determinism contract)', () => {
    // Event-node attrs are inside the canonicalDump determinism contract, so
    // existing graphs must rebuild to surface the new field.
    expect(PROJECTOR_VERSION).toBe(6);
  });

  describe('gateway writers stamp the literal (source pins on plugin code)', () => {
    // plugins/ cannot import src/ (build boundary), so the stamp is a plain
    // JSON field on the row objects — pinned here the same way `tainted` is
    // shipped. Identity provenance: the hook names are hardcoded literals at
    // the write sites; no conversation content can reach the field.
    const pluginSrc = () => fs.readFileSync(path.join(repoRoot, 'plugins', 'openclaw', 'index.ts'), 'utf8');

    it('the llm_input threat entry carries attested: true', () => {
      const src = pluginSrc();
      const at = src.indexOf('type: "threat", hook: "llm_input"');
      expect(at).toBeGreaterThan(-1);
      const entry = src.slice(at, src.indexOf('};', at));
      expect(entry).toMatch(/attested:\s*true/);
    });

    it('the before_agent_run decision row carries attested: true', () => {
      const src = pluginSrc();
      const at = src.indexOf("hook: 'before_agent_run'");
      expect(at).toBeGreaterThan(-1);
      const entry = src.slice(Math.max(0, at - 200), src.indexOf('});', at));
      expect(entry).toMatch(/attested:\s*true/);
    });

    it('the interceptor pipeline call passes sourceAttested: true (literal identity)', () => {
      const src = fs.readFileSync(path.join(repoRoot, 'plugins', 'openclaw', 'interceptor.ts'), 'utf8');
      const at = src.indexOf("pipeline(content, title, { type: 'agent', identifier: 'openclaw' }");
      expect(at).toBeGreaterThan(-1);
      const call = src.slice(at, src.indexOf(');', at));
      expect(call).toMatch(/sourceAttested:\s*true/);
    });
  });
});
