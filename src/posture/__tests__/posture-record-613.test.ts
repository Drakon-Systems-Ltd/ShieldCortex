import { describe, expect, it } from '@jest/globals';
import {
  DEFAULT_MAX_AGE_MS,
  POSTURE_RECORD_VERSION,
  SELF_REPORT_MAX_BYTES,
  deriveMemoryOnlyRecord,
  deriveToolGateRecord,
  parseSelfReport,
  postureLevel,
  renderPostureLine,
  summarisePosture,
  type FieldEvidence,
  type LivenessCheck,
  type PostureRecord,
  type SelfReportRead,
} from '../posture-record.js';
import { H, INSTANCE, NOW, PID, START, denial, iso, otherInstance, reportBody } from './self-report-fixture.js';

/**
 * #613 — the typed posture record. One record per (runtime, profile, plane,
 * instance); every field carries its own evidence and can independently be
 * `unknown`; `bound` never feeds it.
 *
 * These are the pure-function pins. The filesystem collector, the doctor rows
 * and the `policy-evidence` exporter each have their own suite, and
 * posture-firing-613.test.ts drives the Tars r2.1 §1 cases through all three.
 */

function read(over: Record<string, unknown> = {}): SelfReportRead {
  const text = JSON.stringify(reportBody(over));
  return parseSelfReport(text, Buffer.byteLength(text));
}

function gate(
  r: SelfReportRead,
  installed: 'yes' | 'no' | 'unknown' = 'yes',
  liveness: LivenessCheck = 'alive',
  nowMs = NOW,
): PostureRecord {
  return deriveToolGateRecord({ runtime: 'hermes', profile: 'default', installed, read: r, liveness, nowMs });
}

describe('#613 self-report is untrusted input — strict schema', () => {
  it('accepts a well-formed v1 report', () => {
    expect(read().kind).toBe('valid');
  });

  it('rejects an unknown version as invalid (never guessed forward)', () => {
    expect(read({ version: 2 }).kind).toBe('invalid');
  });

  it('rejects the wrong schema id', () => {
    expect(read({ schema: 'something-else' }).kind).toBe('invalid');
  });

  it('rejects unknown keys, top-level and nested', () => {
    expect(read({ enforced: true }).kind).toBe('invalid');
    expect(read({ plugin: { id: 'x', version: null, hash: null, extra: 1 } }).kind).toBe('invalid');
    expect(read({ denials: { blocked_action: { ...denial(), extra: 1 }, synthetic_probe: null, blocked_action_count: 1 } }).kind).toBe('invalid');
  });

  it('rejects a value outside the closed posture set', () => {
    expect(read({ configured_posture: 'enforced' }).kind).toBe('invalid');
    expect(read({ configured_posture: 'on' }).kind).toBe('invalid');
  });

  it('a process may honestly say its posture is not resolved yet', () => {
    const rec = gate(read({ configured_posture: 'unknown' }));
    expect(rec.runtime_loaded.value).toBe('yes');
    expect(rec.configured_posture.value).toBe('unknown');
    expect(postureLevel(rec)).toBe('unknown');
  });

  it('rejects a malformed hash, timestamp, instance key, or control characters in free text', () => {
    expect(read({ policy_hash: 'sha256:zz' }).kind).toBe('invalid');
    expect(read({ heartbeat_at: 'yesterday' }).kind).toBe('invalid');
    expect(read({ instance: { ...otherInstance(1, '2'), key: 'P1/../x' } }).kind).toBe('invalid');
    expect(read({ instance: { ...otherInstance(1, '2'), liveness: 'forever' } }).kind).toBe('invalid');
    expect(read({ denials: { blocked_action: denial({ tested_path: 'two words' }), synthetic_probe: null, blocked_action_count: 1 } }).kind).toBe('invalid');
    expect(read({ degraded_intervals: [{ from: iso(NOW), to: null, reason: 'a\u001b[31mred' }] }).kind).toBe('invalid');
  });

  it('rejects an oversize report without parsing it', () => {
    const r = parseSelfReport('{', SELF_REPORT_MAX_BYTES + 1);
    expect(r.kind).toBe('invalid');
    if (r.kind === 'invalid') expect(r.reason).toMatch(/size/);
  });

  it('rejects non-JSON and non-object JSON', () => {
    expect(parseSelfReport('not json', 8).kind).toBe('invalid');
    expect(parseSelfReport('[]', 2).kind).toBe('invalid');
    expect(parseSelfReport('null', 4).kind).toBe('invalid');
  });

  it('caps degraded_intervals and the blocked-action count', () => {
    const many = Array.from({ length: 50 }, () => ({ from: iso(NOW - 1000), to: iso(NOW - 500), reason: 'scanner-unreachable' }));
    expect(read({ degraded_intervals: many }).kind).toBe('invalid');
    expect(read({ denials: { blocked_action: null, synthetic_probe: null, blocked_action_count: -1 } }).kind).toBe('invalid');
    expect(read({ denials: { blocked_action: null, synthetic_probe: null, blocked_action_count: 1.5 } }).kind).toBe('invalid');
  });

  it('treats a heartbeat dated in the future beyond clock-skew tolerance as unknown', () => {
    const rec = gate(read({ heartbeat_at: iso(NOW + 60 * 60_000) }));
    expect(rec.runtime_loaded.value).toBe('unknown');
    expect(rec.membership).toBe('unobserved');
  });
});

describe('#613 record derivation — per-field evidence, each field independently unknown', () => {
  it('fresh report from a live process: loaded yes, posture from the process, denial not-observed', () => {
    const rec = gate(read());
    expect(rec.record_version).toBe(POSTURE_RECORD_VERSION);
    expect(rec.key).toEqual({ runtime: 'hermes', profile: 'default', plane: 'tool-gate', instance: INSTANCE });
    expect(rec.membership).toBe('current');
    expect(rec.liveness.value).toBe('alive');
    expect(rec.capability.value).toBe('tool-gate');
    expect(rec.installed.value).toBe('yes');
    expect(rec.runtime_loaded.value).toBe('yes');
    expect(rec.configured_posture.value).toBe('enforce');
    expect(rec.scanner.value).toBe('available');
    expect(rec.observed_denial.value).toBe('not-observed');
    expect(rec.effective_policy_hash.value).toBe(H('a'));
    expect(rec.source).toBe(`sc://posture/hermes/default/tool-gate/${INSTANCE}`);
  });

  it('every process-side field carries its own observed_at, max_age, tested path and identities', () => {
    const rec = gate(read());
    for (const f of [rec.runtime_loaded, rec.configured_posture, rec.scanner, rec.effective_policy_hash] as FieldEvidence<unknown>[]) {
      expect(f.method).toBe('process-self-report');
      expect(f.source).toMatch(/^sc:\/\/posture\/self-report\/hermes\/default\//);
      expect(f.observed_at).toBe(iso(NOW - 60_000));
      expect(f.max_age_ms).toBe(DEFAULT_MAX_AGE_MS);
      expect(f.tested_path).toBe('shieldcortex');
      expect(f.process_identity).toMatchObject({ instance: INSTANCE, pid: PID, process_start: START });
      expect(f.plugin_identity).toEqual({ id: 'shieldcortex', version: '0.1.0', hash: H('b') });
      expect(f.effective_policy_hash).toBe(H('a'));
    }
    expect(rec.installed.method).toBe('file-probe');
    expect(rec.installed.source).toMatch(/^sc:\/\/probe\/artefact\//);
  });

  it('no self-report: runtime_loaded is unobserved, posture and denial unknown', () => {
    const rec = gate({ kind: 'absent' });
    expect(rec.key.instance).toBeNull();
    expect(rec.membership).toBe('unobserved');
    expect(rec.installed.value).toBe('yes');
    expect(rec.runtime_loaded.value).toBe('unobserved');
    expect(rec.configured_posture.value).toBe('unknown');
    expect(rec.observed_denial.value).toBe('unknown');
    expect(rec.effective_policy_hash.value).toBeNull();
  });

  it('stale self-report (heartbeat older than max_age): every process-side field is unknown', () => {
    const rec = gate(read({ heartbeat_at: iso(NOW - DEFAULT_MAX_AGE_MS - 1) }));
    expect(rec.membership).toBe('unobserved');
    expect(rec.runtime_loaded.value).toBe('unknown');
    expect(rec.runtime_loaded.note).toMatch(/stale/);
    expect(rec.configured_posture.value).toBe('unknown');
    expect(rec.observed_denial.value).toBe('unknown');
    expect(rec.effective_policy_hash.value).toBeNull();
    expect(postureLevel(rec)).toBe('unknown');
  });

  it('invalid self-report: runtime_loaded unknown (not unobserved — something is there)', () => {
    const rec = gate({ kind: 'invalid', reason: 'version 9 is not supported' });
    expect(rec.runtime_loaded.value).toBe('unknown');
    expect(rec.configured_posture.value).toBe('unknown');
  });

  it('a resident process this host cannot check is not loaded: unverified → unknown', () => {
    const rec = gate(read(), 'yes', 'unsupported');
    expect(rec.liveness.value).toBe('unverified');
    expect(rec.membership).toBe('unobserved');
    expect(rec.runtime_loaded.value).toBe('unknown');
    expect(postureLevel(rec)).toBe('unknown');
  });

  it('a per-call hook (Claude Code) is current on recency alone, and says so', () => {
    const r = read({ runtime: 'claude_code', instance: { key: 'cabc', pid: null, process_start: null, started_at: iso(NOW - 5000), liveness: 'per-call' } });
    const rec = deriveToolGateRecord({ runtime: 'claude_code', profile: 'default', installed: 'yes', read: r, nowMs: NOW });
    expect(rec.liveness.value).toBe('per-call');
    expect(rec.membership).toBe('current');
    expect(rec.runtime_loaded.value).toBe('yes');
    expect(renderPostureLine(rec)).toMatch(/per-call/);
  });

  it('installed unknown stays unknown even with a fresh report', () => {
    const rec = gate(read(), 'unknown');
    expect(rec.installed.value).toBe('unknown');
    expect(rec.runtime_loaded.value).toBe('yes');
    expect(postureLevel(rec)).toBe('unknown');
  });

  it('scanner degraded → observed_denial degraded, intervals carried through', () => {
    const rec = gate(read({
      scanner: 'degraded',
      degraded_intervals: [{ from: iso(NOW - 5000), to: null, reason: 'scanner-unreachable' }],
    }));
    expect(rec.observed_denial.value).toBe('degraded');
    expect(rec.degraded_intervals).toEqual([{ from: iso(NOW - 5000), to: null, reason: 'scanner-unreachable' }]);
    expect(postureLevel(rec)).toBe('degraded');
  });

  it('a recorded denial is observed, and stays narrow: its own timestamp and tested path, nothing wider', () => {
    const rec = gate(read({ denials: { blocked_action: denial(), synthetic_probe: null, blocked_action_count: 1 } }));
    expect(rec.observed_denial.value).toBe('observed');
    expect(rec.observed_denial.kind).toBe('blocked-action');
    expect(rec.observed_denial.observed_at).toBe(iso(NOW - 10_000));
    expect(rec.observed_denial.tested_path).toBe('pre_tool_call:terminal');
    expect(rec.observed_denial.note).toMatch(/nothing wider/);
    expect(rec.incidents.value).toBe(1);
  });

  it('a denial never raises the level: an advisory process that once denied is still advisory', () => {
    const rec = gate(read({
      configured_posture: 'advisory',
      denials: { blocked_action: denial({ configured_posture: 'advisory' }), synthetic_probe: null, blocked_action_count: 1 },
    }));
    expect(rec.observed_denial.value).toBe('observed');
    expect(postureLevel(rec)).toBe('advisory');
    expect(summarisePosture([rec]).green).toBe(false);
  });

  it('not installed and no report: posture unavailable', () => {
    const rec = gate({ kind: 'absent' }, 'no');
    expect(rec.installed.value).toBe('no');
    expect(rec.configured_posture.value).toBe('unavailable');
    expect(rec.runtime_loaded.value).toBe('unobserved');
  });
});

describe('#613 memory-only is never a tool gate', () => {
  it('Codex / Copilot records are capability memory-only on the memory plane', () => {
    for (const runtime of ['codex', 'copilot'] as const) {
      const rec = deriveMemoryOnlyRecord({ runtime, profile: 'default', installed: 'yes', nowMs: NOW });
      expect(rec.capability.value).toBe('memory-only');
      expect(rec.plane).toBe('memory');
      expect(rec.configured_posture.value).not.toBe('enforce');
      expect(postureLevel(rec)).toBe('not-a-gate');
      expect(renderPostureLine(rec)).toMatch(/not a tool gate/);
      expect(renderPostureLine(rec)).not.toMatch(/tool gate ·/);
    }
  });

  it('a memory-only record can never summarise as green, even beside a loaded enforce gate', () => {
    const good = gate(read());
    expect(postureLevel(good)).toBe('loaded-enforce');
    const mem = deriveMemoryOnlyRecord({ runtime: 'codex', profile: 'default', installed: 'yes', nowMs: NOW });
    expect(summarisePosture([good, mem]).level).toBe('not-a-gate');
    expect(summarisePosture([good, mem]).green).toBe(false);
  });
});

describe('#613 the four non-enforce postures render distinctly', () => {
  const advisory = gate(read({ configured_posture: 'advisory' }));
  const off = gate(read({ configured_posture: 'intentionally-off' }));
  const unavailable = gate(read({ configured_posture: 'unavailable' }));
  const unobserved = gate({ kind: 'absent' });

  it('each has its own level', () => {
    expect(postureLevel(advisory)).toBe('advisory');
    expect(postureLevel(off)).toBe('off');
    expect(postureLevel(unavailable)).toBe('unavailable');
    expect(postureLevel(unobserved)).toBe('unobserved');
  });

  it('each renders a different line, and none renders green words', () => {
    const lines = [advisory, off, unavailable, unobserved].map(renderPostureLine);
    expect(new Set(lines).size).toBe(4);
    expect(lines[0]).toMatch(/advisory/);
    expect(lines[1]).toMatch(/intentionally off/);
    expect(lines[2]).toMatch(/unavailable/);
    expect(lines[3]).toMatch(/unobserved/);
    for (const l of lines) expect(l).not.toMatch(/enforced|protected|proves/i);
  });
});

describe('#613 no host-wide rollup to green, and no completeness claim', () => {
  it('summary is the weakest record', () => {
    const good = gate(read());
    const bad = deriveToolGateRecord({ runtime: 'openclaw', profile: 'default', installed: 'yes', read: { kind: 'absent' }, nowMs: NOW });
    const s = summarisePosture([good, bad]);
    expect(s.level).toBe('unobserved');
    expect(s.green).toBe(false);
    expect(s.weakest).toBe(bad.source);
    expect(s.completeness).toBe('not-claimed');
  });

  it('only a current, loaded, enforce record with a working scanner is green', () => {
    expect(summarisePosture([gate(read())]).green).toBe(true);
    expect(summarisePosture([gate(read({ configured_posture: 'advisory' }))]).green).toBe(false);
    expect(summarisePosture([gate(read(), 'yes', 'ended')]).green).toBe(false);
    expect(summarisePosture([gate(read(), 'yes', 'unsupported')]).green).toBe(false);
  });

  it('an ended instance beside a current one is listed but not rolled up; alone it is never green', () => {
    const current = gate(read());
    const ended = gate(read({ instance: otherInstance(77, '5') }), 'yes', 'ended');
    expect(summarisePosture([current, ended]).green).toBe(true);
    expect(summarisePosture([current, ended]).rollup_count).toBe(1);
    expect(summarisePosture([ended]).green).toBe(false);
  });

  it('no records at all is unknown, not green', () => {
    const s = summarisePosture([]);
    expect(s.level).toBe('unknown');
    expect(s.green).toBe(false);
  });

  it('rendered text for a green record still makes no enforcement claim', () => {
    const line = renderPostureLine(gate(read()));
    expect(line).toMatch(/self-reported/);
    expect(line).not.toMatch(/enforced|protected|proves/i);
  });
});
