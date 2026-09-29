import { describe, expect, it } from '@jest/globals';
import {
  DEFAULT_MAX_AGE_MS,
  POSTURE_RECORD_VERSION,
  SELF_REPORT_MAX_BYTES,
  SELF_REPORT_SCHEMA,
  SELF_REPORT_VERSION,
  deriveMemoryOnlyRecord,
  deriveToolGateRecord,
  parseSelfReport,
  postureLevel,
  renderPostureLine,
  summarisePosture,
  type PostureRecord,
  type SelfReportRead,
} from '../posture-record.js';

/**
 * #613 — the typed posture record. One record per (runtime, profile, plane);
 * every field can independently be `unknown`; `bound` never feeds it.
 *
 * These are the pure-function pins. The filesystem collector, the doctor rows
 * and the `policy-evidence` exporter each have their own suite.
 */

const NOW = Date.parse('2026-09-29T12:00:00.000Z');
const iso = (ms: number) => new Date(ms).toISOString();

function report(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    schema: SELF_REPORT_SCHEMA,
    version: SELF_REPORT_VERSION,
    runtime: 'hermes',
    profile: 'default',
    plane: 'tool-gate',
    loaded: true,
    configured_posture: 'enforce',
    scanner: 'available',
    policy_hash: `sha256:${'a'.repeat(64)}`,
    runtime_version: null,
    plugin_id: 'shieldcortex',
    plugin_version: '0.1.0',
    plugin_hash: `sha256:${'b'.repeat(64)}`,
    instance_id: 'pid:4242',
    written_at: iso(NOW - 60_000),
    last_denial_at: null,
    degraded_intervals: [],
    ...over,
  };
}

function read(over: Record<string, unknown> = {}): SelfReportRead {
  const text = JSON.stringify(report(over));
  return parseSelfReport(text, Buffer.byteLength(text));
}

function gate(r: SelfReportRead, installed: 'yes' | 'no' | 'unknown' = 'yes', runtime: 'hermes' | 'claude_code' | 'openclaw' = 'hermes'): PostureRecord {
  return deriveToolGateRecord({ runtime, profile: 'default', installed, read: r, nowMs: NOW });
}

describe('#613 self-report is untrusted input — strict schema', () => {
  it('accepts a well-formed v1 report', () => {
    expect(read().kind).toBe('valid');
  });

  it('rejects an unknown version as invalid (never guessed forward)', () => {
    const r = read({ version: 2 });
    expect(r.kind).toBe('invalid');
  });

  it('rejects the wrong schema id', () => {
    expect(read({ schema: 'something-else' }).kind).toBe('invalid');
  });

  it('rejects unknown keys', () => {
    expect(read({ enforced: true }).kind).toBe('invalid');
  });

  it('rejects a value outside the closed posture set', () => {
    expect(read({ configured_posture: 'enforced' }).kind).toBe('invalid');
    expect(read({ configured_posture: 'on' }).kind).toBe('invalid');
  });

  it('a process may honestly say its posture is not resolved yet', () => {
    const rec = gate(read({ configured_posture: 'unknown' }));
    expect(rec.runtime_loaded).toBe('yes');
    expect(rec.configured_posture).toBe('unknown');
    expect(postureLevel(rec)).toBe('unknown');
  });

  it('rejects a malformed hash, timestamp, or control characters in free text', () => {
    expect(read({ policy_hash: 'sha256:zz' }).kind).toBe('invalid');
    expect(read({ written_at: 'yesterday' }).kind).toBe('invalid');
    expect(read({ instance_id: 'pid:1\nnext-line' }).kind).toBe('invalid');
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

  it('caps degraded_intervals', () => {
    const many = Array.from({ length: 50 }, () => ({ from: iso(NOW - 1000), to: iso(NOW - 500), reason: 'scanner-unreachable' }));
    expect(read({ degraded_intervals: many }).kind).toBe('invalid');
  });

  it('treats a report dated in the future beyond clock-skew tolerance as unknown', () => {
    const r = read({ written_at: iso(NOW + 60 * 60_000) });
    const rec = gate(r);
    expect(rec.runtime_loaded).toBe('unknown');
  });
});

describe('#613 record derivation — each field independently unknown', () => {
  it('fresh report: loaded yes, posture from the process, denial not-observed', () => {
    const rec = gate(read());
    expect(rec.record_version).toBe(POSTURE_RECORD_VERSION);
    expect(rec.capability).toBe('tool-gate');
    expect(rec.plane).toBe('tool-gate');
    expect(rec.installed).toBe('yes');
    expect(rec.runtime_loaded).toBe('yes');
    expect(rec.configured_posture).toBe('enforce');
    expect(rec.observed_denial).toBe('not-observed');
    expect(rec.effective_policy_hash).toBe(`sha256:${'a'.repeat(64)}`);
    expect(rec.process_identity.plugin_id).toBe('shieldcortex');
    expect(rec.process_identity.instance_id).toBe('pid:4242');
    expect(rec.probe.method).toBe('process-self-report');
    expect(rec.probe.max_age_ms).toBe(DEFAULT_MAX_AGE_MS);
    expect(rec.source).toMatch(/^sc:\/\/posture\/hermes\/default\/tool-gate$/);
    expect(rec.probe.source).toMatch(/^sc:\/\//);
  });

  it('no self-report: runtime_loaded is unobserved, posture and denial unknown', () => {
    const rec = gate({ kind: 'absent' });
    expect(rec.installed).toBe('yes');
    expect(rec.runtime_loaded).toBe('unobserved');
    expect(rec.configured_posture).toBe('unknown');
    expect(rec.observed_denial).toBe('unknown');
    expect(rec.effective_policy_hash).toBeNull();
    expect(rec.probe.method).toBe('none');
  });

  it('stale self-report (older than max_age): every process-side field is unknown', () => {
    const rec = gate(read({ written_at: iso(NOW - DEFAULT_MAX_AGE_MS - 1) }));
    expect(rec.runtime_loaded).toBe('unknown');
    expect(rec.configured_posture).toBe('unknown');
    expect(rec.observed_denial).toBe('unknown');
    expect(rec.effective_policy_hash).toBeNull();
    expect(rec.stale).toBe(true);
    expect(postureLevel(rec)).toBe('unknown');
  });

  it('invalid self-report: runtime_loaded unknown (not unobserved — something is there)', () => {
    const rec = gate({ kind: 'invalid', reason: 'version 9 is not supported' });
    expect(rec.runtime_loaded).toBe('unknown');
    expect(rec.configured_posture).toBe('unknown');
  });

  it('installed unknown stays unknown even with a fresh report', () => {
    const rec = gate(read(), 'unknown');
    expect(rec.installed).toBe('unknown');
    expect(rec.runtime_loaded).toBe('yes');
    expect(postureLevel(rec)).toBe('unknown');
  });

  it('scanner degraded → observed_denial degraded, intervals carried through', () => {
    const rec = gate(read({
      scanner: 'degraded',
      degraded_intervals: [{ from: iso(NOW - 5000), to: null, reason: 'scanner-unreachable' }],
    }));
    expect(rec.observed_denial).toBe('degraded');
    expect(rec.degraded_intervals).toEqual([{ from: iso(NOW - 5000), to: null, reason: 'scanner-unreachable' }]);
    expect(postureLevel(rec)).toBe('degraded');
  });

  it('a recorded denial is observed, and stays narrow: timestamped, nothing wider', () => {
    const rec = gate(read({ last_denial_at: iso(NOW - 10_000) }));
    expect(rec.observed_denial).toBe('observed');
    expect(rec.last_denial_at).toBe(iso(NOW - 10_000));
  });

  it('not installed and no report: posture unavailable', () => {
    const rec = gate({ kind: 'absent' }, 'no');
    expect(rec.installed).toBe('no');
    expect(rec.configured_posture).toBe('unavailable');
    expect(rec.runtime_loaded).toBe('unobserved');
  });
});

describe('#613 memory-only is never a tool gate', () => {
  it('Codex / Copilot records are capability memory-only on the memory plane', () => {
    for (const runtime of ['codex', 'copilot'] as const) {
      const rec = deriveMemoryOnlyRecord({ runtime, profile: 'default', installed: 'yes', nowMs: NOW });
      expect(rec.capability).toBe('memory-only');
      expect(rec.plane).toBe('memory');
      expect(rec.configured_posture).not.toBe('enforce');
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

describe('#613 no host-wide rollup to green', () => {
  it('summary is the weakest record', () => {
    const good = gate(read());
    const bad = gate({ kind: 'absent' });
    const s = summarisePosture([good, bad]);
    expect(s.level).toBe('unobserved');
    expect(s.green).toBe(false);
    expect(s.weakest).toBe(bad.source);
  });

  it('only loaded-enforce with a fresh report is green', () => {
    expect(summarisePosture([gate(read())]).green).toBe(true);
    expect(summarisePosture([gate(read({ configured_posture: 'advisory' }))]).green).toBe(false);
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
