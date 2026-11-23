import { describe, expect, it } from '@jest/globals';
import {
  DEFAULT_MAX_AGE_MS,
  POSTURE_RECORD_VERSION,
  SELF_REPORT_MAX_BYTES,
  STALE_NOT_SEEN_MS,
  deriveMemoryOnlyRecord,
  deriveToolGateRecord,
  markStaleRecords,
  noCurrentReportRecord,
  parseSelfReport,
  postureLevel,
  rejectionMayAge,
  renderPostureLine,
  rollupRecords,
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

describe('#1135 a non-stale rejected report stays judged beside a current same-group sibling', () => {
  const DAY = 24 * 60 * 60 * 1000;
  const OLD = NOW - 8 * DAY;
  const RECENT = NOW - 60_000;
  const sources = (records: readonly PostureRecord[]) => rollupRecords(records).map((r) => r.source).sort();

  function rejected(opts: {
    reason?: string;
    instance?: string | null;
    rejection?: 'trust' | 'content';
    lastSeenMs?: number | null;
    profile?: string;
    runtime?: 'hermes' | 'openclaw' | 'claude_code';
  } = {}): PostureRecord {
    const reason = opts.reason ?? 'readable or writable by group or others (must be owner-only)';
    const base = { kind: 'invalid' as const, reason };
    const readInvalid: SelfReportRead = opts.instance === null
      ? (opts.rejection ? { ...base, rejection: opts.rejection } : base)
      : (opts.rejection
        ? { ...base, instance: opts.instance ?? 'p6001-s6001', rejection: opts.rejection }
        : { ...base, instance: opts.instance ?? 'p6001-s6001' });
    return deriveToolGateRecord({
      runtime: opts.runtime ?? 'hermes',
      profile: opts.profile ?? 'default',
      installed: 'yes',
      read: readInvalid,
      nowMs: NOW,
      lastSeenMs: opts.lastSeenMs === undefined ? OLD : opts.lastSeenMs,
    });
  }

  it('keeps a trust rejection beside a current sibling, in either order, recent or old', () => {
    const live = currentLike();
    for (const seen of [OLD, RECENT]) {
      const bad = rejected({ rejection: 'trust', lastSeenMs: seen });
      expect(bad.stale).toBe(false);
      expect(bad.stale_reason).toBeNull();
      expect(bad.runtime_loaded.value).toBe('unknown');
      expect(bad.liveness.value).toBe('not-applicable');
      expect(postureLevel(bad)).toBe('unknown');
      for (const records of [[live, bad], [bad, live]]) {
        expect(sources(records)).toEqual([live.source, bad.source].sort());
        expect(summarisePosture(records)).toMatchObject({
          green: false,
          level: 'unknown',
          weakest: bad.source,
          record_count: 2,
          rollup_count: 2,
          stale_count: 0,
        });
      }
    }
  });

  it('an omitted rejection classification and a rejection with no instance still cannot evade judgment', () => {
    const live = currentLike();
    const omitted = rejected({ lastSeenMs: OLD });
    const noInstance = rejected({ instance: null, rejection: 'trust', lastSeenMs: OLD });
    expect(omitted.stale).toBe(false);
    expect(noInstance.source).toBe('sc://posture/hermes/default/tool-gate/none');
    expect(noInstance.stale).toBe(false);
    expect(sources([live, omitted])).toEqual([live.source, omitted.source].sort());
    expect(sources([noInstance, live])).toContain(noInstance.source);
    expect(summarisePosture([live, omitted]).green).toBe(false);
    expect(summarisePosture([live, noInstance]).green).toBe(false);
  });

  it('reason text does not change selection', () => {
    const live = currentLike();
    const ownerOnly = rejected({ reason: 'must be owner-only', rejection: 'trust' });
    const otherWords = rejected({ reason: 'a completely different sentence', rejection: 'trust' });
    expect(ownerOnly.notes.join(' ')).not.toBe(otherWords.notes.join(' '));
    expect(sources([live, ownerOnly])).toEqual(sources([otherWords, live]));
    expect(sources([live, ownerOnly])).toContain(ownerOnly.source);
  });

  it('a recent content rejection is judged unknown; an aged one is stale and excluded', () => {
    const live = currentLike();
    const recent = rejected({ rejection: 'content', reason: 'not JSON', lastSeenMs: RECENT });
    expect([recent.stale, recent.stale_reason, postureLevel(recent)]).toEqual([false, null, 'unknown']);
    expect(sources([live, recent])).toEqual([live.source, recent.source].sort());
    expect(summarisePosture([recent, live])).toMatchObject({ green: false, level: 'unknown', weakest: recent.source, stale_count: 0 });

    const aged = rejected({ rejection: 'content', reason: 'not JSON', instance: 'p6002-s6002', lastSeenMs: NOW - STALE_NOT_SEEN_MS - 1 });
    expect([aged.stale, aged.stale_reason]).toEqual([true, 'not-seen']);
    expect(sources([live, aged])).toEqual([live.source]);
    expect(summarisePosture([live, aged])).toMatchObject({ green: true, level: 'loaded-enforce', rollup_count: 1, stale_count: 1 });
  });

  it('rejectionMayAge stays fail-closed: only an explicit content rejection may age', () => {
    expect(rejectionMayAge({ kind: 'absent' })).toBe(false);
    expect(rejectionMayAge(read())).toBe(false);
    expect(rejectionMayAge({ kind: 'invalid', reason: 'x' })).toBe(false);
    expect(rejectionMayAge({ kind: 'invalid', reason: 'x', rejection: 'trust' })).toBe(false);
    expect(rejectionMayAge({ kind: 'invalid', reason: 'x', rejection: 'content' })).toBe(true);
    expect(rejectionMayAge({ kind: 'invalid', reason: 'x', rejection: 'bogus' } as unknown as SelfReportRead)).toBe(false);
  });

  it('ended, not-seen and superseded records stay listed but out of judgment', () => {
    const live = currentLike();
    const ended = gate(read({ instance: otherInstance(77, '5') }), 'yes', 'ended');
    expect(ended.stale_reason).toBe('process-ended');
    expect(sources([live, ended])).toEqual([live.source]);
    expect([live, ended]).toHaveLength(2);

    const quiet = gate(read({
      heartbeat_at: iso(NOW - STALE_NOT_SEEN_MS - 1000),
      instance: otherInstance(88, '8'),
    }), 'yes', 'unsupported');
    expect(quiet.stale_reason).toBe('not-seen');
    expect(sources([live, quiet])).toEqual([live.source]);

    const older = deriveToolGateRecord({
      runtime: 'claude_code',
      profile: 'default',
      installed: 'yes',
      read: read({
        runtime: 'claude_code',
        heartbeat_at: iso(NOW - DEFAULT_MAX_AGE_MS - 60_000),
        instance: { key: 'c-old', pid: null, process_start: null, started_at: iso(NOW - DEFAULT_MAX_AGE_MS - 120_000), liveness: 'per-call' },
      }),
      nowMs: NOW,
    });
    const newer = deriveToolGateRecord({
      runtime: 'claude_code',
      profile: 'default',
      installed: 'yes',
      read: read({
        runtime: 'claude_code',
        heartbeat_at: iso(NOW - 60_000),
        instance: { key: 'c-new', pid: null, process_start: null, started_at: iso(NOW - 120_000), liveness: 'per-call' },
      }),
      nowMs: NOW,
    });
    const marked = markStaleRecords([older, newer]);
    expect(marked.find((r) => r.key.instance === 'c-old')).toMatchObject({ stale: true, stale_reason: 'superseded' });
    expect(marked).toHaveLength(2);
    expect(rollupRecords(marked).map((r) => r.key.instance)).toEqual(['c-new']);
  });

  it('does not treat an absent placeholder or an unverified validated sibling as a rejection', () => {
    const live = currentLike();
    const absent = gate({ kind: 'absent' });
    expect(absent.runtime_loaded.value).toBe('unobserved');
    expect(absent.liveness.value).toBe('not-applicable');
    expect(sources([live, absent])).toEqual([live.source]);

    const unverified = gate(read({ instance: otherInstance(77, '5') }), 'yes', 'unsupported');
    expect([unverified.liveness.value, unverified.runtime_loaded.value, unverified.stale]).toEqual(['unverified', 'unknown', false]);
    expect(sources([live, unverified])).toEqual([live.source]);
    expect(sources([unverified])).toEqual([unverified.source]);

    const marker = noCurrentReportRecord(absent, 2);
    expect(marker.runtime_loaded.value).toBe('unobserved');
    expect(marker.stale).toBe(false);
    expect(summarisePosture([marker]).green).toBe(false);
    expect(sources([marker])).toEqual([marker.source]);
  });

  it('a running reporter with an old heartbeat stays a judged unknown, and sibling policy is unchanged', () => {
    const live = currentLike();
    const runningOld = gate(read({
      heartbeat_at: iso(NOW - STALE_NOT_SEEN_MS - 1000),
      instance: otherInstance(99, '9'),
    }), 'yes', 'alive');
    expect(runningOld.stale).toBe(false);
    expect(runningOld.runtime_loaded.value).toBe('unknown');
    expect(sources([live, runningOld])).toEqual([live.source, runningOld.source].sort());
    expect(summarisePosture([live, runningOld]).green).toBe(false);

    const second = gate(read({ instance: otherInstance(4, '4') }));
    expect(summarisePosture([live, second])).toMatchObject({ green: true, level: 'loaded-enforce', rollup_count: 2 });

    const advisory = gate(read({ configured_posture: 'advisory', instance: otherInstance(3, '3') }));
    const off = gate(read({ configured_posture: 'intentionally-off', instance: otherInstance(5, '5') }));
    const unresolved = gate(read({ configured_posture: 'unknown', instance: otherInstance(6, '6') }));
    expect(summarisePosture([live, advisory]).green).toBe(false);
    expect(summarisePosture([live, off]).green).toBe(false);
    expect(summarisePosture([live, unresolved]).green).toBe(false);
    expect(rollupRecords([live, advisory, off, unresolved])).toHaveLength(4);

    const mem = deriveMemoryOnlyRecord({ runtime: 'codex', profile: 'default', installed: 'yes', nowMs: NOW });
    const bad = rejected({ rejection: 'trust' });
    expect(sources([live, mem, bad])).toEqual([live.source, mem.source, bad.source].sort());
    expect(summarisePosture([live, mem]).green).toBe(false);

    // gate() always derives hermes/default; build the other groups explicitly.
    const work = deriveToolGateRecord({
      runtime: 'hermes', profile: 'work', installed: 'yes', liveness: 'alive', nowMs: NOW,
      read: read({ profile: 'work', instance: otherInstance(7, '7') }),
    });
    const otherRuntime = deriveToolGateRecord({
      runtime: 'openclaw', profile: 'default', installed: 'yes', liveness: 'alive', nowMs: NOW,
      read: read({ runtime: 'openclaw', instance: otherInstance(8, '8') }),
    });
    const crossProfile = rejected({ profile: 'default', rejection: 'trust' });
    const crossRuntime = rejected({ runtime: 'claude_code', rejection: 'trust', instance: 'p6001-s6001' });
    expect(sources([work, crossProfile])).toEqual([work.source, crossProfile.source].sort());
    expect(sources([otherRuntime, crossRuntime])).toEqual([otherRuntime.source, crossRuntime.source].sort());
  });
});

function currentLike(): PostureRecord {
  return gate(read());
}
