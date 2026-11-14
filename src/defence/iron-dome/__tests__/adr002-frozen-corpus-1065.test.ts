/**
 * #1065 Phase 0 — the ADR-002 frozen corpus, run against today's classifier.
 *
 * What this suite holds:
 *   - a `settled` fixture's expectation holds on main and keeps holding;
 *   - a `known-gap` verdict fixture's expectation FAILS on main. It runs as
 *     `it.failing`, so the day a change makes it pass, CI goes red until the
 *     marker is removed (and the epic line ticked) in the same change;
 *   - a `cost` fixture is NOT timed here. Elapsed time depends on the
 *     scheduler, GC and JIT warm-up, so it cannot decide red or green. The
 *     default suite checks only what is deterministic about it (the input
 *     grows linearly with the size). The growth measurement is an explicit
 *     report, and it never asserts;
 *   - a `pending-decision` fixture is pinned to today's verdict, so a move is
 *     deliberate and shows up in the PR's moved list;
 *   - a `note` fixture is never executed.
 *
 * It changes no behaviour: it only calls `evaluateToolCall` at default config
 * with a stub script resolver. Nothing in the corpus is executed.
 *
 * Set ADR002_CORPUS_REPORT=1 to print one JSON line per fixture with the
 * verdict main returns today (the input for a moved list), and to run the
 * growth measurement of each `cost` fixture and print its times and ratios.
 */
import { describe, expect, it } from '@jest/globals';
import { evaluateToolCall } from '../tool-action-guard.js';
import { EPIC_LINES, FROZEN_CORPUS } from './fixtures/adr002/index.js';
import type { FrozenFixture } from './fixtures/adr002/types.js';

const REPORT = process.env.ADR002_CORPUS_REPORT === '1';

interface Observed {
  decision: string;
  severity: string;
  signals: string[];
  asked: string[];
}

function observe(tool: string, args: Record<string, unknown>, files: Record<string, string> | undefined): Observed {
  const asked: string[] = [];
  const resolveScriptSource = (p: string): string | null => {
    asked.push(p);
    return files && Object.prototype.hasOwnProperty.call(files, p) ? files[p]! : null;
  };
  const v = evaluateToolCall(tool, args, undefined, { resolveScriptSource });
  return { decision: v.decision, severity: v.severity, signals: [...v.signals].sort(), asked };
}

/** Throws when the fixture's expectation does not hold. */
function assertVerdict(f: FrozenFixture): void {
  const o = observe(f.tool!, f.args!, f.files);
  if (REPORT) {
    // eslint-disable-next-line no-console
    console.log(`[adr002-corpus] ${JSON.stringify({ id: f.id, status: f.status, ...o })}`);
  }
  const e = f.expect!;
  const shown = { id: f.id, decision: o.decision, signals: o.signals };
  switch (e.verdict) {
    case 'allow': expect(shown).toMatchObject({ decision: 'allow' }); break;
    case 'block': expect(shown).toMatchObject({ decision: 'block' }); break;
    case 'gate': expect(shown).not.toMatchObject({ decision: 'allow' }); break;
    case 'not-block': expect(shown).not.toMatchObject({ decision: 'block' }); break;
    case 'any': break;
  }
  for (const s of e.forbidSignals ?? []) expect(o.signals).not.toContain(s);
  for (const s of e.requireSignals ?? []) expect(o.signals).toContain(s);
  for (const p of e.asksFor ?? []) expect(o.asked).toContain(p);
}

/** Best-of-`reps` wall time of one classification, in milliseconds. */
function bestOf(call: { tool: string; args: Record<string, unknown> }, reps: number): number {
  let best = Infinity;
  for (let i = 0; i < reps; i += 1) {
    const t0 = process.hrtime.bigint();
    evaluateToolCall(call.tool, call.args);
    best = Math.min(best, Number(process.hrtime.bigint() - t0) / 1e6);
  }
  return best;
}

/** Length of the string argument a cost fixture scales (its command or content). */
function inputLength(call: { tool: string; args: Record<string, unknown> }): number {
  return Object.values(call.args).reduce<number>((n, v) => n + (typeof v === 'string' ? v.length : 0), 0);
}

/**
 * The deterministic half of a cost fixture: the same size builds the same
 * call, and the input grows by a constant amount per unit of size. So a
 * growth ratio above 2 in the report is the classifier's, not the fixture's.
 */
function assertLinearInput(f: FrozenFixture): void {
  const sizes = f.sizes!;
  expect(f.build!(sizes[0]!)).toEqual(f.build!(sizes[0]!));
  const lengths = sizes.map((n) => inputLength(f.build!(n)));
  const perUnit = lengths.slice(1).map((len, i) => (len - lengths[i]!) / (sizes[i + 1]! - sizes[i]!));
  expect(perUnit[0]).toBeGreaterThan(0);
  for (const step of perUnit) expect(step).toBe(perUnit[0]);
}

/**
 * REPORT ONLY (ADR002_CORPUS_REPORT=1). Growth ratio between consecutive
 * (doubling) sizes, printed beside the fixture's bound. A ratio, never a
 * budget (#519, #1040). It asserts nothing: a clock reading does not turn
 * this suite red or green on any runner. One full pass over every size is
 * discarded first, so the first measured size is not still warming.
 */
function reportGrowth(f: FrozenFixture): void {
  const sizes = f.sizes!;
  for (const n of sizes) evaluateToolCall(f.build!(n).tool, f.build!(n).args);
  const times = sizes.map((n) => bestOf(f.build!(n), 3));
  const ratios = times.slice(1).map((t, i) => t / Math.max(times[i]!, 0.001));
  const bound = f.expect!.maxGrowthPerDoubling!;
  // eslint-disable-next-line no-console
  console.log(`[adr002-corpus] ${JSON.stringify({
    id: f.id,
    status: f.status,
    sizes,
    ms: times.map((t) => Number(t.toFixed(1))),
    ratios: ratios.map((r) => Number(r.toFixed(2))),
    bound,
    withinBound: Math.max(...ratios) <= bound,
    asserted: false,
  })}`);
}

const executable = FROZEN_CORPUS.filter((f) => f.status !== 'note');
const notes = FROZEN_CORPUS.filter((f) => f.status === 'note');

describe('#1065 frozen corpus — fixture shape', () => {
  it('ids are unique and carry their issue number', () => {
    const ids = FROZEN_CORPUS.map((f) => f.id);
    expect(new Set(ids).size).toBe(ids.length);
    for (const f of FROZEN_CORPUS) expect(f.id.startsWith(`${f.issue}/`)).toBe(true);
  });

  it('every fixture answers an epic line, in that line\'s phase', () => {
    for (const f of FROZEN_CORPUS) {
      const line = EPIC_LINES.find((l) => l.issue === f.issue);
      expect({ id: f.id, line: line?.issue }).toEqual({ id: f.id, line: f.issue });
      expect({ id: f.id, phase: f.phase }).toEqual({ id: f.id, phase: line!.phase });
    }
  });

  it('executable fixtures carry a call and an expectation; notes carry neither', () => {
    for (const f of executable) {
      const hasCall = f.class === 'cost' ? Boolean(f.build && f.sizes && f.sizes.length >= 2) : Boolean(f.tool && f.args);
      expect({ id: f.id, hasCall, hasExpect: Boolean(f.expect) }).toEqual({ id: f.id, hasCall: true, hasExpect: true });
    }
    for (const f of notes) {
      expect({ id: f.id, tool: f.tool, expect: f.expect }).toEqual({ id: f.id, tool: undefined, expect: undefined });
    }
  });

  it('a cost fixture states its growth bound and doubling sizes', () => {
    for (const f of FROZEN_CORPUS.filter((x) => x.class === 'cost')) {
      expect(f.expect!.maxGrowthPerDoubling).toBeGreaterThan(2);
      f.sizes!.slice(1).forEach((n, i) => expect(n).toBe(f.sizes![i]! * 2));
    }
  });
});

describe('#1065 frozen corpus — against the classifier on main', () => {
  for (const f of executable.filter((x) => x.class !== 'cost')) {
    const run = f.status === 'known-gap' ? it.failing : it;
    run(`[${f.status}] ${f.id} — ${f.what}`, () => assertVerdict(f));
  }

  // Cost fixtures: no clock in the default suite. A `known-gap` cost fixture
  // is therefore NOT held by `it.failing`; the change that closes it removes
  // the marker on the strength of the report below and its own deterministic
  // test (the Phase 1 lexer can count its own steps; today's tokeniser cannot
  // without a production change, which this corpus does not make).
  for (const f of executable.filter((x) => x.class === 'cost')) {
    it(`[${f.status}, cost: input shape only] ${f.id} — input grows linearly with size`, () => assertLinearInput(f));
    const measure = REPORT ? it : it.skip;
    measure(`[report only, asserts nothing] ${f.id} — growth per doubling (ADR002_CORPUS_REPORT=1)`, () => reportGrowth(f), 120_000);
  }
});

describe('#1065 frozen corpus — coverage of the epic', () => {
  const covered = new Set(FROZEN_CORPUS.map((f) => f.issue));
  const missing = EPIC_LINES.filter((l) => !covered.has(l.issue)).map((l) => l.issue);

  it('reports counts by status and the epic lines still without a fixture', () => {
    const count = (s: FrozenFixture['status']) => FROZEN_CORPUS.filter((f) => f.status === s).length;
    // eslint-disable-next-line no-console
    console.log(
      `[#1065] frozen corpus: fixtures=${FROZEN_CORPUS.length} `
      + `(settled=${count('settled')}, known-gap=${count('known-gap')}, pending-decision=${count('pending-decision')}, note=${count('note')}) | `
      + `epic lines covered=${EPIC_LINES.length - missing.length}/${EPIC_LINES.length} | missing=[${missing.map((n) => `#${n}`).join(', ')}]`,
    );
    expect(FROZEN_CORPUS.length).toBeGreaterThan(0);
  });

  // KNOWN GAP (Phase 0 is not complete at this commit): only the Phase 1 line
  // has fixtures. The Phase 2 to 4 fixture files could not be authored on the
  // builder's host, whose own live Action Guard refused the write of the
  // fixture text (docs/architecture/ADR-002-frozen-corpus.md). When the last
  // line is covered this turns red: remove `.failing` in that change.
  it.failing('every unchecked epic line maps to at least one fixture id', () => {
    expect(missing).toEqual([]);
  });
});
