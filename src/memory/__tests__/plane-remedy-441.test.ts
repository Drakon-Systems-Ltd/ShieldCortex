/**
 * #441 — a remedy must not lose the condition that makes it safe.
 *
 * The dual_legacy drift WARN rendered a bold, copy-pasteable
 * `$ shieldcortex config --memory-plane import_only`. Running it on the host
 * that produced the WARN turned it into a FAIL, and the FAIL's own remedy
 * pointed back at `--memory-plane dual_legacy` — a closed loop with nothing
 * anywhere saying it was one.
 *
 * The command was never wrong. Its precondition ("land the host contract +
 * defended import, THEN ...") lived in the fix sentence, and the renderer
 * recovers commands from that sentence with a backtick regex — so the command
 * reached the terminal and the condition did not.
 *
 * The invariant these tests pin is deliberately general, because the loop is a
 * symptom: IF applying a check's own remedy to the same evidence raises the
 * severity, THEN that remedy must carry a precondition. A future signal that
 * offers a plane change without one fails here, not on someone's host.
 */
import { describe, expect, it } from '@jest/globals';
import { extractFixCommands } from '../../cli/doctor-report.js';
import {
  evaluatePlaneDrift,
  type MemoryPlane,
  type NativeSotEvidence,
  type PlaneDriftCounts,
} from '../plane-drift.js';

/** The real clawdbot1 numbers from the #441 report, not constructed ones. */
const native: NativeSotEvidence = {
  touched7d: true,
  bytes: 7834955,
  touchedPaths: [
    '~/clawd/memory/.dreams/events.jsonl',
    '~/clawd/memory/2026-08-29.md',
  ],
  busActive: [],
};
const counts: PlaneDriftCounts = {
  durableAdmits7d: 271,
  activity7d: 7652,
  injectable: null,
  unscopedExcluded: 42,
};

const evaluate = (plane: MemoryPlane, over: Partial<NativeSotEvidence> = {}) =>
  evaluatePlaneDrift({
    plane,
    counts,
    native: { ...native, ...over },
    requireScope: true,
    nowMs: Date.parse('2026-08-30T07:00:00Z'),
    planeSetAt: null,
  });

/** The plane a remedy command would move the host to, or null if it is not a plane change. */
function planeAfter(commands: string[]): MemoryPlane | null {
  for (const c of commands) {
    const m = /--memory-plane\s+(dual_legacy|import_only|sc_canonical)\b/.exec(c);
    if (m) return m[1] as MemoryPlane;
  }
  return null;
}

const RANK: Record<string, number> = { pass: 0, warn: 1, fail: 2 };

describe('#441 — a remedy that raises severity must state its precondition', () => {
  // The four drift signals that offer a dual_legacy host the same escape.
  const signals: Array<{ name: string; over: Partial<NativeSotEvidence> }> = [
    { name: 'native SoT written in window', over: {} },
    { name: 'native memory bus still on', over: { touched7d: false, busActive: ['OpenClaw agents.defaults.memorySearch.enabled=true'] } },
  ];

  for (const { name, over } of signals) {
    it(`carries a precondition on the dual_legacy remedy — ${name}`, () => {
      const v = evaluate('dual_legacy', over);
      expect(v.status).toBe('warn');
      expect(extractFixCommands(v.fix)).toContain('shieldcortex config --memory-plane import_only');
      expect(v.fixWhen).toBeDefined();
      expect(v.fixWhen).toMatch(/host contract|defended import/i);
      // The precondition must say what happens if you ignore it, or it reads as
      // optional flavour text and gets ignored.
      expect(v.fixWhen).toMatch(/FAIL/i);
    });
  }

  it('THE INVARIANT: following the remedy must not raise severity without warning', () => {
    // This is the general rule the loop broke. Take the verdict, read the plane
    // its own remedy moves you to, re-evaluate against the SAME evidence, and
    // compare. A remedy that makes things worse is allowed to exist — a host
    // mid-migration genuinely has to pass through it — but it may not be
    // offered as an unconditional command.
    const before = evaluate('dual_legacy');
    const target = planeAfter(extractFixCommands(before.fix));
    expect(target).toBe('import_only');

    const after = evaluate(target!);
    expect(RANK[after.status]!).toBeGreaterThan(RANK[before.status]!);
    // Severity goes UP, so the precondition is mandatory.
    expect(before.fixWhen).toBeTruthy();
  });

  it('the loop is real and closes — the FAIL points back at the WARN state', () => {
    // Named so nobody "fixes" the WARN side alone and believes the cycle is
    // gone. import_only's remedy legitimately offers dual_legacy as the honest
    // fallback; that is fine ONLY because the WARN side now states its
    // condition. If this test ever fails, the two ends have drifted apart.
    const failVerdict = evaluate('import_only');
    expect(failVerdict.status).toBe('fail');
    expect(planeAfter(extractFixCommands(failVerdict.fix))).toBe('dual_legacy');
  });

  it('a non-dual_legacy plane gets its own remedy and no plane-change precondition', () => {
    const v = evaluate('sc_canonical');
    expect(v.status).toBe('fail');
    expect(v.fixWhen).toBeUndefined();
  });
});
