import { describe, it, expect } from '@jest/globals';
import { evaluateToolCall } from '../defence/iron-dome/tool-action-guard.js';
import {
  SAFE_CORPUS,
  DANGEROUS_CORPUS,
  GUARD_PRECISION_CORPUS,
  type GuardCorpusEntry,
} from '../defence/iron-dome/guard-precision-corpus.js';

/**
 * #182 — the Action Guard precision gate.
 *
 * The guard's false-positive rate used to be a vibe ("it keeps stopping me").
 * This turns it into a number the build holds to zero: every SAFE command must
 * be allowed (no false positive), every DANGEROUS command must be stopped (no
 * false negative). A precision pass that loosens too far turns a SAFE entry's
 * sibling into a hole and this goes red; an over-broad new rule gates a SAFE
 * entry and this goes red. Either way the regression never reaches main.
 *
 * The gate runs on the CORE `evaluateToolCall` — the classifier both enforcement
 * planes call in normal operation. The blunt degraded-mode fallbacks are guarded
 * separately (signal-set parity) in ws2-gate-degraded-integration-59.test.ts.
 */

const gated = (e: GuardCorpusEntry): boolean =>
  evaluateToolCall(e.tool, e.args).decision !== 'allow';

describe('#182 guard precision corpus — no false positives on the safe surface', () => {
  it.each(SAFE_CORPUS.map((e) => [e.args.command ?? JSON.stringify(e.args), e] as const))(
    'allows: %s',
    (_label, entry) => {
      const v = evaluateToolCall(entry.tool, entry.args);
      // Surface the offending signals in the failure message — a regression
      // reads as "why did the guard gate this?" and the answer is right here.
      expect({ command: entry.args.command, decision: v.decision, signals: v.signals, why: entry.why })
        .toMatchObject({ decision: 'allow' });
    },
  );
});

describe('#182 guard precision corpus — no false negatives on the dangerous surface', () => {
  it.each(DANGEROUS_CORPUS.map((e) => [e.args.command ?? JSON.stringify(e.args), e] as const))(
    'gates: %s',
    (_label, entry) => {
      const v = evaluateToolCall(entry.tool, entry.args);
      expect({ command: entry.args.command, decision: v.decision, why: entry.why })
        .not.toMatchObject({ decision: 'allow' });
    },
  );
});

describe('#182 guard precision gate — measured rates', () => {
  it('reports and enforces 100% precision on safe / 100% recall on dangerous', () => {
    const falsePositives = SAFE_CORPUS.filter((e) => gated(e));
    const falseNegatives = DANGEROUS_CORPUS.filter((e) => !gated(e));

    const precision = (SAFE_CORPUS.length - falsePositives.length) / SAFE_CORPUS.length;
    const recall = (DANGEROUS_CORPUS.length - falseNegatives.length) / DANGEROUS_CORPUS.length;

    // eslint-disable-next-line no-console
    console.log(
      `[#182] guard precision gate: corpus=${GUARD_PRECISION_CORPUS.length} ` +
        `(safe=${SAFE_CORPUS.length}, dangerous=${DANGEROUS_CORPUS.length}) | ` +
        `precision=${(precision * 100).toFixed(1)}% (FP=${falsePositives.length}) | ` +
        `recall=${(recall * 100).toFixed(1)}% (FN=${falseNegatives.length})`,
    );

    expect(falsePositives.map((e) => e.args.command)).toEqual([]);
    expect(falseNegatives.map((e) => e.args.command)).toEqual([]);
  });
});
