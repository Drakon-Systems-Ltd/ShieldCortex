import { describe, it, expect } from '@jest/globals';
import { evaluateToolCall } from '../defence/iron-dome/tool-action-guard.js';
import {
  SAFE_CORPUS,
  DANGEROUS_CORPUS,
  GUARD_PRECISION_CORPUS,
  type GuardCorpusEntry,
} from '../defence/iron-dome/guard-precision-corpus.js';
import { measuredOpenClawSpawnRevisions } from '../defence/iron-dome/tool-input-schema.js';

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

/**
 * #596 — the `sessions_spawn` fixtures say what they prove.
 *
 * The precision rows above are DECISION-only: a spawn row stays `allow` whether
 * or not every key in it is a declared host field, because an undeclared key is
 * dropped as contract drift rather than denied. So a row labelled "all 28
 * declared fields" that quietly carried a key the host never declared
 * (`category`, `timeoutSeconds` — #595 review) would still be green while its
 * label overclaimed. These pins bind each label to the measured revision table
 * in `tool-input-schema.ts`: put a stowaway key back and THIS goes red, not the
 * decision gate.
 */
describe('#596 sessions_spawn fixture honesty — labels pinned to the measured contract', () => {
  const revisions = measuredOpenClawSpawnRevisions();
  const measured2026_8_1 = revisions.find((r) => r.hostVersion === '2026.8.1');
  const measuredUnion = new Set(revisions.flatMap((r) => r.keys));
  const spawnRows = SAFE_CORPUS.filter((e) => e.tool.endsWith('sessions_spawn'));
  const keysOf = (e: GuardCorpusEntry): string[] => Object.keys(e.args).sort();
  /** The one row that DELIBERATELY carries an undeclared key, to prove drift is dropped, not denied. */
  const DRIFT_PROBE_KEY = 'speculativeNewHostField';

  it('the 2026.8.1 revision the labels refer to is in the measured table, at 28 keys', () => {
    expect(measured2026_8_1).toBeDefined();
    expect(measured2026_8_1!.keys).toHaveLength(28);
  });

  it("the 'all 28 declared fields' row carries EXACTLY the measured 2026.8.1 key set", () => {
    const rows = spawnRows.filter((e) => e.why.includes('all 28 declared fields'));
    expect(rows.map((e) => e.why)).toHaveLength(1);
    // Exact equality, both directions: a stowaway key (never declared) and a
    // missing key (declared, not exercised) both falsify the label.
    expect(keysOf(rows[0]!)).toEqual(measured2026_8_1!.keys);
  });

  it("the 'Feb field set' row is a strict subset of the measured 2026.8.1 keys", () => {
    const rows = spawnRows.filter((e) => e.why.includes('Feb field set'));
    expect(rows.map((e) => e.why)).toHaveLength(1);
    const keys = keysOf(rows[0]!);
    const declared = new Set(measured2026_8_1!.keys);
    expect(keys.filter((k) => !declared.has(k))).toEqual([]);
    expect(keys.length).toBeLessThan(measured2026_8_1!.keys.length);
  });

  it('no sessions_spawn SAFE row carries a key no measured host declares, except the drift probe', () => {
    const stowaways = spawnRows
      .map((e) => ({
        why: e.why,
        unmeasured: keysOf(e).filter((k) => !measuredUnion.has(k) && k !== DRIFT_PROBE_KEY),
      }))
      .filter((r) => r.unmeasured.length > 0);
    expect(stowaways).toEqual([]);
    // The exception must still be exercised somewhere, or the carve-out is dead text.
    expect(spawnRows.filter((e) => DRIFT_PROBE_KEY in e.args)).toHaveLength(1);
  });
});
