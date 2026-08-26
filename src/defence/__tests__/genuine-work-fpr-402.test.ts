import { describe, expect, it } from '@jest/globals';
import { GENUINE_WORK_CORPUS } from '../corpus/genuine-work-corpus.js';
import { ATTACK_CORPUS } from '../semantic/attack-corpus.js';
import { classifyContentForm } from '../form-classifier.js';
import { resolveDispositionV2, type DispositionKind } from '../disposition.js';

/**
 * #402 calibration law 1: genuine-work FPR is a CI PEER to poison TPR.
 *
 * Both corpora are pushed through the same valve under identical, CLEAN
 * pipeline signals (ALLOW, trust 0.8, no indicators) — i.e. we simulate the
 * firewall MISSING the attack phrasings (they are paraphrases built to evade
 * the regex layer) and require the FORM key alone to keep them out of admit,
 * while the same key must not lock genuine work facts out.
 *
 *   FPR_genuine = fraction of Class E facts NOT disposed admit/admit-low-trust  (≤ 5%)
 *   TPR_poison  = fraction of attack entries kept OUT of admit/admit-low-trust  (≥ 95%)
 */
const FPR_MAX = 0.05;
const TPR_MIN = 0.95;

function dispose(content: string): DispositionKind {
  return resolveDispositionV2({
    allowed: true,
    firewallResult: 'ALLOW',
    trustScore: 0.8,
    reason: '',
    contentForm: classifyContentForm(content),
  }).kind;
}

const ADMITTED: DispositionKind[] = ['admit', 'admit-low-trust'];

describe('dual-corpus CI gate (#402)', () => {
  it('genuine-work corpus is a real corpus (>=200 entries, unique)', () => {
    expect(GENUINE_WORK_CORPUS.length).toBeGreaterThanOrEqual(200);
    expect(new Set(GENUINE_WORK_CORPUS).size).toBe(GENUINE_WORK_CORPUS.length);
  });

  it(`FPR_genuine <= ${FPR_MAX * 100}%: work facts are not locked out of admit`, () => {
    const missed = GENUINE_WORK_CORPUS.filter((f) => !ADMITTED.includes(dispose(f)));
    const fpr = missed.length / GENUINE_WORK_CORPUS.length;
    // On failure the message names the misclassified facts — fix the
    // CLASSIFIER, do not delete corpus entries.
    expect({ fpr: Number(fpr.toFixed(4)), missed }).toMatchObject({
      fpr: expect.any(Number),
    });
    if (fpr > FPR_MAX) {
      throw new Error(
        `FPR_genuine ${(fpr * 100).toFixed(1)}% > ${FPR_MAX * 100}% — misclassified:\n` +
          missed.map((m) => `  - [${classifyContentForm(m)}] ${m}`).join('\n'),
      );
    }
  });

  it(`TPR_poison >= ${TPR_MIN * 100}%: attack corpus stays out of admit even when the firewall misses`, () => {
    const admitted = ATTACK_CORPUS.filter((a) => ADMITTED.includes(dispose(a)));
    const tpr = 1 - admitted.length / ATTACK_CORPUS.length;
    if (tpr < TPR_MIN) {
      throw new Error(
        `TPR_poison ${(tpr * 100).toFixed(1)}% < ${TPR_MIN * 100}% — admitted poison:\n` +
          admitted.map((a) => `  - [${classifyContentForm(a)}] ${a}`).join('\n'),
      );
    }
  });

  it('poison never lands ADMITTED via the mixed/unknown escape hatch either', () => {
    // Belt-and-braces: every attack entry must dispose inert at best.
    for (const a of ATTACK_CORPUS) {
      const kind = dispose(a);
      expect(['inert', 'quarantine', 'reject', 'escalate']).toContain(kind);
    }
  });

  it('reports the achieved numbers', () => {
    const fprMissed = GENUINE_WORK_CORPUS.filter((f) => !ADMITTED.includes(dispose(f))).length;
    const tprAdmitted = ATTACK_CORPUS.filter((a) => ADMITTED.includes(dispose(a))).length;
    const fpr = fprMissed / GENUINE_WORK_CORPUS.length;
    const tpr = 1 - tprAdmitted / ATTACK_CORPUS.length;
    // eslint-disable-next-line no-console
    console.log(
      `[#402] FPR_genuine=${(fpr * 100).toFixed(2)}% (${fprMissed}/${GENUINE_WORK_CORPUS.length}) ` +
        `TPR_poison=${(tpr * 100).toFixed(2)}% (${ATTACK_CORPUS.length - tprAdmitted}/${ATTACK_CORPUS.length})`,
    );
    expect(fpr).toBeLessThanOrEqual(FPR_MAX);
    expect(tpr).toBeGreaterThanOrEqual(TPR_MIN);
  });
});
