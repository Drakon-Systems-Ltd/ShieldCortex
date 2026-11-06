/**
 * #815 A review (B1) — the public `ActionDescription` contract.
 *
 * `ActionDescription` is exported from `shieldcortex/defence` (#653). Up to
 * 5.17.4 it had three members: `text`, `confident`, `doubts`. #815 A added
 * `actionClass`, the key of the fixed webhook WHAT. A consumer that builds
 * or returns `{ text, confident, doubts }` must keep compiling, and anything
 * that reads the class must treat a missing or unknown one as the generic
 * "Use a tool" template — never as a crash and never as text from the input.
 *
 * What these tests pin:
 *   - the pre-5.18 literal type-checks against the public barrel's type
 *     (`npm run typecheck:tests` is the compile-time half of this test);
 *   - a legacy-shaped description flows through the card's class lookup to
 *     the generic template, and so does an unknown class;
 *   - every internal producer still sets a class that is in the closed set,
 *     so the fallback does not weaken the fixed-template card.
 */
import { describe, expect, it } from '@jest/globals';
import type { ActionDescription } from '../../index.js';
import { describeAction, describeShell } from '../../index.js';
import {
  CARD_ACTION_TEMPLATES,
  buildTemplateApprovalCard,
  cardActionTemplate,
  fixedTemplateAction,
} from '../approval-card.js';

const GENERIC_WHAT = CARD_ACTION_TEMPLATES.tool;
const SESSION_ID = 'sc-fedcba9876543210';

/** A consumer written against 5.17.4: produces the three-member shape. */
function legacyProducer(text: string): ActionDescription {
  return { text, confident: true, doubts: [] };
}

/** A consumer written against 5.17.4: reads only the three members. */
function legacyReader(d: ActionDescription): string {
  return d.confident ? d.text : `${d.text} (${d.doubts.length} doubts)`;
}

/** What the webhook card does with a description's class. */
function cardWhat(d: ActionDescription): string {
  return cardActionTemplate(d.actionClass ?? 'tool');
}

describe('#815 A review B1: ActionDescription stays constructible without actionClass', () => {
  it('a typed literal with only text/confident/doubts compiles and round-trips', () => {
    const legacy: ActionDescription = { text: 'Read a file', confident: true, doubts: [] };
    expect(legacyReader(legacy)).toBe('Read a file');
    expect(legacyReader(legacyProducer('Change files'))).toBe('Change files');
    expect(legacy.actionClass).toBeUndefined();
  });

  it('a legacy-shaped description flows through the card path to the generic template', () => {
    const legacy: ActionDescription = { text: 'Read a file', confident: true, doubts: [] };
    expect(cardWhat(legacy)).toBe(GENERIC_WHAT);
    expect(cardActionTemplate(legacy.actionClass)).toBe(GENERIC_WHAT);
    expect(fixedTemplateAction(cardWhat(legacy))).toBe(GENERIC_WHAT);
  });

  it('an unknown or non-string class still maps to the generic template (validation not weakened)', () => {
    for (const bad of ['', 'nope', 'read:nowhere', 'Read a file in your SSH folder', 42, null, {}, []]) {
      expect(cardActionTemplate(bad)).toBe(GENERIC_WHAT);
    }
    expect(cardActionTemplate('__proto__')).toBe(GENERIC_WHAT);
    expect(cardActionTemplate('constructor')).toBe(GENERIC_WHAT);
  });

  it('every internal producer still sets a class from the closed set', () => {
    const produced: ActionDescription[] = [
      describeAction({ tool: 'Read', input: { file_path: '/home/u/.ssh/id_ed25519' }, signals: [] }),
      describeAction({ tool: 'Write', input: { file_path: '/tmp/x' }, signals: [] }),
      describeAction({ tool: 'WebSearch', input: { query: 'x' }, signals: [] }),
      describeAction({ tool: 'Bash', input: { command: 'git push --force origin main' }, signals: [] }),
      describeAction({ tool: 'Bash', input: {}, signals: [] }),
      describeAction({ tool: 'mcp__acme__frobnicate', input: { a: 1 }, signals: [] }),
      describeShell('rm -rf ./build', { signals: [] }),
      describeShell('true | ; |', { signals: [] }),
    ];
    for (const d of produced) {
      expect(d.actionClass).toBeDefined();
      expect(Object.prototype.hasOwnProperty.call(CARD_ACTION_TEMPLATES, String(d.actionClass))).toBe(true);
      expect(cardActionTemplate(d.actionClass)).toBe(CARD_ACTION_TEMPLATES[d.actionClass!]);
    }
  });

  it('the template card is unchanged for a real input (specific, not generic)', () => {
    const card = buildTemplateApprovalCard({
      tool: 'Read',
      input: { file_path: '/home/u/.ssh/id_ed25519' },
      signals: ['sensitive-path'],
      plane: 'claude-code',
      sessionId: SESSION_ID,
    });
    expect(card.action).toBe(CARD_ACTION_TEMPLATES['read:ssh']);
    expect(card.action).not.toBe(GENERIC_WHAT);
    const unknown = buildTemplateApprovalCard({ tool: 'mcp__acme__frobnicate', input: { a: 1 }, signals: [], plane: 'claude-code', sessionId: SESSION_ID });
    expect(unknown.action).toBe(GENERIC_WHAT);
  });
});
