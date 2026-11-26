/**
 * SCN-010 part C — the closed whole-note preference grammar G, unit level
 * (design scn-010c §3).
 *
 * `isClosedPreferenceNote` is a POSITIVE whole-input parse: true only when the
 * entire trimmed input is exactly one sentence of G. It never asks whether
 * anything "bad" is present (the M4 lesson: an open-world test is defeated by
 * grafting a harmless preference onto an order).
 */
import { describe, expect, it } from '@jest/globals';
import {
  PREFERENCE_NOTE_ACTIONS_FIXED,
  PREFERENCE_NOTE_ARTICLES,
  PREFERENCE_NOTE_ARTIFACTS,
  PREFERENCE_NOTE_DOC_NOUNS,
  PREFERENCE_NOTE_FRAMES,
  PREFERENCE_NOTE_KEEP_PREPOSITIONS,
  PREFERENCE_NOTE_LOCALES,
  PREFERENCE_NOTE_MAX_LENGTH,
  PREFERENCE_NOTE_NUMBER_WORDS,
  PREFERENCE_NOTE_SCOPE_PREPOSITIONS,
  PREFERENCE_NOTE_STYLE_VERBS,
  PREFERENCE_NOTE_STYLES_FIXED,
  PREFERENCE_NOTE_UNITS,
  isClosedPreferenceNote,
} from '../firewall/preference-note-grammar.js';
import {
  PREFERENCE_NOTE_NEGATIVES,
  PREFERENCE_NOTE_POSITIVES,
} from './fixtures/preference-note-grammar-corpus.js';

describe('G — positives parse', () => {
  it('has at least 40 positives', () => {
    expect(PREFERENCE_NOTE_POSITIVES.length).toBeGreaterThanOrEqual(40);
  });
  for (const text of PREFERENCE_NOTE_POSITIVES) {
    it(`parses: ${JSON.stringify(text)}`, () => {
      expect(isClosedPreferenceNote(text)).toBe(true);
    });
  }
});

describe('G — negatives do not parse', () => {
  it('has at least 60 negatives', () => {
    expect(PREFERENCE_NOTE_NEGATIVES.length).toBeGreaterThanOrEqual(60);
  });
  for (const [id, text] of PREFERENCE_NOTE_NEGATIVES) {
    it(`rejects ${id}`, () => {
      expect(isClosedPreferenceNote(text)).toBe(false);
    });
  }

  it('the length-161 row is 161 characters and would otherwise be ASCII single-spaced', () => {
    const row = PREFERENCE_NOTE_NEGATIVES.find(([id]) => id === 'length-161')![1];
    expect(row.length).toBe(161);
    expect(row.length).toBe(PREFERENCE_NOTE_MAX_LENGTH + 1);
    expect(/^[A-Za-z0-9 ,.'-]+$/.test(row)).toBe(true);
  });

  it('non-string input is never a preference note', () => {
    for (const value of [undefined, null, 42, {}, ['From now on, always use Celsius.']]) {
      expect(isClosedPreferenceNote(value as unknown as string)).toBe(false);
    }
  });
});

describe('G — the closed vocabulary is exactly the design §3 lists', () => {
  it('word lists are frozen', () => {
    for (const list of [
      PREFERENCE_NOTE_FRAMES, PREFERENCE_NOTE_STYLE_VERBS, PREFERENCE_NOTE_LOCALES, PREFERENCE_NOTE_STYLES_FIXED,
      PREFERENCE_NOTE_SCOPE_PREPOSITIONS, PREFERENCE_NOTE_DOC_NOUNS, PREFERENCE_NOTE_ARTICLES, PREFERENCE_NOTE_ARTIFACTS,
      PREFERENCE_NOTE_KEEP_PREPOSITIONS, PREFERENCE_NOTE_NUMBER_WORDS, PREFERENCE_NOTE_UNITS, PREFERENCE_NOTE_ACTIONS_FIXED,
    ]) {
      expect(Object.isFrozen(list)).toBe(true);
    }
  });

  it('pins every list (a new slot value is a new grammar version and needs review)', () => {
    expect([...PREFERENCE_NOTE_FRAMES]).toEqual(['from now on', 'going forward', 'in future']);
    expect([...PREFERENCE_NOTE_STYLE_VERBS]).toEqual(['use', 'write in', 'reply in', 'respond in', 'answer in']);
    expect([...PREFERENCE_NOTE_LOCALES]).toEqual(['British', 'UK', 'American', 'US', 'Australian', 'Canadian', 'Irish']);
    expect([...PREFERENCE_NOTE_STYLES_FIXED]).toEqual(['plain English', 'metric units', 'the 24-hour clock', 'Celsius']);
    expect([...PREFERENCE_NOTE_SCOPE_PREPOSITIONS]).toEqual(['in', 'for']);
    expect([...PREFERENCE_NOTE_DOC_NOUNS]).toEqual([
      'replies', 'responses', 'answers', 'messages', 'emails', 'documents', 'summaries', 'drafts', 'notes',
    ]);
    expect([...PREFERENCE_NOTE_ARTICLES]).toEqual(['a', 'an']);
    expect([...PREFERENCE_NOTE_ARTIFACTS]).toEqual([
      'summary', 'recap', 'overview', 'update', 'status update', 'translation', 'draft', 'list', 'explanation',
    ]);
    expect([...PREFERENCE_NOTE_KEEP_PREPOSITIONS]).toEqual(['to', 'under', 'within']);
    expect([...PREFERENCE_NOTE_NUMBER_WORDS]).toEqual([
      'one', 'two', 'three', 'four', 'five', 'six', 'seven', 'eight', 'nine', 'ten',
    ]);
    expect([...PREFERENCE_NOTE_UNITS]).toEqual(['bullet points', 'bullets', 'sentences', 'paragraphs', 'lines', 'words']);
    expect([...PREFERENCE_NOTE_ACTIONS_FIXED]).toEqual(['keep it short', 'keep it brief', 'use bullet points']);
    expect(PREFERENCE_NOTE_MAX_LENGTH).toBe(160);
  });

  it('every slot value appears in at least one positive (coverage of the table above)', () => {
    const lower = PREFERENCE_NOTE_POSITIVES.map((p) => ` ${p.toLowerCase().trim()} `);
    const missing: string[] = [];
    const need = (word: string, shape: (w: string) => string): void => {
      if (!lower.some((p) => p.includes(shape(word.toLowerCase())))) missing.push(word);
    };
    for (const w of PREFERENCE_NOTE_FRAMES) need(w, (x) => ` ${x}`);
    for (const w of PREFERENCE_NOTE_STYLE_VERBS) need(w, (x) => ` always ${x} `);
    for (const w of PREFERENCE_NOTE_LOCALES) need(w, (x) => ` ${x} english`);
    for (const w of PREFERENCE_NOTE_STYLES_FIXED) need(w, (x) => ` ${x}`);
    for (const w of PREFERENCE_NOTE_SCOPE_PREPOSITIONS) need(w, (x) => ` ${x} `);
    for (const w of PREFERENCE_NOTE_DOC_NOUNS) need(w, (x) => ` ${x}`);
    for (const w of PREFERENCE_NOTE_ARTICLES) need(w, (x) => ` for ${x} `);
    for (const w of PREFERENCE_NOTE_ARTIFACTS) need(w, (x) => ` ${x},`);
    for (const w of PREFERENCE_NOTE_KEEP_PREPOSITIONS) need(w, (x) => ` keep it ${x} `);
    for (const w of PREFERENCE_NOTE_NUMBER_WORDS) need(w, (x) => ` ${x} `);
    for (const w of PREFERENCE_NOTE_UNITS) need(w, (x) => ` ${x}`);
    for (const w of PREFERENCE_NOTE_ACTIONS_FIXED) need(w, (x) => `, ${x}`);
    need('spelling', (x) => ` english ${x}`);
    need('all', (x) => ` ${x} `);
    for (const digits of ['3', '10', '99']) need(digits, (x) => ` ${x} `);
    need('reply in', (x) => `, ${x} `);
    expect(missing).toEqual([]);
  });

  it('every positive is well under the length cap (the cap is defence in depth)', () => {
    for (const text of PREFERENCE_NOTE_POSITIVES) expect(text.trim().length).toBeLessThan(PREFERENCE_NOTE_MAX_LENGTH);
  });
});

describe('G — boundary details', () => {
  it('the comma after the frame is optional in T1 and required in T2', () => {
    expect(isClosedPreferenceNote('From now on always use Celsius')).toBe(true);
    expect(isClosedPreferenceNote('From now on, always use Celsius')).toBe(true);
    expect(isClosedPreferenceNote('When the user asks for a recap keep it short')).toBe(false);
  });

  it('the final full stop is optional and single', () => {
    expect(isClosedPreferenceNote('Going forward, always use metric units')).toBe(true);
    expect(isClosedPreferenceNote('Going forward, always use metric units.')).toBe(true);
    expect(isClosedPreferenceNote('Going forward, always use metric units..')).toBe(false);
    expect(isClosedPreferenceNote('.Going forward, always use metric units')).toBe(false);
  });

  it('only ASCII space, tab, CR and LF are trimmed; other edge characters fail the charset', () => {
    expect(isClosedPreferenceNote(' \t\r\nIn future, always use Celsius.\n')).toBe(true);
    for (const edge of [' ', '﻿', '​', ' ', '　', '\v', '\f']) {
      expect(isClosedPreferenceNote(`${edge}In future, always use Celsius.`)).toBe(false);
      expect(isClosedPreferenceNote(`In future, always use Celsius.${edge}`)).toBe(false);
    }
  });

  it('digits are one or two characters', () => {
    expect(isClosedPreferenceNote('When the user asks for a list, keep it to 1 lines.')).toBe(true);
    expect(isClosedPreferenceNote('When the user asks for a list, keep it to 10 lines.')).toBe(true);
    expect(isClosedPreferenceNote('When the user asks for a list, keep it to 100 lines.')).toBe(false);
    expect(isClosedPreferenceNote('When the user asks for a list, keep it to -1 lines.')).toBe(false);
    expect(isClosedPreferenceNote('When the user asks for a list, keep it to 1.5 lines.')).toBe(false);
  });

  it('a count must admit a non-empty answer: no zero, no leading zero, no "under" one (review r2 SF1)', () => {
    const t2 = (action: string): string => `When the user asks for a translation, ${action}.`;
    // The brief's literal rows. "sentence" / "line" are singular, which G's
    // unit list does not contain, so each is also checked in plural below.
    for (const action of [
      'keep it to 0 words', 'keep it to 00 words', 'keep it to 05 words',
      'keep it under one sentence', 'keep it under 1 line',
      // Plural units, so only the count can be what fails.
      'keep it to 0 sentences', 'keep it within 0 lines', 'keep it under 0 words',
      'keep it to 00 lines', 'keep it within 00 words', 'keep it under 00 bullets',
      'keep it to 01 paragraphs', 'keep it within 09 lines', 'keep it under 05 words',
      'keep it under one sentences', 'keep it under 1 lines', 'keep it under one bullet points',
      'keep it under 1 words',
    ]) {
      expect([action, isClosedPreferenceNote(t2(action))]).toEqual([action, false]);
    }
    for (const action of [
      'keep it to 1 sentences', 'keep it to one sentences', 'keep it within one paragraphs', 'keep it within 1 lines',
      'keep it under two sentences', 'keep it under 2 lines', 'keep it under 10 words', 'keep it to 99 words',
    ]) {
      expect([action, isClosedPreferenceNote(t2(action))]).toEqual([action, true]);
    }
  });

  it('a style from the T1 list is the only thing T2 "reply in" accepts', () => {
    expect(isClosedPreferenceNote('When the user asks for a summary, reply in Irish English.')).toBe(true);
    expect(isClosedPreferenceNote('When the user asks for a summary, reply in JSON.')).toBe(false);
    expect(isClosedPreferenceNote('When the user asks for a summary, reply in English.')).toBe(false);
  });
});
