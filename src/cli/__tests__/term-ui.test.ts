/**
 * term-ui primitives + pin card / update panel (design lock v3).
 */
import {
  clampWidth,
  getWidth,
  stripAnsi,
  sanitiseDisplayField,
  wrapText,
  truncatePath,
  renderPinCard,
  renderBatchIdentity,
  renderUpdatePanel,
  deriveUpdateVerdict,
  supportsColor,
  supportsUnicode,
  NO_STYLE,
} from '../term-ui.js';

describe('term-ui width', () => {
  it('clamps below 40 up to 40', () => {
    expect(clampWidth(1)).toBe(40);
    expect(clampWidth(39)).toBe(40);
  });
  it('clamps above 240 down to 240', () => {
    expect(clampWidth(999)).toBe(240);
  });
  it('getWidth respects injected width and floors at 40', () => {
    expect(getWidth({ width: 20 })).toBe(40);
    expect(getWidth({ width: 80 })).toBe(80);
  });
});

describe('term-ui wrap + path', () => {
  it('wrapText stays within width', () => {
    const lines = wrapText('one two three four five six seven eight', 20, 0, 0);
    for (const l of lines) expect(stripAnsi(l).length).toBeLessThanOrEqual(20);
  });
  it('truncatePath keeps basename', () => {
    const p = '/Users/michael/Library/something/long/friday/scripts/backup.sh';
    const t = truncatePath(p, 40);
    expect(t.endsWith('backup.sh') || t.includes('backup.sh')).toBe(true);
    expect(t.length).toBeLessThanOrEqual(40);
  });
});

describe('sanitiseDisplayField', () => {
  it('strips CSI and newlines', () => {
    const s = sanitiseDisplayField('pre\u001b[2Jpath\nnext');
    expect(s).not.toMatch(/\u001b/);
    expect(s).toContain('⏎');
  });
});

describe('supportsColor / unicode independence', () => {
  it('NO_COLOR disables color', () => {
    expect(supportsColor({ NO_COLOR: '1' } as NodeJS.ProcessEnv, true)).toBe(false);
  });
  it('TERM=dumb disables color', () => {
    expect(supportsColor({ TERM: 'dumb' } as NodeJS.ProcessEnv, true)).toBe(false);
  });
  it('unicode can stay on when color off', () => {
    expect(supportsUnicode({ LANG: 'en_US.UTF-8' } as NodeJS.ProcessEnv)).toBe(true);
    expect(supportsUnicode({ TERM: 'dumb', LANG: 'en_US.UTF-8' } as NodeJS.ProcessEnv)).toBe(false);
  });
});

describe('renderPinCard', () => {
  it('default card has no source wall and fits 40 cols', () => {
    const lines = renderPinCard({
      index: 1,
      total: 3,
      status: 'new',
      path: '/Users/michael/Library/Application Support/hermes/friday/scripts/backup.sh',
      sha256: 'a'.repeat(64),
      sources: ['openclaw-cron-db'],
      networkHint: true,
    }, { width: 40, style: NO_STYLE });
    const text = lines.join('\n');
    expect(text).toMatch(/backup\.sh/);
    expect(text).toMatch(/\[y\].*pin/);
    expect(text).toMatch(/network calls likely/);
    expect(text).not.toMatch(/first 40 lines/);
    for (const l of lines) {
      expect(stripAnsi(l).length).toBeLessThanOrEqual(40);
    }
  });

  it('preview page shows bounded source lines', () => {
    const lines = renderPinCard({
      index: 1,
      total: 1,
      status: 'new',
      path: '/tmp/x.sh',
      sha256: 'abcd'.repeat(16),
      sources: ['hermes-cron'],
      previewLines: ['#!/bin/bash', 'echo hi'],
      previewPage: 1,
      previewTotalLines: 40,
    }, { width: 40, style: NO_STYLE });
    const text = lines.join('\n');
    expect(text).toMatch(/source lines 1–2 of 40/);
    expect(text).toMatch(/echo hi/);
  });
});

describe('renderBatchIdentity', () => {
  it('is compact', () => {
    const lines = renderBatchIdentity({
      status: 'new',
      path: '/home/edith/scripts/jotform/club_form_payment_upgrade.py',
      sha256: 'deadbeef'.repeat(8),
    }, { width: 40, style: NO_STYLE });
    expect(lines.join('\n')).toMatch(/NEW/);
    expect(lines.join('\n')).toMatch(/club_form_payment_upgrade\.py/);
  });
});

describe('renderUpdatePanel + verdict', () => {
  it('exitCode !== 0 never yields OK', () => {
    expect(deriveUpdateVerdict({ exitCode: 1, attention: false })).toBe('FAILED');
    expect(deriveUpdateVerdict({ exitCode: 0, attention: true })).toBe('NEEDS ATTENTION');
    expect(deriveUpdateVerdict({ exitCode: 0 })).toBe('OK');
  });

  it('panel framed cells stay closed-vocab; details frameless', () => {
    const lines = renderUpdatePanel({
      fromVersion: '4.54.4',
      toVersion: '4.54.9',
      verdict: 'NEEDS ATTENTION',
      rows: [
        { label: 'package', status: 'ok' },
        { label: 'selfchk', status: 'unproven' },
      ],
      details: ['selfchk: roster could not be read'],
      next: ['shieldcortex doctor --ai'],
    }, { width: 40, style: NO_STYLE, unicode: false });
    const text = lines.join('\n');
    expect(text).toMatch(/VERDICT  NEEDS ATTENTION/);
    expect(text).toMatch(/selfchk\s+unproven/);
    expect(text).toMatch(/detail/);
    expect(text).toMatch(/shieldcortex doctor --ai/);
    for (const l of lines) {
      expect(stripAnsi(l).length).toBeLessThanOrEqual(40);
    }
  });
});
