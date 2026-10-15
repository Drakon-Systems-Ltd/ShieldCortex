/**
 * The calm update screen (owner request, 15 Oct 2026).
 *
 * Five scenarios, rendered from fixtures through the same pure renderer
 * runUpdate() calls. Nothing here runs npm, OpenClaw, Hermes or a gateway.
 */
import { describe, it, expect } from '@jest/globals';

import {
  buildUpdateSummary,
  renderUpdateSummary,
  crossesGuardDefaultOff,
  BANNED_DEFAULT_PHRASES,
  BANNED_DEFAULT_PATTERNS,
  GUARD_ON_COMMAND,
  GUARD_STATUS_COMMAND,
  type UpdateSummaryInput,
} from '../update-summary.js';
import { guardDefaultOffNoticeLines } from '../update.js';
import { defaultColorStyle, NO_STYLE, stripAnsi, renderPinCard } from '../term-ui.js';
import { scriptsNeedAYes } from '../allowlist-scan.js';
import { renderPluginLoadVerdict } from '../doctor.js';

const ok = { status: 'ok' as const };

function base(over: Partial<UpdateSummaryInput> = {}): UpdateSummaryInput {
  return {
    fromVersion: '5.7.0',
    toVersion: '5.9.0',
    packageState: 'updated',
    engine: { ok: true },
    plugin: ok,
    skill: ok,
    hook: ok,
    hermes: { status: 'skip' },
    guardOn: false,
    // Guard off: the live enforcement probe has nothing to prove, so the
    // plugin check comes back "not confirmed" on a perfectly healthy host.
    protection: {
      status: 'unproven',
      loaded: 'unknown',
      pluginVersion: '5.9.0',
      gatewayReloaded: true,
      nextCommand: 'shieldcortex doctor --ai',
    },
    ...over,
  };
}

const SCENARIOS: Record<string, UpdateSummaryInput> = {
  'a: all OK, Guard off': base(),
  'b: all OK, Guard on and proven': base({
    guardOn: true,
    protection: { status: 'ok', loaded: 'yes', pluginVersion: '5.9.0', gatewayReloaded: true },
  }),
  'c: Guard on, plugin load not confirmed': base({ guardOn: true }),
  'd: Hermes present, no interpreter': base({ hermes: { status: 'warn', reason: 'no-interpreter' } }),
  'e: package install failed': base({ packageState: 'failed' }),
};

const EXPECTED_HEADLINE: Record<string, 'updated' | 'check' | 'failed'> = {
  'a: all OK, Guard off': 'updated',
  'b: all OK, Guard on and proven': 'updated',
  'c: Guard on, plugin load not confirmed': 'check',
  'd: Hermes present, no interpreter': 'check',
  'e: package install failed': 'failed',
};

function screen(input: UpdateSummaryInput, opts: { color?: boolean; ascii?: boolean } = {}): string[] {
  const style = opts.color ? defaultColorStyle() : NO_STYLE;
  return renderUpdateSummary(buildUpdateSummary(input), input, { width: 80, style, ascii: opts.ascii });
}

function bannedHits(text: string): string[] {
  const hits: string[] = [];
  for (const phrase of BANNED_DEFAULT_PHRASES) {
    // Short words match as words ("pin" must not match "spinning");
    // upper-case tokens (VERDICT, SoT) are case-sensitive.
    const caseSensitive = phrase !== phrase.toLowerCase();
    const esc = phrase.replace(/[.*+?^$()|[\]\\{}]/g, '\\$&');
    const re = new RegExp('(^|[^A-Za-z])' + esc + '(ned|s)?($|[^A-Za-z])', caseSensitive ? '' : 'i');
    if (re.test(text)) hits.push(phrase);
  }
  for (const re of BANNED_DEFAULT_PATTERNS) if (re.test(text)) hits.push(String(re));
  return hits;
}

describe('update summary: five scenarios', () => {
  for (const [name, input] of Object.entries(SCENARIOS)) {
    it(name + ' (snapshot)', () => {
      expect(screen(input).join('\n')).toMatchSnapshot();
    });

    it(name + ' headline class', () => {
      const summary = buildUpdateSummary(input);
      expect(summary.headline).toBe(EXPECTED_HEADLINE[name]);
      const first = screen(input, { color: true })[0];
      const style = defaultColorStyle();
      const colour = EXPECTED_HEADLINE[name] === 'updated' ? style.green
        : EXPECTED_HEADLINE[name] === 'check' ? style.yellow : style.red;
      expect(first.startsWith(colour)).toBe(true);
    });

    it(name + ' fits 80 columns', () => {
      for (const line of screen(input, { color: true })) {
        expect(stripAnsi(line).length).toBeLessThanOrEqual(80);
      }
    });
  }

  it('(a) is green, with no warning row', () => {
    const summary = buildUpdateSummary(SCENARIOS['a: all OK, Guard off']);
    expect(summary.headline).toBe('updated');
    expect(summary.rows.some((r) => r.mark === 'check' || r.mark === 'fail')).toBe(false);
    expect(screen(SCENARIOS['a: all OK, Guard off'], { color: true })[0]).toContain(defaultColorStyle().green);
  });

  it('Guard off is neutral, never a warning — the same check with Guard on is', () => {
    const off = buildUpdateSummary(base());
    const on = buildUpdateSummary(base({ guardOn: true }));
    expect(off.rows.find((r) => r.label === 'Guard')?.mark).toBe('off');
    expect(on.rows.find((r) => r.label === 'Guard')?.mark).toBe('check');
  });

  it('red only for a real failure: an unconfirmed check with Guard on is yellow', () => {
    expect(buildUpdateSummary(base({ guardOn: true })).headline).toBe('check');
    expect(buildUpdateSummary(base({ guardOn: true, protection: { status: 'failed', loaded: 'no' } })).headline).toBe('failed');
    expect(buildUpdateSummary(base({ engine: { ok: false, remediation: 'x' } })).headline).toBe('failed');
  });

  it('(e) names the version you are still on', () => {
    expect(screen(SCENARIOS['e: package install failed'])[0]).toBe('Update failed \u2014 ShieldCortex is still on 5.7.0');
  });

  it('every non-OK row has what, why (<= 12 words) and exactly one command', () => {
    for (const input of Object.values(SCENARIOS)) {
      for (const row of buildUpdateSummary(input).rows) {
        if (row.mark !== 'check' && row.mark !== 'fail') continue;
        expect(row.text.length).toBeGreaterThan(0);
        expect(row.why).toBeDefined();
        expect(String(row.why).split(/\s+/).filter(Boolean).length).toBeLessThanOrEqual(12);
        expect(row.command).toBeDefined();
        expect(String(row.command)).not.toMatch(/, then |;/);
      }
    }
  });
});

describe('Guard default-off migration notice', () => {
  it('prints when the update crosses 4.54.15', () => {
    const lines = guardDefaultOffNoticeLines('4.54.14', true).join('\n');
    expect(lines).toContain('Action Guard is off by default since 4.54.15.');
    expect(lines).toContain(GUARD_ON_COMMAND);
    expect(lines).toContain(GUARD_STATUS_COMMAND);
    expect(guardDefaultOffNoticeLines('4.10.3', true).length).toBeGreaterThan(0);
  });

  it('does not print for 5.7.0 -> 5.9.0', () => {
    expect(guardDefaultOffNoticeLines('5.7.0', true)).toEqual([]);
  });

  it('does not print when nothing was updated, or on the boundary itself', () => {
    expect(guardDefaultOffNoticeLines('4.54.14', false)).toEqual([]);
    expect(guardDefaultOffNoticeLines('4.54.15', true)).toEqual([]);
    expect(crossesGuardDefaultOff('not-a-version', () => -1)).toBe(false);
  });

  it('points at commands that exist', () => {
    expect(GUARD_ON_COMMAND).toBe('shieldcortex config --action-guard-enable');
    expect(GUARD_STATUS_COMMAND).toBe('shieldcortex guard readiness');
  });
});

describe('banned phrases stay out of the default output', () => {
  for (const [name, input] of Object.entries(SCENARIOS)) {
    it(name, () => {
      for (const opts of [{}, { color: true }, { ascii: true }]) {
        const text = stripAnsi(screen(input, opts).join('\n'));
        expect(bannedHits(text)).toEqual([]);
      }
    });
  }

  it('Guard notice', () => {
    expect(bannedHits(stripAnsi(guardDefaultOffNoticeLines('4.54.14', true, { color: true }).join('\n')))).toEqual([]);
  });

  it('allowlist review card inside update', () => {
    const card = renderPinCard({
      index: 1,
      total: 2,
      status: 'new',
      path: '/Users/friday/.openclaw/scripts/redteam-shieldcortex-cron.sh',
      sha256: '9ebef1ad0e5f'.repeat(5) + 'abcd',
      sources: ['openclaw-cron-db'],
    }, { width: 80, style: NO_STYLE }).join('\n');
    expect(bannedHits(card)).toEqual([]);
    expect(card).toContain("found in OpenClaw's scheduled jobs");
    expect(card).toContain('Trust this scheduled script?');
    expect(card).toContain('[y] trust  [n] not now  [v] view  [q] stop');
    expect(bannedHits(scriptsNeedAYes(2))).toEqual([]);
  });

  it('doctor plugin-load rows that could not check', () => {
    for (const state of ['index-unreadable', 'load-unproven'] as const) {
      for (const live of [null, false] as const) {
        const r = renderPluginLoadVerdict({
          state,
          severity: 'warn',
          recommendedAction: 'none',
          enabledInConfig: true,
          loadedInIndex: false,
          loadedInLiveRoster: live,
          indexReadable: state !== 'index-unreadable',
          configReadable: true,
          configPresent: true,
          openClawTracked: true,
          indexWarnsConflict: false,
          metadataConflict: false,
          indexVersion: null,
          installsJsonVersion: null,
          reasons: [],
        } as unknown as Parameters<typeof renderPluginLoadVerdict>[0]);
        // The env-var name inside a copy-paste command is not prose.
        const text = (r.message + ' ' + (r.fix ?? '')).replace(/\b[A-Z][A-Z0-9_]+=\S+/g, '');
        expect(bannedHits(text)).toEqual([]);
      }
    }
  });
});

describe('NO_COLOR / non-TTY rendering', () => {
  it('plain ASCII markers, no colour codes, no box drawing (snapshot)', () => {
    const all = Object.values(SCENARIOS).map((input) => screen(input, { ascii: true }).join('\n')).join('\n\n');
    expect(all).toMatchSnapshot();
    expect(all).not.toMatch(/\u001b\[/);
    // eslint-disable-next-line no-control-regex
    expect(all).not.toMatch(/[^\x00-\x7f]/);
    expect(all).toContain('[ok]');
    expect(all).toContain('[off]');
    expect(all).toContain('[!]');
    expect(all).toContain('[x]');
  });
});

