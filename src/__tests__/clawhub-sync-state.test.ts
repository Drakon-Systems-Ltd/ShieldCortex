import { describe, expect, it } from '@jest/globals';
// @ts-expect-error -- importing a .mjs release-script utility (no type decls)
import { readLatestVersion, readVersionList, diagnose, describeState, exitCodeFor } from '../../scripts/lib/clawhub-state.mjs';

/**
 * Issue #200 — the publish workflow's ClawHub step false-greened three times
 * (4.47.29, 4.47.30, 4.47.36): it emitted `::warning` on a version mismatch and
 * the job went green while ClawHub served stale code.
 *
 * These tests pin the two things that make the gate real:
 *
 *   1. A mismatch can NEVER map to a success exit code.
 *   2. `pending` (uploaded, behind moderation) is distinguishable from `absent`
 *      (publish never landed) — because those need opposite human responses,
 *      and conflating them is why "just republish" was the standing advice for
 *      a version that already existed.
 */

// Shapes taken from real `clawhub inspect shieldcortex --json` output.
const inspectJson = {
  skill: { slug: 'shieldcortex', tags: { latest: '4.47.36' } },
  latestVersion: { version: '4.47.36', license: 'MIT-0' },
  moderation: { verdict: 'clean' },
};

const versionsJson = {
  versions: [
    { version: '4.47.36', changelog: 'Auto-sync from npm publish v4.47.36' },
    { version: '4.47.35', changelog: 'Auto-sync from npm publish v4.47.35' },
    { version: '4.47.34', changelog: 'Auto-sync from npm publish v4.47.34' },
  ],
};

describe('#200 — reading ClawHub state structurally', () => {
  it('reads the promoted version from latestVersion', () => {
    expect(readLatestVersion(inspectJson)).toBe('4.47.36');
  });

  it('falls back to skill.tags.latest when latestVersion is absent', () => {
    expect(readLatestVersion({ skill: { tags: { latest: '4.47.30' } } })).toBe('4.47.30');
  });

  it('returns empty rather than throwing on junk', () => {
    expect(readLatestVersion(null)).toBe('');
    expect(readLatestVersion({})).toBe('');
    expect(readVersionList(null)).toEqual([]);
    expect(readVersionList({ versions: 'nope' })).toEqual([]);
  });

  it('reads the uploaded-version history', () => {
    expect(readVersionList(versionsJson)).toEqual(['4.47.36', '4.47.35', '4.47.34']);
  });

  it('does not mistake a version-shaped string elsewhere in the payload for the promoted version', () => {
    // The old implementation grepped the first /\d+\.\d+\.\d+/ out of human-readable
    // CLI output, so an engine version or a version inside the summary could win.
    const decoy = {
      skill: { summary: 'Requires engine v2.4.26 and node 20.0.0', tags: { latest: '4.47.36' } },
      latestVersion: { version: '4.47.36' },
    };
    expect(readLatestVersion(decoy)).toBe('4.47.36');
  });
});

describe('#200 — diagnosing a mismatch', () => {
  it('calls it synced only when the promoted version IS the target', () => {
    expect(diagnose({ latest: '4.47.36', versions: ['4.47.36'], target: '4.47.36' })).toBe('synced');
  });

  it('calls it pending when the target is uploaded but not promoted', () => {
    // The real 4.47.36 case: `clawhub publish` returned "already exists" while
    // `latest` still read 4.47.35 for ~26 minutes.
    expect(diagnose({ latest: '4.47.35', versions: ['4.47.36', '4.47.35'], target: '4.47.36' })).toBe('pending');
  });

  it('calls it absent when the target was never uploaded', () => {
    expect(diagnose({ latest: '4.47.35', versions: ['4.47.35', '4.47.34'], target: '4.47.36' })).toBe('absent');
  });

  it('treats a missing version list as absent rather than assuming pending', () => {
    // Fail-closed: if we cannot prove the upload landed, do not claim it did.
    expect(diagnose({ latest: '4.47.35', versions: [], target: '4.47.36' })).toBe('absent');
    expect(diagnose({ latest: '4.47.35', versions: undefined, target: '4.47.36' })).toBe('absent');
  });

  it('refuses to diagnose without a target', () => {
    expect(() => diagnose({ latest: '4.47.36', versions: [], target: '' })).toThrow();
  });
});

describe('#200 — a mismatch can never exit zero', () => {
  it('maps synced to 0', () => {
    expect(exitCodeFor('synced')).toBe(0);
  });

  it('maps BOTH failure states to non-zero', () => {
    // This is the whole issue: the old step warned and exited 0.
    expect(exitCodeFor('pending')).not.toBe(0);
    expect(exitCodeFor('absent')).not.toBe(0);
  });

  it('gives pending and absent DIFFERENT codes so CI can tell them apart', () => {
    expect(exitCodeFor('pending')).not.toBe(exitCodeFor('absent'));
  });

  it('treats an unknown state as a failure, not a pass', () => {
    expect(exitCodeFor('who-knows')).not.toBe(0);
  });
});

describe('#200 — the message tells the operator which failure this is', () => {
  it('pending says the upload landed and no republish is needed', () => {
    const msg = describeState({ state: 'pending', latest: '4.47.35', target: '4.47.36', waitedMs: 1_800_000 });
    expect(msg).toContain('4.47.36');
    expect(msg).toMatch(/moderation/i);
    expect(msg).toMatch(/no republish/i);
    expect(msg).toContain('30m');
  });

  it('absent says the publish did not land and names the fallback', () => {
    const msg = describeState({ state: 'absent', latest: '4.47.35', target: '4.47.36' });
    expect(msg).toMatch(/did not land/i);
    expect(msg).toContain('clawhub.ai/skills/publish');
  });

  it('does not tell an operator to republish a version that already exists', () => {
    // Republishing a pending version returns "Version X already exists" and
    // wastes a version number — the exact wrong move, and what the old
    // single warning message advised in both cases.
    const pending = describeState({ state: 'pending', latest: '4.47.35', target: '4.47.36' });
    expect(pending).not.toContain('clawhub.ai/skills/publish');
  });

  it('synced states the version plainly', () => {
    expect(describeState({ state: 'synced', latest: '4.47.36', target: '4.47.36' })).toContain('4.47.36');
  });
});
