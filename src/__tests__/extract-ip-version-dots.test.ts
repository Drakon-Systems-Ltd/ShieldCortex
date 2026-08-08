import { describe, it, expect } from '@jest/globals';

/**
 * Issue #208: the sentence-bounded capture class `[^.!?\n]` treats EVERY
 * dot as a sentence terminator, so any candidate containing an IP address,
 * version string, dotted host shorthand or filename is truncated at the
 * first internal dot. Field examples (Edith's install, 6-7 Aug 2026):
 *
 *   Fix: (Ring camera squatting .          ← cut inside "172.16.0.10"
 *   Fix: this time by me releasing .       ← cut at host shorthand ".6"
 *   Learned: the systemd unit's stop doesn't actually remove the address, so I removed .
 *
 * ~9 of the 12 most recent auto-extracted memories on that install were
 * stumps of this kind — worst on exactly the infra/networking content
 * where dotted tokens are densest.
 *
 * The fix: a dot/!/? only terminates a sentence when followed by
 * whitespace or end-of-input. Dots followed by a non-space character
 * (IPs, versions, domains, filenames, ".6" shorthand) are content.
 *
 * These tests pin that behaviour for the capture patterns AND the
 * extractFirstSentence headline helper.
 */

const load = () => import('../../scripts/lib/extract-memorable-segments.mjs');

describe('issue #208: dots inside IPs / versions / filenames are not sentence boundaries', () => {
  it('captures a full sentence containing an IP address (the filed repro)', async () => {
    const { extractMemorableSegments } = await load();
    const text =
      'The problem was the Ring camera squatting 172.16.0.10 which reset every tunnel connection. ' +
      'Next we checked the switch.';
    const segments = extractMemorableSegments(text);
    const fixes = segments.filter((s) => s.extractorType === 'error-fix');
    expect(fixes.length).toBeGreaterThan(0);
    for (const f of fixes) {
      expect(f.content).toContain('172.16.0.10');
      expect(f.content).toContain('tunnel connection');
      // still sentence-bounded: must not bleed into the next sentence
      expect(f.content).not.toContain('checked the switch');
    }
  });

  it('captures across version strings', async () => {
    const { extractMemorableSegments } = await load();
    const text =
      'We decided to pin shieldcortex to v4.47.31 until the splitter fix ships. Other work continues.';
    const segments = extractMemorableSegments(text);
    const decisions = segments.filter((s) => s.extractorType === 'decision');
    expect(decisions.length).toBeGreaterThan(0);
    for (const d of decisions) {
      expect(d.content).toContain('v4.47.31');
      expect(d.content).toContain('splitter fix ships');
      expect(d.content).not.toContain('Other work');
    }
  });

  it('captures across dotted host shorthand and filenames', async () => {
    const { extractMemorableSegments } = await load();
    const text =
      'Fixed by releasing .6 from the DHCP pool and renaming config.yaml.bak back into place. The reboot was clean.';
    const segments = extractMemorableSegments(text);
    const fixes = segments.filter((s) => s.extractorType === 'error-fix');
    expect(fixes.length).toBeGreaterThan(0);
    for (const f of fixes) {
      expect(f.content).toContain('.6 from the DHCP pool');
      expect(f.content).toContain('config.yaml.bak');
      expect(f.content).not.toContain('reboot was clean');
    }
  });

  it('never emits a candidate ending on a bare dangling dot', async () => {
    const { extractMemorableSegments } = await load();
    const text =
      'Learned that the systemd unit stop does not remove the address 172.16.0.6 from eth0. ' +
      'The fix was adding an ExecStopPost that releases 172.16.0.6 explicitly. ' +
      'We decided to keep 10.0.0.0/8 for the lab.';
    const segments = extractMemorableSegments(text);
    expect(segments.length).toBeGreaterThan(0);
    for (const s of segments) {
      // the field failure mode: content/title truncated to "... releasing ."
      expect(s.content).not.toMatch(/\s\.$/);
      expect(s.title).not.toMatch(/\s\.$/);
    }
  });

  it('extractFirstSentence returns the whole sentence when it contains dotted tokens', async () => {
    const { extractFirstSentence } = await load();
    const headline = extractFirstSentence(
      'the Ring camera squatting 172.16.0.10 reset every tunnel connection. It took a day to find.',
    );
    expect(headline).toBe('the Ring camera squatting 172.16.0.10 reset every tunnel connection.');
  });

  it('still stops at genuine sentence boundaries (no greedy-capture regression)', async () => {
    const { extractMemorableSegments } = await load();
    const text =
      'I decided to use Postgres for JSON support. The team agreed last week. Next we tune indexes.';
    const segments = extractMemorableSegments(text);
    const decisions = segments.filter((s) => s.extractorType === 'decision');
    expect(decisions.length).toBeGreaterThan(0);
    for (const d of decisions) {
      expect(d.content).not.toContain('The team agreed');
    }
  });
});
