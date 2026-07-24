import { describe, it, expect } from '@jest/globals';

/**
 * Issue #120 — the three truncated specimens the SessionStart preamble surfaced
 * at 100% salience must never be EMITTED by the capture path as-is.
 *
 * Specimen 1 ("has been (zero heartbeat jobs…") is a mid-clause continuation —
 * already screened by the issue-#49 continuation-start rule. Specimens 2 and 3
 * are transactional/status content (a cron run tally and a retry-escalation
 * log); this adds a `transactional_status` rejection so they are dropped at
 * capture rather than merely demoted at recall.
 */

const SPECIMENS = [
  // #1 — mid-clause continuation ("has been …")
  'has been (zero heartbeat jobs across all 10 jobs.json backups going back to early April). It\'s a behavioural ritual defined in AGENTS.md + HEARTBEAT.md',
  // #2 — cron run tally / status line
  '0, reran 0, blocked 2.\n\n• Blocked: Chroma Gel Shopify→Xero Sync — cron: job interrupted by gateway restart\n• Blocked: Shopify→Xero Invoice Sync (Beauty Hair) — cron: job interrupted by gateway restart',
  // #3 — retry / escalation log
  'running the revert out-of-band, which left the cron history\'s last run as `error`, so the watcher re-escalated the same stale failure every ~6h (07:41 → ~13:45 → ~19:50 → 02:00)',
];

describe('Issue #120 — must-not-emit the three injection specimens', () => {
  it('shouldRejectCandidate rejects every specimen with a reason', async () => {
    const mod = await import('../../scripts/lib/extract-memorable-segments.mjs');
    for (const content of SPECIMENS) {
      const verdict = mod.shouldRejectCandidate({ title: '', content });
      expect(verdict.rejected).toBe(true);
      expect(verdict.reason).toBeTruthy();
    }
  });

  it('the two status specimens are rejected specifically as transactional_status', async () => {
    const mod = await import('../../scripts/lib/extract-memorable-segments.mjs');
    expect(mod.shouldRejectCandidate({ title: '', content: SPECIMENS[1] }).reason).toBe('transactional_status');
    expect(mod.shouldRejectCandidate({ title: '', content: SPECIMENS[2] }).reason).toBe('transactional_status');
  });

  it('rejects other transactional shapes: counters, delivery confirmations, retry logs', async () => {
    const mod = await import('../../scripts/lib/extract-memorable-segments.mjs');
    const transactional = [
      '12 delivered, 0 bounced, 3 queued — briefing emails sent successfully at 07:00',
      'Sync completed: 4 synced, 1 skipped, 0 errored',
      'cron: job interrupted by gateway restart, re-escalated the same failure',
    ];
    for (const content of transactional) {
      expect(mod.shouldRejectCandidate({ title: '', content }).rejected).toBe(true);
    }
  });

  it('does NOT reject genuine consequence facts that mention numbers or schedules', async () => {
    const mod = await import('../../scripts/lib/extract-memorable-segments.mjs');
    const benign = [
      'The ClassDojo join-request sentinel fires every 30 minutes and pings on pending joins.',
      'We decided to retry failed operations 3 times with exponential backoff.',
      'Root cause: the OAuth token was cached past its 3600s TTL, so refresh never fired.',
    ];
    for (const content of benign) {
      expect(mod.shouldRejectCandidate({ title: 'x', content }).rejected).toBe(false);
    }
  });

  it('end-to-end: extraction does not emit the status specimens from conversation text', async () => {
    const mod = await import('../../scripts/lib/extract-memorable-segments.mjs');
    // Frame the status lines with trigger words so the extractors would grab
    // them if the rejection did not fire ("the fix was …", "resolved by …").
    const conversation = [
      'The fix was 0, reran 0, blocked 2. cron: job interrupted by gateway restart.',
      'I resolved by running the revert out-of-band, which left the cron history last run as error so the watcher re-escalated the same stale failure every 6 hours.',
    ].join('\n');
    const segments = mod.extractMemorableSegments(conversation);
    const kept = mod.processSegments(segments, mod.BASE_THRESHOLD, { conversationText: conversation });
    for (const seg of kept) {
      expect(seg.content.toLowerCase()).not.toContain('reran 0, blocked');
      expect(seg.content.toLowerCase()).not.toContain('re-escalated');
    }
  });
});
