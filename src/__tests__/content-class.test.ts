import { describe, it, expect } from '@jest/globals';

/**
 * Issue #120 — content-class weighting.
 *
 * Recall over-rated transactional housekeeping (cron run tallies, retry logs,
 * delivery confirmations) at 100% salience while decisions / root-causes /
 * preferences / doctrine ranked lower. The load-bearing discriminator is the
 * CONTENT CLASS of a memory, independent of how often it was reinforced or how
 * recently it was touched.
 *
 * `classifyContentClass(text)` labels a snippet as:
 *   - 'transactional' — run tallies, counters, delivery confirmations, retry
 *      / escalation logs. Zero forward value; must be demoted.
 *   - 'consequence'   — decision, root-cause, preference, doctrine. The facts
 *      recall exists to surface.
 *   - 'neutral'       — everything else (ordinary complete facts).
 *
 * `contentClassFactor(text, opts)` turns that into a salience multiplier:
 *   transactional < 1 (penalty), consequence > 1 (boost), neutral === 1.
 */

// The three truncated specimens from the issue's SessionStart injection set.
const TRANSACTIONAL_SPECIMENS = [
  '0, reran 0, blocked 2.\n\n• Blocked: Chroma Gel Shopify→Xero Sync — cron: job interrupted by gateway restart\n• Blocked: Shopify→Xero Invoice Sync (Beauty Hair) — cron: job interrupted by gateway restart',
  'running the revert out-of-band, which left the cron history\'s last run as `error`, so the watcher re-escalated the same stale failure every ~6h (07:41 → ~13:45 → ~19:50 → 02:00)',
  '12 delivered, 0 bounced, 3 queued — briefing emails sent successfully at 07:00',
];

const CONSEQUENCE_FACTS = [
  'Decision: we decided to pin the OpenClaw plugin to the running gateway version so doctor stops false-flagging.',
  'Root cause: the OAuth refresh failed because the token was cached past its 3600s TTL; the fix was to refresh eagerly.',
  'Preference: Michael mandated the memory side reach excellent — recall quality is the top gap by policy.',
  'Doctrine: never touch gateway/services during a fix (host-safety zeroth law).',
];

const NEUTRAL_FACTS = [
  'npm run build-release rebuilds the native binding in the install dir.',
  '`email_reply.send_reply(message_id, body)` is the canonical reply path.',
  'PostgreSQL chosen for JSONB support.',
];

describe('classifyContentClass', () => {
  it('labels transactional / status specimens as transactional', async () => {
    const { classifyContentClass } = await import('../../scripts/lib/content-class.mjs');
    for (const s of TRANSACTIONAL_SPECIMENS) {
      expect(classifyContentClass(s)).toBe('transactional');
    }
  });

  it('labels decision / root-cause / preference / doctrine as consequence', async () => {
    const { classifyContentClass } = await import('../../scripts/lib/content-class.mjs');
    for (const s of CONSEQUENCE_FACTS) {
      expect(classifyContentClass(s)).toBe('consequence');
    }
  });

  it('labels ordinary complete facts as neutral (no collateral boost)', async () => {
    const { classifyContentClass } = await import('../../scripts/lib/content-class.mjs');
    for (const s of NEUTRAL_FACTS) {
      expect(classifyContentClass(s)).toBe('neutral');
    }
  });

  it('treats empty / non-string input as neutral', async () => {
    const { classifyContentClass } = await import('../../scripts/lib/content-class.mjs');
    expect(classifyContentClass('')).toBe('neutral');
    expect(classifyContentClass(undefined as unknown as string)).toBe('neutral');
  });
});

describe('contentClassFactor', () => {
  it('penalises transactional (< 1), boosts consequence (> 1), leaves neutral at 1', async () => {
    const { contentClassFactor } = await import('../../scripts/lib/content-class.mjs');
    expect(contentClassFactor(TRANSACTIONAL_SPECIMENS[0])).toBeLessThan(1);
    expect(contentClassFactor(CONSEQUENCE_FACTS[0])).toBeGreaterThan(1);
    expect(contentClassFactor(NEUTRAL_FACTS[0])).toBe(1);
  });

  it('never zeroes a memory — the penalty only re-ranks', async () => {
    const { contentClassFactor } = await import('../../scripts/lib/content-class.mjs');
    for (const s of TRANSACTIONAL_SPECIMENS) {
      expect(contentClassFactor(s)).toBeGreaterThan(0);
    }
  });

  it('boost and penalty are opts-tunable', async () => {
    const { contentClassFactor } = await import('../../scripts/lib/content-class.mjs');
    expect(contentClassFactor(TRANSACTIONAL_SPECIMENS[0], { penalty: 0.1 })).toBeCloseTo(0.1, 5);
    expect(contentClassFactor(CONSEQUENCE_FACTS[0], { boost: 2 })).toBeCloseTo(2, 5);
    expect(contentClassFactor(NEUTRAL_FACTS[0], { boost: 2, penalty: 0.1 })).toBe(1);
  });
});
