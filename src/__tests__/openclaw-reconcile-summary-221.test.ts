import { describe, it, expect } from '@jest/globals';
import { summariseCommandOutput } from '../integrations/child-output.js';

/**
 * #221 — the reconcile path summarises the output of `openclaw plugins …`, and
 * that context differs from the one the summariser was written for.
 *
 * Two heuristics that are right for a generic child process are wrong here:
 *
 *  - `[plugins] …` lines are dropped as FOREIGN chatter — another plugin
 *    talking about itself. But when the command IS a `plugins` subcommand,
 *    those are its own words. Filtering them produced an empty summary, i.e. a
 *    failed step with no stated reason, which is the exact defect this work
 *    removes rather than one it may introduce.
 *  - Failure-biased ranking applied to a command that SUCCEEDED picks whichever
 *    line happens to contain a word like "conflict".
 *
 * These pin the options the reconcile call site passes. If it stops passing
 * them, the behaviour below regresses.
 */

/** Exactly what src/setup/openclaw-reconcile.ts passes. */
function reconcileSummary(output: string, ok: boolean): string {
  const s = summariseCommandOutput(output, {
    maxLines: 1,
    dropPluginChatter: false,
    mode: ok ? 'plain' : 'failure',
  });
  return s.lines[0] ?? '';
}

describe('#221 — a failed reconcile step always states a reason', () => {
  it('keeps `[plugins] …` output when the command IS a plugins command', () => {
    const out = '[plugins] shieldcortex-realtime failed during enable: manifest not found';

    expect(reconcileSummary(out, false)).toContain('manifest not found');
  });

  it('never returns empty for a failure that produced output', () => {
    for (const out of [
      '[plugins] something went sideways',
      'plain unstructured failure text',
      '[plugins] a\n[plugins] b',
    ]) {
      expect(reconcileSummary(out, false)).not.toBe('');
    }
  });
});

describe('#221 — a successful step reports its outcome, not a scary-looking line', () => {
  it('leads with the install line, not the later "conflicting" one', () => {
    const out = 'Installed @drakon-systems/shieldcortex-realtime@4.47.39\nRemoved 1 conflicting entry';

    // "conflict" matches the failure signal pattern, so ranking promoted the
    // second line over the actual outcome.
    expect(reconcileSummary(out, true)).toContain('Installed');
  });

  it('preserves source order for successful output generally', () => {
    const out = 'Enabled shieldcortex-realtime\nNothing else to do';
    expect(reconcileSummary(out, true)).toBe('Enabled shieldcortex-realtime');
  });
});

describe('#221 — the foreign-chatter filter still applies where it belongs', () => {
  it('drops other plugins\' chatter by default', () => {
    const out = '[plugins] codex failed during register: TypeError\nnpm error E401 Unauthorized';

    const { lines } = summariseCommandOutput(out, { maxLines: 2, env: {} });

    expect(lines.join('\n')).not.toContain('codex');
    expect(lines.join('\n')).toContain('E401');
  });
});
