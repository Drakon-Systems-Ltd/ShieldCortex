/**
 * ShieldCortex — what repair tells a human (#156).
 *
 * Field report, 1 Aug 2026. An operator ran repair, got this, and told us
 * plainly what it reads like:
 *
 *   ✗ FAILED: could not confirm the plugin is loaded AND enforcing.
 *   roster proof FAILED: could not read the running gateway boot roster …
 *   the SQLite install index lists it as enabled, but that is install state,
 *   not load state; canary proof FAILED: … version proof FAILED: on-disk build
 *   4.47.22 is OLDER than expected 4.47.24 — a silent downgrade (the 4.25.4
 *   class); refuse it
 *
 * His words: "I had to jump through 50 hoops … anyone experiencing this is
 * going to think our software is a piece of shit."
 *
 * Every clause there is true and every clause is written for whoever built it.
 * "roster proof", "plugins_json", "the 4.25.4 class" are internal vocabulary;
 * an operator wants to know one thing — **am I protected, and if not, what is
 * the single next thing I do?**
 *
 * So the detail stays (it is the evidence, and this codebase has spent a week
 * learning not to hide evidence) but it stops being the headline. This module
 * produces the headline: one status, one sentence, at most one command.
 */

export type RepairOutcome =
  /** Loaded and enforcing, both proven. */
  | 'protected'
  /** Everything we can check passed, but enforcement was not actively proven. */
  | 'protected-unproven'
  /** Proven NOT protected. The one case that deserves alarm. */
  | 'unprotected'
  /** We could not establish the truth either way. Never dressed up as either. */
  | 'unknown'
  /** Nothing was applied — a dry run. */
  | 'dry-run';

export interface RepairVerdictInput {
  applied: boolean;
  /** The self-check's own verdict, when it ran. */
  selfCheck?: {
    ok: boolean;
    rosterState?: 'loaded' | 'absent' | 'unproven';
    canaryProof?: boolean;
    versionProof?: boolean;
  };
  /** Post-remediation state, when there was one. */
  postState?: string;
  /** True when the operator had consented to the live canary. */
  canaryConsented: boolean;
  /** True when the gateway was restarted but never proved ready. */
  readinessUnproven?: boolean;
}

export interface RepairVerdict {
  outcome: RepairOutcome;
  /** One line, in English, no internal vocabulary. */
  headline: string;
  /** At most one command. Empty when there is nothing for them to do. */
  nextCommand?: string;
}

/**
 * Reduce the machinery's several proofs to the one thing an operator asked.
 *
 * The ordering is deliberate: PROVEN-BAD outranks unknown, and unknown outranks
 * an optimistic reading of partial evidence. Nothing here may report
 * "protected" without the roster AND the canary, which is the same contract the
 * self-check enforces — this only changes the words, never the standard.
 */
export function summariseRepair(input: RepairVerdictInput): RepairVerdict {
  if (!input.applied) {
    return {
      outcome: 'dry-run',
      headline: 'Nothing was changed — this was a preview of what repair would do.',
      nextCommand: 'shieldcortex repair',
    };
  }

  const sc = input.selfCheck;

  // Proven absent from the running gateway. The only alarm worth raising.
  if (sc?.rosterState === 'absent') {
    return {
      outcome: 'unprotected',
      headline: 'Not protected: the running gateway started without the ShieldCortex plugin.',
      nextCommand: 'shieldcortex repair',
    };
  }

  // A downgrade is a real, actionable fault and deserves its own words.
  if (sc?.versionProof === false) {
    return {
      outcome: 'unprotected',
      headline: 'Not protected by the build you expect: an older version is installed than the one this CLI ships.',
      nextCommand: 'npm i -g shieldcortex@latest && shieldcortex repair',
    };
  }

  if (sc?.ok) {
    return {
      outcome: 'protected',
      headline: 'Protected — the plugin is loaded on the running gateway and enforcement was proven live.',
    };
  }

  // Loaded, current, but enforcement not actively proven. Distinguish WHY:
  // the operator withholding consent is a choice, not a fault.
  if (sc?.rosterState === 'loaded' && sc.canaryProof === false) {
    return input.canaryConsented
      ? {
        outcome: 'unknown',
        headline: 'The plugin is loaded, but the live enforcement probe did not confirm it. That needs a look.',
        nextCommand: 'shieldcortex doctor --ai',
      }
      : {
        outcome: 'protected-unproven',
        headline: 'The plugin is loaded and current. Enforcement was not probed — run repair from a terminal and it will prove it.',
        nextCommand: 'shieldcortex repair',
      };
  }

  if (input.readinessUnproven) {
    return {
      outcome: 'unknown',
      headline: 'The gateway was restarted but did not report back in time, so nothing below could be confirmed. It may simply still be starting.',
      nextCommand: 'shieldcortex doctor',
    };
  }

  return {
    outcome: 'unknown',
    headline: 'Could not confirm whether the plugin is loaded and enforcing — this is unproven, not known-broken.',
    nextCommand: 'shieldcortex doctor --ai',
  };
}

/** The status line, with the marker an operator scans for first. */
export function renderRepairHeadline(v: RepairVerdict): string[] {
  const mark =
    v.outcome === 'protected' ? '✅'
      : v.outcome === 'unprotected' ? '❌'
        : v.outcome === 'dry-run' ? 'ℹ️ '
          : '⚠️ ';
  const lines = [`${mark} ${v.headline}`];
  if (v.nextCommand) lines.push(`   Next: ${v.nextCommand}`);
  return lines;
}
