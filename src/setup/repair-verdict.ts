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

import semver from 'semver';
import { realtimePluginInstallCommand } from './openclaw-plugin-spec.js';

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
    /**
     * #1179 r1: the version proof failed only because the selected copy's
     * version could not be read (see the self-check's `versionUnread`).
     */
    versionUnread?: boolean;
    /**
     * #1179 r2: the version proof failed because the selected copy was not
     * installed from npm or a local path (see the self-check's
     * `versionWrongSource`). A known mismatch, never "could not read".
     */
    versionWrongSource?: boolean;
    /**
     * #1179 r3 (Astra 3): the version proof failed because the install record
     * naming a non-npm source is for a different folder from the selected
     * copy (see the self-check's `versionProvenanceUnverified`). Provenance
     * unverified: not "could not read", and not a known mismatch.
     */
    versionProvenanceUnverified?: boolean;
    /**
     * #1179 r3 (Astra 2): the self-check reader's own reading of the selected
     * copy's version, when the proof failed on its source, not its version.
     */
    selectedCopyVersion?: string | null;
  };
  /** Post-remediation state, when there was one. */
  postState?: string;
  /** True when the operator had consented to the live canary. */
  canaryConsented: boolean;
  /** True when the gateway was restarted but never proved ready. */
  readinessUnproven?: boolean;
  /**
   * #977 review: this run's one gateway restart happened before changes made
   * after it, so the running gateway has not loaded them.
   */
  restartPending?: boolean;
  /**
   * The manual restart command to suggest with `restartPending`. Ignored when
   * `readinessUnproven` is also set: then the next step is always doctor.
   */
  restartCommand?: string;
  /**
   * #260 Sol r2: this run changed the host and the self-check read a gateway
   * not proven restarted since — the restart after the change failed, was
   * skipped, or was not confirmed back up. Its evidence predates the repair.
   */
  changesNotLoaded?: 'failed' | 'skipped' | 'unconfirmed';
  onDiskVersion?: string | null;
  expectedVersion?: string;
  /**
   * #1179 r2 (Astra): the post-remediation verdict's own measurement — its
   * `installedVersion` and where it read it, as one pair from that verdict.
   * Only `selected-build` (read out of the copy OpenClaw selected) is taken
   * as the selected copy's version; a disk-scan copy, a record-path build or
   * an install record never stands in for it here.
   */
  installedVersion?: string | null;
  installedVersionSource?: 'selected-build' | 'disk' | 'index-record' | 'record-path-build' | null;
}

export interface RepairVerdict {
  outcome: RepairOutcome;
  /** One line, in English, no internal vocabulary. */
  headline: string;
  /** At most one command. Empty when there is nothing for them to do. */
  nextCommand?: string;
}

/** A valid version strictly older than a valid expected one. */
function olderThan(version: string | null | undefined, expectedVersion: string | undefined): boolean {
  const v = semver.valid(version ?? '');
  const expected = semver.valid(expectedVersion ?? '');
  return Boolean(v && expected && semver.lt(v, expected));
}

/**
 * #1179 r2 (Astra): the post-state's reading of the build OpenClaw selected —
 * `installedVersion` only when its source is `selected-build`. A disk-scan
 * copy, a record-path build or an install record is never that reading.
 */
function selectedBuildReading(
  input: Pick<RepairVerdictInput, 'installedVersion' | 'installedVersionSource'>,
): string | null {
  return input.installedVersionSource === 'selected-build' ? semver.valid(input.installedVersion ?? '') : null;
}

/**
 * #1179 r1: the version proof failed, but no version older than this CLI was
 * measured — the self-check had no version of its own to compare (it could
 * not read one, or, r2, the copy's source is wrong) and the reading it is
 * judged by is not older. That is not a plugin behind this CLI: it must not
 * be reported as one, or answered with a forced install.
 *
 * r2 (Astra): the reading is the post-state's selected build when it has one
 * (`selectedVersion`, see `selectedBuildReading`). Any version read there is
 * a measurement, and another copy never overrides it.
 *
 * r3 (Astra 2): `selectedVersion` is also the self-check reader's own reading
 * of the selected copy (`selectedCopyVersion`) when the post-state has none,
 * and a source recorded for another folder (`versionProvenanceUnverified`) is
 * a proof with no version of its own too. Without a selected reading, an
 * older `onDiskVersion` still makes this false — but `summariseRepair`
 * reports that as the copy found on disk, never as the selected copy and
 * never with an install command.
 */
export function versionProofUnmeasured(
  selfCheck: { versionProof?: boolean; versionUnread?: boolean; versionWrongSource?: boolean; versionProvenanceUnverified?: boolean } | undefined,
  onDiskVersion?: string | null,
  expectedVersion?: string,
  selectedVersion?: string | null,
): boolean {
  if (selfCheck?.versionProof !== false) return false;
  if (selfCheck.versionUnread !== true && selfCheck.versionWrongSource !== true && selfCheck.versionProvenanceUnverified !== true) return false;
  const selected = semver.valid(selectedVersion ?? '');
  return !olderThan(selected ?? onDiskVersion, expectedVersion);
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

  // #1179 r1: a version proof that failed for want of any version read says
  // nothing about which build is installed. It is answered below, as unknown,
  // after the restart cases; the two branches here need a measured version.
  // r2 (Astra): when the self-check had no version of its own, the version it
  // is judged by is the post-state's reading of the selected build, if any.
  // r3 (Astra 3): a source recorded for another folder is such a proof too.
  const proofHadNoVersion = sc?.versionProof === false &&
    (sc.versionUnread === true || sc.versionWrongSource === true || sc.versionProvenanceUnverified === true);
  // r3 (Astra 2): the selected measurement — the post-state's selected-build
  // reading, else the self-check reader's own reading of the selected copy.
  // Another copy never stands in for it, and never overrides it.
  const selected = proofHadNoVersion
    ? selectedBuildReading(input) ?? semver.valid(sc.selectedCopyVersion ?? '')
    : null;
  // r3: what is known about where the selected copy came from.
  const provenance: 'wrong' | 'unverified' | null = !proofHadNoVersion || sc.versionUnread === true
    ? null
    : sc.versionWrongSource === true ? 'wrong' : sc.versionProvenanceUnverified === true ? 'unverified' : null;
  const versionUnmeasured = versionProofUnmeasured(sc, input.onDiskVersion, input.expectedVersion, selected);
  // r2: that selected build was read older than this CLI. Stale, reported by
  // its own version — but the self-check could not verify the copy, and
  // repair's safety check can refuse the reinstall there: doctor first.
  const selectedStale = proofHadNoVersion && !versionUnmeasured && selected !== null;
  // r3 (Astra 2): no selected reading, but an older copy found on disk. Main's
  // outcome class, reported as that copy, with the selected version
  // unverified: never "the installed plugin", never an install command.
  const otherCopyStale = proofHadNoVersion && !versionUnmeasured && selected === null;
  // r3 (CASE-B1): a live probe the operator consented to that did not confirm
  // the plugin is never left out of a headline that answers for the version.
  const probeFailed = proofHadNoVersion && input.canaryConsented && sc.canaryProof === false;
  const probeNote = probeFailed ? ' The live enforcement probe did not confirm the plugin either.' : '';
  const checkNext = probeFailed ? 'shieldcortex doctor --ai' : 'shieldcortex doctor';
  const expected = semver.valid(input.expectedVersion ?? '');
  const copyFact = provenance === 'wrong'
    ? 'that copy was not installed from npm or a local path'
    : provenance === 'unverified'
      ? 'where that copy was installed from is unverified (the install record that names a source is for a different directory)'
      : 'this run\'s own check could not verify that copy';
  const staleBySelected = `the build OpenClaw selected is v${selected}, older than ${expected}, and ${copyFact}. Check it with shieldcortex doctor before reinstalling`;
  const provenanceClause = provenance === 'wrong'
    ? ' (and that copy was not installed from npm or a local path)'
    : provenance === 'unverified' ? ' (and so is where it was installed from)' : '';
  const otherCopy = `a plugin copy found on disk is v${semver.valid(input.onDiskVersion ?? '')}, older than ${expected}`;

  // An old disk plugin is not proof the gateway is unprotected. A major CLI
  // upgrade can outrun the plugin install; unread logs cannot prove a silent
  // loaded-build downgrade either.
  const measured = selectedStale ? selected : input.onDiskVersion;
  const majorUpgradeLag = measured && input.expectedVersion &&
    semver.valid(measured) && semver.valid(input.expectedVersion) &&
    semver.major(measured) < semver.major(input.expectedVersion);
  if (sc?.versionProof === false && !versionUnmeasured && (sc.rosterState !== 'loaded' || majorUpgradeLag)) {
    if (selectedStale) {
      return {
        outcome: 'protected-unproven',
        headline: `The installed plugin is behind this CLI: ${staleBySelected}; protection by the new build is not yet proven.${probeNote}`,
        nextCommand: checkNext,
      };
    }
    if (otherCopyStale) {
      return {
        outcome: 'protected-unproven',
        headline: `A plugin copy found on disk is v${semver.valid(input.onDiskVersion ?? '')}, older than ${expected}, but the version OpenClaw selected is unverified${provenanceClause}, so protection by this CLI's build is not yet proven. Check it with shieldcortex doctor before reinstalling.${probeNote}`,
        nextCommand: checkNext,
      };
    }
    return {
      outcome: 'protected-unproven',
      headline: 'The installed plugin is behind this CLI. Update the plugin; protection by the new build is not yet proven.',
      nextCommand: realtimePluginInstallCommand(input.expectedVersion),
    };
  }

  // A silent downgrade of the loaded build remains a real fault.
  if (sc?.versionProof === false && !versionUnmeasured) {
    if (selectedStale) {
      return {
        outcome: 'unprotected',
        headline: `Not protected by the build you expect: ${staleBySelected}.${probeNote}`,
        nextCommand: checkNext,
      };
    }
    if (otherCopyStale) {
      // r3: main's class for this reading, but the copy is another one: the
      // selected build is not known to be the old one.
      return {
        outcome: 'unprotected',
        headline: `Not proven protected by the build you expect: ${otherCopy}, and the version OpenClaw selected is unverified${provenanceClause}. Check it with shieldcortex doctor before reinstalling.${probeNote}`,
        nextCommand: checkNext,
      };
    }
    return {
      outcome: 'unprotected',
      headline: 'Not protected by the build you expect: an older version is installed than the one this CLI ships.',
      nextCommand: 'npm i -g shieldcortex@latest && shieldcortex repair',
    };
  }

  // #977 review: whatever the self-check saw, it saw a gateway that has not
  // loaded this run's changes. Not proof of protection; one restart owed.
  if (input.restartPending && input.readinessUnproven) {
    // The run's one restart may still be starting or draining. Restarting
    // into that window is the #977 hazard: check first, never restart.
    return {
      outcome: 'unknown',
      headline: 'This run\'s plugin changes are not loaded yet, and the gateway restart was not confirmed back up — it may still be starting. Do not restart it yet; check it with shieldcortex doctor first.',
      nextCommand: 'shieldcortex doctor',
    };
  }
  if (input.restartPending) {
    return {
      outcome: 'unknown',
      headline: 'This run\'s plugin changes are not loaded yet: the gateway was restarted before them, and a second restart is not issued in one run. Restart the gateway once more, then run shieldcortex doctor.',
      nextCommand: input.restartCommand ?? 'shieldcortex doctor',
    };
  }

  // #260 Sol r2: a passing self-check on the PRE-change gateway is not proof
  // the repaired install is protecting anything. Unknown, with the one safe
  // next step: restart when nothing restarted, doctor when one may be starting.
  if (input.changesNotLoaded) {
    const why = input.changesNotLoaded === 'failed'
      ? 'the gateway restart after them failed'
      : input.changesNotLoaded === 'skipped'
        ? 'the gateway was not restarted after them'
        : 'the gateway restart after them was not confirmed back up';
    return input.changesNotLoaded === 'unconfirmed'
      ? {
        outcome: 'unknown',
        headline: `This run's plugin changes are not confirmed loaded: ${why}, so the checks read the gateway as it was before the repair. It may still be starting — check it with shieldcortex doctor before restarting.`,
        nextCommand: 'shieldcortex doctor',
      }
      : {
        outcome: 'unknown',
        headline: `This run's plugin changes are not loaded: ${why}, so the checks read the gateway as it was before the repair. Restart the gateway, then run shieldcortex doctor.`,
        nextCommand: input.restartCommand ?? 'shieldcortex doctor',
      };
  }

  // #1179 r1: no version was read at all (for example, OpenClaw's plugin list
  // could not be read and no build was found). Unknown — not "behind", not a
  // downgrade — and no install command: doctor says what it could not read.
  // A roster proven absent already returned above.
  // r2 (Astra): a known wrong source is that, not a read failure; and a
  // selected build the post-state read (not older) is named as read.
  // r3: a source recorded for another folder is unverified provenance; the
  // selected copy's own version is named when it was read; and (CASE-B1) a
  // consented probe that did not confirm the plugin leads, with the version
  // fact beside it — never "not known-broken".
  if (versionUnmeasured) {
    const v = selected !== null ? ` (v${selected})` : '';
    if (probeFailed) {
      const fact = provenance === 'wrong'
        ? `the copy OpenClaw selected${v} was not installed from npm or a local path`
        : provenance === 'unverified'
          ? `the install record that names a source is for a different directory from the copy OpenClaw selected${v}, so where that copy was installed from is unverified`
          : selected !== null
            ? `this run's own check could not verify the copy OpenClaw selected, though the plugin state reads that build as v${selected}`
            : 'which plugin version OpenClaw uses could not be read';
      return {
        outcome: 'unknown',
        headline: sc?.rosterState === 'loaded'
          ? `The plugin is loaded, but the live enforcement probe did not confirm it, and ${fact}. That needs a look.`
          : `Could not confirm the plugin is loaded, the live enforcement probe did not confirm it, and ${fact}. That needs a look.`,
        nextCommand: 'shieldcortex doctor --ai',
      };
    }
    if (provenance === 'wrong') {
      return {
        outcome: 'unknown',
        headline: `The plugin copy OpenClaw selected${v} was not installed from npm or a local path, so it is not proven to be this CLI's pinned build. Check it with shieldcortex doctor.`,
        nextCommand: 'shieldcortex doctor',
      };
    }
    if (provenance === 'unverified') {
      return {
        outcome: 'unknown',
        headline: `The install record that names where the plugin came from is for a different directory from the copy OpenClaw selected${v}, so where that copy was installed from is unverified, and it is not proven to be this CLI's pinned build. Check it with shieldcortex doctor.`,
        nextCommand: 'shieldcortex doctor',
      };
    }
    if (selected !== null) {
      return {
        outcome: 'unknown',
        headline: `This run's own check could not verify the copy OpenClaw selected, though the plugin state reads that build as v${selected}, so whether this CLI's build is the one protecting the gateway is unproven, not known-broken.`,
        nextCommand: 'shieldcortex doctor',
      };
    }
    return {
      outcome: 'unknown',
      headline: 'Could not read which plugin version OpenClaw uses, so whether this CLI\'s build is the one protecting the gateway is unproven, not known-broken.',
      nextCommand: 'shieldcortex doctor',
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

  // Canary proved enforcement live, version OK, but boot roster unread.
  // Not unprotected — never scream FAILED for "install healthy, load line missing".
  // versionProof===false already returned above; remaining is true|undefined.
  if (sc?.canaryProof === true && sc.rosterState === 'unproven') {
    return {
      outcome: 'protected-unproven',
      headline:
        'Enforcement is live (probe denied and audited). Boot roster unread — install looks healthy; load line not proven.',
      nextCommand: 'openclaw gateway restart',
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
