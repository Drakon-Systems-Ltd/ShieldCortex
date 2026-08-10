// scripts/lib/clawhub-state.mjs
//
// Pure ClawHub-state logic, split out of clawhub-sync.mjs so the release gate
// can be unit-tested without a network or a CLI (issue #200).
//
// The bug this exists to kill: the publish workflow's "Verify ClawHub sync"
// step could only ever emit `::warning` on a mismatch, so the job went green
// while ClawHub served a stale version — three times (4.47.29, 4.47.30,
// 4.47.36). A check that cannot fail is a decoration, not a check.
//
// The other half of the bug is that a mismatch has TWO very different causes
// and the old code could not tell them apart:
//
//   pending — the version uploaded fine and is sitting behind ClawHub's
//             moderation queue. It promotes itself. Measured at ~26 minutes
//             on 4.47.36 (version createdAt → moderation updatedAt), which is
//             why a 10-minute bound would false-fail a perfectly good release.
//   absent  — the publish never landed. This is the one that needs a human.
//
// `versions[]` is what separates them: it lists uploaded versions regardless of
// which one is promoted to `latest`.

/** Read the promoted version out of `clawhub inspect --json`. */
export function readLatestVersion(inspectJson) {
  if (!inspectJson || typeof inspectJson !== 'object') return '';
  return (
    inspectJson.latestVersion?.version ??
    inspectJson.skill?.tags?.latest ??
    ''
  );
}

/** Read the uploaded-version history out of `clawhub inspect --versions --json`. */
export function readVersionList(inspectJson) {
  if (!inspectJson || !Array.isArray(inspectJson.versions)) return [];
  return inspectJson.versions
    .map((v) => (typeof v === 'string' ? v : v?.version))
    .filter((v) => typeof v === 'string' && v.length > 0);
}

/**
 * Classify the sync state for `target`.
 *
 * Returns one of:
 *   'synced'  — ClawHub serves the target version. The only success.
 *   'pending' — target is uploaded but not promoted (moderation queue).
 *   'absent'  — target was never uploaded. The publish genuinely failed.
 */
export function diagnose({ latest, versions, target }) {
  if (!target) throw new Error('diagnose requires a target version');
  if (latest === target) return 'synced';
  if (Array.isArray(versions) && versions.includes(target)) return 'pending';
  return 'absent';
}

/**
 * The operator-facing line for a state. Deliberately says what to DO — a red
 * step that does not say which of the two failures happened just moves the
 * guesswork rather than removing it.
 */
export function describeState({ state, latest, target, waitedMs = 0 }) {
  const waited = waitedMs > 0 ? ` after ${Math.round(waitedMs / 60_000)}m` : '';
  switch (state) {
    case 'synced':
      return `✅ ClawHub synced at ${target}`;
    case 'pending':
      return (
        `⏳ ClawHub PUBLISHED ${target} but is still serving '${latest || 'none'}'${waited}. ` +
        `The upload landed — this is the moderation queue, which typically promotes within ~30m. ` +
        `Check https://clawhub.ai/skills/shieldcortex; no republish is needed (the version already exists).`
      );
    case 'absent':
    default:
      return (
        `❌ ClawHub does NOT have ${target}; it is serving '${latest || 'none'}'${waited}. ` +
        `The publish did not land. Re-run \`npm run release:clawhub\`, or publish manually at ` +
        `https://clawhub.ai/skills/publish (drop skills/shieldcortex, tick MIT-0, set version ${target}).`
      );
  }
}

/** Process exit code per state. Only a true sync is success — see #200. */
export function exitCodeFor(state) {
  if (state === 'synced') return 0;
  if (state === 'pending') return 2;
  return 1;
}
