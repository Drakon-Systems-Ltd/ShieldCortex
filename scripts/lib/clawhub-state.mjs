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
//
// Two more states keep a verdict from outrunning its evidence:
//
//   submitted — `clawhub publish` said the update was submitted and is pending
//               security scans, but the index does not list it yet. On 5.7.0
//               the scan held it out of BOTH `latest` and `versions[]` for ~5m,
//               so every poll read 'absent' for an upload the CLI had accepted.
//   unknown   — the last read of ClawHub failed. An empty read is not evidence
//               that the version is missing, nor that it is served.

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
 * True when `clawhub publish` output explicitly reports that `target` was
 * submitted and is pending security scans. Wording observed on 5.7.0:
 *
 *   Update submitted for shieldcortex@5.7.0; pending security scans before it becomes public.
 *
 * Both halves must appear on one line and name exactly this version, so other
 * CLI output cannot pass for a submission. The prose is matched
 * case-insensitively, but the version is the whole reported token (every
 * character semver allows, including prerelease and `+` build metadata, minus
 * a sentence-ending dot) and must equal `target` exactly, case included —
 * the same identity the index comparisons in diagnose() use.
 */
export function reportsPendingSubmission(publishOutput, target) {
  if (typeof publishOutput !== 'string' || !target) return false;
  const submittedRe = /\bsubmitted for shieldcortex@([0-9A-Za-z.+-]+)/gi;
  return publishOutput
    .split(/\r?\n/)
    .some(
      (line) =>
        /pending security scans/i.test(line) &&
        [...line.matchAll(submittedRe)].some((m) => m[1].replace(/\.+$/, '') === target),
    );
}

/**
 * Classify the sync state for `target`.
 *
 * Returns one of:
 *   'synced'    — ClawHub serves the target version. The only success.
 *   'pending'   — target is uploaded but not promoted (moderation queue).
 *   'submitted' — the CLI reported the target submitted and pending security
 *                 scans; the index does not list it yet.
 *   'unknown'   — the ClawHub read failed, so nothing is proven either way.
 *   'absent'    — a good read does not list the target and no submission was
 *                 reported. The publish genuinely failed.
 */
export function diagnose({ latest, versions, target, readFailed = false, submitted = false }) {
  if (!target) throw new Error('diagnose requires a target version');
  if (readFailed) return 'unknown';
  if (latest === target) return 'synced';
  if (Array.isArray(versions) && versions.includes(target)) return 'pending';
  if (submitted) return 'submitted';
  return 'absent';
}

/**
 * The operator-facing line for a state. Deliberately says what to DO — a red
 * step that does not say which of the two failures happened just moves the
 * guesswork rather than removing it.
 */
export function describeState({ state, latest, target, waitedMs = 0, submitted = false }) {
  const waited = waitedMs > 0 ? ` after ${Math.round(waitedMs / 60_000)}m` : '';
  switch (state) {
    case 'synced':
      return `✅ ClawHub synced at ${target}`;
    case 'submitted':
      return (
        `⏳ The clawhub CLI reported ${target} submitted and pending security scans, but ClawHub ` +
        `is still serving '${latest || 'none'}'${waited} and does not list ${target} yet. ` +
        `That is not proof the upload failed, and not proof it will go public. ` +
        `Check https://clawhub.ai/skills/shieldcortex, and read the scan findings with \`clawhub scan download shieldcortex --version ${target}\`; do not republish ${target} while its scan may still be running.`
      );
    case 'unknown':
      return (
        `❓ Could not read ClawHub state${waited}, so whether it serves ${target} is UNKNOWN — ` +
        `not confirmed absent, not confirmed served.` +
        (submitted ? ` The clawhub CLI did report ${target} submitted and pending security scans.` : '') +
        ` Re-run \`npm run release:clawhub:check\` (read-only, never publishes) once ClawHub is readable.`
      );
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

/**
 * Process exit code per state. Only a true sync is success — see #200.
 * 2 means "uploaded or submitted, not public yet — do not republish";
 * 3 means the state could not be read at all.
 */
export function exitCodeFor(state) {
  if (state === 'synced') return 0;
  if (state === 'pending' || state === 'submitted') return 2;
  if (state === 'unknown') return 3;
  return 1;
}
