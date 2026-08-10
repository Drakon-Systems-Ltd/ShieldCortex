/**
 * #225 phase 2 — can this host enforce on the conversation path at all?
 *
 * `before_agent_run` is the only conversation hook that can block a run, and it
 * did not exist until OpenClaw **2026.5.12**. Verified by sweeping the
 * published dists: 0 occurrences in 2026.4.23, 2026.5.5, 2026.5.6 and 2026.5.7;
 * 54 in 2026.5.12. Our plugin manifest declares `openclaw >= 2026.3.22`.
 *
 * The trap this module closes: OpenClaw does NOT reject an unknown typed hook.
 * It emits `unknown typed hook "…" ignored` as a warn diagnostic and returns.
 * So on every host in the 2026.3.22–2026.5.7 range, registering the hook would
 * appear to succeed and enforce nothing — a silent no-op, which is the same
 * false-green family as #200, #222 and phase 1 of this issue.
 *
 * DELIBERATELY NOT a hard engine-floor bump. Raising `engines.openclaw` to
 * 2026.5.12 would block installation for every operator on an older host —
 * including from the Action Guard (`before_tool_call`), which is not a
 * conversation hook, works fine on 2026.3.22, and is the plugin's primary
 * defence. Punishing users of a working feature to gate one they may never
 * enable is the wrong trade. The floor stays; the CAPABILITY is detected and
 * reported per host.
 */

import fs from 'fs';
import path from 'path';
import semver from 'semver';

/** First OpenClaw release containing `before_agent_run` (dist-verified). */
export const CONVERSATION_ENFORCEMENT_MIN_OPENCLAW = '2026.5.12';

export type EnforcementSupport = 'supported' | 'unsupported' | 'unknown';

export interface ConversationCapability {
  support: EnforcementSupport;
  /** The detected OpenClaw version, or null when it could not be read. */
  hostVersion: string | null;
  minVersion: string;
}

/**
 * OpenClaw versions are CalVer (`2026.5.12`) which is semver-shaped, so semver
 * comparison is correct — but a build/tag suffix (`2026.7.2-beta.7`) must not
 * make a prerelease compare LOW against a plain version. `semver.coerce` drops
 * the prerelease, which is what we want: 2026.7.2-beta.7 supports the hook.
 */
export function evaluateEnforcementSupport(hostVersion: string | null): ConversationCapability {
  const base = { hostVersion, minVersion: CONVERSATION_ENFORCEMENT_MIN_OPENCLAW };
  if (!hostVersion) return { ...base, support: 'unknown' };

  const coerced = semver.valid(semver.coerce(hostVersion) ?? '');
  if (!coerced) return { ...base, support: 'unknown' };

  return {
    ...base,
    support: semver.gte(coerced, CONVERSATION_ENFORCEMENT_MIN_OPENCLAW) ? 'supported' : 'unsupported',
  };
}

/**
 * Read the installed OpenClaw version. The managed install lives under a
 * node-version-specific directory (`tools/node-v24.15.0/lib/node_modules`),
 * so the path is discovered rather than assumed. Never throws — an unreadable
 * install yields `unknown`, never a confident answer.
 */
export function readOpenClawHostVersion(home: string): string | null {
  const toolsDir = path.join(home, '.openclaw', 'tools');
  let candidates: string[] = [];
  try {
    candidates = fs
      .readdirSync(toolsDir)
      .map((d) => path.join(toolsDir, d, 'lib', 'node_modules', 'openclaw', 'package.json'));
  } catch {
    return null;
  }

  // Prefer the highest version found: a box can carry more than one managed
  // node runtime, and a stale one must not decide the verdict.
  let best: string | null = null;
  for (const file of candidates) {
    try {
      const v = (JSON.parse(fs.readFileSync(file, 'utf-8')) as { version?: unknown }).version;
      if (typeof v !== 'string') continue;
      const coerced = semver.valid(semver.coerce(v) ?? '');
      if (!coerced) continue;
      if (!best || semver.gt(coerced, semver.valid(semver.coerce(best) ?? '') ?? '0.0.0')) best = v;
    } catch {
      continue;
    }
  }
  return best;
}

/** The honest one-liner for a capability verdict. */
export function describeEnforcementSupport(cap: ConversationCapability): string {
  switch (cap.support) {
    case 'supported':
      return `conversation enforcement AVAILABLE on OpenClaw ${cap.hostVersion} (>= ${cap.minVersion}) — not yet enabled; scanning remains observation-only`;
    case 'unsupported':
      return `conversation enforcement UNAVAILABLE — OpenClaw ${cap.hostVersion} predates ${cap.minVersion}, which first shipped the only conversation hook that can block (before_agent_run). Detections here can never be more than advisory`;
    case 'unknown':
    default:
      return 'conversation enforcement support UNKNOWN — could not read the installed OpenClaw version';
  }
}
