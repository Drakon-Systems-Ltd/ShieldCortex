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

/**
 * First STABLE OpenClaw release containing `before_agent_run` (dist-verified).
 *
 * ONE floor, stated in three files that cannot import each other — this one,
 * `CONVERSATION_GATE_MIN_OPENCLAW` in `plugins/openclaw/index.ts`, and
 * `engines.conversationGate` in `plugins/openclaw/openclaw.plugin.json`. The
 * plugin compiles to its own dist under `rootDir: ./plugins/openclaw` and does
 * not carry `semver`, so it cannot import this module; the manifest is JSON the
 * host reads and imports nothing. They are pinned equal by
 * `src/__tests__/conversation-gate-floor-parity-226.test.ts` — edit one and
 * that test names the others.
 *
 * The hook first appears in the 2026.5.9-beta.1 PRERELEASE. That is recorded in
 * the plugin (`CONVERSATION_GATE_FIRST_PRERELEASE_OPENCLAW`) and in the
 * manifest note, and it is deliberately not a floor: it decides nothing an
 * operator is shown. The stable release is the single answer to "can this host
 * enforce".
 */
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
 * Managed-runtime candidates: `~/.openclaw/tools/<node>/lib/node_modules/openclaw`.
 * The node directory is version-specific, so it is discovered rather than assumed.
 */
function managedLayoutCandidates(home: string): string[] {
  const toolsDir = path.join(home, '.openclaw', 'tools');
  try {
    return fs
      .readdirSync(toolsDir)
      .map((d) => path.join(toolsDir, d, 'lib', 'node_modules', 'openclaw', 'package.json'));
  } catch {
    // No managed runtime on this host. NOT a reason to stop looking — a plain
    // `npm i -g openclaw` never creates this directory (#254).
    return [];
  }
}

/**
 * Global-install candidates, resolved from PATH.
 *
 * A global npm install puts a symlink in some `bin/` and the package itself in
 * a sibling `lib/node_modules/openclaw` — the prefix varies by installer
 * (`~/.npm-global`, `/usr/local`, nvm, volta), so the only portable anchor is
 * the binary on PATH. Follow it to its real location and walk up to the
 * `package.json` that owns it.
 *
 * The name check matters: the walk must not accept the first package.json it
 * meets. A differently-named package shipping an `openclaw` bin would
 * otherwise donate its version number to the verdict.
 */
function pathLayoutCandidates(pathEnv: string): string[] {
  const found: string[] = [];
  for (const dir of pathEnv.split(path.delimiter)) {
    if (!dir) continue;
    for (const name of ['openclaw', 'openclaw.mjs', 'openclaw.js']) {
      const bin = path.join(dir, name);
      let real: string;
      try {
        real = fs.realpathSync(bin);
      } catch {
        continue; // absent, dangling symlink, or unreadable PATH entry
      }
      let cursor = path.dirname(real);
      // Bounded walk: a package root is never far above its own bin script.
      for (let depth = 0; depth < 4; depth++) {
        found.push(path.join(cursor, 'package.json'));
        const parent = path.dirname(cursor);
        if (parent === cursor) break;
        cursor = parent;
      }
    }
  }
  return found;
}

/**
 * Read the installed OpenClaw version, across BOTH install layouts — the
 * managed runtime and a plain global npm install on PATH.
 *
 * Never throws. Returns null only when no readable install exists anywhere, so
 * `unknown` means "genuinely could not find it" rather than "did not look
 * there" (#254: searching only the managed layout made every globally
 * installed host report UNKNOWN forever, with the version sitting readable
 * beside the binary).
 *
 * `pathEnv` is injectable so the discovery itself is testable without
 * depending on the machine running the suite.
 */
export function readOpenClawHostVersion(
  home: string,
  pathEnv: string = process.env.PATH ?? '',
): string | null {
  const candidates = [...managedLayoutCandidates(home), ...pathLayoutCandidates(pathEnv)];

  // Prefer the highest version found: a box can carry more than one managed
  // node runtime — and now a global install alongside them — and a stale one
  // must not decide the verdict.
  let best: string | null = null;
  for (const file of candidates) {
    try {
      const pkg = JSON.parse(fs.readFileSync(file, 'utf-8')) as {
        name?: unknown;
        version?: unknown;
      };
      if (pkg.name !== 'openclaw') continue;
      const v = pkg.version;
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
