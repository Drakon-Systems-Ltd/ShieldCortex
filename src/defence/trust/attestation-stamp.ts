/**
 * Ownership keying for self-declared identities.
 *
 * `checkAccess` decides ownership by string equality on `${type}:${identifier}`.
 * That key is the ONLY thing standing between a caller and another identity's
 * memories — it gates owner-read of RESTRICTED rows, `delete`, and the `revoke`
 * own-cleanup branch. Until this module, the key was built from whatever the
 * caller declared, so a below-ceiling declaration wore a peer's name for free:
 * on a default `cli:*` 0.9 deployment a declared `hook:session-end` (0.8) is not
 * an over-claim, is honoured verbatim, and then reads the real hook's RESTRICTED
 * rows as OWNER.
 *
 * The clamp cannot catch this — it asks "does the claim outscore the
 * environment", and a genuine downgrade does not. The question ownership needs
 * is different: "did the environment CONFIRM this identity". Where the answer is
 * no, the identity keeps its declared type and score but is keyed into a
 * separate namespace, so it can only ever own what it wrote itself.
 *
 * Properties this stamp must hold (all covered in attestation-stamp.test.ts):
 * - it NEVER raises a score — `scoreSource` strips it before scoring, with one
 *   deliberate exception below;
 * - it can never collide with a host-attested `${type}:${identifier}` key, because
 *   an attested identifier is by construction unstamped and the stamp sits at the
 *   front of the identifier;
 * - it is idempotent, so re-resolving an already-stamped identity is stable and a
 *   caller cannot escape stamping by pre-stamping its own declaration;
 * - a stamped identifier cannot claim a privileged agent ORIGIN (`env-override>`,
 *   `cron`, `user-spawned`, …). Those origins mean "the host or the integrator's
 *   environment said so"; a self-declared string saying it is one of them earns
 *   the unprivileged default instead. This is the one place the stamp changes a
 *   score, and it only ever lowers it.
 */

import type { DefenceSource } from '../types.js';

/**
 * Origin token marking an identity the environment did not confirm.
 *
 * Shares the `>` hierarchy separator with `env-override>` on purpose: agent
 * identifiers already read as `origin>path`, so a stamped identifier stays
 * legible in the audit ledger and in `source_risk` node keys.
 */
export const UNATTESTED_ORIGIN = 'unattested';

const UNATTESTED_PREFIX = `${UNATTESTED_ORIGIN}>`;

/** True when this identifier carries the unattested stamp. */
export function isUnattestedIdentifier(identifier: string): boolean {
  return identifier.startsWith(UNATTESTED_PREFIX);
}

/** Remove the stamp (no-op when absent). Scoring works off the bare identifier. */
export function stripUnattestedStamp(identifier: string): string {
  return isUnattestedIdentifier(identifier)
    ? identifier.slice(UNATTESTED_PREFIX.length)
    : identifier;
}

/** Stamp an identifier as unattested, idempotently. */
export function stampUnattestedIdentifier(identifier: string): string {
  return isUnattestedIdentifier(identifier) ? identifier : `${UNATTESTED_PREFIX}${identifier}`;
}

/**
 * Apply the ownership stamp to a resolved source.
 *
 * Fed ONCE, at `resolveToolSource` — the single point where a declaration meets
 * the environment. Everything downstream (the stored `source` string, the
 * `checkAccess` caller key, the threat-graph `sourceKey`) is derived from the
 * returned source, so `read`, `delete` and `revoke` cannot drift apart.
 */
export function applyOwnershipStamp(source: DefenceSource, envConfirmed: boolean): DefenceSource {
  if (envConfirmed) return source;
  const identifier = stampUnattestedIdentifier(source.identifier);
  return identifier === source.identifier ? source : { ...source, identifier };
}

/** True when a stored `source` string was written by an unconfirmed identity. */
export function isUnattestedSourceKey(storedSource: string): boolean {
  const sep = storedSource.indexOf(':');
  return sep !== -1 && isUnattestedIdentifier(storedSource.slice(sep + 1));
}
