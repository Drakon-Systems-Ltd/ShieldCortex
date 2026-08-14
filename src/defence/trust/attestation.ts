/**
 * Host-attestation stamp for resolved tool sources (#283).
 *
 * A declared `source` is a SELF-APPLIED identity. `resolveToolSource` only
 * rejects a declaration that OUTSCORES the environment ceiling (or ties it and
 * names a different identity). Anything scoring STRICTLY BELOW the ceiling was
 * honoured verbatim, so on the default `cli:*` 0.9 deployments a caller could
 * declare `hook:session-end` (0.8) or `api:ingest` (0.7) and then read, delete
 * and trust-hierarchy-revoke the rows written by the REAL holder of that name —
 * `checkAccess` keys ownership on `${type}:${identifier}` string equality.
 *
 * The fix is one source of truth, not a side-channel column: when the host did
 * not attest an identity, the identity itself is REWRITTEN with a `claimed>`
 * marker on the identifier. That rewritten string is what gets stored on the
 * row, what becomes the `checkAccess` caller key, and what the read guards see —
 * so ownership, delete, revoke and inbound classification all inherit it from
 * one stamp, fed once.
 *
 * Two invariants make the stamp safe:
 *
 * 1. **It cannot raise trust.** `scoreSource` strips the marker before scoring,
 *    so `hook:claimed>session-end` scores exactly what `hook:session-end`
 *    scores. (Prefixing without stripping WOULD raise trust — `file:import` is
 *    pinned at 0.4 by exact key and would fall back to the `file` type score of
 *    0.6, and `env-override>` deliberately pins agents UP to 0.5.)
 * 2. **It cannot collide with a host-attested key.** The host never mints an
 *    identifier containing the marker, so a stamped key is disjoint from every
 *    host-attested `${type}:${identifier}`.
 *
 * The marker is deliberately readable from the identity string alone. It is not
 * a caller-suppliable privilege: declaring it yourself only DEMOTES you into the
 * unattested keyspace, which is the same place the resolver would have put you.
 */

/** Identifier prefix marking an identity the host did not attest. */
export const UNATTESTED_CLAIM_MARKER = 'claimed>';

/** True when an identifier carries the unattested-claim stamp. */
export function isUnattestedClaimIdentifier(identifier: string | null | undefined): boolean {
  return !!identifier && identifier.startsWith(UNATTESTED_CLAIM_MARKER);
}

/**
 * True when a STORED `"type:identifier"` source string carries the stamp.
 * Parses the type off rather than substring-matching so a literal `claimed>`
 * buried mid-identifier cannot masquerade as the prefix.
 */
export function isUnattestedClaimStoredSource(stored: string | null | undefined): boolean {
  if (!stored) return false;
  const sep = stored.indexOf(':');
  return isUnattestedClaimIdentifier(sep === -1 ? stored : stored.slice(sep + 1));
}

/**
 * Remove the stamp for SCORING purposes. Idempotent and repeat-safe (a caller
 * that declares `claimed>claimed>x` scores as `x`, and re-stamping is a no-op).
 */
export function stripUnattestedClaim(identifier: string): string {
  let out = identifier;
  while (out.startsWith(UNATTESTED_CLAIM_MARKER)) {
    out = out.slice(UNATTESTED_CLAIM_MARKER.length);
  }
  return out;
}

/** Apply the stamp to an identifier, idempotently. */
export function markUnattestedIdentifier(identifier: string): string {
  return isUnattestedClaimIdentifier(identifier)
    ? identifier
    : `${UNATTESTED_CLAIM_MARKER}${identifier}`;
}
