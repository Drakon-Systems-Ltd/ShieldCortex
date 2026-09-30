/**
 * Canonical encoding and hashes for the chained ledger (#617, design §5.7).
 *
 * Every chained row carries:
 *   content_digest = H(canonical(row content))
 *   row_hash       = H("sc-ledger-v1\n" ‖ prev_hash ‖ "\n" ‖ seq ‖ "\n" ‖ content_digest)
 * where H is SHA-256 rendered as 64 lowercase hex characters, prev_hash is the
 * previous row's row_hash (64 zeros at seq 0 of an epoch) and seq is rendered
 * in base-10 ASCII with no sign or leading zeros. The "\n" separators and the
 * fixed-width hex fields make the concatenation unambiguous.
 *
 * Splitting out content_digest is what lets a pruned row keep a 32-byte
 * witness (ledger_skeleton) without its content.
 *
 * canonical(value) is JSON with these rules, applied recursively:
 *   - object keys sorted by UTF-16 code unit order (Array.prototype.sort
 *     default), no whitespace anywhere;
 *   - strings as JSON.stringify writes them; the result is hashed as UTF-8;
 *   - numbers must be finite and are written by ECMAScript Number::toString
 *     (the shortest string that round-trips the IEEE-754 double, which is
 *     what JSON.stringify emits); -0 is written as 0. No NaN, no Infinity, so
 *     there is no float ambiguity;
 *   - null, booleans and arrays as JSON; `undefined`, functions, bigints,
 *     Buffers and any other non-plain object are refused, never guessed.
 *
 * The digest is computed from the row AS STORED (read back inside the write
 * transaction), not from the caller's object, so SQLite type affinity (a
 * string "0.5" stored in a REAL column) cannot make the writer and the
 * verifier disagree.
 */

import { createHash } from 'crypto';

/** prev_hash of the first row (seq 0) of every epoch. */
export const GENESIS_PREV_HASH = '0'.repeat(64);

/** Domain separator for row_hash. Bump only with a new canonical version. */
export const ROW_HASH_DOMAIN = 'sc-ledger-v1';

/** Version tag inside every canonical content object. */
export const CANONICAL_VERSION = 1;

export function sha256Hex(data: string): string {
  return createHash('sha256').update(data, 'utf-8').digest('hex');
}

function encode(value: unknown, path: string): string {
  if (value === null) return 'null';
  switch (typeof value) {
    case 'string':
      return JSON.stringify(value);
    case 'boolean':
      return value ? 'true' : 'false';
    case 'number':
      if (!Number.isFinite(value)) throw new Error(`canonical: non-finite number at ${path}`);
      return JSON.stringify(Object.is(value, -0) ? 0 : value);
    case 'object': {
      if (Array.isArray(value)) {
        return `[${value.map((v, i) => encode(v, `${path}[${i}]`)).join(',')}]`;
      }
      const proto = Object.getPrototypeOf(value);
      if (proto !== Object.prototype && proto !== null) {
        throw new Error(`canonical: non-plain object at ${path}`);
      }
      const obj = value as Record<string, unknown>;
      const keys = Object.keys(obj).sort();
      return `{${keys.map((k) => `${JSON.stringify(k)}:${encode(obj[k], `${path}.${k}`)}`).join(',')}}`;
    }
    default:
      throw new Error(`canonical: unsupported ${typeof value} at ${path}`);
  }
}

/** Canonical JSON (see the module header). Throws on anything ambiguous. */
export function canonicalJson(value: unknown): string {
  return encode(value, '$');
}

export function contentDigest(content: unknown): string {
  return sha256Hex(canonicalJson(content));
}

export function rowHash(prevHash: string, seq: number, digest: string): string {
  if (!Number.isSafeInteger(seq) || seq < 0) throw new Error(`rowHash: invalid seq ${seq}`);
  return sha256Hex(`${ROW_HASH_DOMAIN}\n${prevHash}\n${seq}\n${digest}`);
}

/**
 * The defence_audit columns that make up a chained row's content (v1). A
 * fixed list, not "every column", so adding a column later cannot silently
 * change the digest of rows already written.
 *
 * Deliberately EXCLUDED:
 *   - `id` (storage detail; `seq` is the position);
 *   - the chain columns themselves;
 *   - `memory_id`: its foreign key is ON DELETE SET NULL, so deleting a
 *     memory legitimately rewrites it on every audit row that named it. A
 *     digest over it would turn every memory deletion into a false tamper
 *     finding. The memory id a delete row refers to is also recorded in
 *     `reason`, which IS covered.
 */
export const AUDIT_CONTENT_FIELDS = [
  'project',
  'timestamp',
  'source_type',
  'source_identifier',
  'trust_score',
  'sensitivity_level',
  'firewall_result',
  'operation',
  'content_hash',
  'anomaly_score',
  'threat_indicators',
  'blocked_patterns',
  'reason',
  'fragmentation_score',
  'pipeline_duration_ms',
  'source_attested',
  'risk_modifier',
] as const;

/** Canonical content object of a stored defence_audit row. */
export function auditRowContent(row: Record<string, unknown>, ledgerId: string, epoch: number): Record<string, unknown> {
  const fields: Record<string, unknown> = {};
  for (const f of AUDIT_CONTENT_FIELDS) fields[f] = row[f] ?? null;
  return { v: CANONICAL_VERSION, table: 'defence_audit', ledger_id: ledgerId, epoch, fields };
}

export type LedgerMarkerKind = 'epoch-start' | 'heartbeat' | 'lost-coverage' | 'checkpoint';

/** Canonical content object of a ledger_marker row. */
export function markerRowContent(m: {
  ledger_id: string;
  epoch: number;
  kind: LedgerMarkerKind | string;
  timestamp: string;
  payload: unknown;
}): Record<string, unknown> {
  return {
    v: CANONICAL_VERSION,
    table: 'ledger_marker',
    ledger_id: m.ledger_id,
    epoch: m.epoch,
    kind: m.kind,
    timestamp: m.timestamp,
    payload: m.payload,
  };
}
