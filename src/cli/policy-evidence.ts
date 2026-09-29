/**
 * `shieldcortex policy-evidence` (#613).
 *
 * Emits the per-runtime posture records as JSON. It reads the same typed
 * module doctor reads (`src/posture`), never terminal text, and never the
 * overloaded `bound` boolean. Every record and every probe inside it carries
 * `sc://` provenance, and every field carries its own evidence.
 *
 * This is a local observation by this CLI. The runtime self-reports it reads
 * are written by the runtime processes on this box and are not independently
 * attested; the output says so in `limitations`, and never claims the records
 * found are every runtime process on the host.
 *
 * Read-only: collecting evidence never changes consent, never arms Guard and
 * never edits config.
 */

import { collectPostureRecords, type CollectOptions } from '../posture/collect.js';
import {
  COMPLETENESS_LIMITATION,
  HOST_INTEGRITY_LIMITATION,
  summarisePosture,
  type PostureRecord,
  type PostureSummary,
} from '../posture/posture-record.js';

export const POLICY_EVIDENCE_SCHEMA = 'shieldcortex.policy-evidence';
export const POLICY_EVIDENCE_VERSION = 1;

export interface PolicyEvidence {
  schema: typeof POLICY_EVIDENCE_SCHEMA;
  version: typeof POLICY_EVIDENCE_VERSION;
  source: string;
  generated_at: string;
  scope: string;
  limitations: string[];
  summary: PostureSummary;
  records: PostureRecord[];
}

const SCOPE_NOTE =
  'Local observation by this CLI. Each field carries its own evidence (method, observed_at, max_age, ' +
  'tested path, process / plugin / effective-policy identity). A summary is the weakest of the records ' +
  'it judges. An observed denial covers the path that was denied at that moment, nothing wider; ' +
  'synthetic probes are never counted as incidents.';

export function buildPolicyEvidence(opts: CollectOptions = {}): PolicyEvidence {
  const nowMs = opts.nowMs ?? Date.now();
  const records = collectPostureRecords({ ...opts, nowMs });
  return {
    schema: POLICY_EVIDENCE_SCHEMA,
    version: POLICY_EVIDENCE_VERSION,
    source: 'sc://policy-evidence/local',
    generated_at: new Date(nowMs).toISOString(),
    scope: SCOPE_NOTE,
    limitations: [HOST_INTEGRITY_LIMITATION, COMPLETENESS_LIMITATION],
    summary: summarisePosture(records),
    records,
  };
}

const USAGE = [
  'Usage: shieldcortex policy-evidence [--compact]',
  '',
  'Print the per-runtime posture records (#613) as JSON, one per',
  '(runtime, profile, plane, instance), each field with its own sc:// provenance.',
  'Read-only. Self-reports are host-local evidence, not attestation.',
].join('\n');

export function runPolicyEvidence(
  args: string[],
  opts: CollectOptions = {},
): { code: number; output: string } {
  let compact = false;
  for (const a of args) {
    if (a === '--help' || a === '-h') return { code: 0, output: USAGE };
    if (a === '--compact') {
      compact = true;
      continue;
    }
    return { code: 2, output: `Unknown option: ${a}\n\n${USAGE}` };
  }
  const evidence = buildPolicyEvidence(opts);
  return { code: 0, output: JSON.stringify(evidence, null, compact ? 0 : 2) };
}
