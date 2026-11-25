/**
 * #743 — what happened to one cloud send, and how to report it.
 *
 * Reporting only. The retry policy lives in sync-queue.ts and is unchanged:
 * the classification below reuses its `classifyHttpStatus`, so "permanent"
 * here means exactly what the retry worker will do with that status. Nothing
 * here reads a response body or prints a URL, key, or payload — the only
 * remote fact surfaced is the numeric HTTP status.
 */
import { classifyHttpStatus } from './sync-queue.js';

export type CloudSendOutcome =
  | { ok: true }
  /** Local precondition (cloud not configured, nothing to send). No request was made. */
  | { ok: false; kind: 'skipped' }
  /** The cloud answered with a non-2xx status. */
  | { ok: false; kind: 'http'; status: number }
  /** Network error, timeout/abort, or a response without a usable status. */
  | { ok: false; kind: 'network' };

export type SendFailureClass = 'permanent' | 'transient' | 'skipped';

/** A real HTTP status code, the only remote value this module will print. */
export function isReportableHttpStatus(status: unknown): status is number {
  return typeof status === 'number' && Number.isInteger(status) && status >= 100 && status <= 599;
}

export function classifySendFailure(outcome: Exclude<CloudSendOutcome, { ok: true }>): SendFailureClass {
  if (outcome.kind === 'skipped') return 'skipped';
  if (outcome.kind === 'http' && isReportableHttpStatus(outcome.status)) {
    return classifyHttpStatus(outcome.status);
  }
  return 'transient';
}

export interface SendFailureTally {
  /** Units refused with a status the retry worker treats as permanent. */
  permanent: number;
  /** Units that failed transiently (network, 429, 5xx) — ordinary retries. */
  transient: number;
  /** Units never sent because of a local precondition. */
  skipped: number;
  /** First permanent HTTP status seen in this run, if any. */
  permanentStatus: number | null;
  /** True when a later permanent status differed from `permanentStatus`. */
  mixedPermanentStatus: boolean;
}

export function emptySendFailureTally(): SendFailureTally {
  return { permanent: 0, transient: 0, skipped: 0, permanentStatus: null, mixedPermanentStatus: false };
}

/** Add `units` failed records/batches with this outcome to the tally. */
export function recordSendFailure(
  tally: SendFailureTally,
  outcome: Exclude<CloudSendOutcome, { ok: true }>,
  units: number,
): void {
  const cls = classifySendFailure(outcome);
  tally[cls] += units;
  if (cls === 'permanent' && outcome.kind === 'http') {
    if (tally.permanentStatus === null) tally.permanentStatus = outcome.status;
    else if (tally.permanentStatus !== outcome.status) tally.mixedPermanentStatus = true;
  }
}

export interface FullSyncMemorySummary {
  total: number;
  synced: number;
  failed: number;
  failures?: SendFailureTally;
}

export interface FullSyncGraphSummary {
  entities: number;
  triples: number;
  memoryEntities: number;
  failedBatches: number;
  failures?: SendFailureTally;
}

function statusLabel(t: SendFailureTally): string {
  if (t.permanentStatus === null) return 'HTTP 4xx';
  return t.mixedPermanentStatus ? `HTTP ${t.permanentStatus} and other 4xx` : `HTTP ${t.permanentStatus}`;
}

function failureParts(failed: number, tally: SendFailureTally | undefined, unit: (n: number) => string): string[] {
  if (failed <= 0) return [];
  // No tally (older result shape): every failure is an ordinary retry, as before.
  const t = tally ?? { ...emptySendFailureTally(), transient: failed };
  const parts: string[] = [];
  if (t.transient > 0) parts.push(`${unit(t.transient)} queued for retry`);
  if (t.permanent > 0) parts.push(`${unit(t.permanent)} rejected by the cloud (${statusLabel(t)})`);
  if (t.skipped > 0) parts.push(`${unit(t.skipped)} not sent (cloud sync not configured locally)`);
  return parts;
}

/**
 * The `cloud sync --full` summary. "Queued for retry" is reserved for
 * transient failures. Permanently refused rows are still written to the sync
 * queue as pending (unchanged), so the note says what the worker will do with
 * them rather than claiming they were not queued.
 */
export function formatFullSyncSummary(memory: FullSyncMemorySummary, graph: FullSyncGraphSummary): string[] {
  const memParts = failureParts(memory.failed, memory.failures, (n) => String(n));
  const graphParts = failureParts(
    graph.failedBatches,
    graph.failures,
    (n) => `${n} batch${n === 1 ? '' : 'es'}`,
  );
  const lines = [
    `Finished. ${memory.synced}/${memory.total} memories synced${memParts.map((p) => `, ${p}`).join('')}.`,
    `Graph replica: ${graph.entities} entities, ${graph.triples} relationships, ${graph.memoryEntities} memory links` +
      `${graphParts.map((p) => `, ${p}`).join('')}.`,
  ];
  const anyPermanent = (memory.failed > 0 && (memory.failures?.permanent ?? 0) > 0)
    || (graph.failedBatches > 0 && (graph.failures?.permanent ?? 0) > 0);
  if (anyPermanent) {
    lines.push(
      'Rejected entries are a permanent refusal, not a temporary outage. They are in the sync queue, ' +
      'but the retry worker marks them failed instead of retrying if the cloud refuses them again.',
    );
  }
  return lines;
}

/**
 * Live dispatch has no command summary. This returns a sink that logs the
 * first permanent HTTP status it sees and nothing after that — one line per
 * process, status number only, no per-row repeats.
 */
export function createFirstSendDiagnostic(log: (line: string) => void): (outcome: CloudSendOutcome) => void {
  let reported = false;
  return (outcome) => {
    if (reported || outcome.ok || outcome.kind !== 'http') return;
    if (!isReportableHttpStatus(outcome.status)) return;
    if (classifySendFailure(outcome) !== 'permanent') return;
    reported = true;
    log(
      `[shieldcortex] Cloud sync refused a live update with HTTP ${outcome.status} (permanent, not a temporary outage). ` +
      'The entry stays in the sync queue; the retry worker marks it failed if refused again. ' +
      'Further refusals in this process are not logged.',
    );
  };
}

/** Process-wide live-dispatch diagnostic shared by memory and graph dispatch. */
export const noteLiveDispatchOutcome = createFirstSendDiagnostic((line) => console.error(line));
