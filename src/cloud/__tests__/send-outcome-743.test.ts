/**
 * #743 — full sync reported a permanent HTTP 402 as "queued for retry", and a
 * first send kept no status at all.
 *
 * These are the pure pieces of the reporting fix: classify one send outcome,
 * tally a run, format the `cloud sync --full` summary, and emit at most one
 * live-dispatch diagnostic per process. No database, no transport.
 *
 * The retry policy itself (sync-queue classifyHttpStatus / processRetryQueue)
 * is deliberately NOT touched; the classification here reuses it.
 */
import { describe, expect, it, jest } from '@jest/globals';
import {
  classifySendFailure,
  createFirstSendDiagnostic,
  emptySendFailureTally,
  formatFullSyncSummary,
  recordSendFailure,
  type CloudSendOutcome,
} from '../send-outcome.js';

const http = (status: number): CloudSendOutcome => ({ ok: false, kind: 'http', status });
const network: CloudSendOutcome = { ok: false, kind: 'network' };
const skipped: CloudSendOutcome = { ok: false, kind: 'skipped' };

function memory(total: number, synced: number, outcomes: Array<[CloudSendOutcome, number]>) {
  const failures = emptySendFailureTally();
  let failed = 0;
  for (const [o, n] of outcomes) {
    recordSendFailure(failures, o, n);
    failed += n;
  }
  return { total, synced, failed, failures };
}

function graph(outcomes: Array<[CloudSendOutcome, number]>) {
  const failures = emptySendFailureTally();
  let failedBatches = 0;
  for (const [o, n] of outcomes) {
    recordSendFailure(failures, o, n);
    failedBatches += n;
  }
  return { entities: 4, triples: 2, memoryEntities: 3, syncedBatches: 1, failedBatches, failures };
}

const cleanGraph = graph([]);

describe('#743 classifySendFailure', () => {
  it('matches the retry queue: 402 and other non-429 4xx are permanent', () => {
    expect(classifySendFailure(http(402))).toBe('permanent');
    expect(classifySendFailure(http(400))).toBe('permanent');
    expect(classifySendFailure(http(403))).toBe('permanent');
  });

  it('429, 5xx and network failures are transient', () => {
    expect(classifySendFailure(http(429))).toBe('transient');
    expect(classifySendFailure(http(503))).toBe('transient');
    expect(classifySendFailure(http(500))).toBe('transient');
    expect(classifySendFailure(network)).toBe('transient');
  });

  it('a local skip is its own class, never a remote refusal', () => {
    expect(classifySendFailure(skipped)).toBe('skipped');
  });
});

describe('#743 recordSendFailure', () => {
  it('counts by class and keeps the first permanent status', () => {
    const t = emptySendFailureTally();
    recordSendFailure(t, http(503), 50);
    recordSendFailure(t, http(402), 50);
    recordSendFailure(t, network, 7);
    recordSendFailure(t, http(402), 3);
    recordSendFailure(t, skipped, 2);
    expect(t).toEqual({
      permanent: 53,
      transient: 57,
      skipped: 2,
      permanentStatus: 402,
      mixedPermanentStatus: false,
    });
  });

  it('flags a run whose permanent statuses differ', () => {
    const t = emptySendFailureTally();
    recordSendFailure(t, http(402), 1);
    recordSendFailure(t, http(403), 1);
    expect(t.permanentStatus).toBe(402);
    expect(t.mixedPermanentStatus).toBe(true);
  });
});

describe('#743 formatFullSyncSummary', () => {
  it('a clean run is unchanged', () => {
    expect(formatFullSyncSummary(memory(10, 10, []), cleanGraph)).toEqual([
      'Finished. 10/10 memories synced.',
      'Graph replica: 4 entities, 2 relationships, 3 memory links.',
    ]);
  });

  it('402: does not say "queued for retry", names the status once, and does not claim "not queued"', () => {
    const lines = formatFullSyncSummary(
      memory(120, 0, [[http(402), 120]]),
      graph([[http(402), 2]]),
    );
    const text = lines.join('\n');
    expect(text).not.toMatch(/queued for retry/);
    expect(text).not.toMatch(/not queued/i);
    expect(lines[0]).toBe('Finished. 0/120 memories synced, 120 rejected by the cloud (HTTP 402).');
    expect(lines[1]).toBe(
      'Graph replica: 4 entities, 2 relationships, 3 memory links, 2 batches rejected by the cloud (HTTP 402).',
    );
    // One explanatory line for the whole command, not one per row or batch.
    expect(lines).toHaveLength(3);
    expect(lines[2]).toMatch(/permanent/i);
    expect(lines[2]).toMatch(/sync queue/);
    expect(lines[2]).toMatch(/failed/);
  });

  it('429 and 503 are still "queued for retry", with no permanent note', () => {
    const r429 = formatFullSyncSummary(memory(50, 0, [[http(429), 50]]), cleanGraph);
    expect(r429).toEqual([
      'Finished. 0/50 memories synced, 50 queued for retry.',
      'Graph replica: 4 entities, 2 relationships, 3 memory links.',
    ]);
    const r503 = formatFullSyncSummary(memory(50, 0, [[http(503), 50]]), graph([[http(503), 1]]));
    expect(r503).toEqual([
      'Finished. 0/50 memories synced, 50 queued for retry.',
      'Graph replica: 4 entities, 2 relationships, 3 memory links, 1 batch queued for retry.',
    ]);
  });

  it('a network failure is "queued for retry" and prints no status', () => {
    const lines = formatFullSyncSummary(memory(5, 0, [[network, 5]]), cleanGraph);
    expect(lines[0]).toBe('Finished. 0/5 memories synced, 5 queued for retry.');
    expect(lines.join('\n')).not.toMatch(/HTTP/);
  });

  it('mixed outcomes keep permanent, transient and local skips apart', () => {
    const lines = formatFullSyncSummary(
      memory(160, 50, [[http(402), 50], [http(503), 50], [network, 8], [skipped, 2]]),
      graph([[http(429), 1], [http(402), 1]]),
    );
    expect(lines[0]).toBe(
      'Finished. 50/160 memories synced, 58 queued for retry, 50 rejected by the cloud (HTTP 402), ' +
      '2 not sent (cloud sync not configured locally).',
    );
    expect(lines[1]).toBe(
      'Graph replica: 4 entities, 2 relationships, 3 memory links, 1 batch queued for retry, ' +
      '1 batch rejected by the cloud (HTTP 402).',
    );
    expect(lines).toHaveLength(3);
  });

  it('different permanent statuses are not collapsed into one number', () => {
    const lines = formatFullSyncSummary(memory(2, 0, [[http(402), 1], [http(403), 1]]), cleanGraph);
    expect(lines[0]).toBe('Finished. 0/2 memories synced, 2 rejected by the cloud (HTTP 402 and other 4xx).');
  });

  it('a local skip alone is not described as a cloud refusal or a retry', () => {
    const lines = formatFullSyncSummary(memory(3, 0, [[skipped, 3]]), cleanGraph);
    expect(lines).toEqual([
      'Finished. 0/3 memories synced, 3 not sent (cloud sync not configured locally).',
      'Graph replica: 4 entities, 2 relationships, 3 memory links.',
    ]);
  });

  it('a result without a tally (older caller shape) keeps the old wording', () => {
    expect(
      formatFullSyncSummary(
        { total: 4, synced: 1, failed: 3 },
        { entities: 0, triples: 0, memoryEntities: 0, failedBatches: 2 },
      ),
    ).toEqual([
      'Finished. 1/4 memories synced, 3 queued for retry.',
      'Graph replica: 0 entities, 0 relationships, 0 memory links, 2 batches queued for retry.',
    ]);
  });
});

describe('#743 createFirstSendDiagnostic', () => {
  it('logs the first permanent status once and stays quiet otherwise', () => {
    const log = jest.fn<(line: string) => void>();
    const note = createFirstSendDiagnostic(log);

    note({ ok: true });
    note(http(503));
    note(http(429));
    note(network);
    note(skipped);
    expect(log).not.toHaveBeenCalled();

    note(http(402));
    note(http(402));
    note(http(403));
    expect(log).toHaveBeenCalledTimes(1);
    const line = log.mock.calls[0][0];
    expect(line).toMatch(/HTTP 402/);
    expect(line).not.toMatch(/queued for retry/);
    expect(line).not.toMatch(/not queued/i);
  });

  it('never prints a status outside the HTTP range', () => {
    const log = jest.fn<(line: string) => void>();
    const note = createFirstSendDiagnostic(log);
    note({ ok: false, kind: 'http', status: 4020 });
    expect(log).not.toHaveBeenCalled();
  });
});
