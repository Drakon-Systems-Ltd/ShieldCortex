import { getCloudConfig, getDeviceId, getDeviceName, updateLastSyncAt } from './config.js';
import { enqueueFailedSync } from './sync-queue.js';
import type { DefencePipelineResult, DefenceSource } from '../defence/types.js';

// ── In-flight tracking ───────────────────────────────────
//
// `syncToCloud` / `sendHeartbeat` / `sendKillSwitchAlert` are fire-and-forget
// from the perspective of their 50+ callers (`runDefencePipeline`, the brain
// worker, kill-switch handlers). But short-lived CLI processes
// (`shieldcortex scan ...`) terminate via `process.exit()` within ~1s of
// kicking off the POST — the fetch is aborted before the request leaves the
// machine. Mac users don't notice because the long-running dashboard daemon
// owns its own scan path; headless Linux servers running scans from cron or
// shell scripts lose every sync. (v4.24.1 fixed the gate; this fixes
// delivery from short-lived processes.)
//
// We track every in-flight promise in a module-level Set, and expose
// `flushPendingCloudSync(maxWaitMs)` so CLI entry points can await drain
// with a timeout before exiting. Long-lived processes (MCP server,
// dashboard daemon, OpenClaw hooks) never need to call it — their event
// loop holds the process open until the fetch resolves naturally.

const inFlight = new Set<Promise<unknown>>();

function track<T>(p: Promise<T>): Promise<T> {
  inFlight.add(p);
  p.finally(() => inFlight.delete(p)).catch(() => { /* settled */ });
  return p;
}

/**
 * Drain any pending cloud sync requests (audit-ingest, heartbeat, kill-switch
 * alerts) before the calling process exits. Returns when all in-flight POSTs
 * have settled (resolved or rejected) OR `maxWaitMs` elapses, whichever first.
 *
 * Intended use: at the tail of short-lived CLI subcommands, immediately
 * before `process.exit()`. Long-lived processes (MCP server, brain worker,
 * dashboard daemon) don't need this — their event loop keeps the process
 * alive until the fetch resolves naturally.
 *
 * The timeout is a safety belt for slow / unreachable cloud endpoints; the
 * underlying fetches already abort at 10s.
 */
export async function flushPendingCloudSync(maxWaitMs = 8000): Promise<void> {
  if (inFlight.size === 0) return;
  const drain = Promise.allSettled([...inFlight]).then(() => undefined);
  const timeout = new Promise<void>((resolve) => setTimeout(resolve, maxWaitMs));
  await Promise.race([drain, timeout]);
}

/** Count of in-flight cloud sync requests. Useful for tests + diagnostics. */
export function pendingCloudSyncCount(): number {
  return inFlight.size;
}

/**
 * Fire-and-forget: sends a heartbeat to ShieldCortex cloud so the
 * device shows as "Online" even when idle (no scans triggering syncToCloud).
 * Called by BrainWorker every 5 minutes.
 */
export function sendHeartbeat(): void {
  const config = getCloudConfig();
  if (!config.cloudEnabled || !config.cloudApiKey) return;

  const payload = {
    device_id: getDeviceId(),
    device_name: getDeviceName(),
    platform: `${process.platform}/${process.arch}`,
  };

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 10_000);

  track(
    fetch(`${config.cloudBaseUrl}/v1/devices/heartbeat`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${config.cloudApiKey}`,
      },
      body: JSON.stringify(payload),
      signal: controller.signal,
    })
      .then(() => { clearTimeout(timeoutId); })
      .catch(() => { clearTimeout(timeoutId); })
  );
}

/**
 * Fire-and-forget: sends audit data to ShieldCortex cloud.
 * Never blocks, never throws. Failed requests are logged and queued for retry.
 * Sends audit metadata ONLY — no content or titles.
 */
export function syncToCloud(
  result: DefencePipelineResult,
  source: DefenceSource,
  durationMs: number,
): void {
  const config = getCloudConfig();

  // Bail immediately if cloud sync is not configured
  if (!config.cloudEnabled || !config.cloudApiKey) return;

  const entry = {
    source_type: source.type,
    source_identifier: source.identifier,
    trust_score: result.trust.score,
    sensitivity_level: result.sensitivity.level,
    firewall_result: result.firewall.result,
    anomaly_score: result.firewall.anomalyScore,
    threat_indicators: result.firewall.threatIndicators.map(t =>
      typeof t === 'string' ? t : (t as { pattern?: string }).pattern ?? String(t)
    ),
    blocked_patterns: result.firewall.blockedPatterns,
    fragmentation_score: result.fragmentation?.score ?? null,
    reason: result.firewall.reason,
    pipeline_duration_ms: durationMs,
    device_id: getDeviceId(),
    device_name: getDeviceName(),
    platform: `${process.platform}/${process.arch}`,
    timestamp: new Date().toISOString(),
  };

  // Abort after 10 seconds to prevent pending fetch accumulation
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 10_000);

  // Fire-and-forget — no await, catch all errors silently. The promise is
  // tracked so short-lived CLI processes can drain via flushPendingCloudSync()
  // before exiting.
  track(
    fetch(`${config.cloudBaseUrl}/v1/audit/ingest`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${config.cloudApiKey}`,
      },
      body: JSON.stringify({ entries: [entry] }),
      signal: controller.signal,
    })
      .then((res) => {
        clearTimeout(timeoutId);
        if (!res?.ok) {
          try { enqueueFailedSync(entry); } catch { /* truly silent */ }
        } else {
          try { updateLastSyncAt(); } catch { /* truly silent */ }
        }
      })
      .catch((e: unknown) => {
        clearTimeout(timeoutId);
        console.error('[shieldcortex] Cloud sync failed:', e instanceof Error ? e.message : String(e));
        try { enqueueFailedSync(entry); } catch { /* truly silent */ }
      })
  );
}

/**
 * Fire-and-forget: sends a kill switch alert to ShieldCortex cloud.
 * Shaped as a normal audit ingest entry so the SaaS API accepts it.
 */
export function sendKillSwitchAlert(meta: {
  source: string;
  phrase?: string;
  reason?: string;
  memoryCountAtTrigger?: number;
  triggeredAt: string;
}): void {
  const config = getCloudConfig();
  if (!config.cloudEnabled || !config.cloudApiKey) return;

  const entry = {
    source_type: 'kill_switch',
    source_identifier: meta.source,
    trust_score: 0,
    sensitivity_level: 'RESTRICTED',
    firewall_result: 'BLOCK',
    anomaly_score: 1,
    threat_indicators: ['kill_switch'],
    reason: `Kill switch activated. Source: ${meta.source}.${meta.phrase ? ` Phrase: "${meta.phrase}".` : ''}${meta.reason ? ` ${meta.reason}` : ''}`,
    pipeline_duration_ms: 0,
    device_id: getDeviceId(),
    device_name: getDeviceName(),
    platform: `${process.platform}/${process.arch}`,
    timestamp: meta.triggeredAt,
  };

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 10_000);

  track(
    fetch(`${config.cloudBaseUrl}/v1/audit/ingest`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${config.cloudApiKey}`,
      },
      body: JSON.stringify({ entries: [entry] }),
      signal: controller.signal,
    })
      .then(() => { clearTimeout(timeoutId); })
      .catch(() => { clearTimeout(timeoutId); })
  );
}
