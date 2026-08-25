import { randomBytes } from 'node:crypto';
import { getDatabase } from '../database/init.js';
import {
  getCloudConfig,
  getCloudSyncControls,
  getDeviceId,
  getDeviceName,
  isSensitiveLevel,
  shouldSyncProject,
  updateLastSyncAt,
} from './config.js';
import { enqueueFailedMemorySync, enqueueMemoryOutbox } from './sync-queue.js';
import type { Memory } from '../memory/types.js';

export interface SyncedMemoryRecord {
  external_id: string;
  local_id: number;
  type: string;
  category: string;
  title: string;
  content: string;
  project: string | null;
  tags: string[];
  salience: number;
  scope: string;
  transferable: boolean;
  trust_score: number | null;
  sensitivity_level: string | null;
  source: string | null;
  metadata: Record<string, unknown>;
  cloud_excluded?: boolean;
  created_at: string;
  updated_at: string;
  deleted_at?: string | null;
}

export interface MemorySyncEnvelope {
  memories: SyncedMemoryRecord[];
  device: {
    device_id: string;
    device_name: string;
    platform: string;
  };
}

function safeJsonParse<T>(value: string | null | undefined, fallback: T): T {
  if (!value) return fallback;
  try {
    return JSON.parse(value) as T;
  } catch {
    return fallback;
  }
}

function rowToSyncRecord(row: Record<string, unknown>): SyncedMemoryRecord {
  return {
    external_id: row.uuid as string,
    local_id: row.id as number,
    type: row.type as string,
    category: row.category as string,
    title: row.title as string,
    content: row.content as string,
    project: (row.project as string | null) ?? null,
    tags: safeJsonParse(row.tags as string, []),
    salience: Number(row.salience ?? 0),
    scope: (row.scope as string) ?? 'project',
    transferable: Boolean(row.transferable),
    trust_score: row.trust_score === undefined ? null : Number(row.trust_score),
    sensitivity_level: (row.sensitivity_level as string | null) ?? null,
    source: (row.source as string | null) ?? null,
    metadata: safeJsonParse(row.metadata as string, {}),
    cloud_excluded: Boolean(row.cloud_excluded),
    created_at: new Date((row.created_at as string) ?? Date.now()).toISOString(),
    updated_at: new Date((row.updated_at as string) ?? (row.created_at as string) ?? Date.now()).toISOString(),
    deleted_at: null,
  };
}

function buildEnvelope(records: SyncedMemoryRecord[]): MemorySyncEnvelope {
  return {
    memories: records,
    device: {
      device_id: getDeviceId(),
      device_name: getDeviceName(),
      platform: `${process.platform}/${process.arch}`,
    },
  };
}

/**
 * Per-record sync gate. Exported for unit testing the safety contract:
 * a CONFIDENTIAL record on fresh-default controls MUST return false.
 */
export function shouldSyncRecord(
  record: Pick<SyncedMemoryRecord, 'project' | 'sensitivity_level' | 'cloud_excluded'>,
): boolean {
  if (record.cloud_excluded) return false;
  const controls = getCloudSyncControls();
  if (!shouldSyncProject(record.project, controls)) return false;
  if (controls.excludeSensitive && isSensitiveLevel(record.sensitivity_level)) return false;
  return true;
}

function applyContentMode(record: SyncedMemoryRecord): SyncedMemoryRecord {
  const controls = getCloudSyncControls();
  if (controls.contentMode !== 'metadata') return record;

  return {
    ...record,
    title: `[Metadata only] ${record.category}`,
    content: `[ShieldCortex] Memory content redacted by local sync policy.`,
    metadata: {
      ...record.metadata,
      _shieldcortex_sync: {
        ...(typeof record.metadata?._shieldcortex_sync === 'object' && record.metadata._shieldcortex_sync !== null
          ? record.metadata._shieldcortex_sync as Record<string, unknown>
          : {}),
        content_redacted: true,
        mode: 'metadata',
      },
    },
  };
}

function hydrateMemoryRecord(memoryId: number): SyncedMemoryRecord | null {
  const db = getDatabase();
  const row = db.prepare('SELECT * FROM memories WHERE id = ?').get(memoryId) as Record<string, unknown> | undefined;
  if (!row) return null;
  return rowToSyncRecord(row);
}

async function postEnvelope(envelope: MemorySyncEnvelope): Promise<boolean> {
  const config = getCloudConfig();
  if (!config.cloudEnabled || !config.cloudApiKey || envelope.memories.length === 0) {
    return false;
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 15_000);

  try {
    const res = await fetch(`${config.cloudBaseUrl}/v1/sync/memories`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${config.cloudApiKey}`,
      },
      body: JSON.stringify(envelope),
      signal: controller.signal,
    });

    if (!res.ok) {
      return false;
    }

    updateLastSyncAt();
    return true;
  } catch {
    return false;
  } finally {
    clearTimeout(timeoutId);
  }
}


/**
 * #409 — build the outbound memory record for an upsert (policy-gated).
 * Returns null when cloud sync is off or the record must not leave the host.
 */
export function buildMemoryUpsertOutboxRecord(memoryId: number): SyncedMemoryRecord | null {
  const config = getCloudConfig();
  if (!config.cloudEnabled || !config.cloudApiKey) return null;
  const record = hydrateMemoryRecord(memoryId);
  if (!record) return null;
  if (!shouldSyncRecord(record)) return null;
  return applyContentMode(record);
}

/**
 * #409 — build the outbound tombstone for a delete (policy-gated).
 */
export function buildMemoryDeleteOutboxRecord(memory: Memory): SyncedMemoryRecord | null {
  const config = getCloudConfig();
  if (!config.cloudEnabled || !config.cloudApiKey) return null;
  const gate = deletionPolicyFromMemory(memory);
  if (!gate.ok) return null;
  if (!shouldSyncRecord(gate.policy)) return null;
  return buildMemoryDeleteTombstone(memory);
}

/**
 * #409 — durable outbox write for memory upsert/delete.
 * Call inside the same SQLite transaction as the local mutation.
 * delivery_key: memory:{uuid}:{op}:{updatedAt|deletedAt}
 */
export function writeMemorySyncOutbox(
  record: SyncedMemoryRecord,
  options: {
    op: 'upsert' | 'delete';
    db?: ReturnType<typeof getDatabase>;
    /** Stable key for this logical event. Auto-minted unique when omitted. */
    deliveryKey?: string;
  },
): { inserted: boolean; id: number | null; deliveryKey: string } {
  // Unique per mutation (ms + nonce). Second-resolution updated_at alone collides
  // and a LIKE ack would mark later pending rows synced without sending them.
  const stamp = options.op === 'delete'
    ? (record.deleted_at ?? new Date().toISOString())
    : (record.updated_at ?? new Date().toISOString());
  const deliveryKey = options.deliveryKey
    ?? `memory:${record.external_id}:${options.op}:${stamp}:${Date.now()}:${randomBytes(6).toString('hex')}`;
  const result = enqueueMemoryOutbox(record, {
    deliveryKey,
    db: options.db,
    dueNow: true,
  });
  return { ...result, deliveryKey };
}

/**
 * #409 — after the mutation transaction commits, attempt immediate dispatch.
 * On failure the outbox row remains pending for processRetryQueue (#408).
 * Never throws into the store path.
 */
export function dispatchMemoryOutboxBestEffort(
  record: SyncedMemoryRecord,
  deliveryKey?: string,
): void {
  const envelope = buildEnvelope([record]);
  postEnvelope(envelope).then((ok) => {
    if (ok) {
      try {
        acknowledgeMemoryOutbox(deliveryKey);
      } catch { /* worker will retry */ }
    }
    // On !ok the durable outbox row stays pending — no second enqueue.
  }).catch(() => {
    /* outbox retains the event */
  });
}

/** #409 — ack exactly one outbox row. Never LIKE-prefix (would drop later events). */
function acknowledgeMemoryOutbox(deliveryKey?: string): void {
  if (!deliveryKey) return;
  const db = getDatabase();
  db.prepare(`
    UPDATE sync_queue
    SET status = 'synced', synced_at = ?, last_error = NULL,
        lease_owner = NULL, lease_token = NULL, lease_expires_at = NULL
    WHERE status = 'pending' AND delivery_key = ?
  `).run(new Date().toISOString(), deliveryKey);
}

export function syncMemoryUpsertToCloud(memory: Memory): void {
  // #409 — outbox-first even for non-transactional callers: durable row then dispatch.
  const record = buildMemoryUpsertOutboxRecord(memory.id);
  if (!record) return;
  let deliveryKey: string | undefined;
  try {
    deliveryKey = writeMemorySyncOutbox(record, { op: 'upsert' }).deliveryKey;
  } catch {
    // Degraded: outbox write failed (e.g. DB unavailable) — still try live
    // dispatch; park a legacy row best-effort.
    try { enqueueFailedMemorySync(record); } catch { /* silent */ }
  }
  dispatchMemoryOutboxBestEffort(record, deliveryKey);
}

/**
 * #405 — content-free cloud deletion record.
 * No title/content/tags/metadata/source. Keeps ids + type/category/project/scope timestamps for reconciliation only.
 */
export function buildMemoryDeleteTombstone(memory: Memory): SyncedMemoryRecord {
  const now = new Date().toISOString();
  return {
    external_id: memory.uuid,
    local_id: memory.id,
    type: memory.type,
    category: memory.category,
    title: '',
    content: '',
    project: memory.project ?? null,
    tags: [],
    salience: 0,
    scope: memory.scope,
    transferable: false,
    trust_score: null,
    // Policy is evaluated locally before send; do not re-emit sensitivity/source/metadata.
    sensitivity_level: null,
    source: null,
    metadata: {},
    cloud_excluded: false,
    created_at: memory.createdAt.toISOString(),
    updated_at: memory.updatedAt.toISOString(),
    deleted_at: now,
  };
}

/**
 * Policy fields for a delete event. Fail-closed when the original record's
 * privacy controls cannot be established (missing uuid / unknown exclusion).
 */
export function deletionPolicyFromMemory(memory: Memory): {
  ok: true;
  policy: Pick<SyncedMemoryRecord, 'project' | 'sensitivity_level' | 'cloud_excluded'>;
} | { ok: false; reason: string } {
  if (!memory || typeof memory.uuid !== 'string' || !memory.uuid.trim()) {
    return { ok: false, reason: 'missing-external-id' };
  }
  // cloudExcluded / sensitivityLevel are required columns on Memory; treat
  // non-boolean exclusion as untrustworthy rather than defaulting to share.
  if (typeof memory.cloudExcluded !== 'boolean') {
    return { ok: false, reason: 'missing-cloud-excluded' };
  }
  if (typeof memory.sensitivityLevel !== 'string' || !memory.sensitivityLevel.trim()) {
    return { ok: false, reason: 'missing-sensitivity' };
  }
  return {
    ok: true,
    policy: {
      project: memory.project ?? null,
      sensitivity_level: memory.sensitivityLevel,
      cloud_excluded: memory.cloudExcluded,
    },
  };
}

export function syncMemoryDeleteToCloud(memory: Memory): void {
  // #409 outbox-first; #405 privacy gate stays inside buildMemoryDeleteOutboxRecord.
  const record = buildMemoryDeleteOutboxRecord(memory);
  if (!record) return;
  let deliveryKey: string | undefined;
  try {
    deliveryKey = writeMemorySyncOutbox(record, { op: 'delete' }).deliveryKey;
  } catch {
    try { enqueueFailedMemorySync(record); } catch { /* silent */ }
  }
  dispatchMemoryOutboxBestEffort(record, deliveryKey);
}

export async function syncAllMemoriesToCloud(): Promise<{ total: number; synced: number; failed: number }> {
  const db = getDatabase();
  const rows = db.prepare('SELECT * FROM memories ORDER BY id ASC').all() as Record<string, unknown>[];
  const records = rows.map(rowToSyncRecord).filter(shouldSyncRecord).map(applyContentMode);

  let synced = 0;
  let failed = 0;
  const batchSize = 50;

  for (let i = 0; i < records.length; i += batchSize) {
    const batch = records.slice(i, i + batchSize);
    const ok = await postEnvelope(buildEnvelope(batch));
    if (ok) {
      synced += batch.length;
    } else {
      failed += batch.length;
      for (const record of batch) {
        enqueueFailedMemorySync(record);
      }
    }
  }

  return { total: records.length, synced, failed };
}
