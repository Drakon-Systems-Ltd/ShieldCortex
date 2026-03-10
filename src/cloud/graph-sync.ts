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
import { enqueueFailedGraphSync } from './sync-queue.js';
import type { Memory } from '../memory/types.js';

export interface SyncedGraphEntityRecord {
  external_id: string;
  local_id: number;
  name: string;
  type: string;
  aliases: string[];
  first_seen: string | null;
  memory_count: number;
}

export interface SyncedGraphTripleRecord {
  external_id: string;
  local_id: number;
  subject_external_id: string;
  predicate: string;
  object_external_id: string;
  source_memory_external_id: string | null;
  confidence: number | null;
  created_at: string | null;
}

export interface SyncedGraphMemoryEntityRecord {
  memory_external_id: string;
  entity_external_id: string;
  role: string;
}

export interface GraphSyncEnvelope {
  device: {
    device_id: string;
    device_name: string;
    platform: string;
  };
  entities: SyncedGraphEntityRecord[];
  triples: SyncedGraphTripleRecord[];
  memory_entities: SyncedGraphMemoryEntityRecord[];
  prune_memory_external_ids?: string[];
}

function safeJsonParse<T>(value: string | null | undefined, fallback: T): T {
  if (!value) return fallback;
  try {
    return JSON.parse(value) as T;
  } catch {
    return fallback;
  }
}

function entityExternalId(id: number): string {
  return `entity:${id}`;
}

function tripleExternalId(id: number): string {
  return `triple:${id}`;
}

function getAllowedMemoryExternalIds(): Set<string> {
  const db = getDatabase();
  const rows = db.prepare('SELECT uuid, project, sensitivity_level FROM memories').all() as Array<{
    uuid: string;
    project: string | null;
    sensitivity_level: string | null;
  }>;
  return buildAllowedMemoryExternalIdSet(rows);
}

function buildAllowedMemoryExternalIdSet(rows: Array<{
  uuid: string;
  project: string | null;
  sensitivity_level: string | null;
}>): Set<string> {
  const controls = getCloudSyncControls();

  return new Set(
    rows
      .filter((row) => {
        if (!shouldSyncProject(row.project, controls)) return false;
        if (controls.excludeSensitive && isSensitiveLevel(row.sensitivity_level)) return false;
        return true;
      })
      .map((row) => row.uuid),
  );
}

function buildEnvelope(
  entities: SyncedGraphEntityRecord[],
  triples: SyncedGraphTripleRecord[],
  memoryEntities: SyncedGraphMemoryEntityRecord[],
  pruneMemoryExternalIds: string[] = [],
): GraphSyncEnvelope {
  return {
    device: {
      device_id: getDeviceId(),
      device_name: getDeviceName(),
      platform: `${process.platform}/${process.arch}`,
    },
    entities,
    triples,
    memory_entities: memoryEntities,
    ...(pruneMemoryExternalIds.length > 0 ? { prune_memory_external_ids: pruneMemoryExternalIds } : {}),
  };
}

async function postGraphEnvelope(envelope: GraphSyncEnvelope): Promise<boolean> {
  const config = getCloudConfig();
  if (
    !config.cloudEnabled ||
    !config.cloudApiKey ||
    (
      envelope.entities.length === 0 &&
      envelope.triples.length === 0 &&
      envelope.memory_entities.length === 0 &&
      (!envelope.prune_memory_external_ids || envelope.prune_memory_external_ids.length === 0)
    )
  ) {
    return false;
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 15_000);

  try {
    const res = await fetch(`${config.cloudBaseUrl}/v1/sync/graph`, {
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

function mapEntityRow(row: Record<string, unknown>): SyncedGraphEntityRecord {
  return {
    external_id: entityExternalId(row.id as number),
    local_id: row.id as number,
    name: row.name as string,
    type: row.type as string,
    aliases: safeJsonParse(row.aliases as string, []),
    first_seen: row.first_seen ? new Date(row.first_seen as string).toISOString() : null,
    memory_count: Number(row.memory_count ?? 0),
  };
}

function mapTripleRow(row: Record<string, unknown>): SyncedGraphTripleRecord {
  return {
    external_id: tripleExternalId(row.id as number),
    local_id: row.id as number,
    subject_external_id: entityExternalId(row.subject_id as number),
    predicate: row.predicate as string,
    object_external_id: entityExternalId(row.object_id as number),
    source_memory_external_id: (row.source_memory_uuid as string | null) ?? null,
    confidence: row.confidence === undefined ? null : Number(row.confidence),
    created_at: row.created_at ? new Date(row.created_at as string).toISOString() : null,
  };
}

function mapMemoryEntityRow(row: Record<string, unknown>): SyncedGraphMemoryEntityRecord {
  return {
    memory_external_id: row.memory_uuid as string,
    entity_external_id: entityExternalId(row.entity_id as number),
    role: (row.role as string | null) ?? 'mention',
  };
}

function getMemoryScopedEnvelope(memoryId: number): GraphSyncEnvelope | null {
  const db = getDatabase();
  const memory = db.prepare('SELECT id, uuid, project, sensitivity_level FROM memories WHERE id = ?').get(memoryId) as {
    id: number;
    uuid: string;
    project: string | null;
    sensitivity_level: string | null;
  } | undefined;
  if (!memory) return null;

  const controls = getCloudSyncControls();
  const memoryAllowed =
    shouldSyncProject(memory.project, controls) &&
    !(controls.excludeSensitive && isSensitiveLevel(memory.sensitivity_level));

  if (!memoryAllowed) {
    return buildEnvelope([], [], [], [memory.uuid]);
  }

  const entityRows = db.prepare(`
    SELECT DISTINCT e.*
    FROM entities e
    JOIN memory_entities me ON me.entity_id = e.id
    WHERE me.memory_id = ?
    ORDER BY e.memory_count DESC, e.name ASC
  `).all(memoryId) as Record<string, unknown>[];

  const tripleRows = db.prepare(`
    SELECT t.*, m.uuid as source_memory_uuid
    FROM triples t
    LEFT JOIN memories m ON m.id = t.source_memory_id
    WHERE t.source_memory_id = ?
    ORDER BY t.id ASC
  `).all(memoryId) as Record<string, unknown>[];

  const memoryEntityRows = db.prepare(`
    SELECT me.entity_id, me.role, m.uuid as memory_uuid
    FROM memory_entities me
    JOIN memories m ON m.id = me.memory_id
    WHERE me.memory_id = ?
    ORDER BY me.entity_id ASC
  `).all(memoryId) as Record<string, unknown>[];

  return buildEnvelope(
    entityRows.map(mapEntityRow),
    tripleRows.map(mapTripleRow),
    memoryEntityRows.map(mapMemoryEntityRow),
    [memory.uuid],
  );
}

export function syncGraphForMemoryToCloud(memoryId: number): void {
  const config = getCloudConfig();
  if (!config.cloudEnabled || !config.cloudApiKey) return;

  const envelope = getMemoryScopedEnvelope(memoryId);
  if (!envelope) return;

  postGraphEnvelope(envelope).then((ok) => {
    if (!ok) enqueueFailedGraphSync(envelope);
  }).catch(() => {
    enqueueFailedGraphSync(envelope);
  });
}

export function syncGraphDeleteForMemoryToCloud(memory: Memory): void {
  const config = getCloudConfig();
  if (!config.cloudEnabled || !config.cloudApiKey) return;

  const envelope = buildEnvelope([], [], [], [memory.uuid]);
  postGraphEnvelope(envelope).then((ok) => {
    if (!ok) enqueueFailedGraphSync(envelope);
  }).catch(() => {
    enqueueFailedGraphSync(envelope);
  });
}

export async function syncAllGraphToCloud(): Promise<{
  entities: number;
  triples: number;
  memoryEntities: number;
  syncedBatches: number;
  failedBatches: number;
}> {
  const db = getDatabase();
  const memoryRows = db.prepare('SELECT uuid, project, sensitivity_level FROM memories ORDER BY id ASC').all() as Array<{
    uuid: string;
    project: string | null;
    sensitivity_level: string | null;
  }>;
  const allowedMemoryExternalIds = buildAllowedMemoryExternalIdSet(memoryRows);

  const entityRows = db.prepare('SELECT * FROM entities ORDER BY id ASC').all() as Record<string, unknown>[];
  const tripleRows = db.prepare(`
    SELECT t.*, m.uuid as source_memory_uuid
    FROM triples t
    LEFT JOIN memories m ON m.id = t.source_memory_id
    ORDER BY t.id ASC
  `).all() as Record<string, unknown>[];
  const memoryEntityRows = db.prepare(`
    SELECT me.entity_id, me.role, m.uuid as memory_uuid
    FROM memory_entities me
    JOIN memories m ON m.id = me.memory_id
    ORDER BY me.memory_id ASC, me.entity_id ASC
  `).all() as Record<string, unknown>[];

  const filteredMemoryEntityRows = memoryEntityRows.filter((row) => allowedMemoryExternalIds.has(row.memory_uuid as string));
  const allowedEntityIds = new Set(filteredMemoryEntityRows.map((row) => row.entity_id as number));
  const filteredTripleRows = tripleRows.filter((row) => {
    const sourceMemoryUuid = row.source_memory_uuid as string | null;
    if (sourceMemoryUuid && !allowedMemoryExternalIds.has(sourceMemoryUuid)) return false;
    const subjectId = row.subject_id as number;
    const objectId = row.object_id as number;
    return allowedEntityIds.has(subjectId) || allowedEntityIds.has(objectId);
  });
  for (const row of filteredTripleRows) {
    allowedEntityIds.add(row.subject_id as number);
    allowedEntityIds.add(row.object_id as number);
  }
  const filteredEntityRows = entityRows.filter((row) => allowedEntityIds.has(row.id as number));

  const entities = filteredEntityRows.map(mapEntityRow);
  const triples = filteredTripleRows.map(mapTripleRow);
  const memoryEntities = filteredMemoryEntityRows.map(mapMemoryEntityRow);
  const activeGraphMemoryExternalIds = new Set<string>([
    ...filteredMemoryEntityRows.map((row) => row.memory_uuid as string),
    ...filteredTripleRows
      .map((row) => row.source_memory_uuid as string | null)
      .filter((value): value is string => Boolean(value)),
  ]);
  const pruneMemoryExternalIds = memoryRows
    .map((row) => row.uuid)
    .filter((uuid) => !activeGraphMemoryExternalIds.has(uuid));

  const batchSize = 200;
  let syncedBatches = 0;
  let failedBatches = 0;

  for (let pruneIndex = 0; pruneIndex < pruneMemoryExternalIds.length; pruneIndex += batchSize) {
    const pruneEnvelope = buildEnvelope(
      [],
      [],
      [],
      pruneMemoryExternalIds.slice(pruneIndex, pruneIndex + batchSize),
    );
    const ok = await postGraphEnvelope(pruneEnvelope);
    if (ok) {
      syncedBatches++;
    } else {
      failedBatches++;
      enqueueFailedGraphSync(pruneEnvelope);
    }
  }

  const totalBatches = Math.max(
    Math.ceil(entities.length / batchSize),
    Math.ceil(triples.length / batchSize),
    Math.ceil(memoryEntities.length / batchSize),
    1,
  );

  for (let batchIndex = 0; batchIndex < totalBatches; batchIndex++) {
    const envelope = buildEnvelope(
      entities.slice(batchIndex * batchSize, (batchIndex + 1) * batchSize),
      triples.slice(batchIndex * batchSize, (batchIndex + 1) * batchSize),
      memoryEntities.slice(batchIndex * batchSize, (batchIndex + 1) * batchSize),
    );

    const hasPayload =
      envelope.entities.length > 0 ||
      envelope.triples.length > 0 ||
      envelope.memory_entities.length > 0;
    if (!hasPayload) continue;

    const ok = await postGraphEnvelope(envelope);
    if (ok) {
      syncedBatches++;
    } else {
      failedBatches++;
      enqueueFailedGraphSync(envelope);
    }
  }

  return {
    entities: entities.length,
    triples: triples.length,
    memoryEntities: memoryEntities.length,
    syncedBatches,
    failedBatches,
  };
}
