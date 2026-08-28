import fs from 'fs';
import os from 'os';
import path from 'path';
import { createHash, randomUUID } from 'crypto';
import type Database from 'better-sqlite3';
import type { DefenceSource } from '../defence/types.js';
import type { Memory, MemoryInput } from './types.js';
import {
  addMemory,
  assessMemoryAdmission,
  type MemoryAdmissionAssessment,
} from './store.js';
import { getDatabase } from '../database/init.js';
import { jaccardSimilarity } from './similarity.js';

const MAX_NATIVE_FILE_BYTES = 2 * 1024 * 1024;
const MAX_NATIVE_FILES = 128;
const MAX_NATIVE_CHUNKS = 512;
const MAX_CHUNK_BYTES = 8 * 1024;
const NEAR_DUPLICATE_THRESHOLD = 0.9;
const NATIVE_IMPORT_TRUST_CEILING = 0.7;
const NATIVE_IMPORT_SALIENCE_CEILING = 0.7;

export type NativeImportDisposition =
  | 'would_admit'
  | 'admitted'
  | 'blocked'
  | 'quarantined'
  | 'exact_duplicate'
  | 'higher_trust_preserved'
  | 'near_duplicate_preserved'
  | 'invalid'
  | 'failed';

export interface NativeMarkdownChunk {
  index: number;
  title: string;
  content: string;
  contentHash: string;
}

export interface NativeImportRowResult {
  sourcePath: string;
  chunkIndex: number;
  title: string;
  contentHash: string;
  disposition: NativeImportDisposition;
  defenceVerdict: 'ALLOW' | 'BLOCK' | 'QUARANTINE' | 'ERROR' | null;
  reason: string;
  trustScore: number | null;
  salience: number;
  memoryId?: number;
  preservedMemoryId?: number;
}

export interface NativeImportFileResult {
  sourcePath: string;
  archivePath: string | null;
  chunks: number;
  error?: string;
}

export interface NativeImportResult {
  success: boolean;
  applied: boolean;
  dryRun: boolean;
  batchId: string;
  hostId: string;
  agentId: string;
  project: string | null;
  files: NativeImportFileResult[];
  rows: NativeImportRowResult[];
  archived: string[];
  error?: string;
}

export interface NativeImportOptions {
  paths: string[];
  apply?: boolean;
  hostId?: string | null;
  agentId?: string | null;
  project?: string;
  salience?: number;
  batchId?: string;
  archiveRoot?: string;
}

export interface NativeImportDependencies {
  db?: Database.Database;
  assess?: (
    input: MemoryInput,
    source: DefenceSource,
    options: { sourceAttested: false; recordSideEffects: false },
  ) => MemoryAdmissionAssessment;
  admit?: (
    input: MemoryInput,
    config: undefined,
    source: DefenceSource,
    options: { sourceAttested: false },
  ) => Memory;
  batchId?: () => string;
}

interface PreparedFile {
  sourcePath: string;
  archivePath: string;
  sourceHash: string;
  chunks: NativeMarkdownChunk[];
}

interface PreparedRow {
  file: PreparedFile;
  chunk: NativeMarkdownChunk;
  input: MemoryInput;
  source: DefenceSource;
  assessment: MemoryAdmissionAssessment;
  result: NativeImportRowResult;
}

interface ExistingMemoryRow {
  id: number;
  content: string;
  content_hash: string | null;
  trust_score: number | null;
}

function sha256(value: string): string {
  return createHash('sha256').update(value, 'utf-8').digest('hex');
}

function nonEmptyScope(value: string | null | undefined): string | null {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  return trimmed ? trimmed.slice(0, 128) : null;
}

function validateBatchId(value: string): string {
  if (!/^[A-Za-z0-9._-]{1,128}$/.test(value)) {
    throw new Error('batchId must contain only letters, numbers, dot, underscore, or hyphen');
  }
  return value;
}

function splitUtf8(value: string, maxBytes: number): string[] {
  const parts: string[] = [];
  let rest = value;
  while (Buffer.byteLength(rest, 'utf-8') > maxBytes) {
    let low = 1;
    let high = rest.length;
    while (low < high) {
      const mid = Math.floor((low + high + 1) / 2);
      if (Buffer.byteLength(rest.slice(0, mid), 'utf-8') <= maxBytes) low = mid;
      else high = mid - 1;
    }
    let cut = low;
    const paragraph = rest.lastIndexOf('\n\n', low);
    const line = rest.lastIndexOf('\n', low);
    const whitespace = rest.lastIndexOf(' ', low);
    const natural = Math.max(paragraph >= low / 2 ? paragraph + 2 : -1, line >= low / 2 ? line + 1 : -1, whitespace >= low / 2 ? whitespace + 1 : -1);
    if (natural > 0) cut = natural;
    parts.push(rest.slice(0, cut).trim());
    rest = rest.slice(cut).trim();
  }
  if (rest.trim()) parts.push(rest.trim());
  return parts;
}

/** Pure, deterministic Markdown section chunker. It never interprets content. */
export function chunkNativeMarkdown(markdown: string, fallbackTitle: string): NativeMarkdownChunk[] {
  const normalized = markdown.replace(/\r\n?/g, '\n').trim();
  if (!normalized) return [];

  const sections: Array<{ title: string; body: string[] }> = [];
  let current = { title: fallbackTitle, body: [] as string[] };
  for (const line of normalized.split('\n')) {
    const heading = /^(#{1,6})\s+(.+?)\s*$/.exec(line);
    if (heading && current.body.some((part) => part.trim())) {
      sections.push(current);
      current = { title: heading[2].replace(/\s+#+\s*$/, '').trim() || fallbackTitle, body: [line] };
    } else {
      if (heading) current.title = heading[2].replace(/\s+#+\s*$/, '').trim() || fallbackTitle;
      current.body.push(line);
    }
  }
  if (current.body.some((part) => part.trim())) sections.push(current);

  const chunks: NativeMarkdownChunk[] = [];
  for (const section of sections) {
    const pieces = splitUtf8(section.body.join('\n').trim(), MAX_CHUNK_BYTES);
    for (let part = 0; part < pieces.length; part++) {
      const title = pieces.length === 1 ? section.title : `${section.title} (${part + 1}/${pieces.length})`;
      const content = pieces[part];
      chunks.push({ index: chunks.length, title, content, contentHash: sha256(content) });
    }
  }
  return chunks;
}

function defaultArchiveRoot(): string {
  const configDir = process.env.SHIELDCORTEX_CONFIG_DIR
    ? path.resolve(process.env.SHIELDCORTEX_CONFIG_DIR)
    : path.join(os.homedir(), '.shieldcortex');
  return path.join(configDir, 'native-import-archive');
}

function archivePathFor(root: string, batchId: string, sourcePath: string): string {
  return path.join(root, batchId, sha256(sourcePath).slice(0, 16), path.basename(sourcePath));
}

function prepareFiles(options: NativeImportOptions, batchId: string): PreparedFile[] {
  if (!Array.isArray(options.paths) || options.paths.length === 0) {
    throw new Error('at least one Markdown source path is required');
  }
  if (options.paths.length > MAX_NATIVE_FILES) {
    throw new Error(`at most ${MAX_NATIVE_FILES} source files may be imported at once`);
  }

  const archiveRoot = path.resolve(options.archiveRoot ?? defaultArchiveRoot());
  const seen = new Set<string>();
  const prepared: PreparedFile[] = [];
  let totalChunks = 0;
  for (const supplied of options.paths) {
    if (typeof supplied !== 'string' || !supplied.trim()) throw new Error('source paths must be nonempty strings');
    const requested = path.resolve(supplied);
    const requestedStat = fs.lstatSync(requested);
    if (requestedStat.isSymbolicLink()) throw new Error(`symbolic-link sources are not accepted: ${requested}`);
    const sourcePath = fs.realpathSync(requested);
    if (seen.has(sourcePath)) continue;
    seen.add(sourcePath);
    const stat = fs.statSync(sourcePath);
    if (!stat.isFile()) throw new Error(`source is not a regular file: ${sourcePath}`);
    if (!/\.(?:md|markdown)$/i.test(sourcePath)) throw new Error(`source is not Markdown: ${sourcePath}`);
    if (stat.size <= 0) throw new Error(`source is empty: ${sourcePath}`);
    if (stat.size > MAX_NATIVE_FILE_BYTES) {
      throw new Error(`source exceeds ${MAX_NATIVE_FILE_BYTES} bytes: ${sourcePath}`);
    }
    const sourceContent = fs.readFileSync(sourcePath, 'utf-8');
    const chunks = chunkNativeMarkdown(sourceContent, path.basename(sourcePath, path.extname(sourcePath)));
    if (chunks.length === 0) throw new Error(`source has no importable Markdown content: ${sourcePath}`);
    totalChunks += chunks.length;
    if (totalChunks > MAX_NATIVE_CHUNKS) {
      throw new Error(`sources produce more than ${MAX_NATIVE_CHUNKS} chunks; split the import into smaller batches`);
    }
    const archivePath = archivePathFor(archiveRoot, batchId, sourcePath);
    if (fs.existsSync(archivePath)) throw new Error(`archive target already exists: ${archivePath}`);
    prepared.push({ sourcePath, archivePath, sourceHash: sha256(sourceContent), chunks });
  }
  if (prepared.length === 0) throw new Error('no unique Markdown source files remain after validation');
  return prepared;
}

function findExistingDisposition(
  db: Database.Database,
  chunk: NativeMarkdownChunk,
  hostId: string,
  agentId: string,
  project: string | null,
  importTrust: number,
): { disposition: NativeImportDisposition; memoryId: number; reason: string } | null {
  const exact = db.prepare(`
    SELECT id FROM memories
    WHERE content_hash = ?
      AND host_id = ? AND agent_id = ?
      AND ((project IS NULL AND ? IS NULL) OR project = ?)
      AND COALESCE(status, 'active') NOT IN ('archived', 'suppressed')
    ORDER BY trust_score DESC, id ASC LIMIT 1
  `).get(chunk.contentHash, hostId, agentId, project, project) as { id: number } | undefined;
  if (exact) {
    return { disposition: 'exact_duplicate', memoryId: exact.id, reason: 'exact content hash already exists in this scope' };
  }

  const candidates = db.prepare(`
    SELECT id, content, content_hash, trust_score
    FROM memories
    WHERE host_id = ? AND agent_id = ?
      AND ((project IS NULL AND ? IS NULL) OR project = ?)
      AND COALESCE(status, 'active') NOT IN ('archived', 'suppressed')
    ORDER BY trust_score DESC, id ASC
    LIMIT 256
  `).all(hostId, agentId, project, project) as ExistingMemoryRow[];

  let best: { row: ExistingMemoryRow; similarity: number } | null = null;
  for (const row of candidates) {
    const similarity = jaccardSimilarity(chunk.content, row.content);
    if (similarity >= NEAR_DUPLICATE_THRESHOLD && (!best || similarity > best.similarity)) {
      best = { row, similarity };
    }
  }
  if (!best) return null;
  if (Number(best.row.trust_score ?? 0) > importTrust) {
    return {
      disposition: 'higher_trust_preserved',
      memoryId: best.row.id,
      reason: `near duplicate of higher-trust ShieldCortex memory #${best.row.id}; existing row preserved`,
    };
  }
  return {
    disposition: 'near_duplicate_preserved',
    memoryId: best.row.id,
    reason: `near duplicate of ShieldCortex memory #${best.row.id}; existing row preserved`,
  };
}

function archiveSources(files: PreparedFile[]): string[] {
  const moved: Array<{ from: string; to: string }> = [];
  try {
    for (const file of files) {
      fs.mkdirSync(path.dirname(file.archivePath), { recursive: true, mode: 0o700 });
      fs.renameSync(file.sourcePath, file.archivePath);
      moved.push({ from: file.sourcePath, to: file.archivePath });
    }
    return moved.map((item) => item.to);
  } catch (error) {
    for (const item of [...moved].reverse()) {
      try {
        fs.renameSync(item.to, item.from);
      } catch {
        // The result remains failed and names every successfully moved path.
      }
    }
    throw error;
  }
}

function deleteMemoriesById(db: Database.Database, ids: number[]): void {
  const stmt = db.prepare('DELETE FROM memories WHERE id = ?');
  for (const id of ids) {
    try {
      stmt.run(id);
    } catch {
      // Best-effort rollback; the caller still reports failure.
    }
  }
}

function assertSourcesUnchanged(files: PreparedFile[]): void {
  for (const file of files) {
    if (!fs.statSync(file.sourcePath).isFile()) {
      throw new Error(`source is no longer a regular file: ${file.sourcePath}`);
    }
    const currentHash = sha256(fs.readFileSync(file.sourcePath, 'utf-8'));
    if (currentHash !== file.sourceHash) {
      throw new Error(`source changed during import: ${file.sourcePath}`);
    }
  }
}

function dispositionForAssessment(assessment: MemoryAdmissionAssessment): NativeImportDisposition {
  if (assessment.result.firewall.threatIndicators.includes('pipeline_error')) return 'failed';
  if (assessment.disposition.action === 'store') return 'would_admit';
  return assessment.disposition.firewallResult === 'BLOCK' ? 'blocked' : 'quarantined';
}

function resultFromError(
  options: NativeImportOptions,
  batchId: string,
  hostId: string,
  agentId: string,
  error: unknown,
  invalidSources = false,
): NativeImportResult {
  const reason = error instanceof Error ? error.message : String(error);
  const sourcePaths = invalidSources && Array.isArray(options.paths)
    ? options.paths.filter((item): item is string => typeof item === 'string').map((item) => path.resolve(item))
    : [];
  const salience = Math.max(0, Math.min(
    Number.isFinite(options.salience) ? Number(options.salience) : 0.5,
    NATIVE_IMPORT_SALIENCE_CEILING,
  ));
  return {
    success: false,
    applied: false,
    dryRun: options.apply !== true,
    batchId,
    hostId,
    agentId,
    project: nonEmptyScope(options.project),
    files: sourcePaths.map((sourcePath) => ({ sourcePath, archivePath: null, chunks: 0, error: reason })),
    rows: sourcePaths.map((sourcePath) => ({
      sourcePath,
      chunkIndex: -1,
      title: path.basename(sourcePath),
      contentHash: '',
      disposition: 'invalid',
      defenceVerdict: null,
      reason,
      trustScore: null,
      salience,
    })),
    archived: [],
    error: reason,
  };
}

/**
 * Import native Markdown exactly once. Dry-run is the default. Every chunk is
 * first assessed through the full addMemory decision seam without side effects;
 * apply then admits only through addMemory, never by direct SQL.
 */
export function importNativeMemories(
  options: NativeImportOptions,
  dependencies: NativeImportDependencies = {},
): NativeImportResult {
  const batchId = validateBatchId(options.batchId ?? dependencies.batchId?.() ?? randomUUID());
  const hostId = nonEmptyScope(options.hostId);
  const agentId = nonEmptyScope(options.agentId);
  if (!hostId || !agentId) {
    return resultFromError(options, batchId, hostId ?? '', agentId ?? '', 'native import requires explicit nonempty hostId and agentId');
  }
  const project = nonEmptyScope(options.project);
  const requestedSalience = Number.isFinite(options.salience) ? Number(options.salience) : 0.5;
  const salience = Math.max(0, Math.min(requestedSalience, NATIVE_IMPORT_SALIENCE_CEILING));
  const db = dependencies.db ?? getDatabase();
  const assess = dependencies.assess ?? assessMemoryAdmission;
  const admit = dependencies.admit ?? addMemory;

  let files: PreparedFile[];
  try {
    files = prepareFiles(options, batchId);
  } catch (error) {
    return resultFromError(options, batchId, hostId, agentId, error, true);
  }

  const fileResults: NativeImportFileResult[] = files.map((file) => ({
    sourcePath: file.sourcePath,
    archivePath: null,
    chunks: file.chunks.length,
  }));
  const preparedRows: PreparedRow[] = [];
  const batchByHash = new Map<string, PreparedRow>();
  const batchAdmissible: PreparedRow[] = [];

  for (const [fileIndex, file] of files.entries()) {
    for (const chunk of file.chunks) {
      const source: DefenceSource = {
        type: 'file',
        identifier: `native-import:${batchId}:${fileIndex}:${chunk.index}`,
      };
      const input: MemoryInput = {
        title: chunk.title,
        content: chunk.content,
        type: 'long_term',
        category: 'note',
        project: project ?? undefined,
        tags: ['native-import'],
        salience,
        sourceKind: 'native_import',
        captureMethod: 'native_import',
        hostId,
        agentId,
        captureLayer: 'native_import',
        metadata: {
          source_kind: 'native_import',
          origin_host: hostId,
          origin_path: file.sourcePath,
          archive_path: file.archivePath,
          batch_id: batchId,
          content_hash: chunk.contentHash,
          origin_file_hash: file.sourceHash,
          capture_method: 'native_import',
          project,
        },
      };

      let assessment: MemoryAdmissionAssessment;
      try {
        assessment = assess(input, source, { sourceAttested: false, recordSideEffects: false });
      } catch (error) {
        const row: NativeImportRowResult = {
          sourcePath: file.sourcePath,
          chunkIndex: chunk.index,
          title: chunk.title,
          contentHash: chunk.contentHash,
          disposition: 'failed',
          defenceVerdict: 'ERROR',
          reason: `defence pipeline unavailable: ${error instanceof Error ? error.message : String(error)}`,
          trustScore: null,
          salience,
        };
        return {
          success: false,
          applied: false,
          dryRun: options.apply !== true,
          batchId,
          hostId,
          agentId,
          project,
          files: fileResults,
          rows: [...preparedRows.map((item) => item.result), row],
          archived: [],
          error: row.reason,
        };
      }

      const trustScore = Math.min(
        assessment.disposition.trustClamp ?? assessment.result.trust.score,
        NATIVE_IMPORT_TRUST_CEILING,
      );
      let disposition = dispositionForAssessment(assessment);
      let reason = assessment.disposition.reason;
      let preservedMemoryId: number | undefined;
      if (disposition === 'would_admit') {
        const sameBatch = batchByHash.get(chunk.contentHash);
        if (sameBatch) {
          disposition = 'exact_duplicate';
          reason = `exact duplicate of chunk ${sameBatch.chunk.index} from ${sameBatch.file.sourcePath} in this batch`;
        } else {
          const nearBatch = batchAdmissible.find((candidate) =>
            jaccardSimilarity(chunk.content, candidate.chunk.content) >= NEAR_DUPLICATE_THRESHOLD
          );
          if (nearBatch) {
            disposition = 'near_duplicate_preserved';
            reason = `near duplicate of chunk ${nearBatch.chunk.index} from ${nearBatch.file.sourcePath} in this batch`;
          } else {
            const existing = findExistingDisposition(db, chunk, hostId, agentId, project, trustScore);
            if (existing) {
              disposition = existing.disposition;
              reason = existing.reason;
              preservedMemoryId = existing.memoryId;
            }
          }
        }
      }
      const result: NativeImportRowResult = {
        sourcePath: file.sourcePath,
        chunkIndex: chunk.index,
        title: chunk.title,
        contentHash: chunk.contentHash,
        disposition,
        defenceVerdict: assessment.result.firewall.threatIndicators.includes('pipeline_error')
          ? 'ERROR'
          : assessment.result.firewall.result,
        reason,
        trustScore,
        salience,
        ...(preservedMemoryId === undefined ? {} : { preservedMemoryId }),
      };
      const prepared = { file, chunk, input, source, assessment, result };
      preparedRows.push(prepared);
      if (disposition === 'would_admit') {
        batchByHash.set(chunk.contentHash, prepared);
        batchAdmissible.push(prepared);
      }
    }
  }

  const denied = preparedRows.filter((row) => ['blocked', 'quarantined', 'failed', 'invalid'].includes(row.result.disposition));
  if (options.apply !== true) {
    return {
      success: denied.length === 0,
      applied: false,
      dryRun: true,
      batchId,
      hostId,
      agentId,
      project,
      files: fileResults,
      rows: preparedRows.map((item) => item.result),
      archived: [],
      ...(denied.length > 0 ? { error: 'one or more chunks cannot be admitted safely' } : {}),
    };
  }

  try {
    assertSourcesUnchanged(files);
  } catch (error) {
    return {
      success: false,
      applied: false,
      dryRun: false,
      batchId,
      hostId,
      agentId,
      project,
      files: fileResults,
      rows: preparedRows.map((item) => item.result),
      archived: [],
      error: error instanceof Error ? error.message : String(error),
    };
  }

  // Persist real quarantine semantics for denied chunks, but admit no clean row
  // from a batch that failed preflight. This keeps pipeline-down/poison imports
  // fail-closed with zero durable memories and leaves every source unarchived.
  if (denied.length > 0) {
    for (const row of denied) {
      if (row.result.disposition === 'failed' || row.result.disposition === 'invalid') continue;
      const before = (db.prepare(
        'SELECT COUNT(*) AS count FROM quarantine WHERE source_type = ? AND source_identifier = ?',
      ).get(row.source.type, row.source.identifier) as { count: number }).count;
      try {
        const unexpected = admit(row.input, undefined, row.source, { sourceAttested: false });
        deleteMemoriesById(db, [unexpected.id]);
        row.result.disposition = 'failed';
        row.result.reason = 'preflight denial unexpectedly admitted during apply; rolled back; source not archived';
        delete row.result.memoryId;
      } catch (error) {
        const after = (db.prepare(
          'SELECT COUNT(*) AS count FROM quarantine WHERE source_type = ? AND source_identifier = ?',
        ).get(row.source.type, row.source.identifier) as { count: number }).count;
        if (after <= before) {
          row.result.disposition = 'failed';
          row.result.reason = `denial could not be persisted: ${error instanceof Error ? error.message : String(error)}`;
        }
      }
    }
    return {
      success: false,
      applied: false,
      dryRun: false,
      batchId,
      hostId,
      agentId,
      project,
      files: fileResults,
      rows: preparedRows.map((item) => item.result),
      archived: [],
      error: 'one or more chunks were blocked, quarantined, or failed; no admissible chunks were written',
    };
  }

  const admittedIds: number[] = [];
  for (const row of preparedRows) {
    if (row.result.disposition !== 'would_admit') continue;
    try {
      const memory = admit(row.input, undefined, row.source, { sourceAttested: false });
      admittedIds.push(memory.id);
      row.result.disposition = 'admitted';
      row.result.memoryId = memory.id;
      row.result.defenceVerdict = 'ALLOW';
      row.result.trustScore = Math.min(memory.trustScore, NATIVE_IMPORT_TRUST_CEILING);
      row.result.salience = Math.min(memory.salience, NATIVE_IMPORT_SALIENCE_CEILING);
    } catch (error) {
      deleteMemoriesById(db, admittedIds);
      for (const previous of preparedRows) {
        if (previous.result.disposition === 'admitted') {
          previous.result.disposition = 'failed';
          previous.result.reason = 'batch rolled back after a later admission failure';
          delete previous.result.memoryId;
        }
      }
      row.result.disposition = 'failed';
      row.result.reason = error instanceof Error ? error.message : String(error);
      return {
        success: false,
        applied: false,
        dryRun: false,
        batchId,
        hostId,
        agentId,
        project,
        files: fileResults,
        rows: preparedRows.map((item) => item.result),
        archived: [],
        error: `admission failed; source not archived: ${row.result.reason}`,
      };
    }
  }

  try {
    assertSourcesUnchanged(files);
    const archived = archiveSources(files);
    for (let i = 0; i < files.length; i++) fileResults[i].archivePath = files[i].archivePath;
    return {
      success: true,
      applied: true,
      dryRun: false,
      batchId,
      hostId,
      agentId,
      project,
      files: fileResults,
      rows: preparedRows.map((item) => item.result),
      archived,
    };
  } catch (error) {
    deleteMemoriesById(db, admittedIds);
    for (const previous of preparedRows) {
      if (previous.result.disposition === 'admitted') {
        previous.result.disposition = 'failed';
        previous.result.reason = 'batch rolled back after source archive failed';
        delete previous.result.memoryId;
      }
    }
    return {
      success: false,
      applied: false,
      dryRun: false,
      batchId,
      hostId,
      agentId,
      project,
      files: fileResults,
      rows: preparedRows.map((item) => item.result),
      archived: [],
      error: `source archive failed; admitted rows rolled back: ${error instanceof Error ? error.message : String(error)}`,
    };
  }
}

export function resolveConfiguredNativeImportScope(): { hostId: string | null; agentId: string | null } {
  let hostId = nonEmptyScope(process.env.SHIELDCORTEX_HOST_ID);
  let agentId = nonEmptyScope(process.env.SHIELDCORTEX_AGENT_ID);
  try {
    const configDir = process.env.SHIELDCORTEX_CONFIG_DIR
      ? path.resolve(process.env.SHIELDCORTEX_CONFIG_DIR)
      : path.join(os.homedir(), '.shieldcortex');
    const raw = JSON.parse(fs.readFileSync(path.join(configDir, 'config.json'), 'utf-8')) as Record<string, unknown>;
    const memory = raw.memory && typeof raw.memory === 'object' ? raw.memory as Record<string, unknown> : {};
    const inject = memory.inject && typeof memory.inject === 'object' ? memory.inject as Record<string, unknown> : {};
    hostId ??= nonEmptyScope(inject.hostId as string | undefined)
      ?? nonEmptyScope(memory.hostId as string | undefined)
      ?? nonEmptyScope(raw.hostId as string | undefined);
    agentId ??= nonEmptyScope(inject.agentId as string | undefined)
      ?? nonEmptyScope(memory.agentId as string | undefined)
      ?? nonEmptyScope(raw.agentId as string | undefined);
  } catch {
    // Missing/unreadable config does not create a synthetic global scope.
  }
  return { hostId, agentId };
}
