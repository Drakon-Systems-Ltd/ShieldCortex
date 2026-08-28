import fs from 'fs';
import os from 'os';
import path from 'path';
import { createHash, randomUUID } from 'crypto';
import type Database from 'better-sqlite3';
import type { DefenceSource } from '../defence/types.js';
import type { DispositionKind } from '../defence/disposition.js';
import type { MemoryInput } from './types.js';
import {
  createNativeImportAdmissionSession,
  MemoryClusterAssemblyError,
  type MemoryAdmissionAssessment,
  type NativeImportAdmissionSession,
  type NativeImportAssemblyFragment,
} from './store.js';
import { getDatabase } from '../database/init.js';
import { jaccardSets, tokenize } from './similarity.js';

const MAX_NATIVE_FILE_BYTES = 2 * 1024 * 1024;
const MAX_NATIVE_FILES = 128;
const MAX_NATIVE_CHUNKS = 512;
const MAX_CHUNK_BYTES = 8 * 1024;
const NEAR_DUPLICATE_THRESHOLD = 0.9;
const NATIVE_IMPORT_TRUST_CEILING = 0.7;
const NATIVE_IMPORT_SALIENCE_CEILING = 0.7;

/**
 * Hard bound on the same-scope higher-trust rows the near-duplicate scan may
 * materialise for one batch.
 *
 * The scan runs inside the apply transaction's `BEGIN IMMEDIATE`, so its cost
 * is exclusive-write-lock time for the whole process. The set is loaded ONCE
 * per batch/scope and reused for every chunk; above this bound the importer
 * refuses the batch (`cannot determine near-duplicate set`) rather than
 * silently truncating the comparison — a truncated scan would let a genuinely
 * higher-trust row be overwritten by a thin import. Set materially above the
 * old silent 256 cap so ordinary stores never see it.
 */
export const MAX_NEAR_DUPLICATE_CANDIDATES = 10_000;

export type NativeImportDisposition =
  | 'would_admit'
  | 'admitted'
  | 'blocked'
  | 'quarantined'
  | 'exact_duplicate'
  | 'higher_trust_preserved'
  | 'invalid'
  | 'failed';

export type NativeImportFileDisposition = 'valid' | 'invalid' | 'unprocessed' | 'archived' | 'residual_archived';

export interface NativeMarkdownChunk {
  index: number;
  title: string;
  content: string;
  contentHash: string;
}

export interface NativeImportRowResult {
  sourcePath: string;
  sourceKey: string;
  chunkIndex: number;
  title: string;
  contentHash: string;
  disposition: NativeImportDisposition;
  admissionKind: DispositionKind | null;
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
  disposition: NativeImportFileDisposition;
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
  /**
   * Dry-run only. `false` means `--apply` provably cannot archive from here
   * (the archive is a hard link, so source and archive root must share one
   * filesystem). `true` is NOT a prediction that apply will succeed — apply
   * re-runs the full defence pipeline with side effects and can still deny or
   * fail to archive.
   */
  applyPossible?: boolean;
  applyBlockedReason?: string;
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

/** Internal test seams. This type is deliberately not exported from src/lib.ts. */
export interface NativeImportDependencies {
  db?: Database.Database;
  sessionFactory?: (batchId: string) => NativeImportAdmissionSession;
  batchId?: () => string;
  beforeArchive?: (files: ReadonlyArray<{ sourcePath: string; archivePath: string }>) => void;
  linkSource?: (sourcePath: string, archivePath: string) => void;
  restoreLinkSource?: (archivePath: string, sourcePath: string) => void;
  /** Source `unlink(2)`; injected to fail AFTER the archive inode was hardened. */
  unlinkSource?: (sourcePath: string) => void;
  /** `chmod(2)` for both the 0600 hardening and the rollback restoration. */
  chmodFile?: (target: string, mode: number) => void;
}

interface PreparedFile {
  sourcePath: string;
  archivePath: string;
  sourceHash: string;
  sourceSize: number;
  dev: number;
  ino: number;
  /** Original permission bits, restored if a rollback puts the source back. */
  mode: number;
  fd: number;
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
  trust_score: number | null;
}

/** A same-scope higher-trust row, tokenised once for the whole batch. */
interface NearDuplicateCandidate {
  id: number;
  trust: number;
  tokens: Set<string>;
}

interface MovedSource {
  from: string;
  to: string;
  mode: number;
}

/**
 * An archive hard link that compensation deliberately did NOT remove.
 *
 * The archive `chmod(0600)` lands on the SHARED inode, so it tightens the
 * source too. When the original mode cannot be restored, deleting the archive
 * link would destroy the only evidence that the tightening happened — the
 * envelope would then report a clean rollback over a durably modified file.
 * The link is retained instead and surfaced here, so `archived`, the file
 * disposition and the error text all describe the same disk.
 */
interface ArchiveResidual {
  archivePath: string;
  /** True when the original source path is back on disk despite the residual. */
  sourcePresent: boolean;
  reason: string;
}

/**
 * A filesystem compensation that could not be completed truthfully. Carries the
 * archive links deliberately retained as residual evidence, so the caller can
 * report them instead of claiming a clean rollback.
 */
class NativeImportCompensationError extends Error {
  readonly residuals: readonly ArchiveResidual[];

  constructor(message: string, residuals: ArchiveResidual[]) {
    super(message);
    this.name = 'NativeImportCompensationError';
    this.residuals = residuals;
  }
}

/**
 * A failure that belongs to the batch as a whole, not to whichever file
 * happened to cross the line. Thrown out of per-file validation so a total
 * chunk-budget breach is never reported as "notes.md is invalid".
 */
class NativeImportBatchError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'NativeImportBatchError';
  }
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
    const natural = Math.max(
      paragraph >= low / 2 ? paragraph + 2 : -1,
      line >= low / 2 ? line + 1 : -1,
      whitespace >= low / 2 ? whitespace + 1 : -1,
    );
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

function directoryComponents(target: string): string[] {
  const resolved = path.resolve(target);
  const parsed = path.parse(resolved);
  const relative = resolved.slice(parsed.root.length).split(path.sep).filter(Boolean);
  const components = [parsed.root];
  let current = parsed.root;
  for (const part of relative) {
    current = path.join(current, part);
    components.push(current);
  }
  return components;
}

function ensureNoSymlinkDirectoryChain(target: string, create: boolean): void {
  for (const component of directoryComponents(target)) {
    if (!fs.existsSync(component)) {
      if (!create) continue;
      fs.mkdirSync(component, { mode: 0o700 });
    }
    const stat = fs.lstatSync(component);
    if (stat.isSymbolicLink() || !stat.isDirectory()) {
      throw new Error(`archive path traverses a symlink or non-directory: ${component}`);
    }
  }
}

function readFdContent(fd: number, size: number): string {
  const buffer = Buffer.alloc(size);
  let offset = 0;
  while (offset < size) {
    const count = fs.readSync(fd, buffer, offset, size - offset, offset);
    if (count === 0) break;
    offset += count;
  }
  if (offset !== size) throw new Error('source changed size while being read');
  return buffer.toString('utf-8');
}

function invalidRow(sourcePath: string, reason: string, salience: number): NativeImportRowResult {
  return {
    sourcePath,
    sourceKey: '',
    chunkIndex: -1,
    title: path.basename(sourcePath),
    contentHash: '',
    disposition: 'invalid',
    admissionKind: null,
    defenceVerdict: null,
    reason,
    trustScore: null,
    salience,
  };
}

function prepareFiles(
  options: NativeImportOptions,
  batchId: string,
  salience: number,
): { files: PreparedFile[]; fileResults: NativeImportFileResult[]; invalidRows: NativeImportRowResult[] } {
  if (!Array.isArray(options.paths) || options.paths.length === 0) {
    throw new Error('at least one Markdown source path is required');
  }
  if (options.paths.length > MAX_NATIVE_FILES) {
    throw new Error(`at most ${MAX_NATIVE_FILES} source files may be imported at once`);
  }

  const archiveRoot = path.resolve(options.archiveRoot ?? defaultArchiveRoot());
  ensureNoSymlinkDirectoryChain(archiveRoot, false);
  const seen = new Set<string>();
  const files: PreparedFile[] = [];
  const fileResults: NativeImportFileResult[] = [];
  const invalidRows: NativeImportRowResult[] = [];
  let totalChunks = 0;

  try {
    for (const supplied of options.paths) {
      const requested = path.resolve(typeof supplied === 'string' ? supplied : String(supplied));
      let fd: number | null = null;
      try {
        if (typeof supplied !== 'string' || !supplied.trim()) throw new Error('source paths must be nonempty strings');
        if (!/\.(?:md|markdown)$/i.test(requested)) throw new Error(`source is not Markdown: ${requested}`);
        const leaf = fs.lstatSync(requested);
        if (leaf.isSymbolicLink()) throw new Error(`symbolic-link sources are not accepted: ${requested}`);
        const noFollow = typeof fs.constants.O_NOFOLLOW === 'number' ? fs.constants.O_NOFOLLOW : 0;
        fd = fs.openSync(requested, fs.constants.O_RDONLY | noFollow);
        const held = fs.fstatSync(fd);
        if (!held.isFile()) throw new Error(`source is not a regular file: ${requested}`);
        if (held.size <= 0) throw new Error(`source is empty: ${requested}`);
        if (held.size > MAX_NATIVE_FILE_BYTES) throw new Error(`source exceeds ${MAX_NATIVE_FILE_BYTES} bytes: ${requested}`);
        const sourcePath = fs.realpathSync(requested);
        const current = fs.lstatSync(sourcePath);
        if (!current.isFile() || current.dev !== held.dev || current.ino !== held.ino) {
          throw new Error(`source identity changed while opening: ${requested}`);
        }
        if (seen.has(sourcePath)) {
          fs.closeSync(fd);
          fd = null;
          continue;
        }
        seen.add(sourcePath);
        const sourceContent = readFdContent(fd, held.size);
        const afterRead = fs.fstatSync(fd);
        if (afterRead.dev !== held.dev || afterRead.ino !== held.ino || afterRead.size !== held.size) {
          throw new Error(`source changed while being read: ${sourcePath}`);
        }
        const chunks = chunkNativeMarkdown(sourceContent, path.basename(sourcePath, path.extname(sourcePath)));
        if (chunks.length === 0) throw new Error(`source has no importable Markdown content: ${sourcePath}`);
        totalChunks += chunks.length;
        if (totalChunks > MAX_NATIVE_CHUNKS) {
          // Batch-level: the budget is shared, so no single file is "invalid".
          throw new NativeImportBatchError(
            `sources produce more than ${MAX_NATIVE_CHUNKS} chunks in total; split the import into smaller batches`,
          );
        }
        const archivePath = archivePathFor(archiveRoot, batchId, sourcePath);
        ensureNoSymlinkDirectoryChain(path.dirname(archivePath), false);
        if (fs.existsSync(archivePath)) throw new Error(`archive target already exists: ${archivePath}`);
        files.push({
          sourcePath,
          archivePath,
          sourceHash: sha256(sourceContent),
          sourceSize: held.size,
          dev: held.dev,
          ino: held.ino,
          mode: held.mode & 0o7777,
          fd,
          chunks,
        });
        fd = null;
        fileResults.push({ sourcePath, archivePath: null, chunks: chunks.length, disposition: 'valid' });
      } catch (error) {
        if (fd !== null) {
          try { fs.closeSync(fd); } catch { /* best effort */ }
        }
        if (error instanceof NativeImportBatchError) throw error;
        const reason = error instanceof Error ? error.message : String(error);
        fileResults.push({ sourcePath: requested, archivePath: null, chunks: 0, disposition: 'invalid', error: reason });
        invalidRows.push(invalidRow(requested, reason, salience));
      }
    }
  } catch (error) {
    // A batch-level abort leaves held descriptors behind; the caller never sees
    // `files`, so close them here rather than leaking one fd per prepared file.
    closePreparedFiles(files);
    throw error;
  }
  if (files.length === 0 && invalidRows.length === 0) throw new Error('no unique Markdown source files remain after validation');
  return { files, fileResults, invalidRows };
}

/** Deepest existing ancestor of `target` (the target itself if it exists). */
function nearestExistingAncestor(target: string): string | null {
  const components = directoryComponents(target);
  for (let index = components.length - 1; index >= 0; index--) {
    if (fs.existsSync(components[index])) return components[index];
  }
  return null;
}

/**
 * Archival is `link(2)` + `unlink(2)`, which cannot cross a filesystem
 * boundary. Comparing the source device with the nearest existing archive-root
 * ancestor is a read-only check, so dry-run can say "apply is impossible here"
 * instead of implying it would work. It is deliberately NOT used to pre-empt
 * apply: the real `link` call remains the decider, and it fails closed.
 */
function crossDeviceArchiveReason(files: PreparedFile[], archiveRoot: string): string | null {
  const anchor = nearestExistingAncestor(archiveRoot);
  if (!anchor) return null;
  let archiveDev: number;
  try {
    archiveDev = fs.statSync(anchor).dev;
  } catch {
    return null;
  }
  const crossed = files.filter((file) => file.dev !== archiveDev);
  if (crossed.length === 0) return null;
  return `apply cannot archive from here: ${crossed[0].sourcePath} and the archive root ${archiveRoot} `
    + 'are on different filesystems, and the archive is a hard link (EXDEV). '
    + 'Use an archive root on the sources\' filesystem (SHIELDCORTEX_CONFIG_DIR selects the default root).';
}

function closePreparedFiles(files: PreparedFile[]): void {
  for (const file of files) {
    try { fs.closeSync(file.fd); } catch { /* already closed / best effort */ }
  }
}

function revalidateSource(file: PreparedFile): void {
  const held = fs.fstatSync(file.fd);
  const leaf = fs.lstatSync(file.sourcePath);
  if (
    !held.isFile()
    || !leaf.isFile()
    || leaf.isSymbolicLink()
    || held.dev !== file.dev
    || held.ino !== file.ino
    || held.size !== file.sourceSize
    || leaf.dev !== file.dev
    || leaf.ino !== file.ino
  ) {
    throw new Error(`source identity changed during import: ${file.sourcePath}`);
  }
  const currentHash = sha256(readFdContent(file.fd, file.sourceSize));
  if (currentHash !== file.sourceHash) throw new Error(`source changed during import: ${file.sourcePath}`);
}

function assertSourcesUnchanged(files: PreparedFile[]): void {
  for (const file of files) revalidateSource(file);
}

function archiveSources(
  files: PreparedFile[],
  moved: MovedSource[],
  linkSource: (sourcePath: string, archivePath: string) => void = fs.linkSync,
  unlinkSource: (sourcePath: string) => void = fs.unlinkSync,
  chmodFile: (target: string, mode: number) => void = fs.chmodSync,
): void {
  for (const file of files) {
    revalidateSource(file);
    ensureNoSymlinkDirectoryChain(path.dirname(file.archivePath), true);
    if (fs.existsSync(file.archivePath)) throw new Error(`archive target already exists: ${file.archivePath}`);
    linkSource(file.sourcePath, file.archivePath);
    // The 0600 hardening is applied to the archive PATH but lands on the inode
    // the source still shares. Everything after it can throw, so track it.
    let hardenedSharedInode = false;
    try {
      const archived = fs.lstatSync(file.archivePath);
      if (!archived.isFile() || archived.dev !== file.dev || archived.ino !== file.ino) {
        throw new Error(`archive target identity mismatch: ${file.archivePath}`);
      }
      chmodFile(file.archivePath, 0o600);
      hardenedSharedInode = true;
      const sourceBeforeUnlink = fs.lstatSync(file.sourcePath);
      if (
        !sourceBeforeUnlink.isFile()
        || sourceBeforeUnlink.isSymbolicLink()
        || sourceBeforeUnlink.dev !== file.dev
        || sourceBeforeUnlink.ino !== file.ino
      ) {
        throw new Error(`source identity changed before archive unlink: ${file.sourcePath}`);
      }
      unlinkSource(file.sourcePath);
      moved.push({ from: file.sourcePath, to: file.archivePath, mode: file.mode });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      // Identity validation or the source unlink failed AFTER the shared inode
      // was tightened, so that inode is still on disk wearing 0600. Restoring
      // through `file.sourcePath` would be unsound: that pathname is precisely
      // what the pre-unlink check may have just found to be a REPLACEMENT, so
      // the chmod would re-mode an unrelated file and leave the real hardened
      // inode at 0600 under its new name. The archive link is a second name
      // for the inode that was hardened — verify it still resolves to that
      // identity and restore through it. The link is dropped only AFTER
      // restoration succeeds: it is the only compensating evidence if
      // restoration itself fails.
      if (hardenedSharedInode) {
        try {
          const hardened = fs.lstatSync(file.archivePath);
          if (!hardened.isFile() || hardened.dev !== file.dev || hardened.ino !== file.ino) {
            throw new Error(`archive link no longer identifies the hardened inode: ${file.archivePath}`);
          }
          chmodFile(file.archivePath, file.mode);
        } catch (restoreError) {
          const detail = restoreError instanceof Error ? restoreError.message : String(restoreError);
          throw new NativeImportCompensationError(
            `${message}; the archive hardened the source inode of ${file.sourcePath} to 0600 and its `
            + `original mode 0${file.mode.toString(8)} could not be restored through the archive link `
            + `(${detail}), so the archive link was retained as residual evidence`,
            [{
              archivePath: file.archivePath,
              sourcePresent: fs.existsSync(file.sourcePath),
              reason: `source mode restoration failed: ${detail}`,
            }],
          );
        }
      }
      // Dropping the temporary link can fail too. Rethrowing the original
      // error here would let the envelope report `archived: []` while an extra
      // hard link to the source inode survives on disk, so the survivor is
      // reported as a structured residual instead of silently forgotten.
      try {
        fs.unlinkSync(file.archivePath);
      } catch (cleanupError) {
        const detail = cleanupError instanceof Error ? cleanupError.message : String(cleanupError);
        if (fs.existsSync(file.archivePath)) {
          const restored = hardenedSharedInode
            ? `the source's original mode 0${file.mode.toString(8)} was restored through the archive link, but `
            : '';
          throw new NativeImportCompensationError(
            `${message}; ${restored}the temporary archive ${file.archivePath} could not be removed `
            + `(${detail}) and survives as an extra hard link to the source inode`,
            [{
              archivePath: file.archivePath,
              sourcePresent: fs.existsSync(file.sourcePath),
              reason: `temporary archive cleanup failed: ${detail}`,
            }],
          );
        }
      }
      throw error;
    }
  }
}

function restoreMovedSources(
  moved: MovedSource[],
  restoreLinkSource: (archivePath: string, sourcePath: string) => void = fs.linkSync,
  chmodFile: (target: string, mode: number) => void = fs.chmodSync,
): ArchiveResidual[] {
  const residual: ArchiveResidual[] = [];
  for (const item of [...moved].reverse()) {
    try {
      if (fs.existsSync(item.from)) throw new Error(`source path is occupied: ${item.from}`);
      restoreLinkSource(item.to, item.from);
      // The archive hardened the SHARED inode to 0600, so a source restored in
      // place would keep that tightening as an uncompensated durable effect of
      // an operation the envelope reports as fully rolled back. Put the original
      // mode back BEFORE unlinking the archive: the archive link is the only
      // compensating evidence, and deleting it first would mean discovering the
      // chmod failure with nothing left to report.
      chmodFile(item.from, item.mode);
      fs.unlinkSync(item.to);
    } catch (error) {
      if (fs.existsSync(item.to)) {
        residual.push({
          archivePath: item.to,
          sourcePresent: fs.existsSync(item.from),
          reason: error instanceof Error ? error.message : String(error),
        });
      }
    }
  }
  return residual.reverse();
}

function describeResiduals(residuals: readonly ArchiveResidual[]): string {
  return residuals
    .map((entry) => `${entry.archivePath} (${entry.reason}; original source path `
      + `${entry.sourcePresent ? 'present' : 'absent'})`)
    .join(', ');
}

/** Indexed point lookup; scoped to host/agent/project and non-suppressed rows. */
function findExactScopedDuplicate(
  db: Database.Database,
  chunk: NativeMarkdownChunk,
  hostId: string,
  agentId: string,
  project: string | null,
): number | null {
  const exact = db.prepare(`
    SELECT id FROM memories
    WHERE content_hash = ? AND host_id = ? AND agent_id = ?
      AND ((project IS NULL AND ? IS NULL) OR project = ?)
      AND COALESCE(status, 'active') NOT IN ('archived', 'suppressed')
    ORDER BY trust_score DESC, id ASC LIMIT 1
  `).get(chunk.contentHash, hostId, agentId, project, project) as { id: number } | undefined;
  return exact ? exact.id : null;
}

/**
 * The batch's near-duplicate comparison set: same scope, active, and strictly
 * higher trust than the thinnest row this batch could admit. Loaded ONCE per
 * batch — a per-chunk `.all()` inside `BEGIN IMMEDIATE` held the exclusive
 * write lock for minutes on a large store. Tokenised here so each candidate is
 * tokenised once instead of once per chunk.
 *
 * Bounded by a COUNT of at most `MAX_NEAR_DUPLICATE_CANDIDATES + 1` followed by
 * one bounded fetch. Over the bound this throws — the batch cannot prove it is
 * not overwriting a higher-trust row, so it refuses rather than truncating.
 */
function loadNearDuplicateCandidates(
  db: Database.Database,
  hostId: string,
  agentId: string,
  project: string | null,
  minImportTrust: number,
): NearDuplicateCandidate[] {
  const scopeFilter = `
      WHERE host_id = ? AND agent_id = ?
        AND ((project IS NULL AND ? IS NULL) OR project = ?)
        AND COALESCE(status, 'active') NOT IN ('archived', 'suppressed')
        AND COALESCE(trust_score, 0) > ?`;
  const bounded = db.prepare(`
    /* near-duplicate-candidates: bounded count */
    SELECT COUNT(*) AS count FROM (
      SELECT 1 FROM memories${scopeFilter}
      LIMIT ?
    )
  `).get(
    hostId, agentId, project, project, minImportTrust, MAX_NEAR_DUPLICATE_CANDIDATES + 1,
  ) as { count: number };
  if (bounded.count > MAX_NEAR_DUPLICATE_CANDIDATES) {
    throw new Error(
      `cannot determine near-duplicate set: more than ${MAX_NEAR_DUPLICATE_CANDIDATES} higher-trust active `
      + 'memories share this host/agent/project scope; narrow the scope or import in smaller scopes',
    );
  }
  const rows = db.prepare(`
    /* near-duplicate-candidates: bounded fetch */
    SELECT id, content, trust_score FROM memories${scopeFilter}
    ORDER BY trust_score DESC, id ASC
    LIMIT ?
  `).all(
    hostId, agentId, project, project, minImportTrust, MAX_NEAR_DUPLICATE_CANDIDATES,
  ) as ExistingMemoryRow[];
  return rows.map((row) => ({
    id: row.id,
    trust: row.trust_score ?? 0,
    tokens: tokenize(row.content),
  }));
}

function findNearDuplicate(
  candidates: NearDuplicateCandidate[],
  chunk: NativeMarkdownChunk,
  importTrust: number,
): { memoryId: number; reason: string } | null {
  const chunkTokens = tokenize(chunk.content);
  let best: { id: number; similarity: number } | null = null;
  for (const candidate of candidates) {
    // Only a genuinely higher-trust row may preserve itself against an import
    // (r1 law): lower/equal trust never suppresses.
    if (candidate.trust <= importTrust) continue;
    // Exact size bound: |A∩B| <= min and |A∪B| >= max, so similarity can never
    // exceed min/max. Skipping on that is a pure speed-up, not an approximation.
    const small = Math.min(chunkTokens.size, candidate.tokens.size);
    const large = Math.max(chunkTokens.size, candidate.tokens.size);
    if (large === 0 || small / large < NEAR_DUPLICATE_THRESHOLD) continue;
    const similarity = jaccardSets(chunkTokens, candidate.tokens);
    if (similarity >= NEAR_DUPLICATE_THRESHOLD && (!best || similarity > best.similarity)) {
      best = { id: candidate.id, similarity };
    }
  }
  if (!best) return null;
  return {
    memoryId: best.id,
    reason: `near duplicate of higher-trust scoped active ShieldCortex memory #${best.id}; existing row preserved`,
  };
}

function dispositionForAssessment(assessment: MemoryAdmissionAssessment): NativeImportDisposition {
  if (assessment.result.firewall.threatIndicators.includes('pipeline_error')) return 'failed';
  if (assessment.disposition.action === 'store') return 'would_admit';
  return assessment.disposition.firewallResult === 'BLOCK' ? 'blocked' : 'quarantined';
}

function baseResult(
  options: NativeImportOptions,
  batchId: string,
  hostId: string,
  agentId: string,
): Omit<NativeImportResult, 'success' | 'applied' | 'files' | 'rows' | 'archived'> {
  return {
    dryRun: options.apply !== true,
    batchId,
    hostId,
    agentId,
    project: nonEmptyScope(options.project),
  };
}

function errorResult(
  options: NativeImportOptions,
  batchId: string,
  hostId: string,
  agentId: string,
  error: unknown,
): NativeImportResult {
  return {
    success: false,
    applied: false,
    ...baseResult(options, batchId, hostId, agentId),
    files: [],
    rows: [],
    archived: [],
    error: error instanceof Error ? error.message : String(error),
  };
}

interface AssessedChunk {
  file: PreparedFile;
  chunk: NativeMarkdownChunk;
  input: MemoryInput;
  source: DefenceSource;
  assessment: MemoryAdmissionAssessment;
  trustScore: number;
  disposition: NativeImportDisposition;
  reason: string;
}

function prepareRows(
  files: PreparedFile[],
  session: NativeImportAdmissionSession,
  dryRun: boolean,
  db: Database.Database,
  batchId: string,
  hostId: string,
  agentId: string,
  project: string | null,
  salience: number,
): PreparedRow[] {
  // Pass 1 — assess every chunk through the full pipeline.
  const assessed: AssessedChunk[] = [];
  for (const file of files) {
    const sourceKey = `native-import:${batchId}:file:${sha256(file.sourcePath).slice(0, 24)}`;
    for (const chunk of file.chunks) {
      const source: DefenceSource = { type: 'file', identifier: sourceKey };
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
      const assessment = session.assess(input, source, dryRun);
      const trustScore = Math.min(
        assessment.disposition.trustClamp ?? assessment.result.trust.score,
        NATIVE_IMPORT_TRUST_CEILING,
      );
      assessed.push({
        file,
        chunk,
        input,
        source,
        assessment,
        trustScore,
        disposition: dispositionForAssessment(assessment),
        reason: assessment.disposition.reason,
      });
    }
  }

  // Pass 2 — one bounded candidate load for the whole batch, reused per chunk.
  // Every chunk carries the same source identity, so the scope is constant; the
  // floor is the thinnest trust any admissible chunk would be stamped with.
  const admissibleTrust = assessed
    .filter((entry) => entry.disposition === 'would_admit')
    .map((entry) => entry.trustScore);
  const candidates = admissibleTrust.length === 0
    ? []
    : loadNearDuplicateCandidates(db, hostId, agentId, project, Math.min(...admissibleTrust));

  const rows: PreparedRow[] = [];
  const batchByHash = new Map<string, PreparedRow>();
  for (const entry of assessed) {
    const { file, chunk, input, source, assessment, trustScore } = entry;
    let { disposition, reason } = entry;
    let preservedMemoryId: number | undefined;
    if (disposition === 'would_admit') {
      const sameBatch = batchByHash.get(chunk.contentHash);
      if (sameBatch) {
        disposition = 'exact_duplicate';
        reason = `exact duplicate of chunk ${sameBatch.chunk.index} from ${sameBatch.file.sourcePath} in this batch`;
      } else {
        const exactId = findExactScopedDuplicate(db, chunk, hostId, agentId, project);
        if (exactId !== null) {
          disposition = 'exact_duplicate';
          reason = 'exact scoped active content hash already exists';
          preservedMemoryId = exactId;
        } else {
          const near = findNearDuplicate(candidates, chunk, trustScore);
          if (near) {
            disposition = 'higher_trust_preserved';
            reason = near.reason;
            preservedMemoryId = near.memoryId;
          }
        }
      }
    }
    const result: NativeImportRowResult = {
      sourcePath: file.sourcePath,
      sourceKey: `${source.type}:${source.identifier}`,
      chunkIndex: chunk.index,
      title: chunk.title,
      contentHash: chunk.contentHash,
      disposition,
      admissionKind: assessment.disposition.kind,
      defenceVerdict: assessment.result.firewall.threatIndicators.includes('pipeline_error')
        ? 'ERROR'
        : assessment.result.firewall.result,
      reason,
      trustScore,
      salience,
      ...(preservedMemoryId === undefined ? {} : { preservedMemoryId }),
    };
    const prepared = { file, chunk, input, source, assessment, result };
    rows.push(prepared);
    if (disposition === 'would_admit') batchByHash.set(chunk.contentHash, prepared);
  }
  return rows;
}

function deniedRows(rows: PreparedRow[]): PreparedRow[] {
  return rows.filter((row) => ['blocked', 'quarantined', 'failed', 'invalid'].includes(row.result.disposition));
}

function rollbackRowResults(rows: PreparedRow[], error: string): void {
  for (const row of rows) {
    if (row.result.disposition === 'admitted') {
      row.result.disposition = 'failed';
      row.result.reason = `rolled back: ${error}`;
      delete row.result.memoryId;
    }
  }
}

/**
 * Import native Markdown exactly once. Dry-run is the default. Apply assesses
 * every row, then admits and archives under one outer SQLite transaction.
 */
export function importNativeMemories(
  options: NativeImportOptions,
): NativeImportResult {
  return importNativeMemoriesInternal(options);
}

/** Internal implementation with fault-injection seams for repository tests. */
export function importNativeMemoriesInternal(
  options: NativeImportOptions,
  dependencies: NativeImportDependencies = {},
): NativeImportResult {
  let batchId = '';
  const hostId = nonEmptyScope(options.hostId) ?? '';
  const agentId = nonEmptyScope(options.agentId) ?? '';
  try {
    batchId = validateBatchId(options.batchId ?? dependencies.batchId?.() ?? randomUUID());
  } catch (error) {
    return errorResult(options, batchId, hostId, agentId, error);
  }
  if (!hostId || !agentId) {
    return errorResult(options, batchId, hostId, agentId, 'native import requires explicit nonempty hostId and agentId');
  }

  const project = nonEmptyScope(options.project);
  const requestedSalience = Number.isFinite(options.salience) ? Number(options.salience) : 0.5;
  const salience = Math.max(0, Math.min(requestedSalience, NATIVE_IMPORT_SALIENCE_CEILING));
  let db: Database.Database;
  try {
    db = dependencies.db ?? getDatabase();
  } catch (error) {
    return errorResult(options, batchId, hostId, agentId, error);
  }

  let prepared: ReturnType<typeof prepareFiles>;
  try {
    prepared = prepareFiles(options, batchId, salience);
  } catch (error) {
    return errorResult(options, batchId, hostId, agentId, error);
  }

  const { files, fileResults, invalidRows } = prepared;
  try {
    if (invalidRows.length > 0) {
      const message = 'batch validation failed; valid sources were not processed';
      for (const file of fileResults) {
        if (file.disposition === 'valid') {
          file.disposition = 'unprocessed';
          file.error = message;
        }
      }
      return {
        success: false,
        applied: false,
        ...baseResult(options, batchId, hostId, agentId),
        files: fileResults,
        rows: invalidRows,
        archived: [],
        error: message,
      };
    }

    let session: NativeImportAdmissionSession;
    try {
      session = (dependencies.sessionFactory ?? createNativeImportAdmissionSession)(batchId);
    } catch (error) {
      return {
        ...errorResult(options, batchId, hostId, agentId, error),
        files: fileResults,
      };
    }
    if (options.apply !== true) {
      try {
        const rows = prepareRows(files, session, true, db, batchId, hostId, agentId, project, salience);
        const denied = deniedRows(rows);
        session.discard();
        const crossDevice = crossDeviceArchiveReason(
          files,
          path.resolve(options.archiveRoot ?? defaultArchiveRoot()),
        );
        return {
          success: denied.length === 0,
          applied: false,
          ...baseResult(options, batchId, hostId, agentId),
          files: fileResults,
          rows: rows.map((row) => row.result),
          archived: [],
          applyPossible: crossDevice === null,
          ...(crossDevice === null ? {} : { applyBlockedReason: crossDevice }),
          ...(denied.length > 0 ? { error: 'one or more chunks cannot be admitted safely' } : {}),
        };
      } catch (error) {
        session.discard();
        return {
          ...errorResult(options, batchId, hostId, agentId, error),
          files: fileResults,
        };
      }
    }

    const moved: MovedSource[] = [];
    let rows: PreparedRow[] = [];
    let denied: PreparedRow[] = [];
    // Rows that actually reached the admit seam. On a Class-B assembly abort
    // these are exactly the fragments the cross-row sweep detected, and the
    // only content the post-rollback forensic record may describe.
    const attempted: PreparedRow[] = [];
    try {
      const apply = db.transaction(() => {
        assertSourcesUnchanged(files);
        rows = prepareRows(files, session, false, db, batchId, hostId, agentId, project, salience);
        denied = deniedRows(rows);
        if (denied.length > 0) {
          for (const row of denied) session.persistRejection(row.input, row.source, row.assessment);
          return false;
        }

        for (const row of rows) {
          if (row.result.disposition !== 'would_admit') continue;
          attempted.push(row);
          try {
            const memory = session.admit(row.input, row.source, row.assessment, NATIVE_IMPORT_TRUST_CEILING);
            row.result.disposition = 'admitted';
            row.result.memoryId = memory.id;
            row.result.defenceVerdict = 'ALLOW';
            row.result.trustScore = memory.trustScore;
            row.result.salience = memory.salience;
          } catch (error) {
            row.result.disposition = 'failed';
            row.result.reason = error instanceof Error ? error.message : String(error);
            throw error;
          }
        }

        dependencies.beforeArchive?.(files.map((file) => ({
          sourcePath: file.sourcePath,
          archivePath: file.archivePath,
        })));
        assertSourcesUnchanged(files);
        archiveSources(
          files,
          moved,
          dependencies.linkSource,
          dependencies.unlinkSource,
          dependencies.chmodFile,
        );
        for (let i = 0; i < files.length; i++) {
          fileResults[i].archivePath = files[i].archivePath;
          fileResults[i].disposition = 'archived';
        }
        return true;
      });

      const archivedAndApplied = apply.immediate();
      if (!archivedAndApplied) {
        // Nothing was committed for this batch, so nothing external may fire.
        // finalize() here would flush queued cloud/webhook/embedding/in-process
        // effects for would-admit rows that were never stored.
        session.discard();
        return {
          success: false,
          applied: false,
          ...baseResult(options, batchId, hostId, agentId),
          files: fileResults,
          rows: rows.map((row) => row.result),
          archived: [],
          error: 'one or more chunks were blocked, quarantined, or failed; no admissible chunks were written',
        };
      }
      session.finalize();
      return {
        success: true,
        applied: true,
        ...baseResult(options, batchId, hostId, agentId),
        files: fileResults,
        rows: rows.map((row) => row.result),
        archived: moved.map((item) => item.to),
      };
    } catch (error) {
      session.discard();
      let reason = error instanceof Error ? error.message : String(error);
      if (error instanceof MemoryClusterAssemblyError) {
        // The transaction rolled back the sweep's own quarantine moves and every
        // audit row this batch wrote. Re-state the detection durably, OUTSIDE the
        // rolled-back transaction, as audit + quarantine evidence only — the
        // strongest signal the importer can produce must not vanish with it.
        // `attempted` spans EVERY file in the batch, but the sweep that fired is
        // keyed to one `memories.source`. Filtering on content form alone would
        // implicate an unrelated file that merely happened to contribute a
        // directive-form chunk to the same batch. Attribute on the triggering
        // canonical source identity as well, so the durable evidence names only
        // the assembly that was actually detected.
        const fragments: NativeImportAssemblyFragment[] = attempted
          .filter((row) => {
            const form = row.assessment.disposition.contentForm;
            if (form !== 'directive' && form !== 'mixed') return false;
            return `${row.source.type}:${row.source.identifier}` === error.sourceValue;
          })
          .map((row) => ({ input: row.input, source: row.source, assessment: row.assessment }));
        try {
          const recorded = session.persistAssemblyRejection(fragments, {
            reason: error.clusterReason,
            quarantined: error.quarantined,
            sourceValue: error.sourceValue,
          });
          reason = `${reason}; ${recorded} fragment(s) from ${error.sourceValue} `
            + 'recorded as class_b_cluster evidence';
        } catch (evidenceError) {
          reason = `${reason}; class_b_cluster evidence could not be persisted: `
            + `${evidenceError instanceof Error ? evidenceError.message : String(evidenceError)}`;
        }
      }
      // Compensation residuals come from two places: an archive that was
      // deliberately retained because a source mode could not be restored
      // (thrown out of archiveSources), and the rollback of sources already
      // moved. Both must reach `archived` / the file disposition / the error
      // text, or the envelope would claim a cleaner rollback than the disk has.
      const residuals: ArchiveResidual[] = [
        ...(error instanceof NativeImportCompensationError ? error.residuals : []),
        ...restoreMovedSources(moved, dependencies.restoreLinkSource, dependencies.chmodFile),
      ];
      if (residuals.length > 0) {
        reason = `${reason}; residual archive link(s) retained: ${describeResiduals(residuals)}`;
      }
      const residual = residuals.map((entry) => entry.archivePath);
      rollbackRowResults(rows, reason);
      for (let i = 0; i < files.length; i++) {
        const remainsArchived = residual.includes(files[i].archivePath);
        fileResults[i].archivePath = remainsArchived ? files[i].archivePath : null;
        fileResults[i].disposition = remainsArchived ? 'residual_archived' : 'unprocessed';
        fileResults[i].error = reason;
      }
      return {
        success: false,
        applied: false,
        ...baseResult(options, batchId, hostId, agentId),
        files: fileResults,
        rows: rows.map((row) => row.result),
        archived: residual,
        error: `native import rolled back; source archive/admission failed: ${reason}`,
      };
    }
  } finally {
    closePreparedFiles(files);
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