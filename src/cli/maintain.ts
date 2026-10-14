/** Unattended storage and memory hygiene (#652, slice A). */
import fs from 'node:fs';
import path from 'node:path';
import Database from 'better-sqlite3';
import { DIRECTORY_BUDGET_BYTES } from '../limits.js';
import { assertSafeRuntimeForDbPath, closeDatabase, initDatabase, resolveMemoriesDbPath } from '../database/init.js';
import { resolveMemoryConfig } from '../memory/config.js';
import type { MemoryConfig, ConsolidationResult } from '../memory/types.js';
import { backfillEmbeddings, type EmbedBackfillResult } from './embed-backfill.js';
import { inspectEmbeddingModelCache } from '../embeddings/model-cache.js';
import { checkDiskUsage, runMemoryStatsCheck, runSemanticCoverageCheck, VACUUM_FREE_SHARE, type CheckResult } from './doctor.js';
import { buildMaintenanceFailNotification, deliverOperatorNotification, type NotifyChannel } from '../defence/iron-dome/operator-notify.js';

type Status = 'ran' | 'skipped' | 'noop' | 'failed';
export interface MaintainStep { status: Status; reason: string; [count: string]: string | number | CheckResult[]; }
export interface MaintainReport {
  steps: { consolidate: MaintainStep; embed: MaintainStep; vacuum: MaintainStep; doctor: MaintainStep & { results: CheckResult[] }; notify: MaintainStep };
  failures: number;
  exitCode: number;
}
export interface MaintainDeps {
  dataDir?: string;
  dbPath?: string;
  diskLimit?: number;
  consolidateConfig?: MemoryConfig;
  embed?: (text: string) => Promise<Float32Array>;
  modelCacheReady?: () => Promise<boolean>;
  notifier?: (checks: CheckResult[]) => Promise<boolean>;
  channels?: NotifyChannel[];
  now?: () => Date;
  consolidate?: () => ConsolidationResult;
  doctor?: () => Promise<CheckResult[]>;
  vacuum?: (db: Database.Database) => void;
}

const step = (status: Status, reason: string, counts: Record<string, number> = {}): MaintainStep => ({ status, reason, ...counts });
const errorText = (err: unknown): string => err instanceof Error ? err.message : String(err);
const liveLock = (dbPath: string): boolean => {
  try {
    const lock = JSON.parse(fs.readFileSync(`${dbPath}.lock`, 'utf8')) as { pid?: number };
    if (!Number.isInteger(lock.pid) || !lock.pid) return false;
    process.kill(lock.pid, 0);
    return true;
  } catch (err) { return (err as NodeJS.ErrnoException).code === 'EPERM'; }
};
const lockedError = (err: unknown): boolean => /SQLITE_BUSY|database is locked|database is busy|locked by/i.test(errorText(err));

async function configuredChannels(): Promise<NotifyChannel[]> {
  try {
    const { getActionGuardNotifyConfig } = await import('../cloud/config.js');
    const { normaliseNotifyConfig } = await import('../defence/iron-dome/notify-config.js');
    const { createWebhookNotifyChannel } = await import('../defence/iron-dome/webhook-notify-channel.js');
    const cfg = normaliseNotifyConfig(getActionGuardNotifyConfig());
    return cfg.enabled && cfg.webhookUrl ? [createWebhookNotifyChannel({ url: cfg.webhookUrl, secret: cfg.webhookSecret })] : [];
  } catch { return []; }
}

/** The checks this command can affect, plus any maintenance-step failures. */
async function storageDoctor(dataDir: string, dbPath: string, limit: number, config: MemoryConfig): Promise<CheckResult[]> {
  return [runMemoryStatsCheck(dbPath, config), runSemanticCoverageCheck(dbPath), await checkDiskUsage(dataDir, limit)];
}

export async function maintain(options: { dryRun?: boolean } = {}, deps: MaintainDeps = {}): Promise<MaintainReport> {
  const dbPath = deps.dbPath ?? (deps.dataDir ? path.join(deps.dataDir, 'memories.db') : resolveMemoriesDbPath());
  const injectedPath = deps.dbPath !== undefined || deps.dataDir !== undefined;
  if (!injectedPath) assertSafeRuntimeForDbPath(dbPath);
  const dataDir = deps.dataDir ?? path.dirname(dbPath);
  const config = deps.consolidateConfig ?? resolveMemoryConfig();
  const limit = deps.diskLimit ?? DIRECTORY_BUDGET_BYTES;
  const dryRun = options.dryRun === true;
  const steps: MaintainReport['steps'] = {
    consolidate: step('skipped', 'not checked'), embed: step('skipped', 'not checked'),
    vacuum: step('skipped', 'not checked'), doctor: { ...step('skipped', 'not checked'), results: [] },
    notify: step('skipped', 'not checked'),
  };
  const failedSteps: CheckResult[] = [];
  const failStep = (name: 'consolidate' | 'embed' | 'vacuum', err: unknown): void => {
    steps[name] = step('failed', errorText(err));
    failedSteps.push({ label: `Maintenance ${name}`, status: 'fail', message: `${name} failed: ${errorText(err)}` });
  };
  let db: Database.Database | undefined;
  let dbOwnedByInit = false;
  const locked = !dryRun && liveLock(dbPath);
  try {
    if (locked) {
      steps.consolidate = step('skipped', 'locked');
      steps.embed = step('skipped', 'locked', { missing: 0, embedded: 0 });
      steps.vacuum = step('skipped', 'locked');
    } else if (dryRun) {
      if (fs.existsSync(dbPath)) db = new Database(dbPath, { readonly: true, fileMustExist: true });
    } else {
      db = injectedPath ? initDatabase(dbPath) : initDatabase();
      dbOwnedByInit = true;
    }
  } catch (err) { failStep('consolidate', err); }

  try {
    try {
      if (locked) { /* already skipped before opening */ }
      else if (!db) steps.consolidate = step('skipped', 'database unavailable');
      else {
        const count = (db.prepare("SELECT COUNT(*) AS n FROM memories WHERE type = 'short_term'").get() as { n: number }).n;
        if (count <= config.maxShortTermMemories) steps.consolidate = step('skipped', 'STM within cap', { stm: count, promoted: 0, deleted: 0 });
        else if (dryRun) steps.consolidate = step('skipped', 'dry-run: STM over cap', { stm: count, promoted: 0, deleted: 0 });
        else {
          const { consolidate } = await import('../memory/consolidate.js');
          const result: ConsolidationResult = deps.consolidate ? deps.consolidate() : consolidate(config);
          steps.consolidate = step('ran', 'STM over cap', { stm: count, promoted: result.consolidated, deleted: result.deleted });
        }
      }
    } catch (err) { failStep('consolidate', err); }

    try {
      if (locked) { /* already skipped before opening */ }
      else if (!db) steps.embed = step('skipped', 'database unavailable', { missing: 0, embedded: 0 });
      else {
        const modelCacheReady = deps.modelCacheReady ?? (async () => (await inspectEmbeddingModelCache()).status === 'ok');
        const cacheReady = dryRun || Boolean(deps.embed) || await modelCacheReady();
        if (!cacheReady) {
          const missing = (db.prepare('SELECT COUNT(*) AS n FROM memories WHERE embedding IS NULL').get() as { n: number }).n;
          steps.embed = step('skipped', 'embedding model not cached', { missing, embedded: 0 });
        } else {
          const result: EmbedBackfillResult = await backfillEmbeddings({ db, execute: !dryRun, embed: deps.embed });
          steps.embed = step(dryRun ? 'skipped' : result.embedded > 0 ? 'ran' : result.failed > 0 ? 'failed' : 'noop',
            dryRun ? 'dry-run' : result.failed > 0 ? `${result.failed} vectors could not be embedded` : result.missing === 0 ? 'no missing vectors' : 'backfill complete',
            { missing: result.missing, embedded: result.embedded, failed: result.failed });
          if (result.failed > 0) failedSteps.push({ label: 'Maintenance embed', status: 'fail', message: `${result.failed} vectors could not be embedded` });
        }
      }
    } catch (err) { failStep('embed', err); }
    finally {
      if (db && !deps.embed && !dryRun) {
        try { const { disposeModel } = await import('../embeddings/index.js'); await disposeModel(); }
        catch { /* no model worker was started */ }
      }
    }

    try {
      if (locked) { /* already skipped before opening */ }
      else if (!db) steps.vacuum = step('skipped', 'database unavailable');
      else {
        const pages = db.pragma('page_count', { simple: true }) as number;
        const free = db.pragma('freelist_count', { simple: true }) as number;
        const share = pages ? free / pages : 0;
        if (share < VACUUM_FREE_SHARE) steps.vacuum = step('skipped', 'free-page share below gate', { pages, freePages: free });
        else if (dryRun) steps.vacuum = step('skipped', 'dry-run: free-page share meets gate', { pages, freePages: free });
        else {
          try {
            if (deps.vacuum) deps.vacuum(db);
            else { db.pragma('wal_checkpoint(TRUNCATE)'); db.exec('VACUUM'); db.pragma('wal_checkpoint(TRUNCATE)'); }
            steps.vacuum = step('ran', 'free-page share meets gate', { pages, freePages: free });
          } catch (err) {
            if (lockedError(err)) steps.vacuum = step('skipped', 'locked', { pages, freePages: free });
            else throw err;
          }
        }
      }
    } catch (err) { failStep('vacuum', err); }
  } finally {
    if (dbOwnedByInit) {
      closeDatabase();
    } else if (db && db.open) db.close();
  }

  let results: CheckResult[] = [];
  try {
    results = deps.doctor ? await deps.doctor() : await storageDoctor(dataDir, dbPath, limit, config);
    steps.doctor = { ...step('ran', 'doctor checks completed', { checks: results.length }), results };
  } catch (err) {
    results = [{ label: 'Maintenance doctor', status: 'fail', message: `Doctor checks failed: ${errorText(err)}` }];
    steps.doctor = { ...step('failed', errorText(err)), results };
  }
  results = [...results, ...failedSteps];
  steps.doctor.results = results;
  const failing = results.filter(r => r.status === 'fail');
  steps.doctor.failures = failing.length;
  steps.doctor.warnings = results.filter(r => r.status === 'warn').length;
  if (failing.length === 0) steps.notify = step('noop', 'no doctor failures');
  else if (dryRun) steps.notify = step('skipped', 'dry-run');
  else {
    const stateFile = path.join(dataDir, 'state', 'maintain-notify.json');
    const fingerprint = failing.map(r => r.label).sort().join('\n');
    const now = (deps.now ?? (() => new Date()))().getTime();
    let previous: { fingerprint?: string; sentAt?: number } = {};
    try { previous = JSON.parse(fs.readFileSync(stateFile, 'utf8')) as typeof previous; } catch { /* no earlier delivery */ }
    if (previous.fingerprint === fingerprint && typeof previous.sentAt === 'number' && now - previous.sentAt < 86_400_000 && now >= previous.sentAt) {
      steps.notify = step('skipped', 'throttled');
    } else {
      const channels = deps.channels ?? await configuredChannels();
      if (!deps.notifier && channels.length === 0) steps.notify = step('skipped', 'not-configured');
      else {
        try {
          // Messages leaving the process are deliberately values-free. Detailed
          // doctor messages remain in the local report for diagnosis.
          const safe = failing.map(r => ({ label: r.label, status: 'fail' as const, message: 'Check failed; run shieldcortex doctor for details.' }));
          const delivered = deps.notifier
            ? await deps.notifier(safe)
            : Boolean((await deliverOperatorNotification(buildMaintenanceFailNotification(safe), { channels })).deliveredVia);
          if (delivered) {
            fs.mkdirSync(path.dirname(stateFile), { recursive: true });
            fs.writeFileSync(stateFile, JSON.stringify({ fingerprint, sentAt: now }), { mode: 0o600 });
            steps.notify = step('ran', 'sent');
          } else steps.notify = step('failed', 'delivery failed');
        } catch (err) { steps.notify = step('failed', errorText(err)); }
      }
    }
  }
  return { steps, failures: failing.length, exitCode: failing.length === 0 ? 0 : 1 };
}

export async function runMaintain(args: string[]): Promise<void> {
  if (args.includes('--help') || args.includes('-h')) {
    console.log('Usage: shieldcortex maintain [--dry-run] [--json]\nConsolidate capped STM, backfill vectors, vacuum free pages, then check and notify. Audit-log retention is not included yet.');
    return;
  }
  if (args.some(a => a !== '--dry-run' && a !== '--json')) {
    console.error('maintain: unknown argument'); process.exitCode = 2; return;
  }
  let report: MaintainReport;
  try { report = await maintain({ dryRun: args.includes('--dry-run') }); }
  catch (err) { console.error(errorText(err)); process.exitCode = 1; return; }
  if (args.includes('--json')) console.log(JSON.stringify(report));
  else for (const [name, result] of Object.entries(report.steps)) console.log(`${name}: ${result.status} — ${result.reason}`);
  process.exitCode = report.exitCode;
}
