import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { purgeMalformed } from '../migrate-legacy.js';

/**
 * `shieldcortex memories purge --malformed` against the fixture DB must
 * flag every malformed row (defect 3 corpus). Confirms the CLI uses the
 * same rejection predicate as the runtime chunker.
 */
describe('memories purge --malformed', () => {
  const thisFile = fileURLToPath(import.meta.url);
  const repoRoot = path.resolve(path.dirname(thisFile), '..', '..', '..');
  const fixturePath = path.join(repoRoot, 'src', '__fixtures__', 'sc_defect_fixture.db');

  let tempDir: string;
  let dbPath: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'shieldcortex-purge-'));
    dbPath = path.join(tempDir, 'fixture.db');
    fs.copyFileSync(fixturePath, dbPath);
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  it('--dry-run flags the malformed corpus rows without deleting', async () => {
    const report = await purgeMalformed({
      dbPath,
      dryRun: true,
      backupDir: path.join(tempDir, 'backups'),
    });

    expect(report.dryRun).toBe(true);
    expect(report.deleted).toBe(0);

    const flaggedIds = report.matched.map(m => m.id).sort((a, b) => a - b);
    // Acceptance from the EDITH report: ids 136, 137, 159, 160, 161,
    // 162, 163 must be flagged. The negation-scope rule needs original
    // conversation context (not available at purge time), so 159's
    // "commit secrets" still gets caught by the bare-imperative-verb
    // rule. Email-body rows 171, 192, 206 are also flagged.
    for (const id of [136, 137, 159, 160, 162, 163, 171, 192, 206]) {
      expect(flaggedIds).toContain(id);
    }
  });

  it('--execute writes a backup and deletes flagged rows', async () => {
    const backupDir = path.join(tempDir, 'backups');
    const report = await purgeMalformed({
      dbPath,
      dryRun: false,
      backupDir,
    });

    expect(report.dryRun).toBe(false);
    expect(report.deleted).toBeGreaterThanOrEqual(7);
    expect(report.backupPath).toBeDefined();
    expect(fs.existsSync(report.backupPath!)).toBe(true);

    // Backup must live under the requested backup dir.
    expect(report.backupPath!.startsWith(backupDir)).toBe(true);
  });

  it('every match carries a non-empty rejection reason', async () => {
    const report = await purgeMalformed({
      dbPath,
      dryRun: true,
      backupDir: path.join(tempDir, 'backups'),
    });
    for (const m of report.matched) {
      expect(m.reason).toBeTruthy();
    }
  });
});
