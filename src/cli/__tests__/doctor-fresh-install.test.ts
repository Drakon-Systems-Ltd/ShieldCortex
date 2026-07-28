import fs from 'fs';
import os from 'os';
import path from 'path';
import { createRequire } from 'module';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';

import {
  partitionUninitialisedSkips,
  runDatabaseCheck,
  runHooksCheck,
  runMemoryStatsCheck,
  runSchemaDriftCheck,
  runWritePathProbe,
  type CheckResult,
} from '../doctor.js';

const require = createRequire(import.meta.url);

/**
 * First-run health contract (#129).
 *
 * On a virgin box — global install, nothing written yet — `doctor` used to
 * print a red `❌ Database: not found` plus four dependent ⚠️ lines. Nothing
 * was wrong: the database is created lazily on the first memory operation and
 * `~/.claude/settings.json` only exists once Claude Code has run. But doctor
 * is precisely the command a new user runs to confirm the install worked, and
 * a red cross there reads as "this product is broken".
 *
 * The contract these tests lock in:
 *   - normal-for-a-fresh-install states are ℹ️ with an actionable next step
 *   - the dependent "no database" checks collapse to one note, not four ⚠️
 *   - a genuinely broken database is still ❌
 */
describe('doctor — fresh-install states are informational, not failures', () => {
  const claudeEnv = { hasClaude: true, hasOpenClaw: false, hasVSCode: false, hasCodex: false, isHeadless: false };
  const openClawEnv = { hasClaude: false, hasOpenClaw: true, hasVSCode: false, hasCodex: false, isHeadless: true };

  let tmpDir: string;
  let missingDb: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-firstrun-'));
    missingDb = path.join(tmpDir, 'memories.db');
  });

  afterEach(() => {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ignore */ }
  });

  describe('Database check', () => {
    it('reports "not initialised yet" as info, never a failure', () => {
      const result = runDatabaseCheck(missingDb, claudeEnv);
      expect(result.status).toBe('info');
      expect(result.message).toMatch(/not initialised yet/i);
      expect(result.message).not.toMatch(/not found/i);
    });

    it('gives an actionable next step on a Claude Code host', () => {
      const result = runDatabaseCheck(missingDb, claudeEnv);
      expect(result.fix).toMatch(/shieldcortex scan ["']init["']/);
      expect(result.fix).toMatch(/Claude Code session/i);
      expect(result.fix).toMatch(/lazy-init|MCP server/i);
    });

    it('gives an OpenClaw-only host a next step that does not depend on an MCP server', () => {
      const result = runDatabaseCheck(missingDb, openClawEnv);
      expect(result.fix).toMatch(/shieldcortex scan ["']init["']/);
      expect(result.fix).not.toMatch(/Claude Code session/i);
    });

    it('still reports a healthy database as pass', () => {
      const Database = require('better-sqlite3');
      const db = new Database(missingDb);
      db.exec('CREATE TABLE memories (id INTEGER PRIMARY KEY)');
      db.close();

      const result = runDatabaseCheck(missingDb, claudeEnv);
      expect(result.status).toBe('pass');
      expect(result.message).toMatch(/healthy/);
    });

    it('STILL reports ❌ for a genuinely broken database file', () => {
      // A file that exists but is not a database — the case the info status
      // must never swallow.
      fs.writeFileSync(missingDb, Buffer.from('this is not a sqlite file, at all'));

      const result = runDatabaseCheck(missingDb, claudeEnv);
      expect(result.status).toBe('fail');
      expect(result.fix).toBeDefined();
    });
  });

  describe('dependent checks', () => {
    it.each([
      ['Schema', () => runSchemaDriftCheck(missingDb)],
      ['Write path', () => runWritePathProbe(missingDb)],
      ['Memories', () => runMemoryStatsCheck(missingDb)],
    ])('%s is info + marked skipped when there is no database yet', (label, run) => {
      const result = run();
      expect(result.label).toBe(label);
      expect(result.status).toBe('info');
      expect(result.skipped).toBe('db-uninitialised');
    });

    it('collapses the dependent skips out of the printed report', () => {
      const results: CheckResult[] = [
        runDatabaseCheck(missingDb, claudeEnv),
        runSchemaDriftCheck(missingDb),
        runWritePathProbe(missingDb),
        runMemoryStatsCheck(missingDb),
        { label: 'Processes', status: 'pass', message: 'fine' },
      ];

      const { visible, suppressed } = partitionUninitialisedSkips(results);
      expect(suppressed.map(r => r.label)).toEqual(['Schema', 'Write path', 'Memories']);
      expect(visible.map(r => r.label)).toEqual(['Database', 'Processes']);
    });

    it('keeps real findings visible — suppression is scoped to the uninitialised case', () => {
      const results: CheckResult[] = [
        { label: 'Schema', status: 'warn', message: 'drift: missing defence_verdict' },
        { label: 'Write path', status: 'fail', message: 'round-trip failed' },
      ];
      const { visible, suppressed } = partitionUninitialisedSkips(results);
      expect(suppressed).toHaveLength(0);
      expect(visible).toHaveLength(2);
    });
  });

  describe('Hooks check', () => {
    it('treats a missing settings.json on a Claude host as info with a next step', () => {
      const result = runHooksCheck(path.join(tmpDir, 'settings.json'), claudeEnv);
      expect(result.status).toBe('info');
      expect(result.fix).toMatch(/shieldcortex install/);
    });

    it('treats a host without Claude Code as info, with nothing to fix', () => {
      const result = runHooksCheck(path.join(tmpDir, 'settings.json'), openClawEnv);
      expect(result.status).toBe('info');
      expect(result.message).toMatch(/not applicable/i);
      expect(result.fix).toBeUndefined();
    });

    it('STILL warns when settings.json exists but the hooks are not wired', () => {
      const settingsPath = path.join(tmpDir, 'settings.json');
      fs.writeFileSync(settingsPath, JSON.stringify({ hooks: {} }));

      const result = runHooksCheck(settingsPath, claudeEnv);
      expect(result.status).toBe('warn');
      expect(result.message).toMatch(/missing:/);
    });
  });

  it('produces a clean-box report with no ❌ and no ⚠️', () => {
    // The acceptance criterion from #129, assembled from the checks that were
    // red/yellow on the observed clean-box run.
    const results: CheckResult[] = [
      runDatabaseCheck(missingDb, openClawEnv),
      runSchemaDriftCheck(missingDb),
      runWritePathProbe(missingDb),
      runMemoryStatsCheck(missingDb),
      runHooksCheck(path.join(tmpDir, 'settings.json'), openClawEnv),
    ];

    expect(results.filter(r => r.status === 'fail')).toEqual([]);
    expect(results.filter(r => r.status === 'warn')).toEqual([]);
  });
});
