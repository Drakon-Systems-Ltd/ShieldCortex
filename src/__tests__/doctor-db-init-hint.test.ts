import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';

import { runDatabaseCheck } from '../cli/doctor.js';

/**
 * Lock in the corrected DB-init hint. v4.12.1 doctor pointed users at
 * `shieldcortex quickstart` to "initialise the database" — but quickstart
 * only configures hooks/MCP and doesn't touch the DB. Caused the user to
 * loop on quickstart → doctor → quickstart on TARS during fleet rollout.
 *
 * The reliable one-shot init paths are `shieldcortex scan "..."` (any
 * install shape) or starting an MCP-bound session (Claude Code).
 *
 * Asserted against the check's actual output rather than doctor's source, so
 * the guard survives refactors of how the check is wired up.
 */
describe('doctor — database-not-initialised hint', () => {
  const claudeEnv = { hasClaude: true, hasOpenClaw: false, hasVSCode: false, hasCodex: false, isHeadless: false };
  let tmpDir: string;
  let missingDb: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-db-hint-'));
    missingDb = path.join(tmpDir, 'memories.db');
  });

  afterEach(() => {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ignore */ }
  });

  it('does not suggest `shieldcortex quickstart` as a way to initialise the database', () => {
    const { fix } = runDatabaseCheck(missingDb, claudeEnv);
    expect(fix).not.toMatch(/quickstart/i);
  });

  it('suggests `shieldcortex scan` as the explicit init command', () => {
    const { fix } = runDatabaseCheck(missingDb, claudeEnv);
    expect(fix).toMatch(/shieldcortex scan ["']init["']/);
  });

  it('still mentions the Claude Code MCP-server lazy-init path on Claude+OpenClaw hosts', () => {
    const { fix } = runDatabaseCheck(missingDb, claudeEnv);
    expect(fix).toMatch(/Claude Code session/i);
    expect(fix).toMatch(/lazy-init|MCP server/i);
  });
});
