import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { describe, expect, it } from '@jest/globals';

/**
 * Lock in the corrected DB-init hint. v4.12.1 doctor pointed users at
 * `shieldcortex quickstart` to "initialise the database" — but quickstart
 * only configures hooks/MCP and doesn't touch the DB. Caused the user to
 * loop on quickstart → doctor → quickstart on TARS during fleet rollout.
 *
 * The reliable one-shot init paths are `shieldcortex scan "..."` (any
 * install shape) or starting an MCP-bound session (Claude Code).
 */
describe('doctor — database-not-found hint', () => {
  const thisFile = fileURLToPath(import.meta.url);
  const repoRoot = path.resolve(path.dirname(thisFile), '..', '..');
  const doctorSource = fs.readFileSync(path.join(repoRoot, 'src', 'cli', 'doctor.ts'), 'utf-8');

  it('does not suggest `shieldcortex quickstart` as a way to initialise the database', () => {
    const checkDatabaseFn = doctorSource.match(/async function checkDatabase\(\)[\s\S]*?\n\}/);
    expect(checkDatabaseFn).not.toBeNull();
    expect(checkDatabaseFn![0]).not.toMatch(/quickstart.*?initialise the database/i);
    expect(checkDatabaseFn![0]).not.toMatch(/run `shieldcortex quickstart`/);
  });

  it('suggests `shieldcortex scan` as the explicit init command', () => {
    const checkDatabaseFn = doctorSource.match(/async function checkDatabase\(\)[\s\S]*?\n\}/);
    expect(checkDatabaseFn![0]).toMatch(/shieldcortex scan ["']init["']/);
  });

  it('still mentions the Claude Code MCP-server lazy-init path on Claude+OpenClaw hosts', () => {
    const checkDatabaseFn = doctorSource.match(/async function checkDatabase\(\)[\s\S]*?\n\}/);
    expect(checkDatabaseFn![0]).toMatch(/Claude Code session/i);
    expect(checkDatabaseFn![0]).toMatch(/lazy-init|MCP server/i);
  });
});
