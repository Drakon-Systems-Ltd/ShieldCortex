import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import Database from 'better-sqlite3';

/**
 * Defect 2: firewall_rules and iron_dome_policies start empty in production
 * and never get seeded. The defence pipeline calls getEnabledFirewallRules()
 * and silently no-ops on empty, so the engine has nothing to match against
 * even when invoked.
 *
 * Fix: add a built_in column to firewall_rules and seed ~9 default rules
 * (instruction injection, hidden instruction, imperative tool-call,
 * credential leak variants, command injection, delimiter attack, memory
 * manipulation) on first init. User custom rules count toward the existing
 * 25-rule cap; built-ins are excluded.
 *
 * This test is red until Phase 4 lands.
 */
describe('Defect 2: default firewall_rules seeder', () => {
  const thisFile = fileURLToPath(import.meta.url);
  const repoRoot = path.resolve(path.dirname(thisFile), '..', '..');
  const schemaPath = path.join(repoRoot, 'src', 'database', 'schema.sql');
  const fixturePath = path.join(repoRoot, 'src', '__fixtures__', 'sc_defect_fixture.db');

  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'shieldcortex-rules-seed-'));
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  it('fixture confirms the production state: firewall_rules and iron_dome_policies empty', () => {
    const dbPath = path.join(tempDir, 'fixture.db');
    fs.copyFileSync(fixturePath, dbPath);
    const db = new Database(dbPath, { readonly: true });

    try {
      const rulesCount = (db.prepare('SELECT COUNT(*) as c FROM firewall_rules').get() as { c: number }).c;
      expect(rulesCount).toBe(0);

      const policiesCount = (db.prepare('SELECT COUNT(*) as c FROM iron_dome_policies').get() as { c: number }).c;
      expect(policiesCount).toBe(0);
    } finally {
      db.close();
    }
  });

  it('seeder populates built_in firewall_rules on first init', async () => {
    const dbPath = path.join(tempDir, 'fresh.db');
    const db = new Database(dbPath);
    db.exec(fs.readFileSync(schemaPath, 'utf-8'));

    // Phase 4 introduces this module; import is dynamic so the test file
    // can be authored ahead of the implementation without breaking
    // module resolution at jest collection time.
    const seedModule = await import('../database/seed-firewall-rules.js');
    seedModule.seedDefaultFirewallRules(db);

    try {
      const builtIns = db.prepare('SELECT name, action, condition_type, enabled FROM firewall_rules WHERE built_in = 1').all() as Array<{ name: string; action: string; condition_type: string; enabled: number }>;
      expect(builtIns.length).toBeGreaterThanOrEqual(7);

      const names = builtIns.map((r) => r.name);
      expect(names).toEqual(expect.arrayContaining([
        'builtin:instruction_injection',
        'builtin:hidden_instruction',
        'builtin:imperative_tool_call',
      ]));

      // Every built-in must be enabled by default and have a condition.
      for (const r of builtIns) {
        expect(r.enabled).toBe(1);
        expect(r.condition_type).toBeTruthy();
      }

      // Every built-in action is one of the allowed values.
      for (const r of builtIns) {
        expect(['block', 'quarantine', 'allow']).toContain(r.action);
      }
    } finally {
      db.close();
    }
  });

  it('seeder is idempotent: re-running does not duplicate built_in rows', async () => {
    const dbPath = path.join(tempDir, 'idempotent.db');
    const db = new Database(dbPath);
    db.exec(fs.readFileSync(schemaPath, 'utf-8'));

    const seedModule = await import('../database/seed-firewall-rules.js');
    seedModule.seedDefaultFirewallRules(db);
    const firstCount = (db.prepare('SELECT COUNT(*) as c FROM firewall_rules WHERE built_in = 1').get() as { c: number }).c;

    seedModule.seedDefaultFirewallRules(db);
    const secondCount = (db.prepare('SELECT COUNT(*) as c FROM firewall_rules WHERE built_in = 1').get() as { c: number }).c;

    try {
      expect(secondCount).toBe(firstCount);
    } finally {
      db.close();
    }
  });
});
