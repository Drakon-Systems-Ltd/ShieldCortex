/**
 * #647 — the deliberate re-sign's audit record, through the BUILT CLI.
 *
 * Round-1 review B1: `shieldcortex config --resign --confirm` printed
 * "Recorded in the audit log as config_resigned" while recording nothing. The
 * `config` command never opened the database, `logAudit` returns -1 without
 * one, `logIronDomeAudit` dropped that status and `emitProtectedAudit` swallowed
 * the rest. Every in-process suite mocked the audit boundary with a spy that
 * always succeeded, so none of them could see it.
 *
 * So this suite mocks nothing. Each case spawns `dist/index.js` as a fresh
 * process — the shipped dispatcher, preamble and all — against a throwaway
 * HOME, config dir, protected root, OpenClaw home and database, then reads the
 * row back out of SQLite itself:
 *
 *   - recorded: exit 0, and a `config_resigned` row actually exists, with the
 *     row id the CLI printed, both hashes, the backup and key names — no values;
 *   - audit log unavailable (its directory is a regular file): exit 1, refused
 *     BEFORE anything is written — no backup, bytes unchanged, still tampered.
 *
 * The post-write failure (row insert fails after the re-sign landed: exit 2,
 * "AUDIT NOT RECORDED") cannot be provoked from outside a process without a
 * test-only switch in production code, so it is pinned in-process by
 * config-tamper-preserve-647 and doctor-config-integrity-647.
 *
 * Hermetic: the child gets a built-from-scratch environment (no inherited
 * SHIELDCORTEX_* / CLAUDE_MEMORY_DB), and PATH starts with a fake `npm` so the
 * CLI preamble's `npm ls -g` cannot reach a registry or write ~/.npm. Every
 * child is `spawnSync(process.execPath, [...])` with an argv array.
 */
import { spawnSync } from 'node:child_process';
import { createHash, createHmac, randomBytes } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import Database from 'better-sqlite3';
import { afterEach, beforeAll, beforeEach, describe, expect, it } from '@jest/globals';
import { requireFreshBuiltArtefacts } from './built-artefact-freshness.js';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const DIST_ENTRY = join(repoRoot, 'dist', 'index.js');

const SENTINEL = 'sc_live_SENTINEL_647_dist';

let root: string;
let home: string;
let configDir: string;
let fakeBin: string;

beforeAll(() => {
  // Asserted, never built here — `npm test` builds once before Jest starts.
  requireFreshBuiltArtefacts({
    repoRoot,
    sources: [
      join(repoRoot, 'src', 'index.ts'),
      join(repoRoot, 'src', 'cloud', 'cli.ts'),
      join(repoRoot, 'src', 'cloud', 'config.ts'),
      join(repoRoot, 'src', 'cloud', 'recovery-audit.ts'),
      join(repoRoot, 'src', 'defence', 'iron-dome', 'audit.ts'),
      join(repoRoot, 'src', 'defence', 'iron-dome', 'protected-root.ts'),
    ],
    artefacts: [
      DIST_ENTRY,
      join(repoRoot, 'dist', 'cloud', 'recovery-audit.js'),
      join(repoRoot, 'dist', 'defence', 'iron-dome', 'audit.js'),
    ],
  });
});

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'sc-647-dist-'));
  home = join(root, 'home');
  configDir = join(home, '.shieldcortex');
  fakeBin = join(root, 'bin');
  for (const dir of [home, configDir, fakeBin, join(root, 'protected'), join(root, 'openclaw')]) {
    mkdirSync(dir, { recursive: true });
  }
  // `npm ls -g` answers "nothing installed globally" and touches nothing.
  const npm = join(fakeBin, 'npm');
  writeFileSync(npm, `#!${process.execPath}\nprocess.stdout.write('{}');\n`);
  chmodSync(npm, 0o755);
});

afterEach(() => {
  if (root) rmSync(root, { recursive: true, force: true });
});

const configFile = () => join(configDir, 'config.json');
const sha256 = (b: Buffer) => createHash('sha256').update(b).digest('hex');
const backups = () => readdirSync(configDir).filter((n) => n.includes('.bak-resign-'));

/**
 * A config.json signed exactly as config.ts signs it (HMAC-SHA256 with the
 * co-located `.integrity-key` over `JSON.stringify(withoutSig, null, 2)`), then
 * hand-edited without re-signing: `tampered`. The edit touches only keys no
 * lock or Guard floor holds, so the re-sign is admissible.
 */
function tamperedConfig(): Buffer {
  const key = randomBytes(32).toString('hex');
  writeFileSync(join(configDir, '.integrity-key'), key, { mode: 0o600 });
  const body = {
    cloudApiKey: SENTINEL,
    actionGuard: { enabled: true, enforce: true },
    defenceMode: 'strict',
    proactiveRecall: false,
  };
  const sig = createHmac('sha256', key).update(JSON.stringify(body, null, 2), 'utf-8').digest('hex');
  const edited = { ...body, defenceMode: 'balanced', proactiveRecall: true, _sig: sig };
  writeFileSync(configFile(), `${JSON.stringify(edited, null, 2)}\n`, { mode: 0o600 });
  return readFileSync(configFile());
}

function runCli(args: string[], memoryDb: string): { status: number | null; stdout: string; stderr: string } {
  const run = spawnSync(process.execPath, [DIST_ENTRY, ...args], {
    cwd: home,
    encoding: 'utf8',
    timeout: 120_000,
    env: {
      PATH: `${fakeBin}:/usr/bin:/bin`,
      HOME: home,
      USERPROFILE: home,
      TMPDIR: tmpdir(),
      SHIELDCORTEX_CONFIG_DIR: configDir,
      SHIELDCORTEX_PROTECTED_ROOT: join(root, 'protected'),
      SHIELDCORTEX_AUDIT_DIR: join(root, 'audit-log'),
      OPENCLAW_HOME: join(root, 'openclaw'),
      CLAUDE_MEMORY_DB: memoryDb,
      npm_config_cache: join(root, 'npm-cache'),
      NO_COLOR: '1',
    },
  });
  return { status: run.status, stdout: run.stdout ?? '', stderr: run.stderr ?? '' };
}

function previewSha(memoryDb: string): string {
  const preview = runCli(['config', '--resign'], memoryDb);
  expect(preview.stdout).toMatch(/config\.json integrity: tampered/);
  const match = preview.stdout.match(/--resign --confirm ([0-9a-f]{64})/);
  expect(match).not.toBeNull();
  return match![1];
}

describe('#647 config --resign --confirm, fresh process: the audit record is real', () => {
  it('records a config_resigned row in the audit database, and the CLI names that row', () => {
    const memoryDb = join(root, 'db', 'memories.db');
    const before = tamperedConfig();
    const confirm = previewSha(memoryDb);
    expect(confirm).toBe(sha256(before));
    // The preview opened no database.
    expect(existsSync(memoryDb)).toBe(false);

    const run = runCli(['config', '--resign', '--confirm', confirm], memoryDb);
    expect(run.stderr).not.toMatch(/AUDIT NOT RECORDED/);
    expect(run.status).toBe(0);
    const printed = run.stdout.match(/Recorded in the audit log as config_resigned \(row (\d+), (.+)\)\./);
    expect(printed).not.toBeNull();
    expect(printed![2]).toBe(memoryDb);

    const [backup] = backups();
    expect(backup).toBeDefined();
    expect(readFileSync(join(configDir, backup)).equals(before)).toBe(true);
    const after = readFileSync(configFile());

    // Read the row back ourselves, from the file, in this process.
    const db = new Database(memoryDb, { readonly: true, fileMustExist: true });
    try {
      const rows = db.prepare(
        "SELECT id, reason, firewall_result, source_type, source_identifier FROM defence_audit WHERE reason LIKE '%config_resigned%'",
      ).all() as Array<{ id: number; reason: string; firewall_result: string; source_type: string; source_identifier: string }>;
      expect(rows).toHaveLength(1);
      const row = rows[0];
      expect(row.id).toBe(Number(printed![1]));
      expect(row.reason.startsWith('[iron-dome:policy-lock] config_resigned')).toBe(true);
      expect(row.reason).toContain('previous verdict tampered');
      expect(row.reason).toContain(`previous sha256 ${sha256(before)}`);
      expect(row.reason).toContain(`new sha256 ${sha256(after)}`);
      expect(row.reason).toContain(join(configDir, backup));
      expect(row.reason).toContain('defenceMode');
      expect(row.reason).not.toContain(SENTINEL);
      expect(row.firewall_result).toBe('ALLOW');
      expect(row.source_type).toBe('cli');
      expect(row.source_identifier).toBe('iron-dome');
    } finally {
      db.close();
    }

    // And the file is valid now — a second preview has nothing to re-sign.
    const again = runCli(['config', '--resign'], memoryDb);
    expect(again.stdout).toMatch(/config\.json integrity: valid/);
    expect(again.stdout).toMatch(/Nothing to re-sign/);
  });

  it('an audit database that cannot be opened refuses the re-sign: exit 1, no backup, bytes unchanged, still tampered', () => {
    // The database's directory is a regular file: nothing can be created
    // under it, so the audit log cannot be opened at all.
    const blocker = join(root, 'not-a-directory');
    writeFileSync(blocker, 'x');
    const memoryDb = join(blocker, 'memories.db');
    const before = tamperedConfig();
    const confirm = previewSha(memoryDb);

    const run = runCli(['config', '--resign', '--confirm', confirm], memoryDb);
    expect(run.status).toBe(1);
    expect(run.stderr).toMatch(/audit log that must record a re-sign could not be opened/);
    expect(run.stderr).toMatch(/Nothing was written/);
    expect(run.stdout).not.toMatch(/Re-signed|Recorded in the audit log/);
    expect(readFileSync(configFile()).equals(before)).toBe(true);
    expect(backups()).toEqual([]);

    const again = runCli(['config', '--resign'], memoryDb);
    expect(again.stdout).toMatch(/config\.json integrity: tampered/);
    expect(again.stdout).toContain(sha256(before));
  });
});
