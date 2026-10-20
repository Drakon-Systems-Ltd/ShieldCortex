import Database from 'better-sqlite3';
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { runAllowlistScan } from '../allowlist-scan.js';
import { stringifyJsonTerminalSafe } from '../term-ui.js';

const UNSAFE_RE = /[\u0080-\u009f\u061c\u200b-\u200f\u2028-\u202e\u2060-\u2064\u2066-\u2069\ufeff]/;
const UNSAFE = '\u009b\u202e\u2066\u2028\u200b';
const JOB_ID = 'aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa';
const NOW = 1_760_000_000_000;

describe('terminal-safe JSON (#786)', () => {
  test('escapes every unsafe code point and round-trips its value', () => {
    const all = [
      ...Array.from({ length: 0x20 }, (_, i) => String.fromCharCode(0x80 + i)),
      '\u061c',
      ...Array.from({ length: 5 }, (_, i) => String.fromCharCode(0x200b + i)),
      ...Array.from({ length: 7 }, (_, i) => String.fromCharCode(0x2028 + i)),
      ...Array.from({ length: 5 }, (_, i) => String.fromCharCode(0x2060 + i)),
      ...Array.from({ length: 4 }, (_, i) => String.fromCharCode(0x2066 + i)),
      '\ufeff',
    ].join('');
    const encoded = stringifyJsonTerminalSafe({ all }, 2)!;
    expect(encoded).not.toMatch(UNSAFE_RE);
    for (const char of all) {
      expect(encoded).toContain(`\\u${char.charCodeAt(0).toString(16).padStart(4, '0')}`);
    }
    expect(JSON.parse(encoded)).toEqual({ all });
  });

  test('keeps ordinary printable text and non-BMP emoji unchanged', () => {
    const value = { text: 'ASCII é ÿ 😀' };
    expect(stringifyJsonTerminalSafe(value, 2)).toBe(JSON.stringify(value, null, 2));
  });

  test('handles 100k characters within a generous linear-time budget', () => {
    const value = ('a'.repeat(99) + '\u009b').repeat(1000);
    const start = performance.now();
    const encoded = stringifyJsonTerminalSafe(value)!;
    expect(performance.now() - start).toBeLessThan(500);
    expect(JSON.parse(encoded)).toBe(value);
  });

  test('allowlist scan JSON escapes source path, item path and denial note without changing their values', async () => {
    const root = mkdtempSync(join(tmpdir(), 'sc-786-'));
    const home = join(root, `home${UNSAFE}`);
    const script = join(home, `script${UNSAFE}.py`);
    const deniedScript = join(root, 'denied.py');
    const hermes = join(home, '.hermes', 'cron', 'jobs.json');
    const dbPath = join(home, '.openclaw', 'state', 'openclaw.sqlite');
    const denialsPath = join(home, '.shieldcortex', 'denials.jsonl');
    const jobName = `job${UNSAFE}`;
    const key = `agent:main:cron:${JOB_ID}:run:r1`;
    const logs: string[] = [];
    const errs: string[] = [];
    try {
      mkdirSync(dirname(hermes), { recursive: true });
      mkdirSync(dirname(dbPath), { recursive: true });
      mkdirSync(dirname(denialsPath), { recursive: true });
      writeFileSync(script, 'print(1)\n');
      writeFileSync(deniedScript, 'print(2)\n');
      writeFileSync(hermes, JSON.stringify({ jobs: [] }));
      const db = new Database(dbPath);
      try {
        db.exec('CREATE TABLE cron_jobs (job_id TEXT, name TEXT, enabled INTEGER, payload_message TEXT, trigger_script TEXT, job_json TEXT)');
        db.exec('CREATE TABLE cron_run_logs (job_id TEXT, session_key TEXT, run_at_ms INTEGER, status TEXT)');
        db.prepare('INSERT INTO cron_jobs (job_id, name, enabled, payload_message) VALUES (?, ?, 1, ?)')
          .run(JOB_ID, jobName, `python3 ${deniedScript}`);
        db.prepare('INSERT INTO cron_run_logs (job_id, session_key, run_at_ms, status) VALUES (?, ?, ?, ?)')
          .run(JOB_ID, key, NOW - 61_000, 'ok');
      } finally {
        db.close();
      }
      writeFileSync(denialsPath, JSON.stringify({
        actionId: 'act-0000000000000001', sessionKey: key,
        detectedAt: new Date(NOW - 60_000).toISOString(),
      }) + '\n');

      const code = await runAllowlistScan(['--json'], {
        home, env: {}, cwd: home, interactive: false, openclawDbPath: dbPath,
        denialsPath, globs: [script], now: NOW, log: (s) => logs.push(s), error: (s) => errs.push(s),
        readEntries: () => [],
      });
      expect(code).toBe(3);
      expect(errs).toEqual([]);
      expect(logs).toHaveLength(1);
      const raw = logs[0];
      expect(raw).not.toMatch(UNSAFE_RE);
      const report = JSON.parse(raw) as {
        sources: { hermes: { path: string } };
        items: Array<{ path: string; cronDenied: string | null }>;
      };
      expect(report.sources.hermes.path).toBe(hermes);
      const item = report.items.find((entry) => entry.path === realpathSync(script));
      expect(item).toBeDefined();
      const deniedItem = report.items.find((entry) => entry.path === realpathSync(deniedScript));
      // The cron-store reader already folds job-name whitespace (including U+2028).
      expect(deniedItem?.cronDenied).toBe(`guard-denied in the last 7 days (job: ${jobName.replace(/\s+/g, ' ')})`);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});
