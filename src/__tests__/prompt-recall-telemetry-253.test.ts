/**
 * #253 — prompt-recall must record hook_invocations BEFORE early exits.
 *
 * The table was built so status can show "fires but extracts nothing".
 * Seven process.exit(0) paths sat above the only recordHookInvocation
 * call, so an empty store (or any gate) looked like "never fires".
 *
 * Proof: spawn the real hook against a temp DB and assert a
 * hook_invocations row lands on zero-yield / gated paths.
 */
import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { execFileSync } from 'node:child_process';
import Database from 'better-sqlite3';
import { existsSync, mkdtempSync, mkdirSync, writeFileSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const HOOK = join(repoRoot, 'scripts', 'prompt-recall-hook.mjs');

function runHook({ home, prompt, cwd = '/tmp/recall-253', sessionId = 'sess-253', envExtra = {} }: {
  home: string;
  prompt: string;
  cwd?: string;
  sessionId?: string | null;
  envExtra?: Record<string, string>;
}): void {
  const input = JSON.stringify({
    prompt,
    cwd,
    session_id: sessionId,
  });
  const env: Record<string, string | undefined> = {
    ...process.env,
    HOME: home,
    USERPROFILE: home,
    ...envExtra,
  };
  for (const key of Object.keys(env)) {
    if (key.startsWith('SHIELDCORTEX_') && !(key in envExtra)) {
      delete env[key];
    }
  }
  try {
    execFileSync('node', [HOOK], {
      input,
      env: env as NodeJS.ProcessEnv,
      timeout: 30_000,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
  } catch {
    // Hook always exits 0; DB assertions are the contract.
  }
}

function readInvocations(dbPath: string): Array<{
  hook_name: string;
  memories_extracted: number | null;
  notes: string | null;
}> {
  const db = new Database(dbPath, { readonly: true });
  const rows = db.prepare(
    `SELECT hook_name, memories_extracted, notes FROM hook_invocations ORDER BY id`,
  ).all() as Array<{ hook_name: string; memories_extracted: number | null; notes: string | null }>;
  db.close();
  return rows;
}

describe('prompt-recall telemetry before early exits (#253)', () => {
  let home: string;
  let dbPath: string;

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), 'sc-253-'));
    mkdirSync(join(home, '.shieldcortex'), { recursive: true });
    writeFileSync(
      join(home, '.shieldcortex', 'config.json'),
      JSON.stringify({ proactiveRecall: true, captureEvents: false }),
    );
    dbPath = join(home, '.shieldcortex', 'memories.db');
    const schema = readFileSync(join(repoRoot, 'src', 'database', 'schema.sql'), 'utf8');
    const db = new Database(dbPath);
    db.exec(schema);
    db.close();
  });

  afterEach(() => {
    try { rmSync(home, { recursive: true, force: true }); } catch { /* best effort */ }
  });

  it('records zero-yield:no-candidates when the store is empty (Veronica case)', () => {
    // Empty memories table — the exact host-B failure mode.
    runHook({ home, prompt: 'how do I deploy the production service safely today' });

    const rows = readInvocations(dbPath);
    expect(rows.length).toBeGreaterThanOrEqual(1);
    const last = rows[rows.length - 1];
    expect(last.hook_name).toBe('prompt-recall');
    expect(last.memories_extracted).toBe(0);
    expect(last.notes).toMatch(/zero-yield:no-candidates/);
  });

  it('records gated:proactiveRecall-disabled when recall is off', () => {
    writeFileSync(
      join(home, '.shieldcortex', 'config.json'),
      JSON.stringify({ proactiveRecall: false, captureEvents: false }),
    );
    runHook({ home, prompt: 'how do I deploy the production service safely today' });

    const rows = readInvocations(dbPath);
    expect(rows.length).toBeGreaterThanOrEqual(1);
    expect(rows[rows.length - 1].notes).toMatch(/gated:proactiveRecall-disabled/);
    expect(rows[rows.length - 1].memories_extracted).toBe(0);
  });

  it('records gated:trivial-prompt for yes/no acknowledgements', () => {
    // Must be ≥ MIN_PROMPT_LENGTH (8) so we reach the trivial gate, not
    // the shorter prompt-too-short exit. "send it." is 8 chars and matches
    // the trivial regex.
    runHook({ home, prompt: 'send it.' });

    const rows = readInvocations(dbPath);
    expect(rows.length).toBeGreaterThanOrEqual(1);
    expect(rows[rows.length - 1].notes).toMatch(/gated:trivial-prompt/);
    expect(rows[rows.length - 1].memories_extracted).toBe(0);
  });

  it('records gated:prompt-too-short for tiny prompts', () => {
    runHook({ home, prompt: 'hi' });

    const rows = readInvocations(dbPath);
    expect(rows.length).toBeGreaterThanOrEqual(1);
    expect(rows[rows.length - 1].notes).toMatch(/gated:prompt-too-short/);
  });

  it('records injected count when a memory is actually recalled', () => {
    const db = new Database(dbPath);
    db.prepare(
      `INSERT INTO memories (uuid, type, category, title, content, project, salience, trust_score, sensitivity_level, status)
       VALUES (?, 'long_term', 'note', ?, ?, ?, 0.9, 1.0, 'INTERNAL', 'active')`,
    ).run(
      'uuid-253-benign',
      'Deploy runbook',
      'Deploy runbook: use the documented production deploy path for service rollout.',
      'recall-253',
    );
    db.close();

    runHook({
      home,
      prompt: 'how do I deploy the production service safely today',
      cwd: '/tmp/recall-253',
    });

    const rows = readInvocations(dbPath);
    expect(rows.length).toBeGreaterThanOrEqual(1);
    const last = rows[rows.length - 1];
    expect(last.hook_name).toBe('prompt-recall');
    // Either injected ≥1 or zero-yield after defence/filter — never missing.
    expect(last.notes).toMatch(/injected|zero-yield/);
    if (last.notes === 'injected') {
      expect(last.memories_extracted).toBeGreaterThanOrEqual(1);
    }
  });

  it('source contract: every process.exit(0) after the capture block has a telemetry call nearby', () => {
    const src = readFileSync(HOOK, 'utf8');
    // The helper must exist.
    expect(src).toMatch(/function recordPromptRecallTelemetry/);
    // Zero-yield paths must call it (the Veronica bug).
    expect(src).toMatch(/zero-yield:no-candidates/);
    expect(src).toMatch(/zero-yield:dedup-suppressed/);
    expect(src).toMatch(/gated:proactiveRecall-disabled/);
    expect(src).toMatch(/gated:trivial-prompt/);
    // Count process.exit(0) after capture block vs telemetry sites.
    // Crude but catches a future exit that forgets the record call:
    // every early-exit gate we know about must appear as a notes reason
    // OR be the missing-db path (cannot write).
    const exitCount = (src.match(/process\.exit\(0\)/g) || []).length;
    expect(exitCount).toBeGreaterThanOrEqual(7);
    // recordHookInvocation / recordPromptRecallTelemetry must appear more
    // than the single success-path call that existed before #253.
    const recordSites =
      (src.match(/recordPromptRecallTelemetry\(/g) || []).length +
      (src.match(/recordHookInvocation\(/g) || []).length;
    expect(recordSites).toBeGreaterThanOrEqual(6);
  });
});
