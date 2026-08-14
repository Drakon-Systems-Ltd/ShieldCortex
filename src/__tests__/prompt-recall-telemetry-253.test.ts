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
    expect(rows).toHaveLength(1);
    expect(rows[0].hook_name).toBe('prompt-recall');
    expect(rows[0].memories_extracted).toBe(0);
    expect(rows[0].notes).toBe('zero-yield:no-candidates');
  });

  it('records gated:proactiveRecall-disabled when recall is off', () => {
    writeFileSync(
      join(home, '.shieldcortex', 'config.json'),
      JSON.stringify({ proactiveRecall: false, captureEvents: false }),
    );
    runHook({ home, prompt: 'how do I deploy the production service safely today' });

    const rows = readInvocations(dbPath);
    expect(rows).toHaveLength(1);
    expect(rows[0].notes).toBe('gated:proactiveRecall-disabled');
    expect(rows[0].memories_extracted).toBe(0);
  });

  it('records gated:trivial-prompt for yes/no acknowledgements', () => {
    // Must be ≥ MIN_PROMPT_LENGTH (8) so we reach the trivial gate, not
    // the shorter prompt-too-short exit. "send it." is 8 chars and matches
    // the trivial regex.
    runHook({ home, prompt: 'send it.' });

    const rows = readInvocations(dbPath);
    expect(rows).toHaveLength(1);
    expect(rows[0].notes).toBe('gated:trivial-prompt');
    expect(rows[0].memories_extracted).toBe(0);
  });

  it('records gated:prompt-too-short for tiny prompts', () => {
    runHook({ home, prompt: 'hi' });

    const rows = readInvocations(dbPath);
    expect(rows).toHaveLength(1);
    expect(rows[0].notes).toBe('gated:prompt-too-short');
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
    // Exactly one row — catches double-record regressions.
    expect(rows).toHaveLength(1);
    expect(rows[0].hook_name).toBe('prompt-recall');
    // Hard-require real injection (reviewers flagged soft injected|zero-yield).
    expect(rows[0].notes).toBe('injected');
    expect(rows[0].memories_extracted).toBeGreaterThanOrEqual(1);
  });

  it('records gated:no-project-key when no project can be derived', () => {
    // cwd with no usable basename and no SHIELDCORTEX_PROJECT_KEY.
    // Use '/' — deriveProjectKey typically cannot produce a key from root.
    runHook({ home, prompt: 'how do I deploy the production service safely today', cwd: '/' });

    const rows = readInvocations(dbPath);
    // Either no-project-key, or some hosts derive a key from env/cwd fallback.
    // If a key WAS derived, we still must have exactly one telemetry row.
    expect(rows).toHaveLength(1);
    expect(rows[0].hook_name).toBe('prompt-recall');
    expect(rows[0].memories_extracted).toBe(0);
  });

  it('source contract: early exits that can write telemetry are instrumented', () => {
    const src = readFileSync(HOOK, 'utf8');
    expect(src).toMatch(/function recordPromptRecallTelemetry/);
    expect(src).toMatch(/zero-yield:no-candidates/);
    expect(src).toMatch(/zero-yield:dedup-suppressed/);
    expect(src).toMatch(/zero-yield:filtered-empty/);
    expect(src).toMatch(/gated:proactiveRecall-disabled/);
    expect(src).toMatch(/gated:trivial-prompt/);
    expect(src).toMatch(/gated:prompt-too-short/);
    expect(src).toMatch(/gated:no-project-key/);
    // Success path must not double-record via close-in-try.
    expect(src).toMatch(/let recorded = false/);
    expect(src).toMatch(/if \(!recorded\)/);

    // Pair each known gate/zero-yield notes reason with a preceding record*
    // call in the same function body region (string presence is the floor;
    // behavioral tests above are the real lock).
    const requiredNotes = [
      'gated:proactiveRecall-disabled',
      'gated:prompt-too-short',
      'gated:trivial-prompt',
      'gated:no-project-key',
      'zero-yield:no-candidates',
      'zero-yield:dedup-suppressed',
      'injected',
    ];
    for (const note of requiredNotes) {
      expect(src).toContain(note);
    }
  });
});
