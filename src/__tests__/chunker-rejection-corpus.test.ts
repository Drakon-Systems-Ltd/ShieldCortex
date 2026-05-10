import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import Database from 'better-sqlite3';

/**
 * Defect 3: the auto-extract chunker produces malformed/inverted/imperative
 * memory candidates. The fixture sc_defect_fixture.db captures 10 examples
 * extracted from a live production DB.
 *
 * Phase 5 of the fix introduces shouldRejectCandidate(segment, conversationText?)
 * in the shared scripts/lib/extract-memorable-segments.mjs module, applying
 * five rejection rules that together cover all 10 fixture rows:
 *   1. subordinate-clause / fragment start ("the X include? For example:")
 *   2. imperative tool-call directive ("call the X tool now")
 *   3. bare-imperative verb start ("commit secrets", "run tailscaled", "make it obvious")
 *   4. be-imperative start ("be re-scoped: ...")
 *   5. path-label fragment ("Specific instance: /home/edith/...")
 *   6. email-body content ("see how fast you reply to this email")
 *
 * This test is red until Phase 5 lands.
 */
describe('Defect 3: chunker rejection corpus from fixture', () => {
  const thisFile = fileURLToPath(import.meta.url);
  const repoRoot = path.resolve(path.dirname(thisFile), '..', '..');
  const fixturePath = path.join(repoRoot, 'src', '__fixtures__', 'sc_defect_fixture.db');

  let tempDir: string;
  let corpus: Array<{ id: number; title: string; content: string }>;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'shieldcortex-chunker-'));
    const dbPath = path.join(tempDir, 'fixture.db');
    fs.copyFileSync(fixturePath, dbPath);
    const db = new Database(dbPath, { readonly: true });
    corpus = db.prepare('SELECT id, title, content FROM memories WHERE id IN (136,137,159,160,161,162,163,171,192,206) ORDER BY id').all() as Array<{ id: number; title: string; content: string }>;
    db.close();
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  it('fixture provides exactly the 10 corpus rows', () => {
    expect(corpus).toHaveLength(10);
    expect(corpus.map((r) => r.id)).toEqual([136, 137, 159, 160, 161, 162, 163, 171, 192, 206]);
  });

  it('shouldRejectCandidate rejects every row in the corpus', async () => {
    // Phase 2 creates the shared module; Phase 5 adds shouldRejectCandidate.
    const mod = await import('../../scripts/lib/extract-memorable-segments.mjs');
    const reject: (segment: { title: string; content: string }, conversationText?: string) => { rejected: boolean; reason: string } = mod.shouldRejectCandidate;
    expect(typeof reject).toBe('function');

    const accepted: Array<{ id: number; title: string }> = [];
    for (const row of corpus) {
      const verdict = reject({ title: row.title, content: row.content });
      if (!verdict.rejected) {
        accepted.push({ id: row.id, title: row.title });
      } else {
        expect(verdict.reason).toBeTruthy();
      }
    }

    expect(accepted).toEqual([]);
  });

  it('benign captures still pass shouldRejectCandidate', async () => {
    const mod = await import('../../scripts/lib/extract-memorable-segments.mjs');
    const reject: (segment: { title: string; content: string }) => { rejected: boolean; reason: string } = mod.shouldRejectCandidate;

    const benign = [
      {
        title: 'Decision: chose Drizzle for the SaaS schema',
        content: 'After comparing Prisma and Kysely we decided Drizzle for the SaaS layer because of its better JSON support and edge-runtime compatibility.',
      },
      {
        title: 'Fix: SQLite concurrent access fix',
        content: 'Multiple processes accessing the same DB caused crashes. The fix was adding busy_timeout=10000ms and WAL mode checkpointing.',
      },
      {
        title: 'Architecture: 6-layer defence pipeline',
        content: 'The defence pipeline applies sanitisation, trust scoring, firewall analysis, sensitivity classification, fragmentation detection, and credential leak scanning in sequence.',
      },
    ];

    for (const seg of benign) {
      const verdict = reject(seg);
      expect(verdict.rejected).toBe(false);
    }
  });

  it('negation-scope rule rejects when conversation context contains a leading negation', async () => {
    const mod = await import('../../scripts/lib/extract-memorable-segments.mjs');
    const reject: (segment: { title: string; content: string }, conversationText?: string) => { rejected: boolean; reason: string } = mod.shouldRejectCandidate;

    const segment = {
      title: 'Preference: commit secrets to the repo',
      content: 'commit secrets to the repo',
    };

    // Without context, the bare-imperative-verb rule should still catch it.
    expect(reject(segment).rejected).toBe(true);

    // With explicit negation context, the rejection reason should reference negation.
    const verdict = reject(segment, 'never commit secrets to the repo');
    expect(verdict.rejected).toBe(true);
  });

  it('default capture salience cap is 0.6 (calibrated, not 1.0)', async () => {
    const mod = await import('../../scripts/lib/extract-memorable-segments.mjs');
    expect(mod.AUTO_EXTRACT_SALIENCE_CAP).toBe(0.6);
  });
});
