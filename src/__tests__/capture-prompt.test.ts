/**
 * Tests for the UserPromptSubmit credential-redaction sanitiser at
 * `scripts/lib/capture-prompt.mjs` (Fix #10, v4.28).
 *
 * The hook used to write the raw prompt verbatim into `session_events`. The
 * sanitiser routes the prompt through the defence pipeline's credential
 * scanner + sensitivity classifier before it lands in the DB so a pasted
 * `.env` file never ends up persisted in cleartext.
 *
 * Synthetic credentials in this file are built via string concatenation
 * (e.g. 'sk_' + 'live_' + 'abcdef…') so GitHub's secret-scanner doesn't
 * choke on the test corpus.
 */
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { closeDatabase, getDatabase, initDatabase } from '../database/init.js';
import { classifySensitivity } from '../defence/sensitivity/index.js';
// @ts-expect-error — JS module with no .d.ts
import { recordSessionEvent } from '../../scripts/lib/session-capture.mjs';

// `.mjs` import — Jest with ESM support resolves this at runtime.
// @ts-expect-error — JS module with no .d.ts
import * as captureMod from '../../scripts/lib/capture-prompt.mjs';

const { captureForSessionEvent, __resetCacheForTests } = captureMod as {
  captureForSessionEvent: (text: string) => Promise<{
    redactedText: string;
    sensitivity: string;
    findings: unknown[];
    redactedCount: number;
  }>;
  __resetCacheForTests: () => void;
};

beforeEach(() => {
  __resetCacheForTests();
});

afterEach(() => {
  __resetCacheForTests();
});

describe('captureForSessionEvent', () => {
  describe('#858: stored prompt sensitivity after redaction', () => {
    beforeEach(() => {
      closeDatabase();
      initDatabase(':memory:');
    });

    afterEach(() => {
      closeDatabase();
    });

    // Unlike a Stripe key, this synthetic OpenAI format is detected by the
    // credential scanner but not the sensitivity classifier's key patterns.
    const secret = 'sk-' + 'abcdefghijklmnopqrstuvwxyz';
    const personal = 'Surprise birthday trip for my wife in March.';

    it.each([
      { name: 'PERSONAL with a credential', raw: `${personal} ${secret}`, classified: 'PERSONAL', stored: 'CONFIDENTIAL', redacted: true },
      { name: 'PERSONAL without a credential', raw: personal, classified: 'PERSONAL', stored: 'PERSONAL', redacted: false },
      { name: 'RESTRICTED with a credential', raw: `${personal} api_key=${secret}`, classified: 'RESTRICTED', stored: 'RESTRICTED', redacted: true },
    ])('stores $name as $stored', async ({ raw, classified, stored, redacted }) => {
      // Prove the actual classifier reaches the tier under test, not a
      // higher tier that would make the redaction-floor check vacuous.
      expect(classifySensitivity(raw, '').level).toBe(classified);
      const result = await captureForSessionEvent(raw);
      if (redacted) {
        expect(result.redactedCount).toBeGreaterThan(0);
        expect(result.redactedText).not.toContain(secret);
        expect(result.redactedText).toContain('[REDACTED-');
      } else {
        expect(result.redactedCount).toBe(0);
        expect(result.redactedText).toBe(raw);
      }

      // Same capture → writer boundary as prompt-recall-hook.mjs; inspect
      // the persisted row rather than only the sanitiser's return value.
      const db = getDatabase();
      const id = recordSessionEvent(db, {
        session_id: 'sc-858',
        ts: '2026-01-01T00:00:00Z',
        kind: 'prompt',
        actor: 'user',
        payload: { text: result.redactedText },
        sensitivity_level: result.sensitivity,
      });
      expect(typeof id).toBe('number');
      const row = db.prepare('SELECT payload, sensitivity_level FROM session_events WHERE id = ?')
        .get(id) as { payload: string; sensitivity_level: string };
      expect(JSON.parse(row.payload)).toEqual({ text: result.redactedText });
      expect(row.sensitivity_level).toBe(stored);
    });
  });

  it('redacts a synthetic credential and elevates sensitivity', async () => {
    // Built via concatenation so GitHub's secret-scanner skips it.
    const secret = 'sk_' + 'live_' + 'abcdefghijklmnopqrstuvwx';
    const raw = `please debug this token: ${secret} thanks`;

    const result = await captureForSessionEvent(raw);

    expect(result.redactedText).not.toContain(secret);
    expect(result.redactedCount).toBeGreaterThan(0);
    expect(['CONFIDENTIAL', 'RESTRICTED']).toContain(result.sensitivity);
    expect(Array.isArray(result.findings)).toBe(true);
  });

  it('passes a benign prompt through untouched and tags non-sensitive', async () => {
    const raw = 'can you help me refactor this function to be cleaner';

    const result = await captureForSessionEvent(raw);

    expect(result.redactedText).toBe(raw);
    expect(result.redactedCount).toBe(0);
    // Classifier returns PUBLIC for content with no sensitivity markers; the
    // wrapper only forces ≥CONFIDENTIAL when credentials are found. Either
    // PUBLIC or INTERNAL is acceptable for a benign prompt.
    expect(['PUBLIC', 'INTERNAL']).toContain(result.sensitivity);
    expect(result.findings).toEqual([]);
  });

  it('handles empty / non-string input without throwing', async () => {
    const empty = await captureForSessionEvent('');
    expect(empty.redactedText).toBe('');
    expect(empty.redactedCount).toBe(0);

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const garbage = await captureForSessionEvent(null as any);
    expect(garbage.redactedText).toBe('');
    expect(garbage.redactedCount).toBe(0);
  });

  it('falls back to fail-closed placeholder when defence modules cannot load', async () => {
    // Spawn a child node process running the .mjs in a workdir where the
    // adjacent `dist/defence` directory cannot be resolved. The loader's
    // dynamic-import will throw and the wrapper must return the
    // placeholder shape — that's the contract we need to enforce.
    const { spawnSync } = await import('child_process');
    const { mkdtempSync, mkdirSync, copyFileSync, writeFileSync, rmSync } =
      await import('fs');
    const { tmpdir } = await import('os');
    const { join, dirname, resolve } = await import('path');
    const { fileURLToPath } = await import('url');

    // Build a sandbox that has scripts/lib/capture-prompt.mjs in the right
    // relative position to its (non-existent) ../../dist/ — i.e. the script
    // resolves dist to a directory we never create. The loader catches the
    // import failure and returns null → wrapper returns the placeholder.
    const sandbox = mkdtempSync(join(tmpdir(), 'sc-capture-test-'));
    try {
      const sourceMjs = resolve(
        dirname(fileURLToPath(import.meta.url)),
        '..',
        '..',
        'scripts',
        'lib',
        'capture-prompt.mjs',
      );
      const targetDir = join(sandbox, 'scripts', 'lib');
      mkdirSync(targetDir, { recursive: true });
      copyFileSync(sourceMjs, join(targetDir, 'capture-prompt.mjs'));

      // Write a tiny runner that imports the copied module and prints JSON.
      const runner = join(sandbox, 'run.mjs');
      writeFileSync(
        runner,
        `import { captureForSessionEvent } from './scripts/lib/capture-prompt.mjs';
const r = await captureForSessionEvent('hello world');
process.stdout.write(JSON.stringify(r));
`,
      );

      const result = spawnSync(process.execPath, [runner], {
        cwd: sandbox,
        encoding: 'utf8',
      });

      expect(result.status).toBe(0);
      const parsed = JSON.parse(result.stdout) as {
        redactedText: string;
        sensitivity: string;
        findings: unknown[];
        redactedCount: number;
      };
      expect(parsed.redactedText).toContain('defence_unavailable');
      expect(parsed.sensitivity).toBe('RESTRICTED');
      expect(parsed.redactedCount).toBe(0);
      expect(parsed.findings).toEqual([]);
      // Wrapper should also have logged a stderr warning.
      expect(result.stderr).toMatch(/shieldcortex capture-prompt/);
    } finally {
      rmSync(sandbox, { recursive: true, force: true });
    }
  });
});
