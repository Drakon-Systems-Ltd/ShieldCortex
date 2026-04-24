import fs from 'fs';
import path from 'path';
import { createHash } from 'crypto';
import { describe, expect, it } from '@jest/globals';

/**
 * OpenClaw's claude-cli session binding tracks `extraSystemPromptHash` — the
 * SHA over everything that feeds into the system prompt. If that hash flips
 * between turns, the binding resets (reason=system-prompt) and the session
 * loses context mid-flight.
 *
 * SC contributes to the system prompt through exactly one artefact:
 * the ~/.claude/CLAUDE.md block installed by `setupClaudeCode()`. As long as
 * that text is deterministic (no timestamps, no env-dependent values, no
 * random nonces), re-running the installer on the same SC version produces
 * identical bytes — and the system-prompt hash stays stable.
 *
 * These tests lock in that invariant through static source analysis, so they
 * catch dynamic content regressions even without running the installer.
 * (Runtime invocation isn't viable here because setupClaudeMd imports the
 * OpenClaw setup module, which trips the baseline ESM/CJS issue in Jest.)
 */
describe('ShieldCortex system-prompt hash stability', () => {
  const repoRoot = path.resolve(__dirname, '..', '..');
  const claudeMdSource = path.join(repoRoot, 'src', 'setup', 'claude-md.ts');
  const hookDir = path.join(repoRoot, 'hooks', 'openclaw', 'cortex-memory');

  function readSource(): string {
    return fs.readFileSync(claudeMdSource, 'utf-8');
  }

  function hashFile(file: string): string {
    return createHash('sha256').update(fs.readFileSync(file)).digest('hex');
  }

  it('CLAUDE.md INSTRUCTIONS block has no runtime-dependent interpolations', () => {
    const source = readSource();
    const instructionsMatch = source.match(/const INSTRUCTIONS = `([\s\S]*?)`;/);
    expect(instructionsMatch).not.toBeNull();

    const body = instructionsMatch![1];
    const interpolations = body.match(/\$\{[^}]+\}/g) ?? [];

    // Only allow interpolations of module-level UPPER_SNAKE_CASE constants.
    // Anything else — Date, randomUUID, process.env, function calls — flips
    // the file bytes between installs and resets the binding hash.
    for (const interp of interpolations) {
      expect(interp).toMatch(/^\$\{[A-Z_][A-Z0-9_]*\}$/);
    }
  });

  it('claude-md.ts does not import Date, randomUUID, or other time/nonce sources at module scope', () => {
    const source = readSource();
    // Strip strings and comments to avoid false positives, then scan for
    // forbidden identifiers at the file level.
    const stripped = source
      .replace(/`[\s\S]*?`/g, '""')   // template strings
      .replace(/"[^"]*"/g, '""')       // double-quoted
      .replace(/'[^']*'/g, "''")       // single-quoted
      .replace(/\/\/[^\n]*/g, '')      // line comments
      .replace(/\/\*[\s\S]*?\*\//g, ''); // block comments

    // These are the red flags — they'd produce non-reproducible bytes.
    const forbiddenAtModuleScope = [
      /\brandomUUID\s*\(/,
      /\bDate\s*\.\s*now\s*\(/,
      /\bnew\s+Date\s*\(/,
      /\bMath\s*\.\s*random\s*\(/,
    ];
    for (const pattern of forbiddenAtModuleScope) {
      expect(stripped).not.toMatch(pattern);
    }
  });

  it('all hook files exist on disk and hash deterministically', () => {
    const files = ['HOOK.md', 'handler.ts', 'runtime.mjs'];
    for (const file of files) {
      const full = path.join(hookDir, file);
      expect(fs.existsSync(full)).toBe(true);
      // Hash twice — if the filesystem returned different bytes the second
      // time (e.g. somebody regenerated on read), this fails.
      expect(hashFile(full)).toBe(hashFile(full));
    }
  });

  it('HOOK.md documents that bootstrap context injection is disabled (matches handler.ts behaviour)', () => {
    // handler.ts line ~500 comment states injection was disabled in v2026.2.26
    // because it caused 40x duplication of CORTEX_MEMORY.md in the system prompt.
    // HOOK.md must not claim injection still happens or operators will
    // misconfigure their setups.
    const hookMd = fs.readFileSync(path.join(hookDir, 'HOOK.md'), 'utf-8');
    const handlerSource = fs.readFileSync(path.join(hookDir, 'handler.ts'), 'utf-8');

    // Handler keeps its disabled-injection note; that's the source of truth.
    expect(handlerSource).toMatch(/Context injection disabled as of v2026\.2\.26/);

    // If HOOK.md still promises injection happens, fail.
    const bootstrapSection = hookMd.match(/### On Session Start[\s\S]*?(?=\n## |\n### )/);
    if (bootstrapSection) {
      const text = bootstrapSection[0];
      expect(text).not.toMatch(/Injects them into the agent's bootstrap context/);
    }
  });
});
