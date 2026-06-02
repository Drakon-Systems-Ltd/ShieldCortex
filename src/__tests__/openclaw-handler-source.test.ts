import { describe, expect, it } from '@jest/globals';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

/**
 * Text-level guards for the OpenClaw cortex-memory handler (Task 6a).
 *
 * The handler is jiti-loaded inside the long-lived OpenClaw gateway and pulls
 * in runtime side-effects, so we DON'T import/execute it here. Instead we
 * assert on its source text to lock in the gateway-safety + quality invariants
 * that a refactor could silently regress:
 *
 *   - it routes through the pure chunker wrapper (openclaw-extract)
 *   - it no longer mints importance:high / importance:critical memories
 *     (the "salience wall" the centralized chunker exists to remove)
 *   - it NEVER touches the native DB path inside the gateway
 *     (saveAutoExtractedMemory / initDatabase install global shutdown
 *      handlers + open better-sqlite3 → confirmed crash-loop mechanism)
 */

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const HANDLER_PATH = path.resolve(
  __dirname,
  '../../hooks/openclaw/cortex-memory/handler.ts'
);
const handlerSource = readFileSync(HANDLER_PATH, 'utf-8');

describe('openclaw cortex-memory handler — source invariants', () => {
  it('routes extraction through the openclaw-extract wrapper', () => {
    expect(handlerSource).toContain('openclaw-extract');
  });

  it('no longer mints importance:high or importance:critical memories', () => {
    expect(handlerSource).not.toMatch(/importance:\s*["']high["']/);
    expect(handlerSource).not.toMatch(/importance:\s*["']critical["']/);
  });

  it('persists with importance:"normal" (capped, under the wall)', () => {
    expect(handlerSource).toMatch(/importance:\s*["']normal["']/);
  });

  it('never references the native DB persistence path in the gateway', () => {
    expect(handlerSource).not.toContain('saveAutoExtractedMemory');
    expect(handlerSource).not.toContain('initDatabase');
    expect(handlerSource).not.toContain('getDatabase');
  });

  it('preserves the exact source-identifier strings (P1 backfill / P5 dedup targets)', () => {
    expect(handlerSource).toContain('openclaw-session-end');
    expect(handlerSource).toContain('openclaw-session-stop');
    expect(handlerSource).toContain('openclaw-keyword:');
  });

  it('drops the bespoke regex extractor (PATTERNS / extractMemories)', () => {
    expect(handlerSource).not.toMatch(/function\s+extractMemories\b/);
    expect(handlerSource).not.toMatch(/const\s+PATTERNS\b/);
  });

  it('every KEYWORD_TRIGGERS entry carries an extractorType (authoritative classification)', () => {
    const block = handlerSource.match(/const KEYWORD_TRIGGERS = \[([\s\S]*?)\];/);
    expect(block).not.toBeNull();
    const body = block![1];

    // Count phrase declarations and extractorType declarations — they must be 1:1.
    const phraseCount = (body.match(/phrase:/g) || []).length;
    const extractorTypeCount = (body.match(/extractorType:/g) || []).length;
    expect(phraseCount).toBeGreaterThan(0);
    expect(extractorTypeCount).toBe(phraseCount);

    // Each extractorType value must be one of the chunker's valid keys.
    const VALID_EXTRACTOR_TYPES = [
      'decision',
      'error-fix',
      'learning',
      'architecture',
      'preference',
      'important-note',
    ];
    const usedTypes = [...body.matchAll(/extractorType:\s*["']([^"']+)["']/g)].map((m) => m[1]);
    expect(usedTypes).toHaveLength(phraseCount);
    for (const t of usedTypes) {
      expect(VALID_EXTRACTOR_TYPES).toContain(t);
    }
  });

  it('passes the trigger extractorType into extractKeywordMemory (not re-guessed from content)', () => {
    expect(handlerSource).toMatch(
      /extractKeywordMemory\(\s*content\s*,\s*matchedTrigger\.extractorType\s*\)/
    );
  });
});
