/**
 * Auto-origin salience cap for the `remember` tool.
 *
 * Background — the "salience wall": ~80% of stored memories sit at salience=1.0,
 * so salience can no longer rank anything. One leak is the MCP `remember` tool:
 * it maps `importance` to a fixed salience ({low:0.3, normal:0.5, high:0.8,
 * critical:1.0}) and passes it straight through to addMemory. The OpenClaw hook
 * shells out `remember` with importance:"high"/"critical" AND sourceType:"hook"
 * (handler.ts session-end/session-stop/keyword-trigger paths), which lands rows
 * at 0.8/1.0 — bypassing the 0.6 AUTO_EXTRACT_SALIENCE_CAP that the dedicated
 * auto-extract writer already enforces.
 *
 * Fix (defence-in-depth): when a `remember` call carries an automated/hook
 * source (source.type === 'hook'), hard-cap the importance-derived salience at
 * 0.6. Genuine interactive remembers (a human/agent deliberately saving — no
 * source, or a user/cli/agent source) stay UNCAPPED so deliberate intent is
 * preserved. This holds even if a stale, un-refactored OpenClaw hook keeps
 * calling remember with importance:"high".
 */

import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { initDatabase, closeDatabase } from '../database/init.js';
import { getMemoryById } from '../memory/store.js';
import { executeRemember } from '../tools/remember.js';

// Canonical value lives in scripts/lib/extract-memorable-segments.mjs:24
// (AUTO_EXTRACT_SALIENCE_CAP = 0.6). That is a build-script .mjs outside the
// compiled src/ surface, so we assert the numeric contract here.
const AUTO_EXTRACT_SALIENCE_CAP = 0.6;

describe('remember tool — auto/hook-origin salience cap', () => {
  beforeEach(() => {
    initDatabase(':memory:');
  });

  afterEach(() => {
    closeDatabase();
  });

  it('caps a hook-origin remember (importance:critical) at the 0.6 auto-extract cap', async () => {
    // Mirrors the real OpenClaw hook call shape (handler.ts onSessionEnd):
    // flat sourceType/sourceIdentifier + importance.
    const result = await executeRemember({
      title: 'Hook-saved decision',
      content: 'The session ended and the hook auto-saved this with critical importance.',
      category: 'architecture',
      project: 'openclaw',
      importance: 'critical',
      tags: ['auto-extracted', 'openclaw-hook'],
      sourceType: 'hook',
      sourceIdentifier: 'openclaw-session-end',
    });

    expect(result.success).toBe(true);
    const stored = getMemoryById(result.memory!.id);
    expect(stored).not.toBeNull();
    expect(stored!.salience).toBeLessThanOrEqual(AUTO_EXTRACT_SALIENCE_CAP);
  });

  it('caps a hook-origin remember passed as a nested source object', async () => {
    const result = await executeRemember({
      title: 'Hook keyword trigger',
      content: 'A keyword trigger fired in the OpenClaw hook and saved this note.',
      category: 'note',
      project: 'openclaw',
      importance: 'critical',
      source: { type: 'hook', identifier: 'openclaw-keyword:remember-this' },
    });

    expect(result.success).toBe(true);
    const stored = getMemoryById(result.memory!.id);
    expect(stored!.salience).toBeLessThanOrEqual(AUTO_EXTRACT_SALIENCE_CAP);
  });

  it('does NOT cap a genuine interactive remember (importance:critical stays 1.0)', async () => {
    // No source passed — an agent/human deliberately saving something. The
    // importance→salience map should be honoured verbatim.
    const result = await executeRemember({
      title: 'User-saved critical fact',
      content: 'The human explicitly asked to remember this as critically important.',
      category: 'note',
      project: 'interactive-test',
      importance: 'critical',
    });

    expect(result.success).toBe(true);
    const stored = getMemoryById(result.memory!.id);
    expect(stored!.salience).toBe(1.0);
  });

  it('does NOT cap an interactive remember that declares a non-hook source', async () => {
    const result = await executeRemember({
      title: 'Agent-saved critical fact',
      content: 'An agent deliberately saved this with critical importance via a user source.',
      category: 'note',
      project: 'interactive-test',
      importance: 'critical',
      source: { type: 'user', identifier: 'direct' },
    });

    expect(result.success).toBe(true);
    const stored = getMemoryById(result.memory!.id);
    expect(stored!.salience).toBe(1.0);
  });
});
