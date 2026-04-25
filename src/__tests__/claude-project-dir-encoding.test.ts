import { describe, expect, it } from '@jest/globals';
// @ts-expect-error -- importing a .mjs util for the encoder under test
import { encodeClaudeProjectDir } from '../../scripts/lib/claude-project-dir.mjs';

/**
 * Locks in the Claude Code project-dir encoding. Earlier versions of the
 * pre-compact hook only replaced `/` with `-` and left dots intact, so any
 * session under a dotfile-prefixed dir (e.g. `~/.openclaw/workspace`)
 * silently extracted zero memories: the lookup path
 * `-home-u-.openclaw-workspace` never matched the folder Claude Code
 * actually wrote (`-home-u--openclaw-workspace`).
 *
 * Claude Code's encoding rule (verified empirically on Jarvis 2026-04-25):
 * replace BOTH `/` (and `\` on Windows) AND `.` with `-`, with a leading
 * `-` separator before the first path component.
 */
describe('encodeClaudeProjectDir — Claude Code project-folder slug', () => {
  // Test table reproduced from the v4.12.4 fix prompt
  const cases: Array<{ cwd: string; expected: string; note?: string }> = [
    { cwd: '/home/u/.openclaw/workspace', expected: '-home-u--openclaw-workspace', note: 'dotfile-prefixed dir (the bug repro)' },
    { cwd: '/home/u/foo.bar/baz',         expected: '-home-u-foo-bar-baz',         note: 'dot inside a path component' },
    { cwd: '/home/u/regular/path',        expected: '-home-u-regular-path',        note: 'no dots — same as before' },
    { cwd: 'C:\\Users\\u\\.openclaw\\workspace', expected: '-C--Users-u--openclaw-workspace', note: 'Windows path with dotfile dir' },
  ];

  for (const { cwd, expected, note } of cases) {
    it(`encodes ${JSON.stringify(cwd)} → ${expected}${note ? ` (${note})` : ''}`, () => {
      expect(encodeClaudeProjectDir(cwd)).toBe(expected);
    });
  }

  it('is idempotent on a single-segment input (defensive)', () => {
    expect(encodeClaudeProjectDir('/foo')).toBe('-foo');
  });

  it('coerces non-string input rather than throwing', () => {
    // The hook is invoked from a JSON pipe; defensive against a missing/wrong cwd.
    expect(() => encodeClaudeProjectDir(123 as unknown as string)).not.toThrow();
  });
});
