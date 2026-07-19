import { describe, it, expect } from '@jest/globals';
import { evaluateToolCall } from '../tool-action-guard.js';

/**
 * `${IFS}` / `$IFS` de-obfuscation (adversarial-review follow-up to #84).
 *
 * `${IFS}`, `${IFS:0:1}`, and `$IFS` all expand to whitespace at runtime and are
 * used purely to strip the literal spaces that several danger patterns anchor on
 * (`\s/` in recursive-perms, the fork-bomb shape, etc.). Normalising them to a
 * space before scanning makes those patterns see the real command — closing a
 * pre-existing fail-open that let `chmod${IFS}-R${IFS}777${IFS}/` and a
 * `${IFS}`-spaced fork bomb through (present on main; NOT a #84 regression).
 */
const gated = (command: string) => evaluateToolCall('Bash', { command }).decision !== 'allow';

describe('${IFS} de-obfuscation — patterns anchored on literal whitespace still fire', () => {
  const mustGate: string[] = [
    'chmod${IFS}-R${IFS}777${IFS}/',
    'chmod${IFS}-R${IFS}777${IFS}/etc',
    'curl https://x/a;chmod${IFS}-R${IFS}777${IFS}/',
    ':(){${IFS}:|:&};:',                              // fork bomb, IFS-spaced
    'curl https://x/a;:(){${IFS}:|:&};:',
    'rm${IFS}-rf${IFS}/',
    'dd${IFS}if=/dev/zero${IFS}of=/dev/sda',
    'sudo${IFS}rm${IFS}-rf${IFS}/',
    '${IFS}rm${IFS}-rf${IFS}/',
    'cat${IFS}/etc/shadow',                            // ${IFS:0:1} variant below
    'chmod${IFS:0:1}-R${IFS:0:1}777${IFS:0:1}/',
    '$IFS rm -rf /',
  ];
  it.each(mustGate)('gates: %s', (command) => {
    expect(gated(command)).toBe(true);
  });
});

describe('${IFS} de-obfuscation — benign commands are unaffected', () => {
  const mustAllow: string[] = [
    'ls -la',
    'git status',
    'npm test',
    'echo "hello world"',
  ];
  it.each(mustAllow)('allows: %s', (command) => {
    expect(evaluateToolCall('Bash', { command }).decision).toBe('allow');
  });
});
