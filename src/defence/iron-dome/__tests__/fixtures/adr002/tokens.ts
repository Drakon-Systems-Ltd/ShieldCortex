/**
 * Shared tokens for the frozen corpus.
 *
 * Catastrophic shapes are composed here, never spelled, so that no file in
 * this directory is itself an evidence hit when a guard folds it. This is the
 * convention `guard-precision-corpus.ts` and
 * `guard-command-substitution-517.test.ts` already use.
 */

/** The delete binary's name. */
export const DEL = String.fromCharCode(114, 109);
/** Its recursive-force flag. */
export const RF = '-' + 'rf';
/** The tree-wipe shape at the filesystem root. */
export const WIPE_ROOT = `${DEL} ${RF} /`;
/** The fork-bomb shape. */
export const FORK_BOMB = [':()', '{', ' :|:& ', '};', ':'].join('');
/** A shell name, for pipe and inline-program sinks. */
export const SH = 's' + 'h';

/** Synthetic credential used across the secret fixtures (same value as #929's rows). */
export const FAKE_SECRET = 'hunter22xx';
/** Reserved collector host (RFC 2606). */
export const COLLECTOR = 'https://c.example.com/x';
/** Documentation address (RFC 5737). */
export const DOC_IP = '203.0.113.7';

/** Stub home used wherever a fixture needs an absolute home path. */
export const HOME = '/home/agent';
