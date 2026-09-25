/**
 * The conversation-access consent switch, on its own (#226, extracted in #577).
 *
 * `update` and `repair` both have to answer "did the operator ask for
 * conversation access on this run?" before they reconcile the plugin, and #577
 * made them parse their arguments once at the entry point instead of letting
 * `openclaw-reconcile` reach into `process.argv` hundreds of lines downstream.
 * They need the rule, not the 2,800-line installer module that used to own it —
 * so the rule lives here and `setup/openclaw.ts` re-exports it unchanged.
 */

/** The flag spelling, shared by every command's argument allow-list. */
export const ALLOW_CONVERSATION_ACCESS_FLAG = '--allow-conversation-access';

/** The environment twin of the flag. */
export const ALLOW_CONVERSATION_ACCESS_ENV = 'SHIELDCORTEX_ALLOW_CONVERSATION_ACCESS';

/**
 * Has the operator asked for conversation access on THIS run (#226)?
 *
 * The grant lets a non-bundled plugin read every prompt and every model
 * response on the box. Issue #225 is explicit that it is "the operator's call
 * per box — the installer must never set it silently", and OpenClaw made it a
 * separate key, defaulting off, for the same reason. So installing ShieldCortex
 * does not grant it; ASKING for it does, either way round:
 *
 *   shieldcortex openclaw install --allow-conversation-access
 *   SHIELDCORTEX_ALLOW_CONVERSATION_ACCESS=1 shieldcortex openclaw install
 *
 * Anything else — including a plain install on an interactive terminal — leaves
 * the gate untouched and prints the one-line remedy. Doctor fails on it
 * separately, so the gap is reported until a human closes it.
 */
export function resolveConversationAccessConsent(input: {
  argv?: readonly string[];
  env?: NodeJS.ProcessEnv;
}): boolean {
  const argv = input.argv ?? [];
  if (argv.includes(ALLOW_CONVERSATION_ACCESS_FLAG)) return true;
  return (input.env ?? {})[ALLOW_CONVERSATION_ACCESS_ENV] === '1';
}
