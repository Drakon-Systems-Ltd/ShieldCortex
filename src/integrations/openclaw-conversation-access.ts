/**
 * #225 phase 1 — honest state for OpenClaw conversation-hook access.
 *
 * OpenClaw gates the conversation hooks (`llm_input`, `llm_output`,
 * `before_agent_run`, …) behind an explicit per-plugin consent grant: a
 * non-bundled plugin only receives them when
 * `plugins.entries.<id>.hooks.allowConversationAccess` is exactly `true`.
 * Without it the host DROPS the registration and emits a warn diagnostic:
 *
 *   [plugins] typed hook "llm_input" blocked because non-bundled plugins must
 *   set plugins.entries.shieldcortex-realtime.hooks.allowConversationAccess=true
 *
 * ShieldCortex has been logging `registered (llm_input + llm_output + …)` on
 * exactly the hosts where those two were then dropped — claiming conversation
 * protection it does not have. That is the same false-green class as #222
 * (doctor healthy over a wiped stanza) and #200 (a verify step that could only
 * pass), and this module exists to make the state reportable rather than
 * assumed.
 *
 * IMPORTANT: a grant is NOT protection. Even when granted, `llm_input` is an
 * observation hook with no blocking contract — detections are logged, never
 * stopped. Enforcement is a separate piece of work; do not let "granted" be
 * rendered as "protected".
 *
 * Withholding the grant is a legitimate operator choice — conversation content
 * is sensitive — so an ungranted host is reported as a WARNING with the exact
 * config to add, never as damage.
 */

import fs from 'fs';
import path from 'path';

export interface ConversationAccessState {
  /** `plugins.entries.<id>.hooks.allowConversationAccess === true`. */
  granted: boolean;
  /** openclaw.json parsed. False ⇒ we cannot tell; never claim either way. */
  readable: boolean;
  /** The plugin has an entry in openclaw.json at all. */
  entryPresent: boolean;
}

/** Pure: evaluate a parsed openclaw.json object. */
export function evaluateConversationAccess(config: unknown, pluginId: string): ConversationAccessState {
  if (!config || typeof config !== 'object') {
    return { granted: false, readable: false, entryPresent: false };
  }
  const plugins = (config as { plugins?: unknown }).plugins;
  const entries = plugins && typeof plugins === 'object'
    ? (plugins as { entries?: unknown }).entries
    : undefined;
  const entry = entries && typeof entries === 'object'
    ? (entries as Record<string, unknown>)[pluginId]
    : undefined;

  if (!entry || typeof entry !== 'object') {
    return { granted: false, readable: true, entryPresent: false };
  }

  const hooks = (entry as { hooks?: unknown }).hooks;
  const raw = hooks && typeof hooks === 'object'
    ? (hooks as { allowConversationAccess?: unknown }).allowConversationAccess
    : undefined;

  // Strict `true` only — OpenClaw itself compares `!== true`, so a truthy
  // string or 1 does NOT grant access. Matching that exactly is the whole
  // point: reporting "granted" for a value the host rejects would recreate the
  // bug in the reporting layer.
  return { granted: raw === true, readable: true, entryPresent: true };
}

/** Read `~/.openclaw/openclaw.json` and evaluate the grant. Never throws. */
export function readConversationAccess(home: string, pluginId: string): ConversationAccessState {
  try {
    const raw = fs.readFileSync(path.join(home, '.openclaw', 'openclaw.json'), 'utf-8');
    return evaluateConversationAccess(JSON.parse(raw), pluginId);
  } catch {
    return { granted: false, readable: false, entryPresent: false };
  }
}

/**
 * The exact config an operator must add. Kept here so the doctor message, the
 * plugin's startup line and the tests cannot drift apart.
 */
export function conversationAccessFix(pluginId: string): string {
  return `Add "hooks": { "allowConversationAccess": true } to plugins.entries["${pluginId}"] in ~/.openclaw/openclaw.json, then restart the gateway. Conversation content is sensitive — this is your call, and leaving it ungranted is a valid choice.`;
}

/**
 * The honest one-line description of conversation-scanning state.
 * `granted` deliberately does NOT read as "protected" (see module doc).
 */
export function describeConversationAccess(state: ConversationAccessState, pluginId: string): string {
  if (!state.readable) {
    return 'cannot read ~/.openclaw/openclaw.json — conversation-scanning state unknown';
  }
  if (!state.granted) {
    return `conversation scanning INACTIVE — OpenClaw drops llm_input/llm_output at registration because plugins.entries.${pluginId}.hooks.allowConversationAccess is not true; no conversation content is being scanned on this host`;
  }
  return 'conversation scanning active — OBSERVATION ONLY: detections are logged and audited, never blocked';
}
