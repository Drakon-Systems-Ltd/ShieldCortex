/**
 * #225 phase 1 — the plugin-side copy of the conversation-access grant reader.
 *
 * Duplicated from `src/integrations/openclaw-conversation-access.ts` because
 * the plugin is a separate build with no `src/` imports (same boundary as the
 * reviewed-script allowlist and the fallback guard patterns). The two copies
 * are held together by a parity test — see
 * `src/__tests__/conversation-access-honesty-225.test.ts`.
 *
 * Why the plugin needs it at all: the startup line announced
 * `registered (llm_input + llm_output + …)` unconditionally, on hosts where
 * OpenClaw had just dropped both for want of the grant. The plugin cannot
 * observe that rejection (the host emits it as its own diagnostic and `api.on`
 * returns void), so it must read the same config the host reads and describe
 * only what will actually be live.
 */

import { readFileSync } from 'node:fs';
import path from 'node:path';

export interface ConversationAccessState {
  granted: boolean;
  readable: boolean;
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

  // Strict `true`, matching OpenClaw's own `!== true` comparison exactly.
  return { granted: raw === true, readable: true, entryPresent: true };
}

/** Read `~/.openclaw/openclaw.json` and evaluate the grant. Never throws. */
export function readConversationAccess(home: string, pluginId: string): ConversationAccessState {
  try {
    const raw = readFileSync(path.join(home, '.openclaw', 'openclaw.json'), 'utf-8');
    return evaluateConversationAccess(JSON.parse(raw), pluginId);
  } catch {
    return { granted: false, readable: false, entryPresent: false };
  }
}

/**
 * The hooks this plugin can honestly claim at startup. Conversation hooks are
 * only listed when the host will actually keep them.
 *
 * `before_agent_run` — the conversation firewall's enforcement point (#226) —
 * is a conversation hook too from OpenClaw 2026.5.9-beta.1, so it is listed
 * only when the grant is present AND registration was attempted this session.
 * Claiming it on an ungranted host would recreate the exact bug this function
 * exists to remove, one hook further along.
 */
export function describeRegisteredHooks(opts: {
  access: ConversationAccessState;
  beforeToolCallRegistered: boolean;
  beforeAgentRunRequested?: boolean;
}): string {
  const live: string[] = [];
  if (opts.access.granted) live.push('llm_input', 'llm_output');
  if (opts.beforeToolCallRegistered) live.push('before_tool_call');
  if (opts.access.granted && opts.beforeAgentRunRequested) live.push('before_agent_run');
  live.push('/shieldcortex-status');

  let line = live.join(' + ');
  if (!opts.access.granted) {
    line += opts.access.readable
      ? ' — conversation scanning INACTIVE (llm_input/llm_output dropped by OpenClaw: set plugins.entries.shieldcortex-realtime.hooks.allowConversationAccess=true to enable)'
      : ' — conversation scanning state UNKNOWN (could not read openclaw.json)';
  }
  return line;
}
