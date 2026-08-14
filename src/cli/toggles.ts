/**
 * The feature-toggle registry behind `shieldcortex enable|disable` (#275).
 *
 * Before this, `doctor` prescribed config VALUES (`actionGuard.notify.enabled:
 * true`) with no command that could set them — `shieldcortex config` is
 * cloud-only. The only route left was hand-editing `~/.shieldcortex/config.json`,
 * which invalidates the embedded `_sig` HMAC, so the next read reported
 * "possible tampering detected" and forced `defenceMode: strict`. The tool's own
 * remediation advice degraded the install.
 *
 * So the rule this module exists to enforce: **every toggle writes through the
 * signing writer** (`mutateRawConfig`), never by hand. A feature the operator
 * turned on must never read back as tampering.
 *
 * Adding a toggle: add a descriptor below. Keep `read` free of side effects —
 * `listToggles()` is called by `doctor` and must never mutate the config.
 */

import { readFileSync, writeFileSync, copyFileSync, existsSync } from 'node:fs';
import { mutateRawConfig, readRawConfig } from '../cloud/config.js';
import { openClawConfigPath } from '../setup/openclaw.js';

export type ToggleState = 'on' | 'off' | 'unknown';

export interface ToggleInfo {
  id: string;
  summary: string;
  state: ToggleState;
  /** Where the value lives — shown so an operator knows which file is authoritative. */
  backing: 'shieldcortex' | 'openclaw';
  /** Extra context for the current state (e.g. which channel is configured). */
  detail?: string;
}

export interface ToggleOptions {
  /** notify: deliver through the OpenClaw gateway's approval cards. */
  openclaw?: boolean;
  /** notify: deliver by signed webhook POST. */
  webhookUrl?: string;
  /** notify: HMAC key for the webhook body. */
  webhookSecret?: string;
  /** action-guard: opt down to warn-and-allow for the dangerous tier. */
  warnOnly?: boolean;
}

export interface ToggleResult {
  ok: boolean;
  message: string;
  /** Follow-up the operator still has to do (e.g. restart the gateway). */
  notes: string[];
}

interface ToggleDescriptor {
  id: string;
  summary: string;
  backing: 'shieldcortex' | 'openclaw';
  read(): { state: ToggleState; detail?: string };
  apply(on: boolean, opts: ToggleOptions): ToggleResult;
}

/** The `actionGuard` sub-object, created on demand. */
function guardBlock(raw: Record<string, unknown>): Record<string, unknown> {
  const existing = raw.actionGuard;
  const block = existing && typeof existing === 'object' && !Array.isArray(existing)
    ? (existing as Record<string, unknown>)
    : {};
  raw.actionGuard = block;
  return block;
}

function subBlock(parent: Record<string, unknown>, key: string): Record<string, unknown> {
  const existing = parent[key];
  const block = existing && typeof existing === 'object' && !Array.isArray(existing)
    ? (existing as Record<string, unknown>)
    : {};
  parent[key] = block;
  return block;
}

function readGuard(): Record<string, unknown> {
  const raw = readRawConfig();
  const block = raw.actionGuard;
  return block && typeof block === 'object' && !Array.isArray(block)
    ? (block as Record<string, unknown>)
    : {};
}

/**
 * Same acceptance rule as notify-config.ts: only `http:`/`https:` is a channel.
 * Anything else degrades to "no configured channel" rather than a spoofed one,
 * so we refuse it at the door instead of storing it.
 */
function isAcceptableWebhook(url: string): boolean {
  try {
    const parsed = new URL(url);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:';
  } catch {
    return false;
  }
}

const TOGGLES: ToggleDescriptor[] = [
  {
    id: 'notify',
    summary: 'Send unattended Action Guard denials to a human (OpenClaw card or signed webhook)',
    backing: 'shieldcortex',
    read() {
      const notify = readGuard().notify;
      const block = notify && typeof notify === 'object' ? (notify as Record<string, unknown>) : {};
      const channels = [
        block.openclaw === true ? 'openclaw' : null,
        typeof block.webhookUrl === 'string' && block.webhookUrl ? 'webhook' : null,
      ].filter(Boolean);
      return {
        state: block.enabled === true ? 'on' : 'off',
        detail: channels.length ? `channel: ${channels.join(' + ')}` : 'no channel configured',
      };
    },
    apply(on, opts) {
      if (on && opts.webhookUrl && !isAcceptableWebhook(opts.webhookUrl)) {
        return {
          ok: false,
          notes: [],
          message: `--webhook must be an http(s) URL (got "${opts.webhookUrl}"). A non-http scheme cannot be a notify channel.`,
        };
      }
      // Enabling with no channel named is the #275 trap in reverse: the switch
      // is on and nothing is reachable. Default to the gateway, which needs no
      // endpoint and is what most installs already have wired.
      const useOpenClaw = on && (opts.openclaw === true || (!opts.webhookUrl && opts.openclaw !== false));

      mutateRawConfig((raw) => {
        const notify = subBlock(guardBlock(raw), 'notify');
        notify.enabled = on;
        if (on) {
          if (useOpenClaw) notify.openclaw = true;
          if (opts.webhookUrl) notify.webhookUrl = opts.webhookUrl;
          if (opts.webhookSecret) notify.webhookSecret = opts.webhookSecret;
        }
        // Disabling flips the master switch only — the endpoint is retained so
        // re-enabling does not mean re-entering it.
      });

      if (!on) return { ok: true, notes: [], message: 'notify disabled — denials stay in the audit log only.' };

      const notes: string[] = [];
      if (useOpenClaw) notes.push('Delivering through the OpenClaw gateway — approvals appear on whatever channel it already reaches.');
      if (opts.webhookUrl && !opts.webhookSecret) {
        notes.push('No --secret given: this install can only send UNSIGNED POSTs. Any receiver worth pointing at should reject those.');
      }
      return { ok: true, notes, message: 'notify enabled.' };
    },
  },
  {
    id: 'action-guard',
    summary: 'Gate dangerous tool calls before they run',
    backing: 'shieldcortex',
    read() {
      const guard = readGuard();
      if (guard.enabled === false) return { state: 'off', detail: 'tool calls are not gated' };
      return {
        state: 'on',
        detail: guard.enforce === false ? 'warn-only (dangerous tier warns, does not block)' : 'enforcing',
      };
    },
    apply(on, opts) {
      mutateRawConfig((raw) => {
        const guard = guardBlock(raw);
        guard.enabled = on;
        if (on) guard.enforce = opts.warnOnly !== true;
      });
      if (!on) {
        return {
          ok: true,
          notes: ['Catastrophic operations are no longer blocked on this host.'],
          message: 'action-guard disabled.',
        };
      }
      return {
        ok: true,
        notes: opts.warnOnly === true
          ? ['warn-only: the dangerous tier warns and allows. The catastrophic tier always blocks regardless.']
          : [],
        message: `action-guard enabled (${opts.warnOnly === true ? 'warn-only' : 'enforcing'}).`,
      };
    },
  },
  {
    id: 'threat-graph',
    summary: 'Project the audit ledgers into a per-source security event graph (advisory)',
    backing: 'shieldcortex',
    read() {
      const block = readRawConfig().threatGraph;
      const cfg = block && typeof block === 'object' ? (block as Record<string, unknown>) : {};
      return { state: cfg.enabled === false ? 'off' : 'on', detail: 'advisory — changes no scan verdict' };
    },
    apply(on) {
      mutateRawConfig((raw) => { subBlock(raw, 'threatGraph').enabled = on; });
      return { ok: true, notes: [], message: `threat-graph ${on ? 'enabled' : 'disabled'}.` };
    },
  },
  {
    id: 'strict-source-mode',
    summary: 'Harden consequences for unknown/self-declared callers',
    backing: 'shieldcortex',
    read() {
      return {
        state: readRawConfig().strictSourceMode === true ? 'on' : 'off',
        detail: 'unknown sources score lower; sub-trust writes auto-quarantine',
      };
    },
    apply(on) {
      mutateRawConfig((raw) => { raw.strictSourceMode = on; });
      return { ok: true, notes: [], message: `strict-source-mode ${on ? 'enabled' : 'disabled'}.` };
    },
  },
  {
    id: 'conversation-scanning',
    summary: 'Let the gateway hand conversation content to ShieldCortex for scanning',
    backing: 'openclaw',
    read() {
      try {
        const path = openClawConfigPath();
        if (!existsSync(path)) return { state: 'unknown', detail: 'no openclaw.json on this host' };
        const cfg = JSON.parse(readFileSync(path, 'utf8')) as Record<string, unknown>;
        const entry = ((cfg.plugins as Record<string, unknown> | undefined)?.entries as Record<string, unknown> | undefined)
          ?.['shieldcortex-realtime'] as Record<string, unknown> | undefined;
        if (!entry) return { state: 'unknown', detail: 'realtime plugin not registered' };
        const hooks = entry.hooks as Record<string, unknown> | undefined;
        return {
          state: hooks?.allowConversationAccess === true ? 'on' : 'off',
          detail: 'conversation content is sensitive — leaving this off is a valid choice',
        };
      } catch {
        return { state: 'unknown', detail: 'openclaw.json unreadable' };
      }
    },
    apply(on) {
      const path = openClawConfigPath();
      if (!existsSync(path)) {
        return { ok: false, notes: [], message: `no openclaw.json at ${path} — nothing to change on this host.` };
      }
      let cfg: Record<string, unknown>;
      try {
        cfg = JSON.parse(readFileSync(path, 'utf8')) as Record<string, unknown>;
      } catch {
        // Same discipline as the config writer: never overwrite something we
        // could not parse, or we destroy the operator's gateway settings.
        return { ok: false, notes: [], message: `openclaw.json is unreadable — refusing to overwrite it. Fix ${path} and retry.` };
      }
      const plugins = subBlock(cfg, 'plugins');
      const entries = subBlock(plugins, 'entries');
      const entry = subBlock(entries, 'shieldcortex-realtime');
      subBlock(entry, 'hooks').allowConversationAccess = on;

      // The installer's own snapshot discipline (#214): back up before writing
      // somebody else's config file.
      const backup = `${path}.sc-toggle.bak`;
      try { copyFileSync(path, backup); } catch { /* best-effort */ }
      writeFileSync(path, JSON.stringify(cfg, null, 2) + '\n');

      return {
        ok: true,
        notes: [
          'Restart the OpenClaw gateway for this to take effect.',
          `Previous config saved to ${backup}`,
        ],
        message: `conversation-scanning ${on ? 'enabled' : 'disabled'}.`,
      };
    },
  },
];

export function listToggles(): ToggleInfo[] {
  return TOGGLES.map((t) => {
    let read: { state: ToggleState; detail?: string };
    try {
      read = t.read();
    } catch {
      read = { state: 'unknown', detail: 'could not be read' };
    }
    return { id: t.id, summary: t.summary, backing: t.backing, state: read.state, detail: read.detail };
  });
}

export function applyToggle(id: string, on: boolean, opts: ToggleOptions): ToggleResult {
  const toggle = TOGGLES.find((t) => t.id === id);
  if (!toggle) {
    return {
      ok: false,
      notes: [],
      message: `unknown feature "${id}". Available: ${TOGGLES.map((t) => t.id).join(', ')}.`,
    };
  }
  try {
    return toggle.apply(on, opts);
  } catch (err) {
    return { ok: false, notes: [], message: `could not update "${id}": ${(err as Error).message}` };
  }
}
