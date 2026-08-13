import { describe, it, expect } from '@jest/globals';
import plugin, { conversationPosture, evaluateConversationRun } from '../index.js';

/**
 * Issue #225 — the conversation firewall could not block, by construction.
 *
 * Scanning was registered on `llm_input`, which OpenClaw documents under
 * "Conversation observation": it has no blocking contract, so a detected
 * prompt injection reached the model regardless. The only sink for a
 * detection was a console line and an audit row — nobody was told, nothing
 * was stopped. Meanwhile `before_tool_call` genuinely gated, which is why
 * one half of the product was trustworthy and this half was a logger
 * wearing a firewall's name.
 *
 * The fix registers `before_agent_run` (documented: "can block the run") and
 * gives the verdict three explicit postures. These tests pin the contract of
 * the pure decision function so the posture semantics cannot drift:
 *
 *   off      — do not scan at all
 *   observe  — scan, record, NEVER block  (default; today's real behaviour,
 *              now named honestly instead of implied to be protection)
 *   enforce  — block the run on a dirty verdict
 *
 * `observe` is the default deliberately: #182 says our false-positive rate is
 * still unmeasured, and putting an unmeasured blocker in front of every turn
 * would be a worse incident than the one this fixes.
 */

describe('#225 conversationPosture — config resolution', () => {
  it('defaults to observe when unset (never silently enforcing)', () => {
    expect(conversationPosture(undefined)).toBe('observe');
    expect(conversationPosture({})).toBe('observe');
  });

  it('accepts the three declared postures', () => {
    expect(conversationPosture({ posture: 'off' })).toBe('off');
    expect(conversationPosture({ posture: 'observe' })).toBe('observe');
    expect(conversationPosture({ posture: 'enforce' })).toBe('enforce');
  });

  it('falls back to observe on a junk value rather than guessing upward', () => {
    expect(conversationPosture({ posture: 'block' } as never)).toBe('observe');
    expect(conversationPosture({ posture: true } as never)).toBe('observe');
  });
});

describe('#225 evaluateConversationRun — the decision, not the plumbing', () => {
  const dirty = { clean: false, summary: 'HIGH (2 detections)', available: true };
  const clean = { clean: true, summary: 'unknown', available: true };

  it('enforce + dirty → blocks, and the reason names the verdict', () => {
    const d = evaluateConversationRun('enforce', dirty);
    expect(d.block).toBe(true);
    expect(d.notify).toBe(true);
    expect(d.reason).toMatch(/HIGH \(2 detections\)/);
  });

  it('observe + dirty → does NOT block, but still records and notifies', () => {
    const d = evaluateConversationRun('observe', dirty);
    expect(d.block).toBe(false);
    // The whole point of #225: a detection must reach a human even when we
    // are not stopping the turn. Logging is not a sink.
    expect(d.notify).toBe(true);
    expect(d.audit).toBe(true);
  });

  it('clean input never blocks and never notifies, in any posture', () => {
    for (const p of ['off', 'observe', 'enforce'] as const) {
      const d = evaluateConversationRun(p, clean);
      expect(d.block).toBe(false);
      expect(d.notify).toBe(false);
    }
  });

  it('off → no scan, no audit, no notify, even on a dirty verdict', () => {
    const d = evaluateConversationRun('off', dirty);
    expect(d).toEqual({ block: false, notify: false, audit: false, reason: null, outcome: 'not-scanned' });
  });

  it('a scanner error fails OPEN but is reported — never wedges every turn', () => {
    // A broken scanner must not turn the gateway into a brick. It must also
    // not read as protected: notify carries the failure to a human, and the
    // outcome is its own word — never 'clean', never 'observed'.
    const d = evaluateConversationRun('enforce', {
      clean: false,
      available: false,
      errored: true,
      error: 'no in-process defence module and the MCP fallback returned nothing',
      summary: 'scan unavailable',
    });
    expect(d.block).toBe(false);
    expect(d.notify).toBe(true);
    expect(d.outcome).toBe('unavailable');
    expect(d.reason).toMatch(/unavailable/i);
  });

  it('an unavailable scan is never routed through the clean branch, whatever `clean` says', () => {
    // Belt and braces for the shape the old scanner returned:
    // `{ clean: true, summary: 'scan unavailable' }`. Even if something
    // upstream reconstructs that and marks it unavailable, it must not fall
    // into the silent clean path.
    const d = evaluateConversationRun('observe', { clean: true, summary: 'scan unavailable', available: false });
    expect(d.outcome).toBe('unavailable');
    expect(d.notify).toBe(true);
    expect(d.audit).toBe(true);
  });

  it('names the outcome the operator will be told: blocked vs observed', () => {
    expect(evaluateConversationRun('enforce', dirty).outcome).toBe('blocked');
    expect(evaluateConversationRun('observe', dirty).outcome).toBe('observed');
    expect(evaluateConversationRun('observe', clean).outcome).toBe('clean');
  });
});

describe('#225 manifest declares the blocking hook', () => {
  it('before_agent_run is declared in activation.hooks', async () => {
    const fs = await import('fs');
    const path = await import('path');
    const url = await import('url');
    const here = path.dirname(url.fileURLToPath(import.meta.url));
    const manifest = JSON.parse(
      fs.readFileSync(path.join(here, '..', 'openclaw.plugin.json'), 'utf-8'),
    );
    expect(manifest.activation.hooks).toEqual(expect.arrayContaining(['before_agent_run']));
  });

  it('the plugin config schema accepts the conversation block', () => {
    const parsed = plugin.configSchema.parse({
      interceptor: { conversation: { posture: 'enforce' } },
    }) as any;
    expect(parsed.interceptor?.conversation?.posture).toBe('enforce');
  });
});
