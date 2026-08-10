import { describe, expect, it } from '@jest/globals';
import {
  evaluateConversationAccess,
  describeConversationAccess,
  conversationAccessFix,
} from '../integrations/openclaw-conversation-access.js';
import {
  evaluateConversationAccess as pluginEvaluate,
  describeRegisteredHooks,
} from '../../plugins/openclaw/conversation-access.js';

/**
 * #225 phase 1 — report conversation-scanning state honestly.
 *
 * Verified live on this fleet (gateway log, 2026-08-10, six occurrences):
 *
 *   [shieldcortex] v4.47.35 registered (llm_input + llm_output + before_tool_call + …)
 *   [plugins] typed hook "llm_input" blocked because non-bundled plugins must set
 *             plugins.entries.shieldcortex-realtime.hooks.allowConversationAccess=true
 *   [plugins] typed hook "llm_output" blocked …
 *
 * We announced two hooks the host had just dropped. These tests pin the three
 * things that keep the report honest:
 *
 *   1. The grant is read exactly as OpenClaw reads it (strict `true`), so we
 *      can never report "granted" for a value the host rejects.
 *   2. An ungranted host is reported as INACTIVE — not silently, and not as
 *      damage (withholding conversation access is a legitimate choice).
 *   3. A GRANT IS NOT PROTECTION. `llm_input` is observation-only; the granted
 *      message must never read as "blocked"/"protected", or phase 1 just moves
 *      the false green rather than removing it.
 */

const PLUGIN_ID = 'shieldcortex-realtime';

const granted = { plugins: { entries: { [PLUGIN_ID]: { enabled: true, hooks: { allowConversationAccess: true } } } } };
// The exact shape on this box today.
const ungranted = { plugins: { entries: { [PLUGIN_ID]: { enabled: true } } } };

describe('#225 — reading the grant exactly as OpenClaw does', () => {
  it('grants only on a strict boolean true', () => {
    expect(evaluateConversationAccess(granted, PLUGIN_ID).granted).toBe(true);
  });

  it('does NOT grant on truthy-but-not-true values', () => {
    // OpenClaw compares `explicitConversationAccess !== true`, so these are all
    // rejected by the host. Reporting them as granted would recreate the bug
    // one layer up.
    for (const v of ['true', 1, 'yes', {}, []]) {
      const cfg = { plugins: { entries: { [PLUGIN_ID]: { hooks: { allowConversationAccess: v } } } } };
      expect(evaluateConversationAccess(cfg, PLUGIN_ID).granted).toBe(false);
    }
  });

  it('reports ungranted when the entry exists without the hooks block', () => {
    const s = evaluateConversationAccess(ungranted, PLUGIN_ID);
    expect(s.granted).toBe(false);
    expect(s.entryPresent).toBe(true);
    expect(s.readable).toBe(true);
  });

  it('reports ungranted when the plugin has no entry at all', () => {
    const s = evaluateConversationAccess({ plugins: { entries: {} } }, PLUGIN_ID);
    expect(s.granted).toBe(false);
    expect(s.entryPresent).toBe(false);
  });

  it('distinguishes unreadable config from a denied grant', () => {
    // Unknown must never be reported as a confident answer — the same
    // distinction #222 needed.
    const s = evaluateConversationAccess(null, PLUGIN_ID);
    expect(s.readable).toBe(false);
    expect(s.granted).toBe(false);
  });

  it('never throws on hostile shapes', () => {
    for (const junk of [undefined, 42, 'nope', [], { plugins: 'no' }, { plugins: { entries: 7 } }]) {
      expect(() => evaluateConversationAccess(junk, PLUGIN_ID)).not.toThrow();
    }
  });

  it('does not read another plugin\'s grant as ours', () => {
    const other = { plugins: { entries: { 'someone-else': { hooks: { allowConversationAccess: true } } } } };
    expect(evaluateConversationAccess(other, PLUGIN_ID).granted).toBe(false);
  });
});

describe('#225 — the message tells the truth in both directions', () => {
  it('an ungranted host is told scanning is INACTIVE', () => {
    const msg = describeConversationAccess(evaluateConversationAccess(ungranted, PLUGIN_ID), PLUGIN_ID);
    expect(msg).toMatch(/INACTIVE/);
    expect(msg).toMatch(/allowConversationAccess/);
  });

  it('a GRANTED host is NOT told it is protected — observation only', () => {
    // The trap: `llm_input` has no blocking contract, so "granted" means
    // "we can see it", never "we can stop it".
    const msg = describeConversationAccess(evaluateConversationAccess(granted, PLUGIN_ID), PLUGIN_ID);
    expect(msg.toLowerCase()).toMatch(/observation only/);
    expect(msg.toLowerCase()).not.toMatch(/\bprotected\b/);
    // Any mention of blocking must be a DENIAL of it, never a claim.
    expect(msg.toLowerCase()).toMatch(/never blocked/);
  });

  it('an unreadable config says unknown, not inactive', () => {
    const msg = describeConversationAccess({ granted: false, readable: false, entryPresent: false }, PLUGIN_ID);
    expect(msg.toLowerCase()).toMatch(/unknown|cannot read/);
  });

  it('the fix names the exact key and frames withholding as legitimate', () => {
    const fix = conversationAccessFix(PLUGIN_ID);
    expect(fix).toContain('allowConversationAccess');
    expect(fix).toContain(PLUGIN_ID);
    expect(fix.toLowerCase()).toMatch(/restart/);
    expect(fix.toLowerCase()).toMatch(/valid choice|your call/);
  });
});

describe('#225 — the startup line claims only what is live', () => {
  it('does NOT name llm_input/llm_output when the grant is missing', () => {
    // The exact bug: the gateway logged "registered (llm_input + llm_output …)"
    // and then, on the next two lines, that it had dropped both.
    const line = describeRegisteredHooks({
      access: pluginEvaluate(ungranted, PLUGIN_ID),
      beforeToolCallRegistered: true,
    });
    expect(line).not.toMatch(/llm_input \+/);
    expect(line).toMatch(/INACTIVE/);
    expect(line).toContain('allowConversationAccess');
    // What IS live must still be reported.
    expect(line).toContain('before_tool_call');
  });

  it('names them when the grant IS present', () => {
    const line = describeRegisteredHooks({
      access: pluginEvaluate(granted, PLUGIN_ID),
      beforeToolCallRegistered: true,
    });
    expect(line).toContain('llm_input');
    expect(line).toContain('llm_output');
    expect(line).not.toMatch(/INACTIVE/);
  });

  it('says UNKNOWN rather than INACTIVE when openclaw.json is unreadable', () => {
    const line = describeRegisteredHooks({
      access: { granted: false, readable: false, entryPresent: false },
      beforeToolCallRegistered: true,
    });
    expect(line).toMatch(/UNKNOWN/);
  });

  it('never claims before_tool_call when it was not registered', () => {
    const line = describeRegisteredHooks({
      access: pluginEvaluate(granted, PLUGIN_ID),
      beforeToolCallRegistered: false,
    });
    expect(line).not.toContain('before_tool_call');
  });
});

describe('#225 — the two build-boundary copies agree (drift guard)', () => {
  // src/ and plugins/ are separate builds and cannot import each other, so the
  // grant reader is duplicated. If one copy learns a rule the other does not,
  // doctor and the plugin would report different states for the same host.
  const CASES: unknown[] = [
    granted,
    ungranted,
    { plugins: { entries: {} } },
    { plugins: { entries: { [PLUGIN_ID]: { hooks: { allowConversationAccess: 'true' } } } } },
    { plugins: { entries: { [PLUGIN_ID]: { hooks: { allowConversationAccess: 1 } } } } },
    { plugins: { entries: { [PLUGIN_ID]: { hooks: {} } } } },
    { plugins: 'nope' },
    null,
    undefined,
    42,
  ];

  it('produces identical verdicts for every fixture', () => {
    for (const cfg of CASES) {
      expect(pluginEvaluate(cfg, PLUGIN_ID)).toEqual(evaluateConversationAccess(cfg, PLUGIN_ID));
    }
  });
});
