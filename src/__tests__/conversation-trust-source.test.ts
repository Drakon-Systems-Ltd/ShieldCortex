import { describe, expect, it } from '@jest/globals';
import { classifyConversationOrigin } from '../../plugins/openclaw/conversation-trust.js';

/**
 * Source trust for conversation content — follow-on to #233.
 *
 * Scanning the operator's own typing is nearly pure cost: it produces false
 * alarms, and false alarms are how a control gets switched off. The rule:
 * the human speaks instructions; everything else is data.
 *
 * The two properties that are easy to get backwards, and are pinned here:
 *
 *   1. Trust comes from the SENDER, never the channel. A trusted pipe carrying
 *      pasted web content is still untrusted content — that is precisely how
 *      prompt injection travels.
 *   2. Agent-to-agent traffic is data, NOT trusted. An agent that read a
 *      poisoned page and relays it over a closed platform is a confused deputy
 *      with excellent transport; the closed platform is what lets it spread.
 *
 * And the separation that keeps this from becoming a blind spot: trust gates
 * the CONSEQUENCE (escalation), never the detection. Everything is still
 * scanned and audited.
 */

describe('the owner speaks instructions', () => {
  it('does not let the owner\'s own input tighten the guard', () => {
    const d = classifyConversationOrigin({ senderIsOwner: true });
    expect(d.origin).toBe('owner');
    expect(d.mayTaint).toBe(false);
  });

  it('still SCANS the owner\'s input — trust gates the consequence, not the detection', () => {
    // Going blind on trusted input is how #225 happened. Detection and audit
    // stay unconditional; only escalation is trust-gated.
    expect(classifyConversationOrigin({ senderIsOwner: true }).scan).toBe(true);
  });

  it('honours an operator who wants owner input treated like anything else', () => {
    const d = classifyConversationOrigin({ senderIsOwner: true, trustOwnerInput: false });
    expect(d.mayTaint).toBe(true);
  });
});

describe('everything else is data', () => {
  it('treats a non-owner sender as data', () => {
    const d = classifyConversationOrigin({ senderIsOwner: false });
    expect(d.origin).toBe('non-owner');
    expect(d.mayTaint).toBe(true);
  });

  it('treats an AGENT on a trusted closed platform as data, not as trusted', () => {
    // The inversion that matters. Agent A reads a poisoned issue and relays it
    // to agent B over a closed channel; the channel being closed is exactly
    // what lets the injection spread. senderIsOwner is false for that traffic.
    const d = classifyConversationOrigin({ senderIsOwner: false });
    expect(d.mayTaint).toBe(true);
    expect(d.reason).toMatch(/agent/i);
  });

  it('scans data content too, obviously', () => {
    expect(classifyConversationOrigin({ senderIsOwner: false }).scan).toBe(true);
  });
});

describe('unknown is never mistaken for the owner', () => {
  it('fails toward caution when the host does not say who sent it', () => {
    // A host or host version that omits senderIsOwner must not silently turn
    // escalation off everywhere — that would be a fleet-wide fail-open
    // delivered by an absent field.
    const d = classifyConversationOrigin({});
    expect(d.origin).toBe('unknown');
    expect(d.mayTaint).toBe(true);
  });

  it('requires a strict boolean true — truthy values are not the owner', () => {
    for (const v of ['true', 1, {}, [], 'yes']) {
      const d = classifyConversationOrigin({ senderIsOwner: v as unknown as boolean });
      expect(d.mayTaint).toBe(true);
      expect(d.origin).not.toBe('owner');
    }
  });

  it('never grants trust from the channel, only the sender', () => {
    // There is deliberately no channel/transport input to this function. If a
    // future change adds one, this test is the reminder that a trusted pipe
    // carrying pasted content is still untrusted content.
    const d = classifyConversationOrigin({ senderIsOwner: undefined });
    expect(d.mayTaint).toBe(true);
  });
});

describe('every decision explains itself', () => {
  it('carries a human-readable reason for the audit trail', () => {
    for (const input of [{ senderIsOwner: true }, { senderIsOwner: false }, {}]) {
      expect(classifyConversationOrigin(input).reason.length).toBeGreaterThan(20);
    }
  });
});
