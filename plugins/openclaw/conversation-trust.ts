/**
 * Source trust for conversation content.
 *
 * The operator's own typing is the highest-trust input that exists. Treating it
 * as a possible attack is nearly pure cost: it produces false alarms, and false
 * alarms are how a security control gets switched off. "Delete the old logs"
 * typed by the owner is an INSTRUCTION, not an injection.
 *
 * The rule this encodes:
 *
 *     the human speaks instructions; everything else is data.
 *
 * Two things it deliberately does NOT do:
 *
 * 1. **It does not trust the channel.** Telegram is a trusted pipe, but a web
 *    page pasted into Telegram is untrusted content arriving through it.
 *    Riding a trusted channel is prompt injection's entire trick, so only the
 *    SENDER can confer trust — never the transport.
 *
 * 2. **It does not treat agent-to-agent traffic as trusted.** This is the
 *    counterintuitive one. If agent A reads a poisoned issue and relays it to
 *    agent B over a closed platform, the platform being closed is exactly what
 *    lets the injection spread — a confused deputy with good transport. Anything
 *    whose sender is not provably the owner is data.
 *
 *    ShieldCortex's memory side already says this: a sub-agent write has its
 *    trust cut per level away from the human and lands in a hold band. This is
 *    the same principle applied to the conversation path.
 *
 * IMPORTANT — trust gates the CONSEQUENCE, not the detection. Content is always
 * scanned and a detection is always audited, whatever its origin; trust decides
 * only whether that detection may escalate the Action Guard (#233). Skipping the
 * scan would trade away visibility, which is what got us into #225 in the first
 * place. This keeps the operator's false-alarm cost at zero without going blind.
 */

export type ConversationOrigin = 'owner' | 'non-owner' | 'unknown';

export interface ConversationTrustDecision {
  origin: ConversationOrigin;
  /** Always true. Detection and audit are unconditional — see module note. */
  scan: boolean;
  /** May a detection in this content tighten the Action Guard? */
  mayTaint: boolean;
  reason: string;
}

export interface ConversationTrustInput {
  /** Host-supplied: the message came from the gateway's owner. */
  senderIsOwner?: boolean;
  /**
   * Operator opt-out. `false` makes owner input taint like anything else — for
   * hosts where the owner routinely pastes untrusted content and would rather
   * have the caution than the quiet.
   */
  trustOwnerInput?: boolean;
}

export function classifyConversationOrigin(input: ConversationTrustInput): ConversationTrustDecision {
  // Strict `=== true`. A missing or non-boolean flag is NOT the owner: on a host
  // or host version that does not supply it, defaulting to "trusted" would
  // silently disable escalation everywhere. Unknown fails toward caution.
  const isOwner = input.senderIsOwner === true;
  const trustOwner = input.trustOwnerInput !== false;

  if (isOwner && trustOwner) {
    return {
      origin: 'owner',
      scan: true,
      mayTaint: false,
      reason: 'sender is the gateway owner — their input is an instruction, not an injection vector',
    };
  }
  if (isOwner && !trustOwner) {
    return {
      origin: 'owner',
      scan: true,
      mayTaint: true,
      reason: 'sender is the owner, but conversationTrust.trustOwnerInput is disabled on this host',
    };
  }
  if (input.senderIsOwner === false) {
    return {
      origin: 'non-owner',
      scan: true,
      mayTaint: true,
      reason: 'sender is not the owner — treated as data, including another agent on a trusted channel',
    };
  }
  return {
    origin: 'unknown',
    scan: true,
    mayTaint: true,
    reason: 'sender unknown (host did not supply senderIsOwner) — cannot prove owner, so treated as data',
  };
}
