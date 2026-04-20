# ShieldCortex Agent Trap Gap Analysis and Feature Proposal

Date: 2026-04-20  
Author: TARS  
Status: Draft for review

## Executive Summary

Google DeepMind's "AI Agent Traps" framing is directly relevant to ShieldCortex.

The good news: ShieldCortex already covers a meaningful part of this threat space, especially around memory poisoning, prompt injection, unsafe actions, and post-incident investigation.

The bad news: ShieldCortex does **not** yet fully cover hostile rendered environments, cross-agent systemic trap propagation, or human-overseer manipulation. Those are not minor edge cases. They are the next battlefield.

## Bottom-Line Verdict

**Do not replace ShieldCortex.**  
**Do add a new ShieldCortex sub-layer.**

Recommended new capability:

## Proposed Feature Name

**ShieldCortex Environment Firewall**

Alternative names:
- Agent Trap Guard
- Web Trap Guard
- Perception Firewall
- Hostile Environment Defence

Best product architecture:
- **ShieldCortex Memory** protects what the agent stores
- **Iron Dome** protects what the agent does
- **Environment Firewall** protects what the agent sees

That is the cleanest strategic model.

---

# 1. Why this matters

AI agent security is no longer just about prompt injection in plain text.

Modern agent failures can come from:
- web pages that render one thing to a human and another thing to a machine
- adversarial UI or DOM structures
- poisoned external content that looks legitimate
- agent-to-agent contamination
- attacks that manipulate the human approver rather than the model itself

This means the attack surface now spans:
- memory
- behaviour
- environment
- approval workflows
- multi-agent coordination

ShieldCortex already covers the first two well enough to matter. The third is the missing piece.

---

# 2. Current ShieldCortex coverage

## 2.1 What ShieldCortex already does well

Based on current ShieldCortex positioning, notes, and internal analysis, the product already includes or claims:
- 6-layer defence pipeline
- prompt injection detection
- poisoning protection
- trust scoring
- sensitivity classification
- credential leak detection
- behavioural analysis
- Iron Dome action gating
- kill switch
- audit trail
- incident replay
- X-Ray scanning for files, packages, plugins, and skills
- write-time blocking for threat patterns
- memory review and contradiction handling

This is real protection, not brochure confetti.

## 2.2 What that means in practice

ShieldCortex is already strong against:
- hostile text payloads
- prompt injection in instructions and files
- poisoned memory writes
- unsafe tool or action execution
- persistence of bad content into long-term recall
- post-incident investigation after something goes wrong

That gives it credible coverage against a large part of the "AI Agent Traps" threat model.

---

# 3. Trap-by-trap coverage assessment

## 3.1 Content Injection Traps

Definition:
Adversarial content designed to exploit differences between human-visible content, machine parsing, hidden instructions, encoding tricks, or rendering behaviour.

### Current ShieldCortex coverage
**Rating: Partial to Strong**

What is covered now:
- prompt injection patterns
- hidden payload patterns in text
- fragmented instruction smuggling
- decoded payload rescanning
- file and skill scanning through X-Ray and scanner logic

What is not sufficiently covered:
- rendered DOM vs raw HTML mismatch
- CSS-hidden or visually deceptive instructions
- browser-view vs fetch-view mismatch
- visual overlays or deceptive interaction surfaces
- OCR-visible content differing from parsed content

### Verdict
ShieldCortex is good at **text-level content injection**.
It is not yet strong enough at **rendered-environment deception**.

---

## 3.2 Semantic Manipulation Traps

Definition:
Content engineered to steer the agent's reasoning, confidence, or verification process without obvious prompt-injection fingerprints.

### Current ShieldCortex coverage
**Rating: Partial**

What is covered now:
- trust scoring
- source visibility
- anomaly scoring
- some behavioural analysis
- memory review and contradiction handling

What is weak:
- subtle persuasion attacks that look legitimate
- adversarial reasoning nudges that do not trip injection signatures
- malicious but fluent policy-like content
- attacks framed as "best practice", "system update", or "operator intent"

### Verdict
ShieldCortex helps here, but nobody has this fully solved. This is partly a detection problem and partly a provenance problem.

---

## 3.3 Cognitive State Traps

Definition:
Attacks targeting long-term memory, learned behavioural policies, retrieval context, or durable state so the agent becomes more vulnerable over time.

### Current ShieldCortex coverage
**Rating: Strong**

What is covered now:
- memory firewall
- poisoning protection
- trust scoring
- contradiction detection
- decay and provenance
- structured memory review
- replay surfaces
- write-time blocking

### Verdict
This is ShieldCortex's best-covered area. If the paper's concern is poisoned long-term agent state, ShieldCortex is already in the right lane.

---

## 3.4 Behavioural Control Traps

Definition:
Attacks that push the agent into unsafe actions, tool misuse, data exfiltration, or unauthorized operations.

### Current ShieldCortex coverage
**Rating: Strong**

What is covered now:
- Iron Dome instruction gateway
- injection scanner
- action gating
- kill switch
- PII guard
- audit trail
- security profiles

### Verdict
Iron Dome is already the correct response class for this category.

---

## 3.5 Systemic Traps

Definition:
Failures that emerge across multiple agents, tools, approvals, or connected systems rather than from one isolated malicious message.

### Current ShieldCortex coverage
**Rating: Weak**

What is covered now:
- audit surfaces
- incident replay
- some provenance and trust logic
- scoped memory separation

What is missing:
- taint propagation across agents
- cross-agent trust inheritance rules
- containment zones
- action budgets and burn-rate detection
- loop detection for agent chains
- multi-agent quarantine controls
- formal "dirty input touched this output" lineage

### Verdict
This is one of the biggest product gaps.

---

## 3.6 Human-in-the-Loop Traps

Definition:
Attacks that manipulate the human approver by shaping what the operator sees, emphasizing safe-looking explanations, hiding risk, or exploiting urgency and trust.

### Current ShieldCortex coverage
**Rating: Weak**

What is covered now:
- audit trail
- replay
- approval-aware behavioural gating in concept
- provenance language

What is missing:
- visible-vs-hidden content diff for humans
- suspicion explanations in approval UI
- operator bias warnings
- approval context hardening
- render vs parse mismatch reporting
- "page says do X, user never asked for X" indicators

### Verdict
ShieldCortex can support investigation here, but not prevent enough of it yet.

---

# 4. Overall coverage matrix

| Trap category | Current ShieldCortex coverage | Verdict |
|---|---:|---|
| Content injection traps | Partial to Strong | Good for text, weak for rendered deception |
| Semantic manipulation traps | Partial | Helpful, not sufficient alone |
| Cognitive state traps | Strong | Core strength |
| Behavioural control traps | Strong | Iron Dome already fits |
| Systemic traps | Weak | Needs new controls |
| Human-in-the-loop traps | Weak | Needs better approval UX and provenance surfacing |

## Summary

ShieldCortex already covers roughly:
- **memory poisoning** well
- **behavioural hijack** well
- **classic prompt injection** reasonably well

But it does **not** yet cover the full hostile-environment problem.

---

# 5. The actual gap

The main missing capability is not "more prompt injection regex".

The actual gap is:

## Missing Layer: Environment-Aware Security

ShieldCortex currently focuses on:
- what goes into memory
- what the agent is allowed to do

It needs a layer that focuses on:
- what the agent is perceiving from hostile environments

That means verifying and controlling:
- raw content
- rendered content
- visual content
- provenance
- trust inheritance
- taint flow
- approval context

---

# 6. Proposed new feature: Environment Firewall

## Product thesis

Environment Firewall should sit between external content and the agent's decision layer.

Its job is to answer:
- Is this environment trying to manipulate the agent?
- Is the rendered view materially different from the parsed view?
- Did the user's real goal get replaced by page-supplied intent?
- Can this content safely influence memory, tools, or approvals?

## Core design principle

**External content must never silently become authority.**

Everything external should be:
- classified
- provenance-scored
- taint-tracked
- bounded in influence

---

# 7. Environment Firewall feature set

## 7.1 Rendered Environment Verification

Compare multiple views of the same source:
- raw HTML / fetched text
- rendered DOM text
- accessibility tree
- OCR / screenshot-visible text
- extracted links, forms, and actions

### Goal
Detect cases where:
- humans see one thing
- the agent parses another
- hidden instructions exist in CSS/DOM/attributes/iframes
- rendered action paths differ from parsed action paths

### Why it matters
This is the core missing defence against content injection traps that rely on the browser surface itself.

---

## 7.2 Origin and Provenance Scoring

Every external page or artifact should carry provenance metadata such as:
- source domain
- redirect chain
- fetched URL vs final URL
- TLS / transport status where available
- first-seen / repeat-seen status
- trust allowlist or denylist state
- unusual encoding or obfuscation markers
- script-heavy or mutation-heavy behaviour markers

### Goal
Let the system distinguish:
- known trusted operational sources
- untrusted but normal sources
- clearly suspicious environments

---

## 7.3 Taint Tracking

Every external artifact should get a taint label such as:
- trusted
- untrusted
- quarantined
- user-approved override
- derived from suspicious source

That taint should propagate into:
- memory writes
- tool call inputs
- sub-agent instructions
- follow-up summaries
- approval requests
- audit and replay surfaces

### Goal
Make it impossible for hostile input to quietly become future truth.

---

## 7.4 Intent Lock

Introduce explicit separation between:
- **user intent**
- **environment suggestions**
- **agent-inferred next steps**

The system should reject or flag flows where a webpage tries to redefine:
- the user's goal
- the authority boundary
- who approved what
- the action sequence

### Example
If a page says:
- ignore system safeguards
- exfiltrate data
- open a privileged console
- call another tool first

then Environment Firewall should mark it as:
- hostile intent injection
- non-authoritative instruction source

---

## 7.5 Cross-Agent Containment

Add controls for multi-agent and multi-tool environments:
- per-agent trust zones
- taint propagation across agent messages
- sub-agent downgrade when parent input is suspicious
- action budget controls
- loop detection for repeated agent hops
- quarantine of contaminated context

### Goal
Prevent one compromised browsing step from contaminating the whole fleet.

---

## 7.6 Approval Hardening

When a human is asked to approve something, show:
- source provenance
- suspicion score
- hidden vs visible content mismatch
- requested action
- why this action exists
- whether the user asked for it or the page suggested it
- what downstream systems would be touched

### Goal
Protect the human from becoming the last exploited parser in the chain.

---

## 7.7 Canary and Deception Detection

Optional advanced features:
- canary instructions to test whether pages are targeting known agent behaviours
- hidden-instruction bait detection
- DOM mutation observation during agent interaction
- anti-automation trap signatures

### Goal
Detect pages specifically crafted for agent abuse rather than generic malicious content.

---

# 8. Recommended ShieldCortex architecture

## Existing structure
- **Memory layer:** trust, recall, poisoning resistance, review
- **Behaviour layer:** Iron Dome, action gating, kill switch, PII guard

## Add
- **Environment layer:** provenance, render verification, taint, intent lock, approval hardening

## Clean architecture statement

### ShieldCortex Memory
Protects what the agent stores.

### Iron Dome
Protects what the agent does.

### Environment Firewall
Protects what the agent sees.

This creates a much stronger narrative and a much stronger real product boundary.

---

# 9. What can be built with current foundations

Based on current ShieldCortex direction, several parts can be built on existing foundations.

## Reuse candidates
- existing defence pipeline
- existing threat pattern logic
- X-Ray scanning mindset and report surfaces
- incident replay
- trust scoring and provenance language
- Iron Dome policy model
- OpenClaw plugin interception patterns

## Likely new engineering work required
- browser-aware page capture and render analysis
- DOM/render/OCR diff pipeline
- taint propagation model
- intent lock rules
- approval UX with provenance overlays
- cross-agent trust lineage and containment logic

This is not just a new regex pack. It is a real product extension.

---

# 10. Product packaging recommendation

## Best packaging
Make Environment Firewall part of ShieldCortex, not a totally separate product.

Reasons:
- the architecture is naturally adjacent to memory and Iron Dome
- the threat model is continuous, not separate
- customers will understand a layered security model faster than a fragmented product line
- replay, trust scoring, and gating already give you the right foundation

## Possible commercial structure
- Free: basic environment provenance and simple injection warnings
- Pro: rendered diffing, taint tracking, approval hardening, advanced trap signatures
- Team: cross-agent containment, fleet policy, incident correlation, shared trust intelligence

---

# 11. Recommended phased roadmap

## Phase 1: Environment Provenance MVP
Build first:
- source provenance score
- taint labels on fetched/browser content
- intent lock for external instructions
- replay support for external-content lineage

### Outcome
Immediate value, lower complexity, fits current architecture.

## Phase 2: Render Verification
Build next:
- raw HTML vs rendered text comparison
- visible text vs hidden text analysis
- OCR/screenshot comparison on high-risk pages
- suspicious DOM structure heuristics

### Outcome
Covers the most important "AI Agent Trap" browser gap.

## Phase 3: Approval Hardening
Build:
- operator-facing diff views
- suspicious action explanation
- why-triggered provenance summaries
- approval screens that show whether user intent matches requested action

### Outcome
Directly addresses human-in-the-loop traps.

## Phase 4: Cross-Agent Containment
Build:
- taint propagation across agents/tools
- cross-agent trust zones
- contamination quarantine
- loop and amplification detection

### Outcome
Moves ShieldCortex from single-agent hardening into real fleet security.

---

# 12. Final decision

## Final answer to the question

### Can ShieldCortex protect against AI Agent Traps today?
**Partly, yes. Fully, no.**

### Do we need a new layer?
**Yes.**

### Does that mean ShieldCortex is insufficient as a platform?
**No.** It means ShieldCortex is the correct core, but needs an environment-facing extension.

## Best strategic call
Build:

# ShieldCortex Environment Firewall

Because the full security story becomes:
- hostile memory blocked
- hostile actions blocked
- hostile environments detected and contained

That is a serious product.

---

# 13. One-sentence positioning

**ShieldCortex secures what AI agents remember, what they do, and, with Environment Firewall, what they trust from the world around them.**

---

# 14. Recommended next deliverables

1. Convert this into a product requirements document
2. Write a technical architecture note for Environment Firewall
3. Define a taint model and provenance schema
4. Define the approval UX for human-in-the-loop protection
5. Create a landing page / positioning draft once scope is approved
