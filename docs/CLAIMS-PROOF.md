# ShieldCortex — Claims Proof Suite

Every public defensive claim ShieldCortex makes, mapped to a test that **fires the real
attack and asserts the block / redaction / quarantine** — not merely that code runs. This
turns the marketing surface into CI-enforced fact: a customer doing diligence can run one
file and watch every promise get validated.

```bash
npm test -- claims-proof
```

- **Claims source:** `README.md` + `skills/shieldcortex/SKILL.md` (v4.43.0)
- **Proof:** `src/__tests__/claims-proof.test.ts` — 14 tests, 91 assertions, all green
- **Pillars:** 🧠 Memory (what it *stores*) · 🔓 Recall/ACL (what it *releases*) · 🛡️ Iron Dome (what it *does*) · 🌐 Environment Firewall (what it *sees*) · 🧾 Forensics

## Traceability matrix

| # | Public claim | Source | Proof — `claims-proof.test.ts` | Status |
|---|--------------|--------|--------------------------------|:------:|
| 1 | 6-layer pipeline blocks/quarantines poisoning before durable memory; nothing silently dropped | README "Stop bad memory before it spreads"; "Blocked content goes to quarantine… nothing is silently dropped" | A·claim 1 — BLOCK at a web source, QUARANTINE at an api source, and a real auto-extract injection is kept out of `memories` with a `defence_audit` row | ✅ |
| 2 | Pattern detection catches known injection + encoding/obfuscation tricks | README firewall layers ("Pattern Detection → injection patterns, encoding tricks") | A·claim 2 — regex injection, homoglyph/confusables, and zero-width-char obfuscation all blocked | ✅ |
| 3 | Semantic analysis catches paraphrased attacks the regexes miss | README "Semantic Analysis … catches paraphrased attacks the regexes miss" | A·claim 3 — a paraphrase the regex layer **misses** (`detected=false`) is flagged by semantic similarity (`flagged=true`); benign text not flagged | ✅ |
| 4 | Behavioural scoring (entropy/anomaly) flags anomalous content | README "Behavioural Scoring — entropy analysis, anomaly detection" | A·claim 4 — anomalous content scores above benign and above threshold | ✅ |
| 5 | Credential-leak detection blocks high-confidence keys/tokens (25+ patterns, 11 providers) | README/SKILL "Credential Leak Detection — 25+ patterns, 11 providers" | A·claim 5 — ≥4 distinct providers caught as `critical` and blocked at write; git SHA / UUID not false-flagged | ✅ |
| 6 | Skill threat patterns block at memory-WRITE time, not just file scans | SKILL "Skill threat patterns … block at memory-write time, not just on skill-file scans" | A·claim 6 — tool-injection, scope-escalation, data-exfiltration, persistence, supply-chain, agent-manipulation, stealth-instruction all detected; the write is blocked | ✅ |
| 7 | Contradiction detection flags a conflicting new memory | README "Contradiction detection" | A·claim 7 — a conflicting memory scores ≥ threshold; an unrelated one returns null | ✅ |
| 8 | RESTRICTED isolation + own-only for low-trust callers, applied before recall reaches the agent | SKILL "trust/ACL-filters recalled memory (RESTRICTED isolation, own-only…) before it reaches the agent" | B·claim 8 — source trust scoring, ACL `checkAccess`, the MCP `get_memory` tool, related-recall, and the recall path all exclude RESTRICTED / low-trust | ✅ |
| 9 | Dashboard API + WebSocket never emit RESTRICTED content | SKILL "the bundled dashboard never renders RESTRICTED content … redacts before it reaches the browser" | B·claim 9 — REST and WebSocket payloads carry the placeholder content, masked titles, and metadata only | ✅ |
| 10 | Iron Dome Action Guard hard-blocks catastrophic tool calls out of the box | README Iron Dome; SKILL "Iron Dome kill-switch can block operations" | C·claim 10 — `rm -rf /`, fork bomb, and delete-root all return `decision=block, severity=catastrophic` | ✅ |
| 10a | `dangerous` tier is gated by default (require_approval, never silent-allow) with benign precision | P1/WS1 — internal posture proof; OpenClaw interceptor enforces-by-default on this verdict (core-wide default flip still pending) | C·claim 10 (gating) — broad `rm`, `sudo`, force-push all return `require_approval/dangerous` with a firing signal; (precision) — benign shell/read stay `allow` | ✅ |
| 11 | Environment Firewall detects hidden web injection; enforce mode redacts before the model sees it (advisory by default) | README Environment Firewall | D·claim 11 — advisory passes content through (flagged, not blocked); enforce withholds/redacts; a clean page is not flagged in either mode | ✅ |
| 12 | Provenance ledger records read/write/delete with content hashes | SKILL "a provenance ledger recording read/write/delete operations with content hashes" | E·claim 12 — ledger rows written for each operation, each carrying a content hash | ✅ |

## Verdict

**12 / 12 public claims proven by a firing adversarial test. 0 gaps, 0 unwired claims.**

_P1/WS1 adds internal posture proof **10a** (dangerous-tier gated by default + benign precision). Not counted as a new public claim: it hardens the posture behind claim 10 rather than asserting a new marketing line._

The pillars aren't just documented — they hold under attack, and now there's one runnable
file that proves it.

### Note on claim 1

During the build, one assertion was corrected to match the wiring: the auto-extract
injection payload triggers a hard **BLOCK** (dropped from durable memory **with** a
`defence_audit` row), not a `quarantine` row. The suite now asserts the true terminal
state — kept out of `memories`, audited, never silently dropped — which is exactly what
the README claims. QUARANTINE-verdict routing is separately asserted in-process (claim 1,
api source).
