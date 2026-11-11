# ShieldCortex — Claims Proof Suite

Every public defensive claim ShieldCortex makes, mapped to a test that **fires the real
input through the real code and asserts the block / hold / redaction / quarantine /
report** — not merely that code runs. This turns the public copy into CI-enforced fact: a
customer doing diligence can run one file and watch every promise get checked.

```bash
npm test -- claims-proof                                                  # the TypeScript planes
python3 -m unittest discover -s plugins/hermes/shieldcortex/tests -p 'test_claims_proof.py'   # the Hermes plane
```

- **Claims source:** `README.md` (v2, 5.18), the shieldcortex.ai product copy, `docs/UPDATING.md` (version 5.18.2)
- **Proof:** `src/__tests__/claims-proof.test.ts` — 35 tests; `plugins/hermes/shieldcortex/tests/test_claims_proof.py` — 12 tests (7 against the real policy module, 5 through the real plugin wiring)
- **Pillars:** 🧠 Memory (what it *stores*) · 🔓 Recall/ACL (what it *releases*) · 🛡️ Iron Dome (what it *does*, and what the shipped posture does with that) · 🪪 Cards (what the operator is *shown*) · 🌐 Environment Firewall (what it *sees*) · 🧾 Forensics · 🚧 Fleet isolation (who can read whom) · 📣 Reports changes (what it *tells you*)

Fixture identities are neutral (`agent-a`, `agent-b`, `box-a`). Secret-shaped fixtures are
assembled at runtime so no credential-shaped literal is committed.

## Traceability matrix

| # | Public claim | Source | Proof — `claims-proof.test.ts` unless stated | Status |
|---|--------------|--------|----------------------------------------------|:------:|
| 1 | Writes that go through ShieldCortex are scanned before they stick; recognised injection is quarantined or blocked; nothing silently dropped | README "Memory firewall"; site "Writes that go through ShieldCortex run a six-layer defence pipeline" | A·claim 1 — BLOCK at a web source, QUARANTINE at an api source, and a real auto-extract injection is kept out of `memories` with a `defence_audit` row; claim 1a — a write lacking provenance is rejected, every accepted row carries source + trust + verdict | ✅ |
| 2 | Pattern detectors catch known injection and encoding/obfuscation tricks | site "Built-in injection patterns"; README scan example | A·claim 2 — regex injection, homoglyph/confusables and zero-width-char obfuscation all blocked | ✅ |
| 3 | Semantic analysis catches paraphrased attacks the regexes miss | site "semantic detection layer" | A·claim 3 — a paraphrase the regex layer **misses** is flagged by semantic similarity; benign text is not | ✅ |
| 4 | Anomaly scoring (entropy/behaviour) flags anomalous content | ARCHITECTURE "Anomaly Scorer" | A·claim 4 — anomalous content scores above benign and above threshold | ✅ |
| 5 | Leaked credentials are blocked at write time | README "leaked credentials are quarantined or blocked"; site "credential leaks … caught before they reach storage" | A·claim 5 — ≥4 providers caught as `critical` and blocked at write; a git SHA / UUID is not false-flagged | ✅ |
| 6 | Skill threat patterns block at memory-write time, not just on file scans | `skills/shieldcortex/SKILL.md` | A·claim 6 — seven threat classes detected; the write is blocked | ✅ |
| 7 | Contradiction detection flags a conflicting new memory | site dashboard copy "memories that disagree" | A·claim 7 — a conflicting memory scores ≥ threshold; an unrelated one returns null | ✅ |
| 8 | RESTRICTED isolation + own-only filtering for low-trust callers, before recall reaches the agent | SKILL.md | B·claim 8 — trust scoring, ACL `checkAccess`, MCP `get_memory`, related-recall and the recall path all exclude RESTRICTED / low-trust | ✅ |
| 9 | Dashboard API + WebSocket never emit RESTRICTED content | SKILL.md | B·claim 9 — REST and WebSocket payloads carry the placeholder, masked titles and metadata only | ✅ |
| 10 | A catastrophic command is a hard stop (core verdict) | README "Catastrophe: a hard stop" | C·claim 10 — `rm -rf /`, fork bomb, `dd` to a disk all return `decision=block, severity=catastrophic`, un-relaxable by `autoApprove`; structured delete of `/` blocked | ✅ |
| 10 | A dangerous call classifies as `require_approval`, never `allow`; benign work stays `allow` | README "a suspicious call gets a plain-English card and is held" | C·claim 10 (core verdict) — broad `rm`, `sudo`, force-push all `require_approval/dangerous` with a firing signal; (precision) — `ls && npm test`, a `Read` stay `allow` | ✅ |
| 10a | **Shipped posture:** Action Guard stays **off until you turn it on**; once on and enforcing, a dangerous call is held and a catastrophic one is a hard stop | README "Where it can block"; site "What it is not: on by default" | C2·claim 10a (shipped default) — the real Claude Code hook, `actionGuard.enabled:false`, emits **no decision for any tier**, dangerous or catastrophic, while the core verdict for the same calls is unchanged; (turned on) — `enabled:true, enforce:true`: dangerous → `ask`, catastrophic → `deny`, benign → no decision | ✅ |
| 10b | A call that would switch the guard off or change its configuration is held | site "A call it recognises as switching itself off … is held too"; UPDATING 5.4 "self-protection floor" | C·claim 10b (core) — `shieldcortex config --action-guard-disable` is not `allow` and carries `disable-action-guard`; C2·claim 10b (hook) — with the guard on, the same call is `deny` (always-block, #853: never offered for approval) | ✅ |
| 10c | If the Claude Code hook fails to load, a bounded fallback still blocks recognised catastrophic commands, even with the guard off; unmatched calls stay fail-open | README "Host details and limits"; UPDATING "Claude Code hook fallback" | C2·claim 10c — `shieldcortex hook pre-tool` over an install copy with an unloadable hook and `enabled:false`: `rm -rf /` → `deny`, `ls` → no decision | ✅ |
| 11 | Environment Firewall detects hidden web injection; enforce redacts before the model sees it (advisory by default) | README Environment Firewall (earlier releases); SKILL.md | D·claim 11 — advisory flags but passes through; enforce withholds/redacts; a clean page is not flagged in either mode | ✅ |
| 12 | Provenance ledger records read/write/delete with content hashes | SKILL.md; site "audit trail … logged" | E·claim 12 — ledger rows written for each operation, each carrying a content hash | ✅ |
| 13 | Cross-agent contamination is blocked: peers cannot fetch each other's RESTRICTED rows, cannot become the owner by declaring it, and a web- or tool-sourced write does not bootstrap another agent's `get_context` | SCOPE P4 "zero cross-contamination" | F·claim 13 (×4) — `agent-b` cannot `get_memory`/`recall` `agent-a`'s RESTRICTED row; declared `user:*`/`cli:*` sources are clamped to `cli:mcp`; `web:` and `tool_response:` canaries are absent from both agents' `get_context` | ✅ |
| 14 | Approval cards say what, why and who in plain English, without the raw command; secret-shaped targets are withheld | README "Approval cards (5.6+)"; UPDATING 5.6 | C3·claim 14 — the real guard holds `pkill -f "relay --token=<secret>"`; `buildApprovalCard` and the rendered lines contain neither the token nor the command; WHY is the guard's phrase, not a signal id; WHO is `Claude Code on box-a · session …` | ✅ |
| 15 | Webhook denials and held requests end with a version-1 `card`: fixed-template what, why, who, the exact `shieldcortex approve` command, Approve/Deny choices that carry only the action id; never the raw command or a credential; advisory warnings carry no card | README "Tool gate" + "Host details"; UPDATING 5.18 | C3·claim 15 (×4) — the real webhook channel with a recording `fetch`: held call → `version:1, kind:'approval'`, `what ∈ CARD_ACTION_TEMPLATES`, every `why` part a guard phrase, exact approve/deny commands with `--attempt`, no `actions`; egress check → a card that names `~/.ssh/config` leaves as a fixed template with no path; headless denial → `approve --denial <act-id>`, `actions` keys exactly `action,label,actionId`; `action_guard_warning` → no card | ✅ |
| 16 | Agent config watch reports a hook or MCP change ShieldCortex did not make, by file and kind, never by value; detects and reports, does not block; its own writes do not alert | README "Reports changes"; UPDATING 5.16 | G·claim 16 — real `runAgentConfigWatch` over a temp HOME: silent baseline, one `hook added (SessionStart)` notification + ledger row for a planted hook, the planted command in no notification/row/text, the file still holds the change, no re-alert, `withOwnConfigWrite` edit silent | ✅ |
| 17 | MCP tool-description check reports a changed or suspicious description by name, never the description text | README "Reports changes"; UPDATING 5.14 | G·claim 17 — real `runAutoToolCheck` with the stdio launch replaced: changed → one `mcp_tool_change/changed` for `read_file`; poisoned → `suspicious`, with `ssh`/`IMPORTANT`/`ignore all` absent from notification, row and text; nothing blocks | ✅ |
| 18 | Hermes gates once its plugin is enabled and the local API is up; it enforces by default; it has no approval prompt, so a call Action Guard would hold is blocked while enforcing; advisory still blocks hard-block verdicts and self-protection calls; the API-down fallback is bounded | README "Tool gate" + "Host details and limits" | `test_claims_proof.py` (12) — policy only (7): real `policy.action_guard_decision` / `resolve_enforce`: unset → enforce, only an explicit word opts out; `require_approval` → block when enforcing, `None` in advisory; `block` → block in both; `disable-action-guard` → block even in advisory; API-unreachable flag handling: catastrophic/self-protection fallback block in both, dangerous only while enforcing, unmatched fail-open. End to end (5): the real plugin `register()` → `pre_tool_call` with only the API client stubbed unreachable: a recognised catastrophic and a self-protection command block in both postures, a dangerous one only while enforcing, an unrecognised one fails open; every decision is checked to have come through the stubbed outage path for that very call, and a fifth test confirms that check is itself load-bearing | ✅ |

## Verdict

**18 / 18 public claims proven by a firing test (35 TypeScript + 12 Python). 0 unwired claims.**

### Truth correction in this revision (claim 10a)

The previous revision of this file said the `dangerous` tier was "gated by default". That
was the **core verdict** (a dangerous call classifies as `require_approval`), not the
**shipped posture**: since 5.x the shared `actionGuard.enabled` setting defaults to
`false`, and the Claude Code hook emits no decision for any call while it is off,
catastrophic included (C2·claim 10a, shipped default). The only config-independent
protection on that plane is the hook load-failure fallback (claim 10c). The two are now
separate rows, each with its own firing test, and the README's "stays off until you turn
it on" is asserted rather than contradicted. No runtime default changed.

## Mutation checks

Each new or changed protection was removed once, in source, and the matching proof ran red
before the source was restored (evidence in the PR that landed this revision): hook
`enabled` check forced true → claim 10a (turned on) and 10b (hook) fail; forced false →
claim 10a (shipped default) fails; launcher `launcherCatastrophicMatch` → `false` → 10c
fails; the `--action-guard-disable` rule removed → 10b (core) fails; `safeTarget`
credential withholding removed → 14 fails; `fixedTemplateAction` passing text through →
15 (egress) fails; config-watch diff discarded → 16 fails; autocheck `changed` detection
disabled → 17 fails; Hermes `require_approval` never blocking → two of the 18 tests fail.

## Gaps and scope

Not proven by this suite, stated so nobody reads silence as coverage:

- **OpenClaw plugin plane** (`before_tool_call`, its enforce-by-default and its outage
  fallback). Covered by the plugin's own suites under `plugins/openclaw/__tests__/`, not
  re-proven here.
- **Claude SDK toolsets** (`shieldcortex/toolsets`, observe by default, `mode: 'enforce'`).
  Not in this file.
- **Chained audit ledger / `shieldcortex ledger verify`.** Covered by
  `src/__tests__/chained-ledger*.test.ts`, not re-proven here.
- **Doctor / posture rows, policy lock, one-tap approve endpoint (5.18 B).** Configuration
  and CLI behaviour; not defensive claims this suite fires.
- Claim 16 and 17 prove the detection and the wording through the real modules with the
  process launch replaced; the session-start spawn and the real stdio MCP launch are
  proven in `agent-config-watch*.test.ts` and `mcp-tools-autocheck-production-path.test.ts`.

### Note on claim 1

The auto-extract injection payload triggers a hard **BLOCK** (dropped from durable memory
**with** a `defence_audit` row), not a `quarantine` row. The suite asserts the true
terminal state — kept out of `memories`, audited, never silently dropped — which is what
the README claims. QUARANTINE-verdict routing is separately asserted in-process (claim 1,
api source).
