# ShieldCortex subscription product — Phase 0 design

Status: **draft for owner review** · Base: `origin/main` a2b448eb (v5.2.1) · Branch: `design/subscription-product` · 2026-09-26

No code in this phase. This document is the thing to approve, change, or reject before Phase 1 starts.

---

## Open question for Michael

**Can this engagement change the Cloud API (the `ShieldCortex-internal` repo / `api.shieldcortex.ai`), or must it stay client-only?**

Four paid features need a server half this repo does not contain: issuing entitlement-bearing licence keys from Stripe, issuing device certificates, hosting and signing the threat feed, and accepting ledger anchors. The definition of done ("upgrade to a paid tier with a key, receive a signed feed update") depends on it.

**Assumption I am working on until you say otherwise:** client-only. Everything the client needs is built and tested here against a **test** signing key. The server contract is written down as a spec (request/response shapes, key IDs) so the Cloud side can be built to match. The feed is served as static signed files, so a CDN or GitHub Release is enough to run it. Nothing in this repo ever holds the production signing key.

---

## 1. Ground truth, verified

I checked the prompt's claims against the repo. All hold. Notes where the detail matters:

| Claim | Verified | Detail that matters for this design |
|---|---|---|
| Free + Enterprise only, trial retired | ✅ | Retired in **4.47.0** (2026-07-04). The retired self-serve tiers were **Pro £29/mo** and **Team £99/mo**. `src/license/trial.ts` is an inert stub. `useBillingSetup.ts` (Stripe quick-checkout) is dormant, not deleted. |
| Licence machinery works | ✅, with gaps | Ed25519 over the raw payload, one hardcoded public key, **no key id**. The payload is `{tier, teamId, email, exp, iat, sid}` — **no entitlements, seats, org or device limit**. Expiry grace is 7 days. |
| Revocation polling | ⚠️ **not wired** | `scheduleOnlineValidation` is exported but has no runtime caller. Revocation is only checked during `license activate`. The check also follows the user-settable `cloudBaseUrl`. |
| Every local feature free | ✅ | 19 of 23 `GatedFeature`s are `free`, **including `audit_export`**. Four are team-rank (Enterprise): `cloud_sync`, `team_management`, `shared_patterns`, `memory_scopes`. The last three have no call sites outside `gate.ts`. |
| CLAIMS-PROOF 13/13 | ✅ | Plus internal posture proof 10a. |
| Provenance ledger | ✅, but not evidence-grade | `defence_audit` holds a SHA-256 of the content **per row**. There is **no hash chain**: rows can be edited or deleted without trace, and retention deletes them routinely (90 days / 100k rows). SCOPE.md P3 names this gap ("A ledger you can edit is a diary, not evidence") and it is unbuilt. |
| Detector patterns | Hardcoded TS | No version IDs on detectors or patterns. The only remote fetch is the **unsigned** per-tenant Iron Dome pattern/policy sync (`src/cloud/iron-dome-sync.ts`). `src/environment/provenance.ts` has an empty `KNOWN_BAD_DOMAINS` "populated from threat feeds in later phases". |
| Fleet | Words only | Device UUID + heartbeat exist. The policy lock (`/etc/shieldcortex/policy.json`) is trusted because it is root-owned, not signed. Its design doc names "a remote policy authority" as the future answer. |
| Telemetry | None | No product telemetry anywhere. Cloud egress is opt-in (`cloudEnabled` **and** an API key). |
| Forensics | Pieces | `session_events` (timeline + replay scrubber), `defence_audit`, `denials.jsonl` (commands deliberately redacted), `audit/realtime-*.jsonl` and `audit/session-guard/*.jsonl`. They share `sessionKey` / `actionKey` / `seq` / `audit_id`, but not consistently, and nothing assembles them. |
| Compliance docs | None | No SOC 2 / ISO / EU AI Act / SLA mention anywhere in `docs/`. |

**Found during Phase 0; not subscription work.** Each should be its own issue on the free core, whatever you decide about pricing:

1. **Cloud pattern sync compiles remote regexes with no `validateRegex` / ReDoS check** (`injection-scanner.ts` `setExternalPatterns`). A bad or hostile pattern from the tenant's cloud could stall the write hot path and break the P1 perf budget.
2. **`src/cloud/verify.ts` sends full content** (credentials redacted) but applies **no PII redaction, project filter or `excludeSensitive`**. The other sync paths honour these.
3. **Memory sync applies no credential redaction** (`memory-sync.ts`); quarantine sync does.
4. **Revocation is unwired**, and the check follows the user-set `cloudBaseUrl` (see above).
5. **The audit export CSV omits the ledger columns** (`operation`, `content_hash`, `source_attested`, `risk_modifier`).
6. **Stale "Requires a Pro licence" copy**: `LocalAiFindingExplainer.tsx:268`, `TabBar.tsx:56`, "Team+ key" in `CloudSyncStatus.tsx:97`, the "(Pro feature)" header in `src/defence/audit/export.ts`.

---

## 2. The buyer and the moment they decide to pay

**Who installs it:** a developer. They found ShieldCortex because their agent has shell access and that scared them. They will never pay, and they must never feel pushed to.

**Who pays:** the person who owns the risk budget at a 10–250 person software company that runs agents with tool access on shared or production machines. That is a head of platform, an engineering lead doubling as security lead, or a first security hire. They already have the free package on several boxes because a developer put it there.

**The moment they decide.** It is always a question from someone outside the engineering team that the free tool cannot answer on its own:

1. **The questionnaire.** A customer's security review or the SOC 2 / ISO 27001 auditor asks: *"What controls govern what your AI agents can do, and show me evidence they operated during the period."* Screenshots of a local dashboard are not evidence. A signed, dated, verifiable report is.
2. **The first real block.** The guard denies something ugly. Leadership asks: *"What else did it see, store and try? Can you prove the log wasn't edited?"* The free tool can show the local timeline. It cannot prove to a third party that the timeline is complete.
3. **The fifth machine.** Per-box `protect` works until someone asks *"are all of them still in policy?"* Nobody can answer that by SSH-ing into 30 boxes.

Each moment happens roughly once a year and comes back every year. Audit cycles are annual, attestation is annual, and so the subscription is annual.

---

## 3. The free/paid line

### The rule

> **Anything that protects a machine is free, forever, MIT. You pay for things that need a third party: a signature someone else can check, updates someone else curates, and a view across machines that no single machine has.**

Three tests every paid feature must pass. If a feature fails any one of them, it is free:

1. **Structural test.** The free tool, running alone on one box, cannot do it. It needs Drakon's key, Drakon's feed, or an org-wide view.
2. **No-subtraction test.** Nothing that is free in v5.2.1 moves behind the licence. That includes `audit_export`, custom patterns, custom policies, X-Ray deep, local timeline replay, `doctor`, `protect` and the free Cloud tier.
3. **Lapse test.** When a subscription lapses, the machine is exactly as protected as the day before. It stops *getting new proof and new updates*; it never loses protection it already has.

### The one-line "why pay"

> **"The protection is free. You pay for proof it worked — signed, current, across every machine — that an auditor can verify offline."**

A developer can accept this without resentment because it is true. Nothing they use is taken away, and what is sold is something their laptop could not produce on its own anyway.

---

## 4. Tiers and prices

Annual only, self-serve by card, prices in GBP with USD list prices alongside. There is no monthly plan (see §7).

| | **Free** | **Assure** | **Fleet** | **Enterprise** |
|---|---|---|---|---|
| Price | £0 | **£1,490 / year** ($1,990) | **£5,900 / year** ($7,900) | **from £24,000 / year** (sales-led) |
| Machines | unlimited, per-machine | up to **10** | up to **50**, then £99 / machine / year | negotiated |
| Buy | `npm install` | card, self-serve | card, self-serve | sales@drakonsystems.com |

A "machine" is one installation holding an active **device certificate** (§5.1). Machines are counted by certificates issued, **not by telemetry**. At the limit, the only thing that happens is that the next device gets a plain-English card saying no new certificate was issued. Protection on that machine is unaffected. There is 10% headroom before the card appears.

### Why these prices — what each one replaces

These numbers are **assumptions to validate with 5–10 buyer conversations before launch, not measurements.** The reasoning is written out so you can attack it.

**Assure £1,490.** It replaces:
- **Evidence assembly.** A senior engineer collecting "agent controls" evidence for one audit cycle: screenshots, config exports, explaining which hosts actually gate. At 2–3 days at £600–700/day, that is about £1,500–2,000 per cycle, before the auditor bills for chasing it. Assure is priced below one cycle's internal cost.
- **Upgrading a production gateway just to get new patterns.** SCOPE §1a (never break the host) makes package upgrades on a live OpenClaw box a real risk. The feed delivers detection updates with no package upgrade.

It also sits deliberately **under the ~£2,000 corporate-card threshold** common at this company size, so an engineering lead can buy it without procurement. For comparison, the retired Team tier was £1,188/year and sold local features that are now free. Assure costs about the same but sells things the free tool cannot do.

**Fleet £5,900.** At 50 machines that is £118 per machine per year, about £10 a month. It replaces:
- **Building signed config distribution plus drift alerting in-house.** Ansible roles, custom checks, alert routing, and keeping all of it working as ShieldCortex's config evolves: about 2 engineer-weeks (~£6–7k) to build, then upkeep.
- **Stitching per-box evidence together** for the auditor.

It sits under the ~£10k line where many companies of this size require a formal procurement process.

**Enterprise from £24,000.** The floor covers:
- a named engineer (~0.1 FTE)
- SSO/SCIM
- DPA and security-questionnaire work
- custom control mappings
- an air-gapped feed mirror

That is at the low end of enterprise security-tooling contracts, and anything below it would be sold at a loss.

---

## 5. Exact feature list per tier

### Free (unchanged, and gains the verifier)

Everything in v5.2.1, including: memory firewall (6 layers, 7 detectors), Action Guard, Environment Firewall, local dashboard, provenance ledger, quarantine, review queue, knowledge graph, `audit_export` JSON/CSV, custom patterns/policies/firewall rules, X-Ray deep, local session timeline/replay, `doctor`, `protect`, free Cloud (500 scans/month, 7-day retention, 1 member).

**New and free under this plan:**

- **Hash-chained ledger** (SCOPE P3). It is local integrity, so under the rule it is free. Retention prunes write a chained checkpoint row, so deletions are *accounted for* rather than invisible.
- **`shieldcortex evidence verify <pack>`**, plus a standalone verifier with no ShieldCortex install and no licence. Whoever checks a pack must never need a subscription to do it.
- **`shieldcortex evidence preview`.** It produces the same report an Assure pack would, stamped **UNSIGNED — NOT EVIDENCE**, so a buyer can see exactly what they would get. This replaces the trial.
- **Incident reconstruction, local.** Assembling the cross-store view of one blocked event is just reading your own data, so it is free.
- **Every feed pattern reaches npm** in the next release, and within 30 days at most. **Actively exploited in-the-wild patterns ship to npm the same day, for everyone.** The feed does not withhold emergency protection.

### Assure

Everything in Free, plus:

1. **Signed threat intelligence feed.**
   - Signed pattern updates for injection families, poisoning shapes, credential formats and known-bad domains, as they land. The target cadence is weekly.
   - Delivered with no package upgrade.
   - Comes with a signed changelog the customer can show an auditor ("detector set 2026.40.2 was active on these machines from these dates").
2. **Signed evidence packs.** On demand, plus an automatic pack each quarter. Contents: what ran, what was blocked, detector and feed versions, config hash, policy-lock state, **per-host binding state from the same logic `doctor` uses**, and ledger chain status. Mapped to SOC 2 / ISO 27001 / ISO 42001 / EU AI Act controls (§5.2). Verifiable offline.
3. **Ledger anchoring.** Hourly, the ledger's chain head (**a hash only, no content**) is countersigned by Drakon. This lets a pack prove that the ledger wasn't rewritten after the fact, **back to the last anchor**.
4. **Sealed incident bundles.** The local reconstruction, signed and anchored, exportable for an auditor, insurer or customer. An off-box copy is retained in Cloud **only if content upload is explicitly opted into**.
5. **False-positive support.** Triage within **2 business days**, measured against the FP budget (§5.4).
6. Up to 10 machines.

### Fleet

Everything in Assure, plus:

1. **Fleet policy.** One signed org policy file sets:
   - which hosts must be bound;
   - the Action Guard posture;
   - what is denied and what needs approval;
   - `autoApprove` lists and memory posture.

   It is applied through the existing root-owned policy lock, and "tighter wins" is kept: a local config can make a machine stricter than the fleet policy, never looser.
2. **Drift detection.** Each enrolled machine reports its policy hash, per-host binding state, package version and feed sequence. The Cloud Devices view shows the result per machine: in policy, drifted, or **unknown**. A machine that stops reporting is shown as unknown, never compliant.
3. **Org-wide evidence pack.** One signed roll-up across all machines, with a per-machine appendix.
4. Unlocks the existing `team_management` and `shared_patterns` entitlements.
5. False-positive triage within **1 business day**.
6. Up to 50 machines, then £99 per machine per year.

### Enterprise

Everything in Fleet, plus:
- SSO/SCIM
- full memory/graph replication (existing `cloud_sync`, `memory_scopes`)
- an air-gapped / self-hosted feed mirror
- custom retention for anchors and bundles
- DPA
- custom control mappings reviewed with their auditor
- **4-hour response on critical FPs**
- a named engineer
- SIEM connectors beyond the free webhook

Existing Enterprise keys keep everything they have today (see §5.1 for re-issue).

### 5.1 Licence and entitlement model

- **New key version.** v1 keys (`sc_pro_`/`sc_team_`/`sc_ent_`) keep verifying exactly as today.
  - A new `sc_v2_` payload adds `plan`, `org`, `ent[]` (explicit entitlements), `machines`, and **`kid`** (key id, so keys can be rotated).
  - Paid features are checked by **entitlement**, not `TIER_RANK`. A grandfathered v1 Pro/Team key therefore cannot accidentally unlock Assure/Fleet features.
  - **Recommendation:** re-issue live Enterprise customers v2 keys with every entitlement at no charge until their renewal.
- **Device certificates.** On a paid activation, the machine generates a local Ed25519 key pair. Only the public half is sent, and Drakon returns a certificate over `{org, device_id, plan, not_before, not_after}`.
  - Evidence packs and incident bundles are signed by the device key and carry the certificate.
  - A verifier checks: Drakon root key → certificate → pack.
- **Fail open for the free core, fail closed only for paid surfaces.**
  - A Phase 1 test pins that **no free code path reads the licence**.
  - Paid surfaces keep working for a **30-day offline grace period**, counted from the last successful online validation.
  - After that, the machine shows one plain-English card and the agent is never touched:

    > Your ShieldCortex Assure subscription couldn't be checked for 30 days. Protection is unchanged. New feed updates and signed evidence packs are paused until the key can be checked. Run `shieldcortex license status`.
- **Revocation.** Wire the (currently dead) daily check, gated to paid surfaces only, against a **pinned** licence host rather than `cloudBaseUrl`.

| State | Free core | Feed | Evidence / bundles | Existing packs |
|---|---|---|---|---|
| Active | ✅ | updates | signs | verify forever |
| Offline ≤ 30 days | ✅ | last verified feed stays active | signs | verify forever |
| Offline > 30 days / expired > grace | ✅ | **last verified feed stays active**, no new updates | paused, card shown | verify forever |
| Revoked | ✅ | last verified feed stays active | stopped | packs signed before revocation still verify, within cert validity |

### 5.2 Evidence packs — what they prove and what they don't

**What a pack is.** A deterministic JSON document plus a detached Ed25519 signature, with a human-readable PDF/markdown rendering generated *from* the JSON. It contains:

- the period covered
- package version
- detector-set and feed sequence numbers active over the period, with change dates
- config hash (canonical JSON)
- policy-lock state
- per-host binding (`bound` / `memory-only — not a gate` / `unknown`)
- Action Guard on/off and enforce posture
- counts and IDs of blocks, quarantines and approvals
- the ledger chain head plus the latest Drakon anchor
- `doctor` findings at export time

**Control mapping.** Each field maps to controls, framed as "supports evidence for", **never "compliant with"**:

- **SOC 2:** CC6.1, CC7.2, CC8.1
- **ISO 27001:2022 Annex A:** 8.9, 8.15, 8.16
- **ISO 42001 Annex A**
- **EU AI Act:** Art. 9 (risk management), 12 (record-keeping), 14 (human oversight), 15 (robustness/cybersecurity)

Articles 12–15 apply to high-risk systems, and the pack says so. **Residual:** the mapping is written by Drakon and not yet reviewed by an auditor. Get it reviewed before any marketing copy names a framework.

**What a pack proves:**
- it came from a certified installation of that org;
- it was not altered after export;
- the ledger it summarises was not rewritten after the last anchor.

**What it does not prove, stated inside every pack:**
- It says nothing about hosts marked `memory-only`: **ShieldCortex cannot deny actions there.**
- An attacker with root on the box *before* an anchor could forge the underlying data.
- An unsigned "UNSIGNED" preview proves nothing.

`doctor`'s honesty rule applies to packs verbatim: **a pack never prints "protected" for a host that cannot deny.**

### 5.3 Threat feed — safety rules

The feed is a new remote input into the detection path, so it is also a new attack surface. It ships with these rules, each with a firing test:

- **Signed and pinned.** Every feed file is signed by Drakon's feed key (`kid`-rotatable). A bad signature is rejected and the last good feed stays.
- **Monotonic.** Each file carries a sequence number, and a lower one is rejected. This stops rollback / replay of an old feed.
- **Additive only.** A feed can add detection and can retract *its own* earlier items. It **cannot disable or relax a built-in detector**, so a stolen feed key cannot switch protection off.
- **Data, not code.** Items are regex/string/domain data. Each passes `validateRegex` and the ReDoS timing budget before it is compiled, and oversize or too-slow items are rejected.
- **Shadow first.** New items run in observe mode for a stated window (default 7 days). They count would-have-fired locally before they start enforcing. Those counts stay local unless the customer opts into sharing them.
- **FP gate.** Before signing, every item runs against the must-ALLOW corpora (`fp-tune-71-73`, `fp-precision-88-89`, `guard-tune-91-89`, `span-classifier-84`, `guard-precision-corpus`, genuine-work corpus). **Zero flips**, the same ceiling as `P1-fp-budget.md`. The client re-runs the shipped corpus on arrival and refuses any item that flips a fixture.
- **Perf.** Feed items count toward the write-path budget (**p95 ≤ 5 ms, mean ≤ 2 ms** on ≤2 KB, `P1-perf-budget.md`). There is a hard cap on item count and total pattern bytes. Adding the feed is a stated revisit trigger for that budget.

### 5.4 False-positive support

The subscriber reports an FP from the dashboard or CLI. It is triaged against the FP budget. Then:

- **A feed item caused it:** the item is retracted or fixed in the feed, with a must-ALLOW fixture added.
- **A built-in detector caused it:** a local workaround is provided within the triage SLA using the existing free escape hatches (`autoApprove`, `enforce:false` per op, custom rules). The fix lands in the next npm patch with its fixture.

The feed is never used to relax built-ins (§5.3). **The SLA is for triage and response, not for time-to-fix**, and the tier copy says so.

### 5.5 Fleet policy and bound hosts

A fleet policy can *require* Action Guard enforcement, but only three hosts can deny: Claude Code, OpenClaw, Hermes. So:
- For Codex, Cursor, Copilot and MCP machines, the drift view shows **`memory-only — not a gate`**, never "in policy: enforced".
- The Fleet tier copy says so on the pricing page.

**Drift reporting is opt-in.** The opt-in copy lists exactly what leaves the machine:
- device id
- hostname (can be replaced by a label)
- policy hash
- per-host bound state
- package version
- feed sequence

It contains no content, commands, paths or memory.

---

## 6. New claims and the proof matrix

Each lands in `docs/CLAIMS-PROOF.md` with a firing test in the same PR, or it does not ship:

| Proposed claim | Firing test |
|---|---|
| A feed with a bad signature, a lower sequence, or an item that disables a built-in is rejected, and the last good feed stays | Forge / replay / relax-attempt feeds → rejected, detection unchanged |
| A feed item that flips a must-ALLOW fixture or blows the ReDoS budget is refused on arrival | Craft such an item → refused, logged |
| An evidence pack altered by one byte, or signed by an uncertified key, fails offline verification | Tamper / re-sign → `verify` fails |
| Editing or deleting a ledger row is detectable | Mutate a row / delete a row → chain verify fails at that row; a retention prune → accounted for by a checkpoint, not a break |
| A pack never reports a `memory-only` host as protected | Pack from a Codex-only machine → says "not a gate" |
| A lapsed or offline subscription never changes a free-core verdict | Same attack corpus with the licence valid / expired / revoked / unreachable → identical verdicts |

The matrix goes from 13 to 19 public claims.

---

## 7. What is NOT being built, and why

- **Nothing free moves behind the licence.** This includes `audit_export`, which people might expect to be "the evidence feature". Evidence packs are a different thing (signed, attested, mapped), built beside it.
- **No per-developer seats.** Agents aren't seats, and counting developers would need telemetry. Machines are counted by certificate.
- **No monthly self-serve plan.** The unit of value is the annual attestation, and annual-only halves billing/dunning work. Enterprise can contract any way it likes.
- **No trial.** The free tier plus `evidence preview` does the job, and there are no nag screens or expiry banners. The retired upsell machinery stays retired.
- **No protection claims for hosts that cannot deny**, in any tier, pack or pricing page.
- **No usage telemetry.** Everything that leaves the machine is opt-in and listed in the opt-in copy.
- **No kill switch.** A lapse or revocation never reduces protection (§5.1 table).
- **No compliance certification or GRC product.** We supply evidence *into* Vanta/Drata/an auditor. We do not compete with them or claim anyone is compliant.
- **No LLM-powered paid features.** They bring per-call cost, privacy exposure, and FP risk the budget cannot yet measure.
- **No Drakon-held memory content in self-serve tiers by default.** Off-box incident bundles contain content only on explicit opt-in.
- **No refactor of the built-in detectors into data files.** The feed layers on top as an additive external set per detector family. Moving hardcoded TypeScript detectors to data is a large, risky change the feed does not need.
- **No SSO, SIEM connectors or air-gapped mirror in self-serve.** They are Enterprise, because each one is real per-customer work.

---

## 8. Sequencing

One feature per PR, each opened as a draft with a failing test first. Order is chosen so the engagement's definition of done — install → upgrade with key → signed feed update → export pack → verify offline — is reachable at the earliest point:

1. **Generic Ed25519 verifier with `kid`.** Lift the pattern out of `src/license/verify.ts`; v1 licence behaviour must be byte-for-byte unchanged. *Test:* existing licence tests plus rotation/unknown-kid cases.
2. **v2 entitlements + free-core isolation.** `sc_v2_` payload, `hasEntitlement()`, and a test that no free path reads the licence. Adds the 30-day grace state, the plain-English card, and the revocation wiring (pinned host, paid surfaces only). A key-issuing script uses a **test** key only. `doctor` gains a Plan row.
3. **Signed feed client.** Fetch, verify, monotonic sequence, additive-only, `validateRegex` + ReDoS, arrival FP check, shadow mode, lapse keeps last feed. `doctor` gains Feed rows (sequence, age, verified). Proof claims 14–15.
4. **Hash-chained ledger (free).** Forward-only migration, chained prune checkpoints, `ledger verify`. The perf budget is re-measured. Proof claim 17.
5. **Device certificates + evidence packs + offline verifier.** Includes the free `preview` and the standalone verifier. Proof claims 16, 18.
6. **Anchoring** (hash-only, opt-in copy).
7. **Sealed incident bundles.** Cross-store correlation on `sessionKey`/`actionKey`/`seq`/`audit_id`. Respects the `denials.jsonl` redaction.
8. **Fleet policy + drift reporting.** Signed org policy through the policy lock, tighter-wins pinned by a test, opt-in drift heartbeat.
9. **Dashboard + copy.**
   - Plan card in Settings (replacing the static Enterprise card); remove the stale Pro/Team strings.
   - README pricing section, with the bound-host caveat on every tier.
   - CHANGELOG entries in the house register, with residuals disclosed.
   - Proof claim 19 lands with whichever PR first touches the lapse path (step 2).

**Server-side dependencies** (per the open question): v2 key issuance from Stripe annual products, device-certificate endpoint, feed build/sign/publish pipeline with the FP gate in its CI, and an anchor countersign endpoint. Until the Cloud side exists, steps 1–5 are fully testable client-side against test keys. Steps 6 and 8 need the server to be useful.

**The six free-core issues in §1 should go in first or in parallel**, whatever you decide about pricing. Two of them (cloud regex ReDoS, verify.ts PII) are the same class of risk the feed rules in §5.3 exist to prevent.

---

## 9. Risks and residuals

- **Price validation.** The prices are reasoned, not tested. **Mitigation:** 5–10 buyer conversations with existing free users who have more than 3 machines, before the pricing page ships.
- **Evidence integrity is bounded by host integrity.** A root-level attacker before the last anchor can forge the underlying data. This is stated in every pack; hourly anchoring shrinks the window but cannot close it.
- **Feed key compromise.** Bounded by the additive-only rule, but a stolen key could still push over-blocking items. **Mitigation:** the arrival FP check, shadow mode, and `kid` rotation. The feed key should be kept offline and separate from the licence signing key.
- **Control mappings unreviewed** (§5.2).
- **Grandfathered v1 keys** stay on `TIER_RANK` indefinitely. That is harmless (they only unlock what they unlock today), but it is two code paths to maintain.
- **"Machines" can be gamed** by reusing one certificate across clones. Accepted: the certificate carries `device_id`, drift shows duplicates, and this is a trust-based self-serve tier.

---

## Provenance of this document

- Written by Claude, model **Opus 5.5** (`claude-opus-5-5`), running in Claude Code — `claude --version`: `2.1.283 (Claude Code)`.
- Exploration was read-only: no install, test, build or `openclaw` command, and `~/.shieldcortex` / `~/.openclaw` were not touched. All file/line claims come from reading `origin/main` a2b448eb in the `sc-wt-subscription` worktree.
