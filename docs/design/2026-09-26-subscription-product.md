# ShieldCortex subscription product — Phase 0 design

Status: **draft for owner review — revision 2.2** · Base: `origin/main` a2b448eb (v5.2.1) · Branch: `design/subscription-product` · r1 2026-09-26 (7ad519eb) · r2 2026-09-29 (e655dcf6) · r2.1 2026-09-29 (775f9b3b) · r2.2 2026-09-29

No code in this phase. This document is the thing to approve, change, or reject before Phase 1 starts. Tars's review of r1 (`2026-09-26-subscription-product-review-tars.md`) did **not** approve implementation. Tars's re-review of r2.1 returned **CHANGES REQUESTED**: step 1's direction is accepted but its exported schema needs correcting, and the later ledger/paid-slice items gate the paid slice. r2.2 answers that verdict and needs a fresh review before step 1's schema is approved.

---

## Revision 2.2 — 29 Sep 2026

Answers Tars's r2.1 verdict §1–§8. Tars's line references are to r2.1 (775f9b3b). Section numbers below are r2.2's.

| Tars § | Topic | Change | Where answered |
|---|---|---|---|
| §1 | Step 1 / #613 observation contract | Observations keyed by `(runtime, profile/scope, plane, instance)`; every instance retained with membership `current` / `ended` / `unobserved`; no host-completeness claim. Evidence is **per field** (`value`, `observed_at`, `max_age`, `tested_path`, identity of process / plugin / effective policy). Denial evidence becomes obsolete on restart, policy or plugin change, stale or future timestamps and scanner degradation; a heartbeat never refreshes a denial. Self-report file defined as bounded host-local evidence, not liveness (atomic write, ownership/permissions, bounded parsing, profile scoping, process-start check). `installed` split into directory-only / artefacts-present-unloaded / loaded. Synthetic probes tagged apart from real blocked actions. Tars's nine firing cases are step 1's acceptance tests. | §5.6 (rewritten); §5.2 counts; §6 row 1; §8 step 1 |
| §2 | Ledger identity vs certificate serial | Stable tenant-bound **`ledger_id`**, bound to the device key and named in the certificate; anchors, idempotency, fork and latest-head lookup keyed by `ledger_id`, not serial. Renewal keeps the history; re-enrolment, key replacement, restore and epoch reset are explicit, recorded transitions. One ledger per ShieldCortex database; several profiles/DBs on one machine are separately identified ledgers under one device key, never clones. | §5.7 "Ledger identity"; §4 "What counts as a machine"; §5.1 certificate table; §5.9 anchors; §6 |
| §3 | Time evidence ≠ pack-signature time | A ledger anchor timestamps ledger content, not the later pack. Contract chosen: the verifier reports **ledger-content existence time** and **pack-signing time** separately; the second is unproven unless the canonical signed pack envelope has its own **pack-timestamp receipt**. Effective compromise time defined apart from administrative retirement; verifier rules for device, issuer and anchor-signer keys; anchor-signer backdating detectable only against a separately retained trusted checkpoint. | §5.7 "Pack timestamps"; §5.8 "Key compromise and verifier rules"; §5.1 state table; §5.2; §5.9; §9; §6 |
| §4 | Offline rollback is conditional | Rollback is detected only relative to a **checker-supplied later receipt/checkpoint** or an explicitly optional authenticated online check. The four-part result states freshness "as of supplied trusted evidence". A complete supplied chain is never reported as the latest or complete history. | §5.7 "Rollback"; §5.2 offline result; §6 |
| §5 | Retention commitment path | Row hash construction changed so pruned rows can keep a **content-digest skeleton**; the checkpoint carries the boundary hash; exact verifier inputs listed; anchored checkpoint vs locally rewritten unanchored history distinguished; free-core tamper claim narrowed to inconsistent edits (not coherent full rewrite or tail truncation without an independently retained head). No retrofit to pre-migration history. | §5.7 "Chain", "Retention checkpoints", "What the free chain detects"; §5 Free; §6 |
| §6 | Audit failure must not flip verdicts | Only telemetry persistence is best-effort. DENY stays DENY under disk-full / ledger throw; ALLOW is not blocked by an evidence-service outage; lost coverage reported on recovery, never reconstructed. | §5.7 "Audit-write failure"; §5.8 outage contract; §6 |
| §7 | #605 status and authorship | Every citation now reads "merged; 54 focused tests/typechecks verified (Tars, worktree `sc-patrol-20260927-602` at `8fa5cc8f`); real 2026.9.6 discovery/interception smoke pending receipt". Authorship: Tars authored the fix, Jarvis gave the independent review. | §1 item 7; §8 step 0; Microsoft section compatibility note; Revision 2 row 12; Provenance |
| §8 | Upstream and listing | Plugin never published from v5.2.1 (tag → `1c255445`, parent of #605). Listing only from a reviewed release containing #605 (5.2.2 candidate), sandbox-validated on the exact artefact, Guard not auto-armed. `scripts/clawhub-sync.mjs` publishing only `skills/shieldcortex` recorded as an automation gap, not a decision. Upstream: one provider-neutral proposal after policy-evidence ships and is validated against the actual Policy schema/version. Microsoft/Autopilot claims flagged as needing primary-source checks. | Microsoft section items 4, 6 and context; §8 step 0 and "Later" |

Also: wording tightened to bounded language throughout (no "proves" for observations or checks).

---

## Revision 2 — 29 Sep 2026

Every change below answers a lettered item in Tars's review. Section numbers are r2's.

| # | Change | Tars item | Where |
|---|---|---|---|
| 1 | Positioning line "proves what it did" replaced everywhere by "verifiable records of observed controls and actions". New subsection on what a signature does and does not prove; "a pack with zero blocks may mean zero visibility" is stated in every pack. | g1 | §3, §5.2, Microsoft section |
| 2 | One structured **per-runtime posture record** with separate fields (capability / installed / runtime-loaded / configured posture / observed denial capability), observation time, process/plugin identity, effective policy hash, probe provenance and freshness, degraded intervals, explicit `unknown`. Doctor's `bound` is never exported as enforced. Shared typed model for doctor and exporter. | c | §5.6 (new); §5.2, §5.5, §6 updated |
| 3 | **Anchoring** defined precisely: an anchor commits the prefix through head *by receipt time*; fork, reset-epoch, gap and rollback detection; retention checkpoints; gating failure-mode tests. Anchoring is part of the first paid evidence slice, not a later upgrade. Pre-migration history labelled unchained. | a, g2 | §5.7 (new); §5 Assure, §8 |
| 4 | **Signing architecture** made single and consistent: offline root → online issuer (certs) and online anchor signer; device keys sign packs; separate offline feed key. Resolves the r1 contradiction between §5.1/§5.2 (device-signed on-demand packs, hourly countersigning) and the hosting note (everything signed at release time on an operator box). | b, g3 | §5.8 (new); §5.1, Hosting section rewritten |
| 5 | Certificate tuple now includes device **public key**, issuer and key ID, serial, org, purpose, scope, validity. Domain-separated signatures for licence / feed / cert / anchor / pack. Canonical encoding and strict schemas. Test roots never accepted in production builds. | g3 | §5.1, §5.8 |
| 6 | "Verify forever" dropped. Offline verification reports four separate results: signature validity, time evidence, coverage integrity, revocation status *as of the bundled snapshot*. | g4 | §5.1 table, §5.2 |
| 7 | Feed rules extended: freeze/expiry detection, engine/schema compatibility, key rotation, isolated regex with killable budget, cumulative perf bounds, last-known-good atomic activation, emergency vs 7-day shadow, retraction cannot erase a built-in or an npm-shipped protection. | g5 | §5.3 |
| 8 | §5.4 no longer offers broad `autoApprove` / `enforce:false` as the paid FP workaround. Narrow reviewed exceptions with scope, expiry and audit entry; doctor reports the reduction. | g6 | §5.4 |
| 9 | Cloud service obligations: tenant isolation, authenticated idempotent anchors and billing webhooks, cert/key recovery, backup/restore, anchor retention and export, shutdown continuity, redact-before-hash. Cloud scope remains **Michael's decision**; nothing here decides it. | b, g7 | §5.9 (new); Open question |
| 10 | "UNSIGNED — NOT EVIDENCE" → **"LOCAL / NOT INDEPENDENTLY ATTESTED"**. Active certificate lease, retirement/reassignment, rebuilds, clones, CI/ephemeral hosts and multi-profile counting defined. | e | §4 "What counts as a machine", §5 Free |
| 11 | Commercial terms that r1 left undefined: VAT, currency, renewal/cancellation, support hours/timezone, response vs resolution. Enterprise 4-hour response and named engineer conditional on a staffed rota; SSO/SCIM/SLA never advertised before they exist. Pricing stays discovery hypotheses; we sell issuance, anchoring, curation and support, not the ability to sign local data. | e | §3, §4, §9 |
| 12 | §8 rewritten in Tars's order: #602 merged (PR #605, `ad95afd4`, on `origin/main`; status wording corrected in r2.2 §7 row); free-core defects; posture record → free chained ledger + verifier → thin paid slice (enrolment/cert → external anchor → pack → offline verification) → feed → fleet. Client work against test keys is labelled a prototype. | a, b, f | §8 |
| 13 | Policy-plugin upstream namespace moved off the Phase 1 critical path; the embedded Policy attestation tuple is described as a configuration snapshot with schema/version, scope, acquisition time and provenance, not a runtime witness. No claim of Microsoft support or endorsement. | d | Microsoft section |

---

## Open question for Michael

> **DECIDED 29 Sep 2026 22:19 UTC — "Cloud too".** The owner approved Cloud scope, Phase 1 and public engagement in one message. Cloud work starts in **sandbox** (test Stripe, test root, sandbox issuer and anchor signer). Production signing keys, live billing and any new paid infrastructure remain **separate later approvals**. The "if client-only" branch below is kept for the record and no longer applies.

**Can this engagement change the Cloud API (the `ShieldCortex-internal` repo / `api.shieldcortex.ai`), or must it stay client-only?**

Four paid features need a server half this repo does not contain: issuing entitlement-bearing licence keys from Stripe, issuing device certificates, hosting and signing the threat feed, and accepting ledger anchors. The definition of done ("install → pay → verify") depends on it.

Tars's review (b) recommends **Cloud too, subject to your explicit approval of that scope**, starting with sandbox billing/enrolment, device-certificate issuance and an anchor service, and **no production signing deployed under that review**. r2 does not decide this. It records the consequence of each answer:

- **If client-only:** the client is built and tested against **test** keys. That is a **prototype**, not the install → pay → verify product, and it cannot be sold. The server contract (§5.8, §5.9) is written as a spec so the Cloud side can be built to match later.
- **If Cloud is approved:** sandbox first (test Stripe, test root, sandbox issuer and anchor signer). Production signing keys are created and deployed only in a later, separately approved step.

Either way, nothing in this repo ever holds a production signing key, and test roots are rejected by production builds (§5.8).

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
| **"Bound" is not a gate** (added r2, from Tars c) | ⚠️ | `src/memory/host-contract.ts:61–64` defines `bound` as installed **or** SC-integrated, not runtime gating. `src/setup/host-table.ts:40–47,399–409` has Claude/OpenClaw gate planes but no Hermes posture. `src/cli/doctor.ts:6933–6947` probes `~/.hermes` directory existence, which cannot attest the active profile or process. `plugins/hermes/shieldcortex/__init__.py:87–91` reads `SHIELDCORTEX_ENFORCE` inside the plugin process, so a separate CLI's view is not that process's posture. `policy.py:45–79,94–113` has a scanner-degraded fallback and differing denial/approval behaviour. Consequence: §5.6. |

**Found during Phase 0; not subscription work.** Each is its own issue on the free core, whatever you decide about pricing:

1. **Cloud pattern sync compiles remote regexes with no `validateRegex` / ReDoS check** (`injection-scanner.ts` `setExternalPatterns`). A bad or hostile pattern from the tenant's cloud could stall the write hot path and break the P1 perf budget.
2. **`src/cloud/verify.ts` sends full content** (credentials redacted) but applies **no PII redaction, project filter or `excludeSensitive`**. The other sync paths honour these.
3. **Memory sync applies no credential redaction** (`memory-sync.ts`); quarantine sync does.
4. **Revocation is unwired**, and the check follows the user-set `cloudBaseUrl` (see above).
5. **The audit export CSV omits the ledger columns** (`operation`, `content_hash`, `source_attested`, `risk_modifier`).
6. **Stale "Requires a Pro licence" copy**: `LocalAiFindingExplainer.tsx:268`, `TabBar.tsx:56`, "Team+ key" in `CloudSyncStatus.tsx:97`, the "(Pro feature)" header in `src/defence/audit/export.ts`.
7. OpenClaw 2026.9.6 `cli-metadata` registration noise (#602). **Status: merged; 54 focused tests/typechecks verified (Tars, worktree `sc-patrol-20260927-602` at `8fa5cc8f`); real 2026.9.6 discovery/interception smoke pending receipt.** PR #605 ("quiet cli-metadata register; keep full-mode init loud"), merge `ad95afd4`, reviewed head `8fa5cc8f`, merged 27 Sep 2026. Tars authored the fix; Jarvis gave the independent review. It stayed a free-core compatibility PR, separate from subscription work (Tars f). The original real-host acceptance is not yet met (§8 step 0).

---

## 2. The buyer and the moment they decide to pay

**Who installs it:** a developer. They found ShieldCortex because their agent has shell access and that scared them. They will never pay, and they must never feel pushed to.

**Who pays:** the person who owns the risk budget at a 10–250 person software company that runs agents with tool access on shared or production machines. That is a head of platform, an engineering lead doubling as security lead, or a first security hire. They already have the free package on several boxes because a developer put it there.

**The moment they decide.** It is always a question from someone outside the engineering team that the free tool cannot answer on its own:

1. **The questionnaire.** A customer's security review or the SOC 2 / ISO 27001 auditor asks: *"What controls govern what your AI agents can do, and show me evidence they operated during the period."* A local dashboard is evidence, but only the operator's own. A record whose integrity an outsider can check independently answers the question better.
2. **The first real block.** The guard denies something ugly. Leadership asks: *"What else did it see, store and try? Can you show the log wasn't edited?"* The free tool shows the local timeline and (after §5.7) can detect inconsistent local edits, though not a coherent rewrite of the whole chain unless the head was retained elsewhere. It cannot show a third party that the history up to a point existed at a time they can check.
3. **The fifth machine.** Per-box `protect` works until someone asks *"are all of them still in policy?"* Nobody can answer that by SSH-ing into 30 boxes.

Each moment happens roughly once a year and comes back every year. Audit cycles are annual, attestation is annual, and so the subscription is annual. **All of this is a hypothesis to test in buyer conversations (§9), not a finding.**

---

## 3. The free/paid line

### The rule

> **Anything that protects a machine is free, forever, MIT. You pay for things that need a third party: independent certificate issuance, external anchoring, curated updates, support, and a view across machines that no single machine has.**

We do **not** sell the ability to sign or export local data. Any machine can sign its own bytes; that is free and worth little to an outsider. What is sold is the independent issuer, the independent timestamped anchor, the curation work behind the feed, and support (Tars e).

Three tests every paid feature must pass. If a feature fails any one of them, it is free:

1. **Structural test.** The free tool, running alone on one box, cannot do it. It needs Drakon's issuer, Drakon's anchor service, Drakon's curated feed, or an org-wide view.
2. **No-subtraction test.** Nothing that is free in v5.2.1 moves behind the licence. That includes `audit_export`, custom patterns, custom policies, X-Ray deep, local timeline replay, `doctor`, `protect` and the free Cloud tier.
3. **Lapse test.** When a subscription lapses, the machine is exactly as protected as the day before. It stops *getting new anchors, certificates and updates*; it never loses protection it already has.

### The one-line "why pay"

> **"The protection is free. You pay for verifiable records of observed controls and actions — independently certified, externally anchored, kept current, across every machine — that an auditor can check offline."**

It does not claim the records are complete or that prevention succeeded everywhere; §5.2 says what they do and do not show. A developer can accept this without resentment because nothing they use is taken away, and what is sold needs a party other than their laptop.

---

## 4. Tiers and prices

Annual only, self-serve by card. **Every number in this section is a discovery hypothesis, not validated economics** (Tars e). They are there to be tested in 5–10 buyer conversations before any pricing page exists.

| | **Free** | **Assure** | **Fleet** | **Enterprise** |
|---|---|---|---|---|
| Price (hypothesis) | £0 | **£1,490 / year** ($1,990) | **£5,900 / year** ($7,900) | **from £24,000 / year** (sales-led) |
| Machines | unlimited, per-machine | up to **10** active leases | up to **50** active leases, then £99 / machine / year | negotiated |
| Buy | `npm install` | card, self-serve | card, self-serve | sales@drakonsystems.com |

### Commercial terms (to define before launch)

These were missing from r1. Proposed defaults, all to confirm:

- **Currency.** Billed in GBP for UK and EU buyers, USD elsewhere; the customer's billing currency is fixed at first purchase and does not change at renewal.
- **VAT.** Prices exclude VAT. UK B2B: 20% VAT charged. EU B2B: reverse charge with a validated VAT number; without one, local VAT via the payment processor's tax handling. Non-UK/EU: no VAT. To confirm with the accountant before launch.
- **Renewal.** Auto-renews annually; reminder 30 days before renewal; price changes announced at least 60 days ahead and applied only at the next renewal.
- **Cancellation.** Cancel any time; access continues to the end of the paid year; no pro-rata refund after 14 days from purchase. Lapse behaviour is the §5.1 table: protection never changes.
- **Support hours.** UK business hours, 09:00–17:30 Europe/London, Monday–Friday excluding English bank holidays. "Business day" means that.
- **Response vs resolution.** Every SLA in this document is a **response** time (a human has triaged and replied with a classification and next step). None is a resolution or time-to-fix commitment, and the tier copy says so.

### What counts as a machine

A "machine" is one **active certificate lease** (Tars e). Definitions:

- **Active certificate lease.** A device certificate (§5.1) that is unexpired, unrevoked and not retired. Certificates are short-lived (90 days, auto-renewed while the subscription is active), so a machine that disappears stops counting within one lease period even if nobody retires it.
- **Renewal.** A renewed certificate has a new serial but the **same device key and the same `ledger_id`s** (§5.7 "Ledger identity"), so the history continues unbroken. Counting follows the device key, not the serial.
- **Retirement / reassignment.** `shieldcortex license retire` (or the Cloud Devices view) retires a lease immediately and frees the slot. Retirement is **administrative** (§5.8): it stops *new* signatures. Packs signed earlier are reported per the time-evidence rules in §5.7 "Pack timestamps": signing time counts as before retirement only when the pack has its own pack-timestamp receipt from before it; a ledger anchor alone does not date a pack.
- **Rebuilds.** A rebuilt host is a new key pair and a new lease. The old lease is retired by the operator or expires. Reusing a device ID with a new key is allowed and recorded as an explicit **key-replacement** transition (§5.7), not a clone. Whether the old `ledger_id` continues depends on whether the old database was restored (§5.7 "Transitions").
- **Clones.** Two installations presenting the **same device key**, or two divergent chains under the **same `ledger_id`**, are a clone. The anchor service detects it as a fork at the same `(ledger_id, epoch, seq)` (§5.7). A clone is shown to the org admin; it is never silently counted as one machine, and never auto-revokes the original.
- **CI / ephemeral hosts.** Short-lived runners use **ephemeral leases** (hours, not 90 days) issued to a CI enrolment token. They count by **peak concurrent** active leases per day, not by total issued, so a runner that spins up 500 times a month is not 500 machines.
- **Multi-profile hosts.** One machine = one device key, however many runtimes or profiles it runs (Claude Code, OpenClaw, several Hermes profiles). Profiles appear as separate posture records (§5.6), not as extra machines. Each ShieldCortex database on the machine is a **separately identified ledger** under that one device key (§5.7), so independent profile DBs are never misclassified as cloned machines.

At the limit, the next device gets a plain-English card saying no new certificate was issued. Protection on that machine is unaffected. There is 10% headroom before the card appears.

### Why these prices — what each one replaces

The reasoning is written out so it can be attacked; it is not evidence that anyone will pay.

**Assure £1,490.** It replaces:
- **Evidence assembly.** A senior engineer collecting "agent controls" evidence for one audit cycle: screenshots, config exports, explaining which hosts actually gate. At 2–3 days at £600–700/day, that is about £1,500–2,000 per cycle, before the auditor bills for chasing it.
- **Upgrading a production gateway just to get new patterns.** SCOPE §1a (never break the host) makes package upgrades on a live OpenClaw box a real risk. The feed delivers detection updates with no package upgrade.

It also sits deliberately **under the ~£2,000 corporate-card threshold** common at this company size. For comparison, the retired Team tier was £1,188/year and sold local features that are now free. Assure costs about the same but sells things the free tool cannot do.

**Fleet £5,900.** At 50 machines that is £118 per machine per year. It replaces building signed config distribution plus drift alerting in-house (about 2 engineer-weeks, ~£6–7k, then upkeep) and stitching per-box records together for the auditor. It sits under the ~£10k line where many companies of this size require formal procurement.

**Enterprise from £24,000.** The floor is meant to cover a named engineer (~0.1 FTE), DPA and security-questionnaire work, custom control mappings and an air-gapped feed mirror. **Conditions before it is sold:** the 4-hour critical response and named engineer need a **staffed on-call rota** with written exclusions (customer-caused config, unsupported hosts, out-of-hours non-critical), which Drakon does not have today. SSO/SCIM and any SLA are **not advertised until they exist and have been tested** (Tars e). Hosting cost is not cost-to-serve: support time, the issuer/anchor service and its availability (§5.9) are the real costs, and they are not yet estimated.

A preview (§5 Free) lets a buyer see the report shape. It is **not** a buyer's evaluation of onboarding, enrolment or fleet coverage; that needs a sandbox enrolment, which is a Phase 1 deliverable only if Cloud is approved.

---

## 5. Exact feature list per tier

### Free (unchanged, and gains the chained ledger and verifier)

Everything in v5.2.1, including: memory firewall (6 layers, 7 detectors), Action Guard, Environment Firewall, local dashboard, provenance ledger, quarantine, review queue, knowledge graph, `audit_export` JSON/CSV, custom patterns/policies/firewall rules, X-Ray deep, local session timeline/replay, `doctor`, `protect`, free Cloud (500 scans/month, 7-day retention, 1 member).

**New and free under this plan:**

- **Per-runtime posture record** (§5.6). Honest, structured, shared by `doctor` and every exporter.
- **Hash-chained ledger** (SCOPE P3, §5.7). Local integrity, so free. Retention prunes write a chained checkpoint. History from before the migration is labelled **unchained**, and coverage is stated as starting at the migration: a ledger cannot reconstruct observations it never recorded (Tars a). **What it detects alone:** inconsistent edits (a changed or deleted row in the middle of the chain). It does **not** detect a coherent rewrite of the whole chain or deletion of its tail unless the head was retained somewhere the rewriter could not reach: `shieldcortex ledger head` prints a head the user can keep elsewhere, and an external anchor (Assure) does the same independently (§5.7 "What the free chain detects").
- **`shieldcortex evidence verify <pack>`**, plus a standalone verifier with no ShieldCortex install and no licence. Whoever checks a pack must never need a subscription to do it.
- **`shieldcortex evidence preview`.** The same report an Assure pack would contain, stamped **LOCAL / NOT INDEPENDENTLY ATTESTED**. Unsigned local logs can still be evidence; what the preview lacks is an independent issuer and external anchor. This replaces the trial.
- **Incident reconstruction, local.** Assembling the cross-store view of one blocked event is just reading your own data, so it is free.
- **Every feed pattern reaches npm** in the next release, and within 30 days at most. **Actively exploited in-the-wild patterns ship to npm the same day, for everyone.** The feed does not withhold emergency protection.

### Assure

Everything in Free, plus:

1. **Device enrolment and certificate** (§5.1, §5.8). The independent issuer vouches that a key belongs to an enrolled machine of that org.
2. **External anchoring** (§5.7). Part of the evidence product from day one, not an optional upgrade. Hash-only, batched, off the agent's request path.
3. **Signed evidence packs.** On demand, plus an automatic pack each quarter. Contents in §5.2. Verifiable offline with the four-part result in §5.2.
4. **Signed threat intelligence feed** (§5.3). Delivered with no package upgrade; comes with a signed changelog ("detector set 2026.40.2 was active on these machines from these dates, as observed").
5. **Sealed incident bundles.** The local reconstruction, signed and anchored, exportable for an auditor, insurer or customer. An off-box copy is retained in Cloud **only if content upload is explicitly opted into**.
6. **False-positive support.** Response within **2 business days**, handled per §5.4.
7. Up to 10 active leases.

### Fleet

Everything in Assure, plus:

1. **Fleet policy.** One signed org policy file sets:
   - which runtimes/profiles must have an observed tool gate;
   - the Action Guard posture;
   - what is denied and what needs approval;
   - reviewed exceptions (§5.4) and memory posture.

   It is applied through the existing root-owned policy lock, and "tighter wins" is kept: a local config can make a machine stricter than the fleet policy, never looser.
2. **Drift detection.** Each enrolled machine reports its posture records (§5.6, summary fields only), policy hash, package version and feed sequence. The Cloud Devices view shows per machine and per runtime: in policy, drifted, or **unknown**. A machine or runtime that stops reporting is **unknown**, never compliant. No machine is shown green because one of its profiles gates.
3. **Org-wide evidence pack.** One signed roll-up across all machines, with a per-machine appendix and each machine's own coverage statement.
4. Unlocks the existing `team_management` and `shared_patterns` entitlements.
5. False-positive response within **1 business day**.
6. Up to 50 active leases, then £99 per machine per year.

### Enterprise

Everything in Fleet, plus (each **only once built, tested and staffed**; none is advertised before then):
- SSO/SCIM
- full memory/graph replication (existing `cloud_sync`, `memory_scopes`)
- an air-gapped / self-hosted feed mirror
- custom retention for anchors and bundles
- DPA
- custom control mappings reviewed with their auditor
- **4-hour response on critical FPs**, conditional on a staffed rota and written exclusions (§4)
- a named engineer
- SIEM connectors beyond the free webhook

Existing Enterprise keys keep everything they have today (see §5.1 for re-issue).

### 5.1 Licence, certificates and entitlement model

- **New key version.** v1 keys (`sc_pro_`/`sc_team_`/`sc_ent_`) keep verifying exactly as today.
  - A new `sc_v2_` payload adds `plan`, `org`, `ent[]` (explicit entitlements), `machines`, and **`kid`** (key id, so keys can be rotated). Signed under the licence domain (§5.8).
  - Paid features are checked by **entitlement**, not `TIER_RANK`. A grandfathered v1 Pro/Team key therefore cannot accidentally unlock Assure/Fleet features.
  - **Recommendation:** re-issue live Enterprise customers v2 keys with every entitlement at no charge until their renewal.
- **Device certificates.** On a paid activation, the machine generates a local Ed25519 key pair. Only the public half is sent. The online issuer (§5.8) returns a certificate whose **signed fields** are:

  | Field | Purpose |
  |---|---|
  | `schema`, `version` | strict schema id; unknown versions rejected |
  | `serial` | unique per certificate, used by revocation |
  | `issuer`, `issuer_kid` | which issuer key signed it; chains to the offline root |
  | `subject_pubkey` | **the device public key** (absent in r1) |
  | `org` | customer org id |
  | `device_id` | stable device label; not the identity (the key is) |
  | `ledger_ids` | the stable ledger identities (§5.7) this device key is authorised to write and anchor. The issuer records each `ledger_id` against the org and device key at registration; a renewal carries the same list |
  | `purpose` | `pack-signing` only; a device cert cannot sign licences, feeds, anchors or other certs |
  | `scope` | plan and entitlements the cert may assert (`assure` / `fleet` / `enterprise`), lease type (`standard` / `ephemeral`) |
  | `not_before`, `not_after` | validity; 90 days standard, hours for ephemeral |

  Encoding and domain separation are in §5.8.
  - Evidence packs and incident bundles are signed by the device key and carry the certificate.
  - A verifier checks: pinned offline root → issuer certificate → device certificate → pack, each under its own signature domain, then the anchor receipts (§5.7).
- **Fail open for the free core, fail closed only for paid surfaces.**
  - A Phase 1 test pins that **no free code path reads the licence**.
  - Paid surfaces keep working for a **30-day offline grace period**, counted from the last successful online validation.
  - After that, the machine shows one plain-English card and the agent is never touched:

    > Your ShieldCortex Assure subscription couldn't be checked for 30 days. Protection is unchanged. New feed updates, anchors and signed evidence packs are paused until the key can be checked. Run `shieldcortex license status`.
- **Revocation.** Wire the (currently dead) daily check, gated to paid surfaces only, against a **pinned** licence host rather than `cloudBaseUrl`. The issuer publishes a signed, dated revocation list. Each entry carries the serial (and device key), `revoked_at` (when it was entered — administrative), `effective_compromise_at` (for compromise only; §5.8) and reason (`retired` / `superseded` / `key-compromise` / `org-revoked`). Packs bundle the latest list they saw.

| State | Free core | Feed | New packs / bundles / anchors | Existing packs (offline verification) |
|---|---|---|---|---|
| Active | ✅ | updates | signs, anchors | four-part result (§5.2) |
| Offline ≤ 30 days | ✅ | last verified feed stays active (subject to §5.3 expiry notice) | signs; anchors queue locally | four-part result |
| Offline > 30 days / expired > grace | ✅ | **last verified feed stays active**, no new updates | paused, card shown | four-part result |
| Expired (normal) / renewed | ✅ | per above | renewed cert signs, same `ledger_id` history | pack signing time is checked against the certificate validity window **only where the pack has its own pack-timestamp receipt**; otherwise "signed, signing time unproven" (§5.7) |
| Retired / revoked | ✅ | last verified feed stays active | stopped | signature still checks. **Two times are reported separately** (§5.7 "Pack timestamps"): *ledger-content existence time* from ledger anchor receipts, and *pack-signing time* from the pack's own pack-timestamp receipt. A pack with a pack-timestamp receipt earlier than `revoked_at` (retirement) or `effective_compromise_at` (compromise) is reported as signed before it. A pack without one is "signed, signing time unproven, key later retired/revoked", **even if every ledger row it cites was anchored long before**. |

There is no "verifies forever" (Tars g4). A device key — stolen or not — can sign a new pack at any time, backdate its claimed signing time, and cite genuine old ledger receipts. An old ledger anchor therefore never dates the pack signature (Tars r2.1 §3). An offline verifier knows revocation status only **as of the revocation snapshot bundled in the pack** (or supplied by the checker); it cannot know about a later revocation, and says so.

### 5.2 Evidence packs — what they show and what they don't

**What a pack is.** A canonical JSON document (§5.8) plus a detached Ed25519 signature in the `pack` domain, with a human-readable PDF/markdown rendering generated *from* the JSON. It contains:

- the period covered, and the **coverage start** (ledger migration date or first chained row; earlier history marked unchained)
- package version
- detector-set and feed sequence numbers active over the period, with change dates
- config hash (canonical JSON) and effective policy hash
- policy-lock state
- **per-runtime, per-instance posture records** (§5.6), with each field's evidence (value, observation time, freshness, tested path, identity), instance membership (current / ended / unobserved), and every degraded or unobserved interval in the period
- counts and IDs of **real** blocks, quarantines, approvals and reviewed exceptions in force (§5.4); synthetic probe denials listed **separately** and never counted as blocked actions (§5.6)
- ledger identity (`ledger_id`s), chain head(s), reset epochs, recorded transitions, gaps, lost-coverage markers and checkpoints (§5.7)
- the anchor receipts covering the period, and the unanchored suffix, stated explicitly
- the issuer's revocation snapshot the pack was built with, and its date
- `doctor` findings at export time
- if present, the `openclaw policy` attestation tuple as a **configuration snapshot** (Microsoft section)

**Control mapping.** Each field maps to controls, framed as "supports evidence for", **never "compliant with"**:

- **SOC 2:** CC6.1, CC7.2, CC8.1
- **ISO 27001:2022 Annex A:** 8.9, 8.15, 8.16
- **ISO 42001 Annex A**
- **EU AI Act:** Art. 9 (risk management), 12 (record-keeping), 14 (human oversight), 15 (robustness/cybersecurity)

Articles 12–15 apply to high-risk systems, and the pack says so. **Residual:** the mapping is written by Drakon and not yet reviewed by an auditor. Get it reviewed before any marketing copy names a framework.

#### What a signature does and does not show

A signature authenticates bytes. That is all it does. Stated inside every pack, in this wording or stronger:

**A valid pack signature and chain show:**
- these exact bytes were signed by a key holding a certificate the issuer gave to an enrolled machine of this org, for pack signing. *When* they were signed is a separate result: it has independent evidence only if the pack has its own pack-timestamp receipt (§5.7); otherwise the signing time is the device's claim;
- the bytes were not altered after signing;
- the ledger prefix up to each ledger anchor receipt existed, in that form, no later than the anchor service's receipt time, and the retained ledger matches it (§5.7). That dates the **ledger content**, not the pack.

**They do not show:**
- **Completeness.** Only what the instrumented runtimes observed is recorded. **A pack showing zero blocks may mean zero visibility**; read the posture records and gap intervals before reading the counts.
- **Truthful instrumentation.** An attacker with root before an event is recorded, or a modified ShieldCortex, can record false data. Anchoring bounds *when* history was fixed, not whether it was true.
- **Successful prevention.** A recorded deny shows the gate returned deny on that path. It does not show the action could not happen another way.
- **Universal agent coverage.** Runtimes with no tool gate (memory-only), runtimes that were never observed, and processes outside ShieldCortex are not covered. The pack lists what it saw; it cannot list what it did not.
- **The unanchored suffix.** Events after the last anchor receipt are signed by the device only; their time is the device's claim.
- **When the pack was signed**, unless it carries its own pack-timestamp receipt (§5.7).
- **That this is the latest or complete history.** A complete, internally consistent chain in the pack says nothing about whether newer history exists. That is known only relative to later trusted evidence the checker supplies, or an optional online check (§5.7 "Rollback").
- **Future revocation.** Revocation status is as of the bundled snapshot.

**Offline verification result.** `evidence verify` never prints a single "valid". It prints four separate results (Tars g4), each stated **as of the trusted evidence supplied**:

1. **Signature validity** — pack, certificate chain and domains check out against the pinned production root (test roots rejected); certificate valid at the pack-signing time *if* that time is evidenced, otherwise "validity at signing time unproven".
2. **Time evidence** — two separate lines: **ledger-content existence time** (which ledger ranges are covered by ledger anchor receipts, with receipt times; which are device-claimed only) and **pack-signing time** (the pack-timestamp receipt time, or "unproven — device claim"). Receipts from an anchor-signer key later reported compromised are accepted only per §5.8.
3. **Coverage integrity** — chain continuity, reset epochs and transitions, gaps, lost-coverage markers, checkpoints and which pruned ranges remain re-checkable, degraded/unknown posture intervals, and the stated coverage start.
4. **Revocation and freshness** — revocation status as of the bundled (or supplied) revocation snapshot and its date; and **history freshness as of the latest trusted receipt/checkpoint the checker supplied** (or the optional online check, if used). With nothing newer supplied, it prints "newer history: not checked".

`doctor`'s honesty rule applies verbatim: **a pack never prints "protected" or "enforced" for a runtime without an observed denial capability** (§5.6).

### 5.3 Threat feed — safety rules

The feed is a new remote input into the detection path, so it is also a new attack surface. It ships with these rules, each with a firing test (§6):

- **Signed and pinned.** Every feed file is signed in the `feed` domain by Drakon's **offline** feed key, separate from every other key (§5.8). A bad signature is rejected and the last good feed stays.
- **Monotonic.** Each file carries a sequence number, and a lower one is rejected. This stops rollback / replay of an old feed.
- **Freeze and expiry detection.** Each feed manifest carries `issued_at` and `expires_at` (default 14 days) and the feed server publishes a signed heartbeat manifest at least daily even with no new items. A client whose newest verified manifest is older than its `expires_at` reports **feed stale / possibly frozen** in `doctor` and in packs. It keeps enforcing the last good items (lapse test) but never presents them as current. This catches an attacker who withholds updates by replaying the latest valid file.
- **Compatibility.** Each file declares `schema_version` and `min_engine` / `max_engine`. A client that does not support the schema or falls outside the engine range rejects the file, keeps last-known-good, and says why.
- **Key rotation.** The feed key is certified by the offline root with a `kid` and validity. Rotation: the new key is announced in a manifest signed by the **old** key and certified by the root; both are accepted during an overlap window; the old key is then retired and its `kid` added to the root-signed revoked list. A feed signed by an unknown or revoked `kid` is rejected.
- **Additive only.** A feed can add detection and can retract *its own* earlier items. It **cannot disable or relax a built-in detector**, so a stolen feed key cannot switch protection off. **A signed retraction never removes protection that has since shipped in npm**: once an item is promoted into the built-in set, it is a built-in and only a package release can change it. Retractions are logged locally with the item id.
- **Data, not code; isolated evaluation.** Items are regex/string/domain data. Each passes `validateRegex` and the ReDoS timing budget before it is compiled. Feed regexes are evaluated with a **non-backtracking engine where the pattern allows it**, otherwise in an **isolated worker with a hard, killable time budget per item and per input**. An item that exceeds its budget is disabled locally and reported; it never blocks the write path and never takes down the host.
- **Cumulative perf bounds.** Feed items together count toward the write-path budget (**p95 ≤ 5 ms, mean ≤ 2 ms** on ≤2 KB, `P1-perf-budget.md`). There is a hard cap on item count, total pattern bytes and **cumulative measured evaluation time**. A feed that would exceed the cumulative budget on the client's own measurement is not activated. Adding the feed is a stated revisit trigger for that budget.
- **Last-known-good atomic activation.** A new feed is verified, compiled and benchmarked in full, then swapped in atomically. Any failure leaves the previous feed active unchanged. There is never a partially loaded feed.
- **Shadow first, with an emergency path.** New items run in observe mode for a stated window (default **7 days**). They count would-have-fired locally before they start enforcing. Those counts stay local unless the customer opts into sharing them. **Emergency items** (actively exploited in the wild) may skip shadow, but only if: they are flagged `emergency` in the signed file, they passed the full FP gate, they ship to npm the same day for everyone (§5 Free), and the client records that shadow was skipped. Customers can set policy to shadow even emergency items.
- **FP gate.** Before signing, every item runs against the must-ALLOW corpora (`fp-tune-71-73`, `fp-precision-88-89`, `guard-tune-91-89`, `span-classifier-84`, `guard-precision-corpus`, genuine-work corpus). **Zero flips**, the same ceiling as `P1-fp-budget.md`. The client re-runs the shipped corpus on arrival and refuses any item that flips a fixture. **This does not prevent over-blocking.** A signature and a finite corpus cannot; shadow mode, local would-have-fired counts, reviewed exceptions (§5.4) and fast retraction are the mitigations.

### 5.4 False-positive support

The subscriber reports an FP from the dashboard or CLI. It is triaged and a response given within the tier's response time (§4: response, not resolution). Then:

- **A feed item caused it:** the item is retracted or fixed in the feed, with a must-ALLOW fixture added.
- **A built-in detector caused it:** Drakon provides a **narrow reviewed exception**, not a broad escape hatch. An exception:
  - matches the specific pattern/action/path that false-positived, and nothing wider;
  - is scoped to named runtimes, profiles or machines;
  - has an **expiry** (default 30 days, max 90) and lapses back to full enforcement;
  - writes an **audit entry** to the chained ledger when created, used and expired, naming the ticket;
  - is shipped as a signed exception file (org-scoped) or applied locally by the customer, never silently.

  The fix lands in the next npm patch with its fixture, and the exception is retired then.
- **`doctor` reports every reduction** from default posture: active exceptions (scope, expiry, reason), plus any `autoApprove` lists or `enforce:false` settings the customer has set themselves. Evidence packs list them too.

Broad `autoApprove` or `enforce:false` stay available as the customer's own free controls, but Drakon **does not recommend them as the standard paid workaround**, because they weaken the very controls the customer is paying to show (Tars g6). The feed is never used to relax built-ins (§5.3).

### 5.5 Fleet policy and gated runtimes

A fleet policy can *require* Action Guard enforcement, but a requirement is judged against the **observed** posture record (§5.6), not against doctor's `bound`:

- Only runtimes with a tool-gate **capability** can ever show `observed denial capability`. Today that is Claude Code, OpenClaw and Hermes, per profile and process, not per host.
- For Codex, Cursor, Copilot and MCP-only machines, the drift view shows **`memory-only — not a tool gate`**, never "in policy: enforced".
- A runtime whose gate was not observed recently shows **unknown**, not compliant.
- No host-wide green because one profile gates.
- The Fleet tier copy says so on the pricing page.

**Drift reporting is opt-in.** The opt-in copy lists exactly what leaves the machine:
- device id, certificate serial and `ledger_id`s
- hostname (can be replaced by a label)
- policy hash
- per-runtime posture summary (the §5.6 enum fields and observation times; no paths or process arguments)
- package version
- feed sequence

It contains no content, commands, paths or memory. Identifiers and timing are still metadata; §5.9 covers how they are handled.

### 5.6 Per-runtime posture record (new in r2; observation contract revised r2.2)

**Why.** r1 exported doctor's `bound` as if it meant enforced. It does not (§1, Tars c): `bound` is installed-or-integrated, Hermes posture is inferred from a directory, and the Hermes plugin's enforce flag lives in the plugin process, not the CLI. The export must describe what was observed, per runtime and per instance, with its limits. r2.2 closes the observation contract Tars's r2.1 verdict §1 found open (issue #613).

**Observation key: `(runtime, profile/scope id, plane, instance)`.** `plane` is `tool-gate` or `memory`. `instance` is the identity of one running process/session of that runtime:

- `instance_id`: a random id the plugin/hook generates when it starts, plus the **pid and process start time** it reads for itself. A pid alone is never the identity (pids are reused).
- For per-invocation hooks with no long-lived process (Claude Code hooks), the instance is the hook configuration generation plus the session id the host passes; there is no process-liveness claim for it, only the time of the last invocation.

**Every instance is retained; none overwrites another.** Two live instances on one profile produce two records. The collector never collapses them by last-writer-wins. Each instance has a **membership** state:

| Membership | Meaning |
|---|---|
| `current` | The self-report is fresh (within `max_age`) **and**, where the host supports it, a process with that pid *and the same start time* exists. |
| `ended` | The process-start check shows that pid no longer exists or now has a different start time (restart / pid reuse). Its denial evidence is obsolete. The record is kept for history, never shown as current. |
| `unobserved` | The report is stale, cannot be checked (host has no start-time lookup, or the file failed validation), or no report exists. All its fields read as `unknown`/`unobserved` now. |

A profile summary lists every instance and its membership. The collector reports **what it found**; it makes **no host-completeness claim** (it cannot see instances that never wrote a report, or runtimes it does not know).

**Per-field evidence.** Each field below is an evidence object, not a bare value:

`{ value, observed_at, max_age, source, tested_path?, identity: { instance_id, runtime_version, plugin_id, plugin_version, plugin_content_hash, effective_policy_hash } }`

- `source` is `process-self-report`, `synthetic-probe`, `real-action` or `file-probe` (CLI filesystem inspection).
- `tested_path` is set for denial evidence: which gate path (hook, tool, rule) returned deny.
- Freshness is evaluated **at read time**: `now − observed_at > max_age` → `unknown` (reason `stale`); `observed_at` more than a small clock-skew allowance **in the future** → `unknown` (reason `future-dated`) and the report is flagged.

| Field | Values | Meaning |
|---|---|---|
| `capability` | `tool-gate` / `memory-only` / `none` / `unknown` | What this runtime can support at all. Memory-only is **never** a tool gate. |
| `installed` | `absent` / `runtime-dir-only` / `artefacts-present` / `unknown` | `runtime-dir-only`: the runtime's directory (e.g. `~/.hermes`) exists but no ShieldCortex artefacts were found in the active profile. A runtime directory is **not** evidence that ShieldCortex is installed. |
| `runtime_loaded` | `loaded` / `present-not-loaded` / `unobserved` / `unknown` | `loaded` only from a fresh, valid process-side self-report of a `current` instance. `present-not-loaded`: artefacts present and the runtime is observed running without reporting the plugin loaded. File presence alone never gives `loaded`. |
| `configured_posture` | `enforce` / `advisory` / `intentionally-off` / `unavailable` / `unknown` | What the **running process** reports its configuration asks for. Advisory ≠ off ≠ unavailable ≠ unobserved. |
| `observed_denial` | `observed` / `not-observed` / `obsolete` / `degraded` / `unknown` | Whether this instance's gate has denied on a tested path, with the evidence object above. `obsolete` per the invalidation rules below. |
| `degraded_intervals` | list of `{from, to, reason}` | E.g. scanner-degraded fallback (`policy.py:45–79`), plugin not loaded, probe failures, report validation failures. |

**Denial evidence invalidation.** A denial observation is valid only for the identity it tested. It becomes `obsolete` (kept in history, never current) when any of these happens after it:

- the instance **restarts** or ends (new `instance_id`, or the pid/start-time check fails);
- the **effective policy hash** or the **plugin content hash/version** changes;
- its timestamp is **stale** (beyond `max_age`) or **future-dated**;
- the instance reports **scanner degradation** (the scanner-degraded fallback) after it.

**A heartbeat never refreshes a denial.** Heartbeats update liveness and `configured_posture` only. So a process that is now `advisory` or `intentionally-off` is shown as that, however many denials it recorded earlier; a past deny never makes it look enforced now.

**Self-report file: bounded host-local evidence, not liveness.**

- One file per instance: `<profile's ShieldCortex dir>/posture/<runtime>/<instance_id>.json`. Directory mode `0700`, file `0600`, owned by the user running the runtime.
- **Atomic write:** temp file in the same directory, fsync, rename. Readers never see a partial file.
- **Checks on read:** opened without following symlinks; owner and mode must match or the file is rejected; **size cap** (64 KiB) and **strict schema** (unknown fields, wrong types or oversize values rejected); the `profile` field inside must match the directory's profile, so a report **from the wrong profile** is rejected.
- **Process-start check** where the host supports it (Linux `/proc/<pid>/stat` start time; macOS process info). Where it does not, or the check fails, the instance is `unobserved`/`ended`, never `current`. A file cannot keep an instance `loaded` indefinitely.
- A rejected file is recorded as a degraded interval with its reason; it never falls back to a guessed value.
- **Host-integrity limitation, stated in every export:** any process running as that user can write this file. It is a local self-report, bounded by host integrity, not attestation. Step 1 adds no attestation infrastructure.

**Synthetic probes vs real blocked actions.** Every denial carries `source: synthetic-probe` or `source: real-action`. Counts of blocked actions (doctor, packs, drift) include **only** `real-action`. Probes are listed separately. A fresh synthetic denial is narrow tested-path evidence for that instance and policy: it shows that path denied at that moment, **not** universal prevention.

**Other rules.**
- **Explicit unknown.** Anything not observed within `max_age` is `unknown`. `unknown` is never rendered green.
- **No green-by-consent-change.** Collecting posture never changes consent, arms Guard, writes config or probes a runtime into green (Tars c). An **intentionally-off** runtime is reported as that; it is not armed or probed, and it does not need to be.
- **No requirement to have blocked a real attack.** A healthy, `enforce`, `loaded` runtime with `observed_denial: not-observed` is reported as exactly that.
- **No host-wide rollup to green.** A host summary is the *weakest* of its current records, and lists ended/unobserved instances.
- **Shared typed model.** `doctor`, `policy-evidence`, packs and drift all read one typed observation module, not terminal text and not today's overloaded boolean. The existing `bound` boolean stays for backwards-compatible display only and is **never** exported as `enforced`.
- **Process-side reporting.** Runtimes that can gate (Claude Code hook, OpenClaw plugin, Hermes plugin) write the self-report above. Where a runtime cannot self-report, `runtime_loaded` is `unobserved`.

**Step 1 acceptance tests (Tars r2.1 §1, verbatim).** Each must fire through the shared model **and** through both consumers (`doctor` and the `policy-evidence` export):

1. two instances with conflicting posture;
2. restart/PID reuse;
3. fresh heartbeat plus stale deny;
4. policy/plugin change after deny;
5. malformed/future-dated/self-report from the wrong profile;
6. directory only;
7. unloaded plugin;
8. collector leaves config/consent unchanged;
9. probe distinguished from an actual blocked action.

This is a targeted schema correction. It does not split every field into a separate feature, and it does not require every healthy runtime to have blocked a real attack.

### 5.7 Chained ledger, anchoring and retention (new in r2; identity, time, rollback and retention revised r2.2)

**Ledger identity** (Tars r2.1 §2). Each ShieldCortex database has one **`ledger_id`**: a random 128-bit id created with the chain at migration. It is the stable identity of that history. It is not the certificate serial (serials change at every renewal) and not the device key (a key can be replaced; the history continues).

- **Tenant binding.** At enrolment the device registers each of its `ledger_id`s with the issuer, signed by the device key. The issuer binds `(org, ledger_id)` to that device key and lists the `ledger_id`s in the device certificate (§5.1). A `ledger_id` already bound to another org is refused.
- **Authorised writer.** Anchor requests name the `ledger_id` and are accepted only when signed by a device key whose current certificate lists it.
- **Keying.** Anchor idempotency, fork detection and latest-head lookup are keyed by `(ledger_id, epoch, seq)`, never by certificate serial. A divergent history cannot escape the fork test by presenting it under a fresh serial.
- **Multiple profiles/DBs on one machine.** Each database is a **separately identified ledger** under the same device key. Chains are serialised per database through its DB transaction. Two independent profile DBs are two `ledger_id`s — never a clone. A database *copied* to a second profile keeps the source's `ledger_id`; once they diverge that shows as a fork until the copy is explicitly re-identified (new `ledger_id`, with a transition row naming the source head).

**Transitions** are explicit ledger rows, anchored like any other, and registered with the issuer/anchor service:

| Transition | When | What is recorded |
|---|---|---|
| `renewal` | New certificate, same device key | Nothing in the chain changes; the issuer links the new serial to the same key and `ledger_id`s. History continues. |
| `re-enrolment` | Subscription lapsed and resumed, same key and DB | Same `ledger_id`; the issuer re-binds it to the org after checking the earlier binding. The gap in anchoring is visible as an interval with no receipts. |
| `key-replacement` | Device key rotated or lost | With the old key: a rotation statement signed by old and new keys. Without it (lost key): an org-admin-authorised replacement recorded by the issuer, flagged "old key not present". The `ledger_id` continues under the new key; the pack shows the transition. |
| `restore` | DB restored from a backup | A new epoch that names the restored-from head. The anchor service shows the rows anchored after that head that the restored chain no longer has. |
| `epoch-reset` | Reinstall or deliberate reset | A new epoch at `seq 0`, naming the last anchored head of the previous epoch where known. Always shown. |

**Chain (free).** Each `defence_audit` row carries `ledger_id`, `epoch`, `seq`, `prev_hash`, `content_digest = H(canonical(row content))` and `row_hash = H(prev_hash ‖ seq ‖ content_digest)`. Splitting out `content_digest` lets a pruned row keep a 32-byte witness without its content (retention, below). `ledger verify` walks the chain.

**What the free chain detects alone.** A local chain with no independently retained head detects **inconsistent edits**: a row changed or deleted in the middle breaks the hashes from there. It does **not** detect an adversary who rewrites the **whole chain coherently**, or who **deletes the tail** (suffix), because nothing outside the database says what the head should be. Those are detectable only against an **independently retained head**: one the user kept elsewhere (`shieldcortex ledger head`, free), or an external anchor receipt (Assure). The free-core claim says exactly this (§6).

**What an external ledger anchor commits** (Tars g2). The device submits `{ledger_id, epoch, seq, head_hash}` signed in the `anchor-request` domain. The anchor service returns a receipt signed in the `anchor` domain: `{ledger_id, epoch, seq, head_hash, received_at, receipt_serial, prev_receipt_hash}`. A receipt commits **the ledger prefix from the start of the epoch through `seq`, as existing no later than `received_at`.** It does **not**:
- say anything about rows after `seq` (the unanchored suffix);
- show that suppressed or never-recorded events did not happen;
- show the recorded content is true (§5.2);
- **date any later pack signed over that prefix** (next paragraph).

**Pack timestamps** (Tars r2.1 §3). A ledger receipt timestamps ledger content. A pack is signed later, and a device key (stolen or not) can sign a new pack citing genuine old receipts and claim any signing time. The contract:

- The verifier reports **ledger-content existence time** (from ledger anchor receipts) and **pack-signing time** separately, always.
- **Pack-signing time has independent evidence only from a pack-timestamp receipt.** After signing, the device submits `H(canonical signed pack envelope)` — the canonical pack bytes *and* the detached signature — to the anchor service in the `pack-timestamp-request` domain. The service returns a receipt in the `pack-timestamp` domain: `{envelope_hash, ledger_id, received_at, receipt_serial, prev_receipt_hash}`, delivered as a sidecar next to the pack. It shows the signed envelope existed no later than `received_at`.
- Without that receipt, pack-signing time is reported **"unproven — device claim"**, however old the ledger receipts inside are.
- Certificate validity, retirement and compromise are checked against the **pack-timestamp receipt time**, never against a ledger receipt time or the pack's own claim (§5.1 state table, §5.8 verifier rules).

**Verification against anchors.** The verifier recomputes the retained prefix and checks it hashes to each receipt's `head_hash` at that `seq`, then detects:
- **Forks** — two different heads at the same `(ledger_id, epoch, seq)`. This is also the clone signal (§4).
- **Reset epochs and transitions** — always shown, with the last anchored head of the previous epoch.
- **Missing intervals** — gaps in `seq`, or time ranges with no rows and no heartbeat row; the ledger writes a periodic heartbeat row so silence is distinguishable from a missing interval.
- **Lost-coverage markers** — written on recovery after an audit-write failure (below).

**Rollback** (Tars r2.1 §4). An attacker can present an older, internally consistent pack and leave out later receipts. From the old pack alone, an offline verifier cannot know newer history exists; an honest exporter bundling its latest known receipt does not help against a dishonest one. So rollback is detected **only relative to independent later evidence**:
- a **checker-supplied** later receipt or checkpoint for that `ledger_id` (for example one from an earlier pack the checker kept, or exported from the Cloud account); or
- an **explicitly optional authenticated online check** that asks the anchor service for the latest receipt for that `ledger_id`. It is never run implicitly, and its result is labelled with its time.

The four-part result states freshness **"as of supplied trusted evidence"** (§5.2). A complete, consistent supplied chain is **never** reported as the latest or complete history of the device.

**Retention checkpoints** (Tars r2.1 §5). Pruning `[a, b]` deletes those rows' **content**. What is kept, and what the verifier can check with it:

- **Checkpoint row** (appended to the chain at prune time): `{pruned range [a, b], count, boundary_hash = row_hash(b), start_hash = prev_hash(a), receipt_serials covering the range, skeleton_kept: yes/no}`.
- **Skeleton (default on):** for every pruned row, `(seq, content_digest)` — 32 bytes plus seq per row, no content. With it, the verifier recomputes `row_hash` from `start_hash` through `b` and checks each receipt *inside* the pruned range. Skeletons can themselves be pruned by an explicit, logged setting; then those receipts become "anchored; contents and witnesses pruned — not re-checkable", stated as such.
- **Verifier inputs**, exactly: (1) retained rows `b+1 … head`; (2) the checkpoint row(s); (3) the skeleton for pruned ranges, if kept; (4) ledger anchor receipts; (5) any checker-supplied later receipt/checkpoint.
- **What is checked:** the first retained row's `prev_hash` equals `boundary_hash`; the retained rows recompute to every receipt at `seq > b`; with a skeleton, the pruned range recomputes to every receipt inside it. **A receipt at some `seq ≥ b+1` is what ties the pruned range's `boundary_hash` to externally anchored history.** Without one, the checkpoint is only a local claim.
- **Anchored vs locally rewritten.** An anchored checkpoint (covered by a later receipt) is externally committed. An unanchored checkpoint, and everything around it, can be coherently rewritten locally; the verifier reports it as "local, not independently committed".
- **The pack says plainly** that pruned rows' contents cannot be reconstructed; only their commitments remain.

**Migration.** The chain starts at migration. Rows written before it are carried over as **unchained history**, labelled so, and coverage is stated as starting at the migration (Tars a). **No evidential assurance is retrofitted** to pre-migration history: it is not re-hashed into the chain as if it had been chained, and it is never anchored as if it were.

**Off the request path.** Anchoring (ledger and pack-timestamp) is a background job, batched hourly for ledger heads, on demand for packs. It never runs on the agent's request path, never blocks a write, and an anchor-service outage only delays receipts (queued locally, sent later). A delayed anchor narrows nothing retroactively: the receipt time is when the service received it.

**Audit-write failure** (Tars r2.1 §6). Only **telemetry persistence** is best-effort. Security verdicts are computed before, and independently of, the ledger write:

- A **DENY stays DENY** if the disk is full, the ledger write throws or the anchor queue fails. The failure never turns a deny into an allow.
- A legitimate action that would have been **ALLOWed is not blocked** solely because an evidence service (ledger write, anchor, pack-timestamp, Cloud) is unavailable.
- On recovery the ledger writes a chained **lost-coverage marker** `{from, to, reason, events_lost: count if known, else unknown}`. The lost events are **not reconstructed**, and packs report the interval as lost coverage, not as a quiet period.

**Gating tests** (must pass before the chained ledger or anchoring ships): crash mid-write; concurrent writers; **ALLOW and DENY under audit failure** (disk full, ledger throw); migration from a populated v5.2.1 DB with no retrofit; **prune with and without receipts**; **pruned checkpoint alteration**; **pruned range crossing anchors** (with and without skeleton); **full-chain rewrite** and **suffix deletion** (undetected without a retained head, detected with a user-retained head or receipt); fork, reset and transition detection; **rollback** with and without a checker-supplied later receipt; **certificate renewal, re-enrolment, key replacement and two profiles on one machine** (one continuous history per `ledger_id`, two ledgers never flagged as a clone); **a new backdated pack over an old genuine prefix** (pack-signing time unproven); **certificate expiry/renewal** against pack-timestamp time; **backdated receipts from a later-compromised anchor signer** (detected only against a separately retained checkpoint, §5.8).

### 5.8 Signing architecture and trust roots (new in r2)

This replaces r1's two inconsistent descriptions (§5.1/§5.2 said packs are device-signed on demand and anchors countersigned hourly; the hosting note said everything is signed at release time on an operator box and Fly only serves files). The r2 architecture, one place, used by every other section:

| Key | Where it lives | Signs | Domain tag |
|---|---|---|---|
| **Offline root** | Offline, not on any server; used only in a documented ceremony | issuer, anchor-signer and feed-key certificates; key revocation list | `sc/v1/root` |
| **Online issuer** | Narrowly scoped online signer (§5.9), not in this repo | licences (v2) and device certificates; certificate revocation list | `sc/v1/licence`, `sc/v1/cert`, `sc/v1/crl` |
| **Online anchor signer** | Separate narrowly scoped online signer | ledger anchor receipts, pack-timestamp receipts, published receipt checkpoints | `sc/v1/anchor`, `sc/v1/pack-timestamp`, `sc/v1/anchor-checkpoint` |
| **Feed key** | Offline, separate from all others; release-time signing | feed files and manifests | `sc/v1/feed` |
| **Device key** | The customer's machine | evidence packs, incident bundles, anchor and pack-timestamp requests, ledger registrations, key-rotation statements | `sc/v1/pack`, `sc/v1/bundle`, `sc/v1/anchor-request`, `sc/v1/pack-timestamp-request`, `sc/v1/ledger-register`, `sc/v1/key-rotation` |

- **Domain separation.** Every signature is over `domain_tag || 0x00 || canonical_bytes`. A verifier checks the tag matches the expected use; a pack signature can never verify as a licence, a feed as a certificate, and so on.
- **Canonical encoding.** RFC 8785 JSON Canonicalization Scheme for every signed object. Every object has a `schema` id and `version`; verifiers use **strict schemas** (unknown fields rejected, required fields enforced, sizes bounded).
- **Test roots.** Test and sandbox roots have distinct key IDs and a `test` flag inside the signed root certificate. Production builds pin only the production root and **reject any test root**, enforced by a build-time check and a test. Test builds show "TEST — NOT PRODUCTION TRUST" on every output.
- **Rotation and revocation.** Every online and feed key has a `kid`, a validity window and a root-signed certificate. Rotation overlaps old and new keys; retirement adds the old `kid` to the root-signed revocation list. The root itself is not rotated online; a root change is a package release.
- **Outage contract.** Issuer down: existing certificates keep working until expiry; new enrolments and renewals queue; the 30-day grace applies. Anchor signer down: anchors and pack timestamps queue locally; packs state the unanchored suffix and "pack-signing time unproven" until the receipt arrives. Feed server down: last-known-good stays; staleness surfaces per §5.3. Local ledger write failing: §5.7 "Audit-write failure" — only telemetry persistence is lost; DENY stays DENY and ALLOW is not blocked. No outage ever changes a free-core verdict.

**Key compromise and verifier rules** (Tars r2.1 §3). Revocation records separate two times:

- **Administrative retirement** (`revoked_at`, reason `retired` / `superseded` / `org-revoked`): the key is honest but no longer authorised from that time. Signatures with independent time evidence before `revoked_at` are reported as made while authorised.
- **Effective compromise time** (`effective_compromise_at`, reason `key-compromise`): the earliest time the key may have been in someone else's hands. Set by the org admin or Drakon from the incident; when it is unknown it defaults to the key's **certificate `not_before`**, so nothing signed by it is trusted on time grounds. `effective_compromise_at` can be earlier than `revoked_at`, and usually is.

Verifier rules per key:

| Key | A signature/object is accepted as made before compromise/retirement only if… | Otherwise reported as |
|---|---|---|
| **Device key** | the pack has a **pack-timestamp receipt** (§5.7) with `received_at` before `effective_compromise_at` (compromise) or `revoked_at` (retirement), and the certificate was valid at that time. Ledger receipts inside the pack do not count. | "signed, signing time unproven, key later revoked/compromised" |
| **Issuer key** | the device certificate appears in the issuer's **issuance log**, whose head is anchored like a ledger, in a checkpoint dated before the issuer's `effective_compromise_at` that the checker holds or that is root-signed. | "certificate issued by a compromised issuer; issuance time unproven" |
| **Anchor-signer key** | the receipt is included in an **anchor checkpoint** (`sc/v1/anchor-checkpoint`: signed receipt-chain head, published at least daily, and on key rotation countersigned under the next key) dated before `effective_compromise_at`, **and** that checkpoint was retained independently of the pack: kept by the checker from earlier, exported from the org's account beforehand, or root-signed at rotation. | "receipt from a compromised anchor signer; time unproven" |

A compromised anchor signer can mint receipts with any `received_at`, and it can mint an internally consistent `prev_receipt_hash` chain too. **Receipt chaining alone does not expose that against an attacker-supplied standalone chain.** It is exposed only by comparison with a **separately retained trusted checkpoint/history**. The verifier says which checkpoint it compared against, or that none was supplied.
- **Production signing is not deployed under this design.** Sandbox keys only until Michael approves Cloud scope and, separately, production key creation.

### 5.9 Cloud service obligations (new in r2)

Applies only if Michael approves Cloud scope. Written so the service can be built to it, or so the gap is visible if it is not.

- **Tenant isolation.** Every record (licences, certificates, anchors, drift, bundles) is keyed by org and enforced at the query layer; cross-tenant reads are tested for in CI. One org's anchor receipts reveal nothing about another's.
- **Authenticated, idempotent anchors.** Anchor requests are authenticated by the device key and a current certificate that lists the `ledger_id` (§5.7). The idempotency key is `(ledger_id, epoch, seq, head_hash)` — **not** the certificate serial, which changes at renewal: a retry returns the same receipt; a different head at the same `(ledger_id, epoch, seq)` is a fork and is recorded, not overwritten. Latest-head lookup is by `ledger_id`. Transitions (renewal, re-enrolment, key replacement, restore, epoch reset) are recorded against the `ledger_id`. Pack-timestamp requests are idempotent by `envelope_hash`.
- **Billing webhooks.** Stripe webhooks are signature-verified, processed idempotently by event id, and replay-safe. Entitlement changes are derived from Stripe state, not from webhook order.
- **Certificate and key recovery.** Device keys are never escrowed. A lost device key means an explicit `key-replacement` transition (§5.7) under an org-admin authorisation; old packs are reported per §5.1 and §5.8 (signing time evidenced only by pack-timestamp receipts). An org admin can revoke all certificates for the org. Loss of an online issuer or anchor key: revoke via the offline root with an `effective_compromise_at`, and re-certify a new key. Receipts and certificates already issued are accepted as pre-compromise **only** per the §5.8 verifier rules (inclusion in an independently retained checkpoint dated before compromise), not merely because they chain.
- **Receipt checkpoints.** The anchor service publishes signed anchor checkpoints and issuance-log checkpoints at least daily, and lets each org export them. Customers and auditors are told to retain them **outside** the packs they check; that retained copy is what makes a later anchor-signer compromise detectable (§5.8).
- **Backup and restore.** Anchor receipts, revocation lists and certificate records are backed up daily with a tested restore; the restore test runs at least quarterly.
- **Anchor retention and export.** Receipts retained for the life of the subscription plus 7 years by default. An org can export all its receipts and revocation lists at any time, in the canonical format, verifiable without Drakon.
- **Shutdown continuity.** If the service ends, customers get at least 90 days' notice, a full export, and the final revocation list and root material needed to verify offline. Packs stay verifiable offline because verification never calls the service.
- **Redact before hash and export.** Anchors carry hashes only, but identifiers and timing are still metadata. Hostnames can be labels; device ids are random; drift and anchors never include paths, commands or content. **Low-entropy fields** (e.g. short command strings, small enums) are never hashed bare into anything that leaves the machine; they are redacted first or keyed with a per-org secret so a hash cannot be brute-forced back to content.
- **Availability and cost.** The issuer and anchor signer are availability-relevant services and were **absent from r1's £15–25/month estimate**. Their hosting, key custody and on-call cost are not yet estimated (Hosting section).

---

## 6. New claims and the proof matrix

Each lands in `docs/CLAIMS-PROOF.md` with a firing test in the same PR, or it does not ship:

| Proposed claim | Firing test |
|---|---|
| The posture record never exports `enforced` for a runtime without observed denial capability, keeps every instance, and never lets old or unverifiable evidence look current | The nine step-1 cases in §5.6 (two conflicting instances; restart/PID reuse; fresh heartbeat + stale deny; policy/plugin change after deny; malformed / future-dated / wrong-profile self-report; directory only; unloaded plugin; config/consent unchanged; probe vs real block), plus memory-only host → `memory-only`, "not a tool gate". Each through the shared model, `doctor` and `policy-evidence` |
| Editing or deleting a row **in the middle** of the local chain is detectable; a coherent full rewrite or tail deletion is detectable **only** against an independently retained head | Mutate / delete a middle row → verify fails at that row. Full-chain rewrite and suffix deletion → *not* detected with no retained head (stated), detected against a user-retained head or receipt. A retention prune → accounted for by a checkpoint, not a break |
| Pruned history stays checkable to the extent its witnesses were kept | Prune with and without receipts; alter a pruned checkpoint; prune a range crossing anchors with and without skeleton → each reported as checked / local-only / not re-checkable |
| A ledger forked, reset, transitioned or rewritten relative to an anchor receipt is detected, keyed by `ledger_id` | Fork at same `(ledger_id, epoch, seq)` including under a renewed serial; new epoch; restore; rewrite before anchor → each reported distinctly. Renewal, re-enrolment, key replacement → one continuous history. Two profile DBs on one machine → two ledgers, never a clone |
| Rollback is reported only relative to supplied later evidence | Older valid pack alone → "newer history: not checked"; with a checker-supplied later receipt/checkpoint → rollback reported |
| Ledger-content time and pack-signing time are reported separately | New backdated pack over an old genuine prefix → ledger content dated, pack-signing time "unproven"; with a pack-timestamp receipt → signing time dated. Certificate expiry/renewal → validity checked at pack-timestamp time only |
| Receipts from a later-compromised anchor signer are not trusted on their own say-so | Backdated receipts (with a consistent receipt chain) from a signer with an earlier `effective_compromise_at` → rejected on time grounds against a retained checkpoint; reported "time unproven" when no retained checkpoint is supplied |
| An evidence pack altered by one byte, signed by an uncertified key, signed in the wrong domain, or chained to a test root in a production build fails verification | Tamper / re-sign / cross-domain / test-root → `verify` fails with the specific reason |
| Offline verification reports signature, time evidence, coverage and revocation/freshness separately, as of the supplied evidence, and never "valid forever" | Pack with unanchored suffix and later-revoked key → four results, suffix flagged "time unproven" |
| An audit-write failure never flips a security verdict | Disk full / ledger throw during an attack corpus → every DENY still denies, every legitimate ALLOW still allows; lost-coverage marker on recovery, no reconstructed events |
| A feed with a bad signature, a lower sequence, an unsupported schema, an unknown/revoked `kid`, or an item that disables a built-in is rejected, and the last good feed stays | Forge / replay / wrong schema / retired kid / relax-attempt → rejected, detection unchanged |
| A frozen feed is reported stale | Replay the latest valid manifest past `expires_at` → doctor and packs say stale |
| A feed item that flips a must-ALLOW fixture, blows the ReDoS or cumulative perf budget, or times out in evaluation is refused or disabled, and never stalls the write path | Craft such items → refused/disabled, logged, write-path p95 unchanged |
| A lapsed or offline subscription never changes a free-core verdict | Same attack corpus with the licence valid / expired / revoked / unreachable → identical verdicts |

The matrix goes from 13 to 27 public claims.

---

## 7. What is NOT being built, and why

- **Nothing free moves behind the licence.** This includes `audit_export`, which people might expect to be "the evidence feature". Evidence packs are a different thing (independently certified, anchored, mapped), built beside it.
- **Not selling the ability to sign local data.** Local signing and export are free; the paid part is the independent issuer, anchor, curation and support.
- **No per-developer seats.** Agents aren't seats, and counting developers would need telemetry. Machines are counted by active certificate lease (§4).
- **No monthly self-serve plan.** The unit of value is the annual attestation, and annual-only halves billing/dunning work. Enterprise can contract any way it likes. Annual-only is itself a hypothesis to test.
- **No trial.** The free tier plus `evidence preview` does the job, and there are no nag screens or expiry banners. The retired upsell machinery stays retired.
- **No protection or enforcement claims for runtimes without an observed tool gate**, in any tier, pack or pricing page.
- **No completeness claims.** No pack, page or copy says the records are complete or that prevention succeeded everywhere.
- **No usage telemetry.** Everything that leaves the machine is opt-in and listed in the opt-in copy.
- **No kill switch.** A lapse or revocation never reduces protection (§5.1 table).
- **No compliance certification or GRC product.** We supply evidence *into* Vanta/Drata/an auditor. We do not compete with them or claim anyone is compliant.
- **No LLM-powered paid features.** They bring per-call cost, privacy exposure, and FP risk the budget cannot yet measure.
- **No Drakon-held memory content in self-serve tiers by default.** Off-box incident bundles contain content only on explicit opt-in.
- **No refactor of the built-in detectors into data files.** The feed layers on top as an additive external set per detector family.
- **No SSO, SIEM connectors, air-gapped mirror or SLA advertised in any tier before they exist.** They are Enterprise, because each one is real per-customer work.
- **No production signing keys deployed under this design** (§5.8).

---

## 8. Sequencing

One feature per PR, each opened as a draft with a failing test first. Order follows Tars (a): honest posture first, then local integrity, then the thinnest paid slice that exercises the whole trust chain, then the feed, then fleet. **r1's order (feed before ledger, anchoring as a later add-on) is withdrawn.**

**0. Done / parallel free-core work (not subscription work)**
- **#602** OpenClaw 2026.9.6 `cli-metadata` register — **merged; 54 focused tests/typechecks verified (Tars, worktree `sc-patrol-20260927-602` at `8fa5cc8f`); real 2026.9.6 discovery/interception smoke pending receipt.** PR #605, merge `ad95afd4`, reviewed head `8fa5cc8f`, merged 27 Sep 2026. Tars authored the fix; Jarvis gave the independent review (his extra host-shape probe was not committed). The original acceptance criteria (real 2026.9.6 cli-metadata discovery with no runtime access or chatter, commands discoverable, normal gateway registration/interception unchanged) are **not all met** until that live isolated receipt exists; no listing or release claim relies on them before then.
- **Plugin listing / release** (Tars r2.1 §8). The plugin is **never published from v5.2.1**: its tag resolves to `1c255445`, the parent of #605, and lacks the metadata fix. Listing happens only from a **reviewed release containing #605** (the 5.2.2 candidate), without moving the v5.2.1 tag or substituting different bytes under an existing version. Before listing: confirm the current plugin-package publishing contract, then in a **sandbox** validate, on the **exact candidate artefact**, search/discovery, clean install, help/metadata, full runtime hooks, update and uninstall. **Guard is not auto-armed** for that smoke. `scripts/clawhub-sync.mjs` publishes only `skills/shieldcortex` today; that is an automation gap to close, not a decision against listing the plugin. Publication itself remains a separate owner approval.
- The six free-core defects in §1 (remote regex ReDoS, `verify.ts` PII, memory-sync redaction, revocation wiring, CSV ledger columns, stale copy) go in first or in parallel. Two of them are the same class of risk the feed rules in §5.3 exist to prevent.

**1. Per-runtime posture record (free; issue #613).** Shared typed observation module (§5.6) with per-instance keys, per-field evidence, invalidation rules and the bounded self-report file; doctor and a `policy-evidence` exporter read it; process-side self-reports for Claude Code, OpenClaw and Hermes. *Acceptance tests:* Tars's nine firing cases, verbatim in §5.6, each through the shared model and both the doctor and export consumers. The existing skeleton and failing cases can be kept and extended; the later ledger/paid-slice items do not block this step.

**2. Free chained ledger + verifier.** `ledger_id` per database, forward-only migration with unchained-history labelling (no retrofit), `content_digest` row hashing, chained prune checkpoints with skeletons, heartbeat rows, lost-coverage markers, `ledger head`, `ledger verify`, the standalone verifier and `evidence preview` (LOCAL / NOT INDEPENDENTLY ATTESTED). Gating failure-mode tests from §5.7. Perf budget re-measured.

**3. Thin paid vertical slice** — the whole trust chain once, end to end, against **sandbox** keys:
   1. Generic Ed25519 verifier with `kid`, domain tags and RFC 8785 canonical encoding; v1 licence behaviour byte-for-byte unchanged; test-root rejection in production builds.
   2. v2 entitlements + free-core isolation test, 30-day grace, plain-English card, revocation wiring (pinned host, paid surfaces only).
   3. **Enrolment and device certificate** (§5.1 tuple, including `ledger_id` registration and binding; renewal, re-enrolment and key-replacement transitions).
   4. **External anchor** (§5.7), background, hash-only, keyed by `ledger_id`; **pack-timestamp receipts**; published anchor checkpoints.
   5. **Evidence pack** (§5.2) embedding posture records, chain, receipts and revocation snapshot.
   6. **Offline verification** with the four-part result, separate ledger-content and pack-signing times, freshness as of supplied evidence, and the §5.8 compromise rules.

   *Gates the paid slice (not step 1):* the §5.7 gating tests on identity (renewal, re-enrolment, key replacement, two profiles), time (backdated pack over old genuine prefix, cert expiry/renewal, backdated receipts from a later-compromised signer), rollback and retention.

   Without Cloud approval this slice runs against a local sandbox issuer/anchor and is **a prototype, not the install → pay → verify product**.

**4. Signed feed client** (§5.3 in full). Proof claims for feed rejection, freeze and budgets.

**5. Sealed incident bundles.** Cross-store correlation on `sessionKey`/`actionKey`/`seq`/`audit_id`; respects the `denials.jsonl` redaction.

**6. Fleet policy + drift reporting.** Signed org policy through the policy lock, tighter-wins pinned by a test, reviewed exceptions (§5.4), opt-in drift heartbeat using posture summaries.

**7. Dashboard + copy.** Plan card in Settings (replacing the static Enterprise card); remove the stale Pro/Team strings; README pricing section with the gated-runtime caveat on every tier; CHANGELOG entries in the house register, with residuals disclosed. The lapse-path proof claim lands with step 3.2.

**Later, not critical path:** one provider-neutral Policy-plugin upstream proposal, only after `policy-evidence` has shipped and been validated against the actual Policy schema/version (Microsoft section item 4).

**Server-side dependencies** (per the open question, all subject to Michael's approval of Cloud scope): sandbox billing/enrolment, device-certificate issuer, anchor service (§5.8, §5.9), then feed build/sign/publish with the FP gate in CI. Production signing is a separate later approval.

---

## 9. Risks and residuals

- **Price validation.** The prices and terms are hypotheses, not tested. **Mitigation:** 5–10 buyer conversations with existing free users who have more than 3 machines, before the pricing page ships. A preview is not an evaluation of onboarding or fleet coverage; those need a sandbox enrolment.
- **Cost-to-serve unknown.** Hosting is not cost-to-serve. Support time, the issuer/anchor service, key custody and any on-call rota are not estimated. Enterprise's 4-hour response cannot be offered without a staffed rota.
- **Records are bounded by host integrity and instrumentation.** A root-level attacker, or a modified runtime, can record false data or suppress events. Anchoring fixes *when* a prefix existed; it cannot make it complete or true (§5.2). Stated in every pack.
- **Zero-visibility read as zero-incidents.** The biggest misuse risk of a pack. Mitigated by posture records and gap intervals placed before counts in the rendering.
- **Feed key compromise.** Bounded by additive-only, offline key custody and rotation, but a stolen key could still push over-blocking items. Mitigation: arrival FP check, shadow mode, isolated evaluation, reviewed exceptions, fast retraction.
- **Online signer compromise.** An issuer or anchor-signer key compromise can mint certificates or receipts — including backdated ones with a consistent `prev_receipt_hash` chain — until revoked via the offline root. Mitigation: narrow scope, separate keys, revocation lists with `effective_compromise_at` bundled into packs, and published checkpoints. **Receipt chaining alone does not expose forgery in an attacker-supplied standalone chain**; it is exposed only against a checkpoint/history retained independently beforehand (§5.8). Customers who never retain checkpoints get weaker time evidence after such a compromise, and the verifier says so.
- **Stolen device key.** It can sign new packs citing genuine old ledger receipts. Mitigation: pack-signing time is reported separately and is unproven without a pack-timestamp receipt (§5.7); `effective_compromise_at` defaults conservatively (§5.8).
- **Offline rollback.** A checker with only an old pack cannot tell newer history exists. Mitigation: freshness stated "as of supplied trusted evidence"; checkers are told to keep later receipts/checkpoints or use the optional online check (§5.7).
- **Posture self-reports are host-local.** Any same-user process can write them. Bounded by host integrity and stated in every export (§5.6).
- **Control mappings unreviewed** (§5.2).
- **Grandfathered v1 keys** stay on `TIER_RANK` indefinitely. Harmless (they only unlock what they unlock today), but two code paths to maintain.
- **Machine counting can be gamed** by cloning a device key. Accepted for self-serve: clones surface as forks (§4, §5.7) and are shown to the org admin; nothing auto-revokes.

---

## Provenance of this document

- r1 written by Claude, model **Opus 5.5** (`claude-opus-5-5`), running in Claude Code — `claude --version`: `2.1.283 (Claude Code)`. Exploration was read-only: no install, test, build or `openclaw` command, and `~/.shieldcortex` / `~/.openclaw` were not touched. All file/line claims come from reading `origin/main` a2b448eb in the `sc-wt-subscription` worktree.
- r2 (29 Sep 2026) written by Claude Opus 5.5 as a docs-only revision answering Tars's review (`2026-09-26-subscription-product-review-tars.md`). No code, no network, no `openclaw` command. The source line references added to §1 are Tars's, spot-checked by Jarvis against a2b448eb as recorded in the review file; r2 did not re-read them. #605's merge was confirmed from local git (`ad95afd4` contained in `origin/main`), not from GitHub.
- r2.2 (29 Sep 2026) written by Claude Opus 5.5 (`claude-opus-5-5`) as a docs-only revision answering Tars's r2.1 verdict §1–§8. No code, no network, no `openclaw` command, no push. The #605 status, merge/head SHAs, the 54/54 focused-test and typecheck result, the v5.2.1 tag commit (`1c255445`), the npm version and the `scripts/clawhub-sync.mjs` behaviour are **as reported by Tars** in that verdict; r2.2 did not re-run or re-read them.

## Hosting cost (Fly.io, verified 26 Sep 2026)

Existing footprint (org "personal", region lhr): `shieldcortex-api` 2 × shared-cpu-1x 768MB (scale-to-zero, one running), `shieldcortex` site 1 × 256MB (stopped), `shieldcortex-db` Fly Postgres 1 machine + 1GB volume. Approx $8/month today.

Fly list prices, lhr (docs.fly.io/about/pricing, markup 1.1346): shared-cpu-1x 256MB $2.21, 768MB $5.04, 1GB $6.46, 2GB $12.14 per always-on machine-month; stopped machine rootfs $0.15/GB; volumes $0.15/GB; dedicated IPv4 $2; egress $0.02/GB (NA/EU); Standard support $29/month (lapsed Aug 2026).

Serving layer on the same API app: one always-on 768MB–1GB machine for licence checks (+$5–7), a second for availability when paying customers exist (+$5–7), volume growth for anchor receipts and policy history (+$1–2). Estimate +$10–20/month → ~$20–30/month (£15–25) **for serving only**.

**Corrected in r2.** r1 said "feed and evidence packs are signed at release time on the operator's box; Fly only serves signed artefacts and verifies licences." That was wrong for evidence and inconsistent with §5.1/§5.2. The r2 architecture (§5.8):
- **Feed:** signed at release time with an offline feed key, not on Fly. (r1 was right about this part.)
- **Evidence packs:** signed on the customer's machine by the device key. No Drakon key is involved at pack time.
- **Device certificates and anchor receipts:** need **online** signers (issuer, anchor signer), narrowly scoped, certified by an offline root. If the "no signing keys on Fly" constraint stands, those signers run outside Fly (e.g. a separate hardened host or a managed KMS/HSM signing call); where they run is a Michael decision tied to the Cloud-scope question.
- **Not in the estimate:** the online signers, their key custody (HSM/KMS or equivalent), their availability, backup/restore and on-call. The £15–25 figure must not be read as the cost of the paid product.

## Microsoft Autopilot and the OpenClaw Policy plugin (added 26 Sep 2026, Michael's direction; revised r2)

**Context.** Microsoft Autopilot (formerly Scout; announced Build 2 Jun 2026; private preview expanding from end Sep 2026) is built on OpenClaw. Microsoft is upstreaming *policy conformance*: the bundled **Policy plugin** (`openclaw policy`, `extensions/policy`, present in OpenClaw 2026.9.6) lets an operator author `policy.jsonc`, observes the workspace as evidence, reports drift through `doctor --lint`, and produces an **attestation tuple** (`policy.hash`, `workspace.hash`, `findingsHash`, `attestationHash`) with structured evidence sections (channels, mcpServers, modelProviders, network, gatewayExposure, agentWorkspace, secrets, authProfiles). Its docs state plainly: *"Policy does not enforce tool calls or rewrite runtime behavior at request time, and it does not attest per-agent credential stores."* **Unverified:** the Autopilot/Build/preview/"built on OpenClaw"/upstreaming assertions in this paragraph have not been checked against primary sources by Tars, r2 or r2.2. They need primary-source checks (Microsoft's own announcement and docs, the OpenClaw repository) **before any public copy** uses them.

**Positioning (agreed with the owner, wording revised r2).** *Policy says how the agent should be set up. ShieldCortex provides verifiable records of observed controls and actions.* Static configuration conformance and runtime enforcement records are complementary halves of the same enterprise question. Autopilot itself runs OpenClaw as an untrusted runtime inside Microsoft's container with a curated signed supply chain, so Autopilot users are unlikely to install third-party plugins; the addressable market is every other OpenClaw deployment. We make **no claim that Microsoft supports or endorses** ShieldCortex.

**Changes to this plan.**
1. **Phase 1 order** follows §8 (posture → chained ledger → thin paid slice → feed → fleet). r1's "evidence packs first, feed second, fleet third" stands in spirit; §8 is authoritative.
2. **Policy-compatible record (free).** `shieldcortex policy-evidence` emits our **provider-neutral** posture record (§5.6) in a JSON section following the Policy plugin's evidence idiom (`source: "sc://..."` provenance per item): per-runtime posture records, Action Guard and policy-lock state, memory firewall mode, detector set / feed sequence, ledger chain head. It is **never** built from doctor's `bound` boolean. Before it ships it is validated against the actual Policy schema in OpenClaw 2026.9.6.
3. **Embedding the Policy tuple.** Evidence packs embed the current `openclaw policy` attestation tuple when present, with its schema/version, scope, acquisition time and provenance. It is labelled a **configuration snapshot, not a runtime witness**: it shows how things were configured at acquisition time, not what happened.
4. **Upstream alignment (small follow-up, not Phase 1 critical path).** **One** provider-neutral proposal, made only after `policy-evidence` has shipped and been validated against the **actual Policy schema and version** it targets, and only within Michael's go for public engagement: an optional `runtime-enforcement` evidence provider, with a concrete versioned example, its limitations and a test receipt. No comments on unrelated upstream repairs (e.g. #101916) as advertising; no Microsoft endorsement claim; nothing in Phase 1 depends on upstream acceptance.
5. **Windows.** Test install and posture on the native Windows OpenClaw companion (MXC sandbox backend) and document it.
6. **Ecosystem listing.** OpenClaw ecosystem page and Foundation plugin list — under the §8 step 0 listing rules: never from v5.2.1; only a reviewed release containing #605 (5.2.2 candidate), sandbox-validated on the exact artefact, Guard not auto-armed; publication a separate owner approval.

**Compatibility note found while checking (26 Sep).** On OpenClaw 2026.9.6 the ShieldCortex plugin logged `runtime is intentionally unavailable during "cli-metadata" registration`. Filed as #602. PR #605 (merge `ad95afd4`, head `8fa5cc8f`), Tars authored, Jarvis independent review: **merged; 54 focused tests/typechecks verified (Tars, worktree `sc-patrol-20260927-602` at `8fa5cc8f`); real 2026.9.6 discovery/interception smoke pending receipt** (§8 step 0).
