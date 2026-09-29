# ShieldCortex subscription product — Phase 0 design

Status: **draft for owner review — revision 2** · Base: `origin/main` a2b448eb (v5.2.1) · Branch: `design/subscription-product` · r1 2026-09-26 (7ad519eb) · r2 2026-09-29

No code in this phase. This document is the thing to approve, change, or reject before Phase 1 starts. Tars's review of r1 (`2026-09-26-subscription-product-review-tars.md`) did **not** approve implementation; r2 is the revision it asked for and needs a fresh review before any Phase 1 code.

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
| 12 | §8 rewritten in Tars's order: #602 **done** (PR #605, `ad95afd4`, on `origin/main`); free-core defects; posture record → free chained ledger + verifier → thin paid slice (enrolment/cert → external anchor → pack → offline verification) → feed → fleet. Client work against test keys is labelled a prototype. | a, b, f | §8 |
| 13 | Policy-plugin upstream namespace moved off the Phase 1 critical path; the embedded Policy attestation tuple is described as a configuration snapshot with schema/version, scope, acquisition time and provenance, not a runtime witness. No claim of Microsoft support or endorsement. | d | Microsoft section |

---

## Open question for Michael

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
7. ~~OpenClaw 2026.9.6 `cli-metadata` registration noise (#602).~~ **Done:** PR #605 (`ad95afd4`, "quiet cli-metadata register; keep full-mode init loud") is on `origin/main`. It stayed a free-core compatibility PR, separate from subscription work (Tars f).

---

## 2. The buyer and the moment they decide to pay

**Who installs it:** a developer. They found ShieldCortex because their agent has shell access and that scared them. They will never pay, and they must never feel pushed to.

**Who pays:** the person who owns the risk budget at a 10–250 person software company that runs agents with tool access on shared or production machines. That is a head of platform, an engineering lead doubling as security lead, or a first security hire. They already have the free package on several boxes because a developer put it there.

**The moment they decide.** It is always a question from someone outside the engineering team that the free tool cannot answer on its own:

1. **The questionnaire.** A customer's security review or the SOC 2 / ISO 27001 auditor asks: *"What controls govern what your AI agents can do, and show me evidence they operated during the period."* A local dashboard is evidence, but only the operator's own. A record whose integrity an outsider can check independently answers the question better.
2. **The first real block.** The guard denies something ugly. Leadership asks: *"What else did it see, store and try? Can you show the log wasn't edited?"* The free tool shows the local timeline and (after §5.7) can detect local edits. It cannot show a third party that the history up to a point existed at a time they can check.
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
- **Retirement / reassignment.** `shieldcortex license retire` (or the Cloud Devices view) retires a lease immediately and frees the slot. The retired certificate is revoked for *new* signatures; packs it signed earlier still verify as-of their anchors (§5.1).
- **Rebuilds.** A rebuilt host is a new key pair and a new lease. The old lease is retired by the operator or expires. Reusing a device ID with a new key is allowed and recorded as a rebuild, not a clone.
- **Clones.** Two installations presenting the **same device key** are a clone. Drift and the anchor service detect it (two chains under one certificate → fork, §5.7). A clone is shown to the org admin; it is never silently counted as one machine, and never auto-revokes the original.
- **CI / ephemeral hosts.** Short-lived runners use **ephemeral leases** (hours, not 90 days) issued to a CI enrolment token. They count by **peak concurrent** active leases per day, not by total issued, so a runner that spins up 500 times a month is not 500 machines.
- **Multi-profile hosts.** One machine = one device key, however many runtimes or profiles it runs (Claude Code, OpenClaw, several Hermes profiles). Profiles appear as separate posture records (§5.6), not as extra machines.

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
- **Hash-chained ledger** (SCOPE P3, §5.7). Local integrity, so free. Retention prunes write a chained checkpoint. History from before the migration is labelled **unchained**, and coverage is stated as starting at the migration: a ledger cannot reconstruct observations it never recorded (Tars a).
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
- **Revocation.** Wire the (currently dead) daily check, gated to paid surfaces only, against a **pinned** licence host rather than `cloudBaseUrl`. The issuer publishes a signed, dated revocation list (serials + revocation time + reason); packs bundle the latest list they saw.

| State | Free core | Feed | New packs / bundles / anchors | Existing packs (offline verification) |
|---|---|---|---|---|
| Active | ✅ | updates | signs, anchors | four-part result (§5.2) |
| Offline ≤ 30 days | ✅ | last verified feed stays active (subject to §5.3 expiry notice) | signs; anchors queue locally | four-part result |
| Offline > 30 days / expired > grace | ✅ | **last verified feed stays active**, no new updates | paused, card shown | four-part result |
| Revoked | ✅ | last verified feed stays active | stopped | signature still checks; **time evidence decides**: content anchored *before* the revocation time is reported as such; unanchored content from that key is reported as "signed, time unproven, key later revoked" |

There is no "verifies forever" (Tars g4). A compromised device key can backdate an unanchored pack, so without an anchor the signing time is only the signer's claim. An offline verifier knows revocation status only **as of the revocation snapshot bundled in the pack** (or supplied by the checker); it cannot know about a later revocation, and says so.

### 5.2 Evidence packs — what they show and what they don't

**What a pack is.** A canonical JSON document (§5.8) plus a detached Ed25519 signature in the `pack` domain, with a human-readable PDF/markdown rendering generated *from* the JSON. It contains:

- the period covered, and the **coverage start** (ledger migration date or first chained row; earlier history marked unchained)
- package version
- detector-set and feed sequence numbers active over the period, with change dates
- config hash (canonical JSON) and effective policy hash
- policy-lock state
- **per-runtime posture records** (§5.6), with each field's value, observation time and provenance, and every degraded or unobserved interval in the period
- counts and IDs of blocks, quarantines, approvals and reviewed exceptions in force (§5.4)
- ledger chain head(s), reset epochs, gaps and checkpoints (§5.7)
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

#### What a signature does and does not prove

A signature authenticates bytes. That is all it does. Stated inside every pack, in this wording or stronger:

**A valid pack signature and chain show:**
- these exact bytes were signed by a key holding a certificate the issuer gave to an enrolled machine of this org, for pack signing, valid at the stated time (subject to time evidence below);
- the bytes were not altered after signing;
- the ledger prefix up to each anchor receipt existed, in that form, no later than the anchor service's receipt time, and the retained ledger matches it (§5.7).

**They do not show:**
- **Completeness.** Only what the instrumented runtimes observed is recorded. **A pack showing zero blocks may mean zero visibility**; read the posture records and gap intervals before reading the counts.
- **Truthful instrumentation.** An attacker with root before an event is recorded, or a modified ShieldCortex, can record false data. Anchoring bounds *when* history was fixed, not whether it was true.
- **Successful prevention.** A recorded deny shows the gate returned deny on that path. It does not show the action could not happen another way.
- **Universal agent coverage.** Runtimes with no tool gate (memory-only), runtimes that were never observed, and processes outside ShieldCortex are not covered. The pack lists what it saw; it cannot list what it did not.
- **The unanchored suffix.** Events after the last anchor receipt are signed by the device only; their time is the device's claim.
- **Future revocation.** Revocation status is as of the bundled snapshot.

**Offline verification result.** `evidence verify` never prints a single "valid". It prints four separate results (Tars g4):

1. **Signature validity** — pack, certificate chain and domains check out against the pinned production root (test roots rejected).
2. **Time evidence** — which parts are covered by anchor receipts (with receipt times), which are device-claimed only.
3. **Coverage integrity** — chain continuity, reset epochs, gaps, checkpoints, degraded/unknown posture intervals, and the stated coverage start.
4. **Revocation status** — as of the bundled (or supplied) revocation snapshot and its date.

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
- device id and certificate serial
- hostname (can be replaced by a label)
- policy hash
- per-runtime posture summary (the §5.6 enum fields and observation times; no paths or process arguments)
- package version
- feed sequence

It contains no content, commands, paths or memory. Identifiers and timing are still metadata; §5.9 covers how they are handled.

### 5.6 Per-runtime posture record (new in r2)

**Why.** r1 exported doctor's `bound` as if it meant enforced. It does not (§1, Tars c): `bound` is installed-or-integrated, Hermes posture is inferred from a directory, and the Hermes plugin's enforce flag lives in the plugin process, not the CLI. The export must describe what was observed, per runtime, with its limits.

**One record per `(runtime, profile/scope id, plane)`.** `plane` is `tool-gate` or `memory`. Fields are **separate** and each can independently be `unknown`:

| Field | Values | Meaning |
|---|---|---|
| `capability` | `tool-gate` / `memory-only` / `none` / `unknown` | What this runtime can support at all. Memory-only is **never** a tool gate. |
| `installed` | `yes` / `no` / `unknown` | ShieldCortex artefacts present for this profile. |
| `runtime_loaded` | `yes` / `no` / `unobserved` / `unknown` | The runtime process actually loaded the plugin/hook, observed from the process side. |
| `configured_posture` | `enforce` / `advisory` / `intentionally-off` / `unavailable` / `unknown` | What configuration asks for. These are not interchangeable: advisory ≠ off ≠ unavailable ≠ unobserved. |
| `observed_denial` | `observed` / `not-observed` / `degraded` / `unknown` | Whether a deny from this runtime's gate has been observed, including a synthetic probe. |
| `observed_at` | timestamp | When this record was observed. |
| `process_identity` | runtime name + version, plugin id + version + content hash, pid/instance id | Which process and plugin the observation came from. |
| `effective_policy_hash` | hash | Hash of the policy the *runtime process* reports it is enforcing, not the CLI's reading of config. |
| `probe` | `{method, source, observed_at, max_age}` | How the value was obtained (process self-report, synthetic denial, file probe) and when it goes stale. A stale value becomes `unknown`. |
| `degraded_intervals` | list of `{from, to, reason}` | E.g. scanner-degraded fallback (`policy.py:45–79`), plugin not loaded, probe failures. |

**Rules.**
- **Explicit unknown.** Anything not observed within `max_age` is `unknown`. `unknown` is never rendered green.
- **Synthetic denial is narrow.** A fresh synthetic denial proves the tested path denied at that moment. It is recorded as that, not as universal prevention.
- **No green-by-consent-change.** Collecting posture never changes consent, arms Guard, or flips config to make the record look better (Tars c).
- **No host-wide rollup to green.** A host summary is the *weakest* of its records.
- **Shared typed model.** `doctor`, `policy-evidence`, packs and drift all read one typed observation module, not terminal text and not today's overloaded boolean. The existing `bound` boolean stays for backwards-compatible display only and is **never** exported as `enforced`.
- **Process-side reporting.** Runtimes that can gate (Claude Code hook, OpenClaw plugin, Hermes plugin) write a small, versioned self-report (loaded, posture, policy hash, last deny/probe) to a local file the CLI reads. Where a runtime cannot self-report, `runtime_loaded` is `unobserved`.

### 5.7 Chained ledger, anchoring and retention (new in r2)

**Chain (free).** Each `defence_audit` row carries `prev_hash`, `seq`, `epoch` and a row hash over canonical content. `ledger verify` walks the chain. Concurrent writers are serialised through the DB transaction; the chain is per device key.

**What an external anchor commits** (Tars g2). The device submits `{cert serial, epoch, seq, head_hash}` signed in the `anchor-request` domain. The anchor service returns a receipt signed in the `anchor` domain: `{cert serial, epoch, seq, head_hash, received_at, receipt_serial, prev_receipt_hash}`. A receipt commits **the ledger prefix from the start of the epoch through `seq`, as existing no later than `received_at`.** It does **not**:
- say anything about rows after `seq` (the unanchored suffix);
- show that suppressed or never-recorded events did not happen;
- show the recorded content is true (§5.2).

**Verification against anchors.** The verifier recomputes the retained prefix and checks it hashes to each receipt's `head_hash` at that `seq`, then detects:
- **Forks** — two different heads at the same `(serial, epoch, seq)`, or two chains under one certificate (also the clone signal, §4).
- **Reset epochs** — a new epoch starting at `seq 0`. Allowed (reinstall, restore) but always shown, with the last anchored head of the previous epoch.
- **Missing intervals** — gaps in `seq`, or time ranges with no rows and no heartbeat row; the ledger writes a periodic heartbeat row so silence is distinguishable from a missing interval.
- **Rollback to an older valid anchor** — a pack whose head is older than a receipt the anchor service has already issued for that serial/epoch. The anchor service returns the latest receipt for a serial on request, and packs bundle the latest receipt known at export, so a verifier can see that newer history existed.

**Retention checkpoints.** A prune writes a chained checkpoint row: `{pruned seq range, count, hash of the pruned rows' hashes, last anchor receipt covering them}`. Verification afterwards proves the retained rows chain to the checkpoint and the checkpoint to its receipt. The pack states plainly that **the pruned rows' contents can no longer be independently reconstructed**; only their commitment remains.

**Migration.** The chain starts at migration. Rows written before it are carried over as **unchained history**, labelled so, and coverage is stated as starting at the migration (Tars a).

**Off the request path.** Anchoring is a background job, batched hourly. It never runs on the agent's request path, never blocks a write, and an anchor-service outage only delays receipts (queued locally, sent later). A delayed anchor narrows nothing retroactively: the receipt time is when the service received it.

**Gating tests** (must pass before the chained ledger or anchoring ships): crash mid-write, concurrent writers, disk full, audit-write failure (the agent path fails open for the free core; the ledger records a gap marker on recovery), migration from a populated v5.2.1 DB, prune with and without anchors, fork, reset and rollback detection.

### 5.8 Signing architecture and trust roots (new in r2)

This replaces r1's two inconsistent descriptions (§5.1/§5.2 said packs are device-signed on demand and anchors countersigned hourly; the hosting note said everything is signed at release time on an operator box and Fly only serves files). The r2 architecture, one place, used by every other section:

| Key | Where it lives | Signs | Domain tag |
|---|---|---|---|
| **Offline root** | Offline, not on any server; used only in a documented ceremony | issuer, anchor-signer and feed-key certificates; key revocation list | `sc/v1/root` |
| **Online issuer** | Narrowly scoped online signer (§5.9), not in this repo | licences (v2) and device certificates; certificate revocation list | `sc/v1/licence`, `sc/v1/cert`, `sc/v1/crl` |
| **Online anchor signer** | Separate narrowly scoped online signer | anchor receipts | `sc/v1/anchor` |
| **Feed key** | Offline, separate from all others; release-time signing | feed files and manifests | `sc/v1/feed` |
| **Device key** | The customer's machine | evidence packs, incident bundles, anchor requests | `sc/v1/pack`, `sc/v1/bundle`, `sc/v1/anchor-request` |

- **Domain separation.** Every signature is over `domain_tag || 0x00 || canonical_bytes`. A verifier checks the tag matches the expected use; a pack signature can never verify as a licence, a feed as a certificate, and so on.
- **Canonical encoding.** RFC 8785 JSON Canonicalization Scheme for every signed object. Every object has a `schema` id and `version`; verifiers use **strict schemas** (unknown fields rejected, required fields enforced, sizes bounded).
- **Test roots.** Test and sandbox roots have distinct key IDs and a `test` flag inside the signed root certificate. Production builds pin only the production root and **reject any test root**, enforced by a build-time check and a test. Test builds show "TEST — NOT PRODUCTION TRUST" on every output.
- **Rotation and revocation.** Every online and feed key has a `kid`, a validity window and a root-signed certificate. Rotation overlaps old and new keys; retirement adds the old `kid` to the root-signed revocation list. The root itself is not rotated online; a root change is a package release.
- **Outage contract.** Issuer down: existing certificates keep working until expiry; new enrolments and renewals queue; the 30-day grace applies. Anchor signer down: anchors queue locally; packs state the unanchored suffix. Feed server down: last-known-good stays; staleness surfaces per §5.3. No outage ever changes a free-core verdict.
- **Production signing is not deployed under this design.** Sandbox keys only until Michael approves Cloud scope and, separately, production key creation.

### 5.9 Cloud service obligations (new in r2)

Applies only if Michael approves Cloud scope. Written so the service can be built to it, or so the gap is visible if it is not.

- **Tenant isolation.** Every record (licences, certificates, anchors, drift, bundles) is keyed by org and enforced at the query layer; cross-tenant reads are tested for in CI. One org's anchor receipts reveal nothing about another's.
- **Authenticated, idempotent anchors.** Anchor requests are authenticated by the device key and certificate. The idempotency key is `(serial, epoch, seq, head_hash)`: a retry returns the same receipt; a different head at the same position is a fork and is recorded, not overwritten.
- **Billing webhooks.** Stripe webhooks are signature-verified, processed idempotently by event id, and replay-safe. Entitlement changes are derived from Stripe state, not from webhook order.
- **Certificate and key recovery.** Device keys are never escrowed. A lost device key means retire and re-enrol; old packs still verify per §5.1. An org admin can revoke all certificates for the org. Loss of an online issuer or anchor key: revoke via the offline root and re-certify a new key; receipts already issued stay verifiable against the old key's certificate and its revocation time.
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
| The posture record never exports `enforced` for a runtime without observed denial capability, and stale observations become `unknown` | Memory-only host, Hermes dir with no loaded plugin, stale probe → record shows `memory-only` / `unobserved` / `unknown`, pack says "not a tool gate" |
| Editing or deleting a ledger row is detectable | Mutate / delete a row → chain verify fails at that row; a retention prune → accounted for by a checkpoint, not a break |
| A ledger rewritten, forked, reset or rolled back relative to an anchor receipt is detected | Rewrite before anchor, fork at same seq, new epoch, present an older valid head → each reported distinctly |
| An evidence pack altered by one byte, signed by an uncertified key, signed in the wrong domain, or chained to a test root in a production build fails verification | Tamper / re-sign / cross-domain / test-root → `verify` fails with the specific reason |
| Offline verification reports signature, time evidence, coverage and revocation separately, and never "valid forever" | Pack with unanchored suffix and later-revoked key → four results, suffix flagged "time unproven" |
| A feed with a bad signature, a lower sequence, an unsupported schema, an unknown/revoked `kid`, or an item that disables a built-in is rejected, and the last good feed stays | Forge / replay / wrong schema / retired kid / relax-attempt → rejected, detection unchanged |
| A frozen feed is reported stale | Replay the latest valid manifest past `expires_at` → doctor and packs say stale |
| A feed item that flips a must-ALLOW fixture, blows the ReDoS or cumulative perf budget, or times out in evaluation is refused or disabled, and never stalls the write path | Craft such items → refused/disabled, logged, write-path p95 unchanged |
| A lapsed or offline subscription never changes a free-core verdict | Same attack corpus with the licence valid / expired / revoked / unreachable → identical verdicts |

The matrix goes from 13 to 22 public claims.

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
- ✅ **#602** OpenClaw 2026.9.6 `cli-metadata` register — **done**, PR #605 (`ad95afd4`) merged to `origin/main` 27 Sep 2026. Tars's acceptance criteria for it (real 2026.9.6 cli-metadata discovery with no runtime access or chatter, commands discoverable, normal gateway registration/interception unchanged) are recorded here for the review trail.
- The six free-core defects in §1 (remote regex ReDoS, `verify.ts` PII, memory-sync redaction, revocation wiring, CSV ledger columns, stale copy) go in first or in parallel. Two of them are the same class of risk the feed rules in §5.3 exist to prevent.

**1. Per-runtime posture record (free).** Shared typed observation module (§5.6); doctor and a `policy-evidence` exporter read it; process-side self-reports for Claude Code, OpenClaw and Hermes. *Tests:* the §6 posture claim, including Hermes dir-without-plugin and stale-probe cases.

**2. Free chained ledger + verifier.** Forward-only migration with unchained-history labelling, chained prune checkpoints, heartbeat rows, `ledger verify`, the standalone verifier and `evidence preview` (LOCAL / NOT INDEPENDENTLY ATTESTED). Gating failure-mode tests from §5.7. Perf budget re-measured.

**3. Thin paid vertical slice** — the whole trust chain once, end to end, against **sandbox** keys:
   1. Generic Ed25519 verifier with `kid`, domain tags and RFC 8785 canonical encoding; v1 licence behaviour byte-for-byte unchanged; test-root rejection in production builds.
   2. v2 entitlements + free-core isolation test, 30-day grace, plain-English card, revocation wiring (pinned host, paid surfaces only).
   3. **Enrolment and device certificate** (§5.1 tuple).
   4. **External anchor** (§5.7), background, hash-only.
   5. **Evidence pack** (§5.2) embedding posture records, chain, receipts and revocation snapshot.
   6. **Offline verification** with the four-part result.

   Without Cloud approval this slice runs against a local sandbox issuer/anchor and is **a prototype, not the install → pay → verify product**.

**4. Signed feed client** (§5.3 in full). Proof claims for feed rejection, freeze and budgets.

**5. Sealed incident bundles.** Cross-store correlation on `sessionKey`/`actionKey`/`seq`/`audit_id`; respects the `denials.jsonl` redaction.

**6. Fleet policy + drift reporting.** Signed org policy through the policy lock, tighter-wins pinned by a test, reviewed exceptions (§5.4), opt-in drift heartbeat using posture summaries.

**7. Dashboard + copy.** Plan card in Settings (replacing the static Enterprise card); remove the stale Pro/Team strings; README pricing section with the gated-runtime caveat on every tier; CHANGELOG entries in the house register, with residuals disclosed. The lapse-path proof claim lands with step 3.2.

**Later, not critical path:** the Policy-plugin upstream proposal (Microsoft section).

**Server-side dependencies** (per the open question, all subject to Michael's approval of Cloud scope): sandbox billing/enrolment, device-certificate issuer, anchor service (§5.8, §5.9), then feed build/sign/publish with the FP gate in CI. Production signing is a separate later approval.

---

## 9. Risks and residuals

- **Price validation.** The prices and terms are hypotheses, not tested. **Mitigation:** 5–10 buyer conversations with existing free users who have more than 3 machines, before the pricing page ships. A preview is not an evaluation of onboarding or fleet coverage; those need a sandbox enrolment.
- **Cost-to-serve unknown.** Hosting is not cost-to-serve. Support time, the issuer/anchor service, key custody and any on-call rota are not estimated. Enterprise's 4-hour response cannot be offered without a staffed rota.
- **Records are bounded by host integrity and instrumentation.** A root-level attacker, or a modified runtime, can record false data or suppress events. Anchoring fixes *when* a prefix existed; it cannot make it complete or true (§5.2). Stated in every pack.
- **Zero-visibility read as zero-incidents.** The biggest misuse risk of a pack. Mitigated by posture records and gap intervals placed before counts in the rendering.
- **Feed key compromise.** Bounded by additive-only, offline key custody and rotation, but a stolen key could still push over-blocking items. Mitigation: arrival FP check, shadow mode, isolated evaluation, reviewed exceptions, fast retraction.
- **Online signer compromise.** An issuer or anchor-signer key compromise can mint certificates or receipts until revoked via the offline root. Mitigation: narrow scope, separate keys, revocation lists bundled into packs, receipt chaining (`prev_receipt_hash`) so a forged receipt stream is detectable against exported history.
- **Control mappings unreviewed** (§5.2).
- **Grandfathered v1 keys** stay on `TIER_RANK` indefinitely. Harmless (they only unlock what they unlock today), but two code paths to maintain.
- **Machine counting can be gamed** by cloning a device key. Accepted for self-serve: clones surface as forks (§4, §5.7) and are shown to the org admin; nothing auto-revokes.

---

## Provenance of this document

- r1 written by Claude, model **Opus 5.5** (`claude-opus-5-5`), running in Claude Code — `claude --version`: `2.1.283 (Claude Code)`. Exploration was read-only: no install, test, build or `openclaw` command, and `~/.shieldcortex` / `~/.openclaw` were not touched. All file/line claims come from reading `origin/main` a2b448eb in the `sc-wt-subscription` worktree.
- r2 (29 Sep 2026) written by Claude Opus 5.5 as a docs-only revision answering Tars's review (`2026-09-26-subscription-product-review-tars.md`). No code, no network, no `openclaw` command. The source line references added to §1 are Tars's, spot-checked by Jarvis against a2b448eb as recorded in the review file; r2 did not re-read them. #605's merge was confirmed from local git (`ad95afd4` contained in `origin/main`), not from GitHub.

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

**Context.** Microsoft Autopilot (formerly Scout; announced Build 2 Jun 2026; private preview expanding from end Sep 2026) is built on OpenClaw. Microsoft is upstreaming *policy conformance*: the bundled **Policy plugin** (`openclaw policy`, `extensions/policy`, present in OpenClaw 2026.9.6) lets an operator author `policy.jsonc`, observes the workspace as evidence, reports drift through `doctor --lint`, and produces an **attestation tuple** (`policy.hash`, `workspace.hash`, `findingsHash`, `attestationHash`) with structured evidence sections (channels, mcpServers, modelProviders, network, gatewayExposure, agentWorkspace, secrets, authProfiles). Its docs state plainly: *"Policy does not enforce tool calls or rewrite runtime behavior at request time, and it does not attest per-agent credential stores."* (Tars noted he did not independently verify the Autopilot/news assertions; neither did r2.)

**Positioning (agreed with the owner, wording revised r2).** *Policy says how the agent should be set up. ShieldCortex provides verifiable records of observed controls and actions.* Static configuration conformance and runtime enforcement records are complementary halves of the same enterprise question. Autopilot itself runs OpenClaw as an untrusted runtime inside Microsoft's container with a curated signed supply chain, so Autopilot users are unlikely to install third-party plugins; the addressable market is every other OpenClaw deployment. We make **no claim that Microsoft supports or endorses** ShieldCortex.

**Changes to this plan.**
1. **Phase 1 order** follows §8 (posture → chained ledger → thin paid slice → feed → fleet). r1's "evidence packs first, feed second, fleet third" stands in spirit; §8 is authoritative.
2. **Policy-compatible record (free).** `shieldcortex policy-evidence` emits our **provider-neutral** posture record (§5.6) in a JSON section following the Policy plugin's evidence idiom (`source: "sc://..."` provenance per item): per-runtime posture records, Action Guard and policy-lock state, memory firewall mode, detector set / feed sequence, ledger chain head. It is **never** built from doctor's `bound` boolean. Before it ships it is validated against the actual Policy schema in OpenClaw 2026.9.6.
3. **Embedding the Policy tuple.** Evidence packs embed the current `openclaw policy` attestation tuple when present, with its schema/version, scope, acquisition time and provenance. It is labelled a **configuration snapshot, not a runtime witness**: it shows how things were configured at acquisition time, not what happened.
4. **Upstream alignment (small follow-up, not Phase 1 critical path).** After our record is shipped, versioned and validated, and only with Michael's go for public engagement, propose an optional `runtime-enforcement` evidence provider to the Policy plugin authors. Nothing in Phase 1 depends on upstream acceptance.
5. **Windows.** Prove install and posture on the native Windows OpenClaw companion (MXC sandbox backend) and document it.
6. **Ecosystem listing.** OpenClaw ecosystem page and Foundation plugin list.

**Compatibility note found while checking (26 Sep).** On OpenClaw 2026.9.6 the ShieldCortex plugin logged `runtime is intentionally unavailable during "cli-metadata" registration`. Filed as #602; **fixed by PR #605 (`ad95afd4`), merged 27 Sep 2026** (§8 step 0).
