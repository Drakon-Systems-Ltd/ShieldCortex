# Encoding precision (#51): round 4 contract and residuals

## Balanced policy

Encoding is evidence, not an automatic hostile verdict at normal trust. Ordinary
URLs plus mixed-script or zero-width prose remain ALLOW without independent
hostile evidence. Bidi overrides, strict mode, low-trust escalation, decoded
instructions, credential leakage, privilege escalation, and exfiltration retain
their enforcement paths. The strictest raw/derived verdict wins.

Normalized/decoded anomaly alone no longer quarantines. The raw balanced anomaly
gate retains its real title and existing `> 0.7 && lowTrust` condition; adding a
Cyrillic lookalike or a ZWJ emoji to a code-heavy note must not introduce a stricter
anomaly policy through a near-copy of that note.

## Decode accounting and coverage

`decodedSnippets` contains complete readable base64/hex/URL decode results, not
100-character previews. `normalizedContents` remains the separate whole-document
confusable/zero-width channel. Neither channel is cut into context-free windows.

Only readable decode results spend the candidate count and candidate-byte budgets.
Unreadable SHA-like tokens and lockfile integrity hashes do not exhaust those
budgets or prevent a later real payload from being discovered. This is not a
blanket hash-prefix exemption: a hash-shaped string that actually decodes to a
readable payload still receives the normal checks.

Failed attempts remain bounded by the input, decoded-surface and normalized-surface
byte limits and the fixed decoder set. Count, bytes and depth still fail closed
when they prevent coverage of actual decode work: `scanIncomplete` quarantines in
balanced mode and withholds enforced tool output and affected recall rows. The
64th readable candidate can complete coverage; a 65th readable candidate cannot
silently pass. Permissive mode retains its explicit allow-and-report policy.

## Tool-response redaction versus withholding

A raw-visible credential or markdown exfiltration image remains surgically
redactable when an unrelated BOM, joiner or confusable makes the normalized channel
re-find it. New normalized threats are checked on a normalized copy of the
raw-redacted surface, not by comparing masked finding strings or merely checking
whether *some* raw credential/image was detected. Thus an existing raw finding
cannot exempt another hidden finding.

Actual decoded blobs remain separate smuggling surfaces. A decoded blocked
credential or exfiltration image still withholds the response even when a plaintext
copy also exists elsewhere. Decoded credentials are checked after normalization as
well. Advisory mode does not replace the response. This is not a guarantee that a
response containing independent injection evidence will be delivered after redaction.

## Credential scan work

Identifier boundaries are indexed once per complete surface and expanded-span
classifications are cached. Repeated bounded matches inside one long identifier no
longer walk or slice that identifier repeatedly. Prefix coverage, ordered entropy
range processing, stable offset ordering and single-pass redaction also remove
repeated whole-range searches and whole-output copying.

This bounds the repeated-match bookkeeping and output assembly linearly in input
length for a fixed pattern catalog. Complete credential coverage, public SHA/UUID
allowlisting, pattern priority, overlap redaction, and distinct entropy reporting
are retained. It does not certify arbitrary custom regular expressions as
linear-time or introduce a general regex execution budget.

The synthetic work-bound regressions use 2,000 Azure-shaped matches in one token,
plus a later blocked credential, on decoded and normalized surfaces. They count
identifier tests, range callbacks and copied slice characters, aborting on an
excessive work bound rather than using a wall-clock timeout as the assertion.

## Explicitly unfixed residuals

- ZWJ emoji sanitization is NOT fixed. `sanitiseInput` still strips U+200D: an
  allowed `👨‍💻` becomes `👨💻` on that path. ALLOW is not a byte-preservation
  guarantee. Emoji variation selectors U+FE0E/U+FE0F are a separate, preserved case.
- Write-path derived BLOCK/QUARANTINE effects are still not copied into
  `threatIndicators` or `blockedPatterns`. A folded credential can BLOCK with only
  `encoding_obfuscation` / `unicode_homoglyph` in those arrays. Raw sensitivity
  classification can still report PUBLIC for that same content. The persisted
  audit/scan-existing metadata is therefore not a complete derived detection set;
  the verdict/reason carries evidence that the arrays omit. This remains an
  audit, sensitivity and allowance-input fidelity limitation, not a claimed fix.
- Oversized plain content still sets `encoding_scan_incomplete` and is reported
  under `encoding_obfuscation`, even without an actual encoding candidate. The
  fail-closed policy is retained; the indicator taxonomy is not corrected here.
- Candidate discovery is not arbitrary encoding recovery. Greedy unseparated
  blobs and shifted base64 alignment can still fail the readable-decode heuristic.
  Neither this change nor its tests claim to recover every possible segmentation.
- Read/write detector parity is not claimed. Tool responses omit write-path
  privilege, anomaly and trust policy. Recall's derived loop checks instructions
  and blocked credentials, not the write firewall's full privilege/skill/exfil
  surface; its markdown-image check runs on the sanitized raw row.
- Exact licensed DEV replay is opt-in via `SC_ENCODING_FP_DEV_FIXTURE`. With the
  variable unset, those optional rows are absent; a green synthetic run is not an
  exact DEV-corpus validation. Round 4 uses public/synthetic fixtures only, without
  private data or a corpus fallback.

The companion `encoding-round4-contracts-51.test.ts` records the emoji and metadata
residuals and exercises synthetic scan-existing/recall rows with hostile positive
controls. The main `encoding-prose-fp-51.test.ts` covers the policy and work bounds.
