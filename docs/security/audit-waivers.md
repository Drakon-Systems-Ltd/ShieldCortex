# Production audit waivers

`npm audit --omit=dev` is the release gate for ShieldCortex (#466). Every
advisory it reports must either be **fixed** or **appear below with a reason**.
There is no third option, and "we'll look at it later" is not a reason.

`npm run audit:release` reads this file, applies the waivers by exact advisory
ID, and exits non-zero if anything else is outstanding — so a waiver has to be
written down here before the gate will go green, and the gate re-checks the
expiry date on every run.

## How a waiver is applied

The machine-readable block at the bottom of this file is the only thing the
script reads. Each waiver names **exact npm advisory IDs**; nothing is waived
by package name, severity, or wildcard.

`npm audit --json` also emits a node for each *dependent* of a vulnerable
package (for example `@huggingface/transformers`, whose `via` is just
`["sharp"]` and which carries no advisory ID of its own). Those nodes are
waived transitively: a node with no advisory IDs of its own is waived only if
every package it derives from is itself fully waived. A brand-new advisory
filed directly against `@huggingface/transformers` would therefore still fail
the gate.

## Active waivers

### SC-WAIVER-466-sharp — `sharp` libvips/libheif decoder advisories

| | |
|---|---|
| **Advisory IDs** | `1124066` ([GHSA-f88m-g3jw-g9cj](https://github.com/advisories/GHSA-f88m-g3jw-g9cj)), `1193725` ([GHSA-rgj7-g3m4-5g8c](https://github.com/advisories/GHSA-rgj7-g3m4-5g8c)) |
| **Underlying CVEs** | libvips: CVE-2026-33327, CVE-2026-33328, CVE-2026-35590, CVE-2026-35591. libheif: GHSA-g89c-p67h-r497, GHSA-2jg2-4ch7-h545 |
| **Severity** | high ×2 |
| **Chain** | `shieldcortex` → `@huggingface/transformers@3.8.1` (**optionalDependencies**) → `sharp@0.34.5` |
| **Reviewed** | 2026-09-12 |
| **Expires** | 2026-12-12 (the gate fails after this date until someone re-reviews) |
| **Owner** | Michael Kyriacou (`author` in `package.json`) |

#### Why there is no version to move to

This is not "no patch exists" — it is "no patch is reachable". Measured on
2026-09-12:

* `sharp@0.35.4` **is published and is patched** for both advisories
  (`1124066` is `<0.35.0`, `1193725` is `<0.35.4`).
* `@huggingface/transformers@3.8.1` depends on `sharp: ^0.34.1`. The latest
  release, `@huggingface/transformers@4.2.0`, depends on `sharp: ^0.34.5`.
  A caret range on `0.34.x` can never resolve `0.35.x`, so **no released
  version of Transformers accepts the patched sharp.** Bumping Transformers
  to 4.x would change the embedding product (new `@huggingface/tokenizers`
  dependency, different `onnxruntime-node`) and would still not clear the
  advisory. That is why `npm audit` reports `"fixAvailable": false`.
* Adding a direct `sharp: ^0.35.4` dependency does **not** work and must not
  be attempted: it fails Transformers' `^0.34.5` range, so npm installs
  `0.35.4` at the root *and* keeps a nested vulnerable `0.34.x` under
  `@huggingface/transformers`. The vulnerable copy would still be in the tree,
  merely shadowed. The same trap applies to `overrides` — and a consumer does
  not honour a dependency's root `overrides` anyway (rejected in #466).

#### Why it is not reachable in ShieldCortex

The advisories are memory-safety bugs in the libvips and libheif **image
decoders**. Reaching them requires handing image bytes to sharp.

ShieldCortex uses `@huggingface/transformers` for exactly two things, both
text-only:

| Call site | Pipeline | Model |
|---|---|---|
| `src/embeddings/worker.ts:59,81` | `feature-extraction` | `Xenova/all-MiniLM-L6-v2` |
| `src/defence/judge/worker.ts:27` | `text-generation` | caller-supplied text model id |

Measured greps over `src/`, `scripts/`, `plugins/`, `hooks/`, `templates/`
(full transcript in the #466 report):

* no `import`/`require` of `sharp` anywhere — the only textual hits are the
  English word "sharp" in comments and an entry in the X-Ray popular-package
  list;
* no `RawImage`, `AutoProcessor`, `AutoImageProcessor`, nor any image pipeline
  task string (`image-to-text`, `image-classification`,
  `image-feature-extraction`, `zero-shot-image-*`, `object-detection`,
  `image-segmentation`, `depth-estimation`, `text-to-image`, `image-to-image`);
* no multipart/upload handling at all (`multer`, `busboy`, `formidable`,
  `multipart`), and no image MIME types or image file reads. There is no API
  endpoint that accepts image bytes, so there is no user-controlled path to a
  decoder.

#### Residual risk, stated honestly

**`sharp` is loaded into the process, it is just never called.**
`@huggingface/transformers`' Node bundle has a *static* top-level
`import ... from "sharp"` (line 6 of
`dist/transformers.node.mjs`), so any ShieldCortex worker that imports
Transformers also links libvips and libheif into that worker process. A probe
that substituted a recording stub for `sharp` and imported Transformers the
way the workers do confirmed the split: the sharp module body was evaluated,
and there were **zero** calls and zero property reads against it.

What that leaves:

1. **Native code is mapped into the embedding/judge worker.** The vulnerable
   decoders are present but never fed input by us. Exploiting them requires a
   caller that can already execute code in that process — at which point sharp
   is not the interesting primitive.
2. **Any local process can `require('sharp')` from `node_modules`.** This is
   true of every installed package and is not specific to this advisory.
3. **Blast radius is bounded by the dependency being optional.** Installs with
   `--omit=optional` (or where the ~349 MB ML stack fails to build) have no
   `@huggingface/transformers` and therefore no `sharp` at all; the advisory
   is simply absent from those trees. Verified by running the packed-tarball
   audit both ways in #466.
4. **Transformers is deliberately kept.** Removing it would remove local text
   embeddings — the memory/recall product — which is a far larger change than
   the risk being carried here.

#### What retires this waiver

Delete this entry and the JSON record below as soon as **any one** of these is
true:

* a released `@huggingface/transformers` widens its `sharp` range to admit
  `>= 0.35.4` (check: `npm view @huggingface/transformers dependencies.sharp`)
  — then bump Transformers, re-run `npm run audit:release`, and delete this;
* ShieldCortex drops the `@huggingface/transformers` optional dependency;
* a new advisory lands on `sharp` outside these two IDs — the gate will fail on
  it, and it must be assessed on its own merits rather than folded in here.

Do **not** extend the expiry without re-doing the reachability greps above. If
the codebase has grown an image path since, the reasoning is void.

## Waiver records

<!-- Machine-readable. Parsed by scripts/lab/audit-report.mjs. Keep in sync
     with the prose above; the script checks IDs and dates, not English. -->

```json audit-waivers
{
  "waivers": [
    {
      "id": "SC-WAIVER-466-sharp",
      "package": "sharp",
      "advisories": [1124066, 1193725],
      "ghsa": ["GHSA-f88m-g3jw-g9cj", "GHSA-rgj7-g3m4-5g8c"],
      "severity": "high",
      "chain": "shieldcortex -> @huggingface/transformers (optional) -> sharp",
      "reason": "libvips/libheif image-decoder bugs; ShieldCortex runs text-only Transformers pipelines and has no path that hands image bytes to sharp.",
      "reviewed": "2026-09-12",
      "expires": "2026-12-12",
      "owner": "Michael Kyriacou (package.json author)",
      "retire_when": "a released @huggingface/transformers accepts sharp >= 0.35.4, or the optional dependency is dropped",
      "issue": 466
    }
  ]
}
```
