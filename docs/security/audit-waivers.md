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

### SC-WAIVER-466-sharp — `sharp` libvips/libheif/librsvg decoder advisories

| | |
|---|---|
| **Advisory IDs** | `1124066` ([GHSA-f88m-g3jw-g9cj](https://github.com/advisories/GHSA-f88m-g3jw-g9cj)), `1193725` ([GHSA-rgj7-g3m4-5g8c](https://github.com/advisories/GHSA-rgj7-g3m4-5g8c)), `1241331` ([GHSA-wq5f-xc86-pv6w](https://github.com/advisories/GHSA-wq5f-xc86-pv6w), added 2026-10-06, #655) |
| **Underlying CVEs** | libvips: CVE-2026-33327, CVE-2026-33328, CVE-2026-35590, CVE-2026-35591. libheif: GHSA-g89c-p67h-r497, GHSA-2jg2-4ch7-h545. librsvg: CVE-2026-96889 |
| **Severity** | high ×3 |
| **Chain** | `shieldcortex` → `@huggingface/transformers@3.8.1` (**optionalDependencies**) → `sharp@0.34.5` |
| **Reviewed** | 2026-09-12 (`1124066`, `1193725`); 2026-10-06 (`1241331` assessed on its own, reachability greps re-run for all three, #655) |
| **Expires** | 2026-12-12 (the gate fails after this date until someone re-reviews; **not** extended when `1241331` was added) |
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

#### `1241331` (GHSA-wq5f-xc86-pv6w), assessed on its own — 2026-10-06, #655

Published 2026-10-06 13:43Z (publish time, CVE and lowest-fixed version taken from the `npm audit` record on 6 Oct 2026; not independently verified against the GitHub advisory): a memory-safety bug in **librsvg**, the SVG
decoder that sharp's prebuilt libvips bundles. Vulnerable range `sharp <0.35.5`;
fixed in `sharp@0.35.5` (librsvg 2.63.2). The advisory says it "can lead to
possible remote code execution (RCE) on glibc-based Linux" when the `node`
binary is not a position-independent executable, and notes the official
Node.js binaries are not PIE. Its suggested workaround,
`sharp.block({ operation: ["VipsForeignLoadSvg"] })`, needs a caller that
imports sharp; ShieldCortex does not, and adding that import would load sharp
into the main process for no gain.

It is the same class as the two IDs above: a decoder bug in a native image
library, reached only by handing **encoded image bytes** (here, SVG) to sharp.
Measured on 2026-10-06, on `main` at `ee87c5c5` with `@huggingface/transformers@3.8.1`:

* **No patched sharp is reachable without a Transformers major.**
  `npm view @huggingface/transformers@3 dependencies.sharp` gives `^0.34.1`
  for every 3.x release up to 3.8.1, which can never resolve `0.35.5`.
  `@huggingface/transformers@4.3.1` declares `^0.35.4` (it would resolve
  `0.35.5`), but that is the 3.x → 4.x embedding-stack change already deferred
  above. `npm audit` reports the fix only as that semver-major bump.
* **The decoder entry in Transformers is not on our path.** In
  `dist/transformers.node.mjs` the only call that hands encoded bytes to sharp
  is `RawImage.fromBlob` (`sharp(await blob.arrayBuffer())`), reached from
  `RawImage.read` / `fromURL`. Its callers are `prepareImages()` in the eleven
  image pipelines (`image-feature-extraction`, `image-to-text`,
  `image-classification`, `image-segmentation`, `background-removal`,
  `zero-shot-image-classification`, `object-detection`,
  `zero-shot-object-detection`, `document-question-answering`,
  `image-to-image`, `depth-estimation`) and `VLChatProcessor`. The two classes
  ShieldCortex instantiates, `FeatureExtractionPipeline` and
  `TextGenerationPipeline`, contain no reference to `RawImage`, a processor or
  an image. The other sharp calls in the bundle build images from raw pixel
  buffers, which involves no decoder.
* **ShieldCortex's own code is unchanged on this point.** The greps above were
  re-run over `src/`, `scripts/`, `plugins/`, `hooks/` and `templates/`: still
  no `sharp` import, no image processor or image pipeline task, no
  multipart/upload library. Added for this advisory: no `image/svg+xml` or
  other image MIME type, no `.svg` read, no `VipsForeign*` / `librsvg`
  reference. The call sites are still `src/embeddings/worker.ts`
  (`feature-extraction`, `Xenova/all-MiniLM-L6-v2`) and
  `src/defence/judge/worker.ts` (`text-generation`).
* **The dashboard does not ship sharp.** `dashboard/` has its own lockfile, in
  which `next@16.3.5` pulls an optional `sharp@0.35.4`, also in this
  advisory's range. `dashboard/next.config.ts` excludes
  `**/node_modules/sharp/**` and `**/node_modules/@img/**` from the standalone
  output that goes into the npm tarball, so the published dashboard has no
  sharp runtime (a manifest-only `sharp/package.json` can remain in the
  standalone output; it carries no code or binary). That copy runs only at build time, on the build machine, over
  repository assets. It is outside the `npm audit --omit=dev` gate and this
  waiver.

The residual-risk points below apply unchanged. Point 1 matters more for this
advisory: on a non-PIE `node` (the official Node.js binaries), the advisory
puts the worst case at code execution rather than a crash, but only if
something in the worker process feeds sharp an SVG, which nothing in
ShieldCortex does.

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

> **2026-09-20 (#513): the first trigger below has fired.**
> `@huggingface/transformers@4.3.0` now declares `sharp: ^0.35.4`, so a patched
> tree is reachable — but only through the 3.x → 4.x major, which changes the
> embedding stack (tokenizers, `onnxruntime-node`). That bump needs its own
> embedding-parity run and was deliberately left out of the #513 dependency
> pass; the waiver stays in force until it lands or the expiry date, whichever
> is first. The "no patch is reachable" measurements above are dated 2026-09-12
> and no longer describe the registry.

Delete this entry and the JSON record below as soon as **any one** of these is
true:

* ShieldCortex moves to an `@huggingface/transformers` release whose `sharp`
  range resolves `>= 0.35.5` (4.3.1 does, through `^0.35.4`; 3.x never does;
  check: `npm view @huggingface/transformers dependencies.sharp`) — then
  re-run `npm run audit:release` and delete this;
* ShieldCortex drops the `@huggingface/transformers` optional dependency;
* a new advisory lands on `sharp` outside these three IDs — the gate will fail
  on it, and it must be assessed on its own merits before it can be added here
  (as `1241331` was on 2026-10-06, in its own subsection above). If it is a
  different class, or reachable, it does not belong in this waiver.

Do **not** extend the expiry without re-doing the reachability greps above. If
the codebase has grown an image path since, the reasoning is void.

### SC-WAIVER-639-sprintf-js — `sprintf-js` unbounded precision denial of service

| | |
|---|---|
| **Advisory IDs** | `1241202` ([GHSA-hp3w-g68c-fv3c](https://github.com/advisories/GHSA-hp3w-g68c-fv3c)) |
| **Severity** | moderate |
| **Chain** | `shieldcortex` → `@huggingface/transformers@3.8.1` (**optionalDependencies**) → `onnxruntime-node@1.21.0` → `global-agent@3.0.0` → `roarr@2.15.4` → `sprintf-js@1.1.3` |
| **Reviewed** | 2026-10-06 |
| **Expires** | 2027-01-06 (the gate fails after this date until someone re-reviews) |
| **Owner** | Michael Kyriacou (`author` in `package.json`) |

#### Why there is no version to move to

Measured on 2026-10-06 against the npm registry:

```sh
npm view sprintf-js dist-tags.latest          # 1.1.3
npm view global-agent@3 version               # 3.0.0 (only 3.x release)
npm view roarr@^2.15.3 version                # 2.15.4 (latest accepted)
npm view @huggingface/transformers@3.8.1 dependencies.onnxruntime-node   # 1.21.0
npm audit --omit=dev --json                   # sprintf-js range "<=1.1.3", source 1241202
```

`sprintf-js@1.1.3` is the latest published version, and the cached npm audit
report marks `<=1.1.3` vulnerable. `roarr@2.15.4` is the latest 2.x release
accepted by `global-agent@3.0.0`'s `^2.15.3`; it requires `sprintf-js: ^1.1.2`.
`global-agent@3.0.0` is the only 3.x release accepted by
`onnxruntime-node@1.21.0`'s `^3.0.0`. Transformers pins
`onnxruntime-node: 1.21.0` exactly (`rg -n 'onnxruntime-node|global-agent|roarr|sprintf-js' package-lock.json`).
Newer major versions of these packages cannot be selected by a lockfile
refresh within this tree's ranges.

#### Why it is not reachable in ShieldCortex

The vulnerable call needs an attacker-controlled **format string** containing
a huge precision value. `rg -n 'global-agent|roarr|sprintf'
node_modules/@huggingface/transformers/node_modules/onnxruntime-node` found
`global-agent` only in `script/install.js`, where it is required and bootstrapped
to support proxy settings during binary installation. The same grep found no
runtime import. `rg -n 'sprintf|global-agent|roarr' src scripts plugins hooks
templates` found no ShieldCortex import or call to any of them. Inspection of
`node_modules/global-agent/dist/` logging calls and
`node_modules/roarr/dist/factories/createLogger.js` showed that `roarr` passes
log message strings to `sprintf-js`, while `global-agent` supplies fixed format
strings and puts request URLs, proxy settings, errors and headers in separate
context values. Thus the measured ShieldCortex path does not pass an
attacker-controlled format string to `sprintf-js`.

#### Residual risk, stated honestly

The vulnerable package remains installed when optional Transformers is
installed. The ONNX install script loads `global-agent`, which loads `roarr`
and `sprintf-js`; installation can process network and proxy data, and logging
may process that data as values. A change to `global-agent` logging or another
caller that supplies a variable format string could expose the vulnerable
formatter. The grep and call-site inspection above establish the current path,
not a guarantee about future dependency code or every execution environment.

#### What retires this waiver

Delete this section and its JSON record when a patched `sprintf-js` release is
accepted by the chain, or an updated compatible chain removes `sprintf-js`, or
ShieldCortex drops the optional Transformers dependency. Re-run the audit and
the reachability checks before changing the waiver or its expiry. A new
advisory ID is assessed separately by the release gate.

## Waiver records

<!-- Machine-readable. Parsed by scripts/lab/audit-report.mjs. Keep in sync
     with the prose above; the script checks IDs and dates, not English. -->

```json audit-waivers
{
  "waivers": [
    {
      "id": "SC-WAIVER-466-sharp",
      "package": "sharp",
      "advisories": [1124066, 1193725, 1241331],
      "ghsa": ["GHSA-f88m-g3jw-g9cj", "GHSA-rgj7-g3m4-5g8c", "GHSA-wq5f-xc86-pv6w"],
      "severity": "high",
      "chain": "shieldcortex -> @huggingface/transformers (optional) -> sharp",
      "reason": "libvips/libheif/librsvg image-decoder bugs; ShieldCortex runs text-only Transformers pipelines and has no path that hands image bytes (SVG included) to sharp.",
      "reviewed": "2026-10-06",
      "expires": "2026-12-12",
      "owner": "Michael Kyriacou (package.json author)",
      "retire_when": "ShieldCortex moves to an @huggingface/transformers release whose sharp range resolves >= 0.35.5 (4.3.1+), or the optional dependency is dropped",
      "issue": 466
    },
    {
      "id": "SC-WAIVER-639-sprintf-js",
      "package": "sprintf-js",
      "advisories": [1241202],
      "ghsa": ["GHSA-hp3w-g68c-fv3c"],
      "severity": "moderate",
      "chain": "shieldcortex -> @huggingface/transformers (optional) -> onnxruntime-node -> global-agent -> roarr -> sprintf-js",
      "reason": "Unbounded precision format strings can cause denial of service; the measured ONNX install-script path uses global-agent logging with fixed format strings and ShieldCortex does not call sprintf-js.",
      "reviewed": "2026-10-06",
      "expires": "2027-01-06",
      "owner": "Michael Kyriacou (package.json author)",
      "retire_when": "a patched sprintf-js is reachable, the chain removes it, or the optional Transformers dependency is dropped",
      "issue": 639
    }
  ]
}
```
