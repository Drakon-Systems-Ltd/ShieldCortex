# Design decision: npx/bunx gating is shape-based, not name-based

**Status:** accepted and shipped (PR #92, v4.47.5). Owner-reviewed tradeoff.
**Origin:** filed as issue #96 (2026-07-14) so the PR #92 summary-table
discrepancy reads as documented intent; moved into the repo here so the record
lives with the code it describes.

## Decision

The `registry-code-exec` signal in the Action Guard
(`src/defence/iron-dome/tool-action-guard.ts`) gates `npx`/`bunx` invocations
by **shape, not package name**. `isGatedNpxBunx` requires one of three
explicit-remote-fetch shapes before it flags an `npx`/`bunx` statement:

- an auto-confirm / explicit-install flag: `-y` / `--yes` / `-p` / `--package`
  / `-c` / `--call` / `--registry` / `--ignore-existing`
- a version/tag pin (`tsc@5.4.0`, `@scope/pkg@next` — any `@` not at the start
  of its token)
- an explicit URL / git ref / relative path / tarball reference

Any of those → `require_approval`. A bare local-tool invocation — `npx tsc`,
`npx jest`, `npx prettier`, or a bare scoped package like `npx @angular/cli` —
has none of the three shapes, so it → `allow`.

`uvx` and `pnpm dlx` / `yarn dlx` are **not** subject to this narrowing — both
are unconditional `DANGEROUS` pattern matches, because they always fetch a
fresh ephemeral environment with no local-bin reuse, on every invocation.

## Accepted consequence

`npx malicious-pkg` — bare, unscoped, no version, no flags — returns `allow`.
The guard cannot distinguish it from `npx tsc` by name alone; npx/bunx resolve
`node_modules/.bin` locally first, so there is no reliable shape signal that
separates "malicious package name" from "legitimate installed dev tool"
without a registry fetch (which the guard does not perform).

Coverage for a malicious *bare-named* package therefore falls through to the
**npm-install gating** and the **pipe/RCE rules** rather than the npx rule
catching it directly.

Note: PR #92's own summary table lists the npx/bunx/uvx/dlx family as a single
`allow → require_approval` row. That row is accurate for `uvx`/`pnpm dlx`/
`yarn dlx` (unconditional) but overstates the `npx`/`bunx` case — the actual
shipped boundary is the conditional one described above.

## Rationale

Gating every bare `npx`/`bunx` invocation was pure approval-noise — `npx tsc`,
`npx jest`, `npx eslint`, `npx prettier` make up the overwhelming majority of
real-world calls and are already-installed local tools, not live registry
fetches. Blanket npx approval is exactly the false-positive friction the
4.47.x line exists to remove; over-gating everyday dev tooling harms the
end-user experience more than the residual bare-package-name gap costs in
security coverage (backstopped by the install-gating and pipe/RCE rules).

The shape boundary was advisor-reviewed during PR #92 (see the
"advisor-reviewed boundary" comment block above `isGatedNpxBunx` in
`tool-action-guard.ts`). The repo owner reviewed and signed off on the
tradeoff.

## Revisit triggers

Reopen this decision if any of these change:

- npx/bunx stop preferring local `node_modules/.bin` resolution (every bare
  invocation becomes a potential fetch);
- the guard gains a registry-metadata or allowlist capability that can
  distinguish package names cheaply;
- field evidence shows bare-name npx abuse in the wild that the install-gating
  and pipe/RCE backstops miss.

## Related

- PR #92 — closed the unconditional `uvx`/`dlx` gap and added the conditional
  `npx`/`bunx` gate.
- Issues #93 / #94 / #95 — open follow-ups from the same guard-hardening pass
  (write-then-exec bypass, health-check false-green, audit-trail gaps); none
  concern this boundary.
