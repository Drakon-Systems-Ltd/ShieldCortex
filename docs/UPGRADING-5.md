# Upgrading to ShieldCortex 5.0

**Read this before you run `npm install -g shieldcortex`.** 5.0 is a breaking release. It will not install on Node 20.

## Should I update?

Run `node -v`. Then:

| Your Node | What happens |
|---|---|
| **22.14 or newer 22.x** | Fine. Install 5.0. |
| **24.x** | Fine. Install 5.0. This is the line 5.0 was built to un-break. |
| **20.x** | **Install refuses.** Upgrade Node first, then install 5.0. Stay on 4.54.15 until you can. |
| **23.x** | **Not supported** (never was a release line — it lacks Node-API 10). Use 22 LTS or 24. |
| **18 or older** | Already unsupported. Upgrade Node, then install 5.0. |

If you are not sure: stay on 4.54.15 until you have read the rest of this page.

```bash
npm view shieldcortex version          # what npm will give you
npm ls -g shieldcortex                 # what you have now
```

## What breaks

That is the whole list. If you are not on this list, 5.0 is a normal update.

### 1. Node 20 is gone

**Who it affects:** anyone still on Node 20.

**Why:** the database engine (`better-sqlite3`) moved to version 13, which needs Node-API 10. Node 20 does not have it. Node 22.14+ and Node 24 do. This is also what stops `shieldcortex doctor` from crashing on Node 24.

**What to do:** upgrade Node, then install.

```bash
node -v                                # confirm 22.14+ or 24
npm install -g shieldcortex@5
shieldcortex doctor
```

### 2. Node 23 is not supported

**Who it affects:** anyone on the odd-numbered Node 23 line.

**Why:** Node 23 never shipped Node-API 10. We never claimed to support it; 5.0 says so in `engines` so npm can refuse it.

**What to do:** move to Node 22 LTS or Node 24.

### 3. Three Express 5 behaviour changes — dashboard API clients only

**Who it affects:** anyone calling the local dashboard HTTP API **directly** (scripts, integrations, curl). The dashboard UI itself is unaffected.

**What changed** (each is pinned by a test):

- Nested bracket query strings (`?a[b]=1`) no longer become nested objects. Nothing in ShieldCortex or the dashboard sends those. Reversible with one line if you have an external client that does.
- A mutating request with no JSON body now gets a clean `400` instead of a `500`.
- An unhandled API error is JSON, never an HTML page with a stack trace.

Full wording: [CHANGELOG.md](../CHANGELOG.md) → *Unreleased* → *Changed* → Express 4 → 5.

## What is not breaking, but you should know

- **Action Guard stays off by default.** 4.54.15 already did this. 5.0 does not turn it back on. Existing hosts with `actionGuard.enabled: true` stay on. Everyone else: tool calls are ungated until you enable it deliberately.
- **Automatic memory-injection scanning stays off.** Same as 4.54.15.
- **One production advisory is waived, not fixed.** `sharp` (via the optional Transformers package) still has two libvips CVEs. We never send it image data; a patched sharp exists but Transformers will not take it yet. Details: [docs/security/audit-waivers.md](security/audit-waivers.md). `npm run audit:release` fails if anything *else* appears.

## Security fixes you get by updating

- **#474 — dashboard API auth bypass.** `/API/…` (capitals) skipped the password check; `HEAD /api/…` ran the GET handler without a token and leaked whether a secret existed in memory via `Content-Length`. Both are 401 now.
- **Stack traces no longer leave the process.** Unhandled API errors and the dashboard error page no longer print filesystem paths to the caller.

Do not stay on 4.54.15 if the dashboard is reachable from anything other than you.

## Step-by-step upgrade

**Back up first.** Schema migrations are forward-only. We have not verified that a 5.0 database opens cleanly in 4.x.

```bash
cp -a ~/.shieldcortex ~/.shieldcortex.bak-$(date +%Y%m%d)
```

**Global install:**

```bash
node -v                                 # must be 22.14+ or 24
npm install -g shieldcortex@5
shieldcortex doctor
```

A good doctor run prints `0 fail` and a Database-engine line naming `better-sqlite3 13` on your Node. Warnings are fine; a fail is not.

**Project dependency:**

```bash
npm install shieldcortex@5
npx shieldcortex doctor
```

**Stay on 4.x instead:**

```bash
npm install -g shieldcortex@4           # last 4.x is 4.54.15
```

Pin it (`shieldcortex@4.54.15`) if you do not want 5.0 the next time you type `@latest`.

## Rollback

```bash
npm install -g shieldcortex@4.54.15
```

Then restore the backup if doctor complains about the database:

```bash
mv ~/.shieldcortex ~/.shieldcortex-5-failed
mv ~/.shieldcortex.bak-YYYYMMDD ~/.shieldcortex
```

If you never ran 5.0 against the live DB, the backup is unused and you can delete it.

## npm will also tell you

`package.json` `engines` is `^22.14.0 || >=24.0.0`. A Node 20 `npm install` prints `EBADENGINE` and, on modern npm, refuses. `--ignore-engines` gets you as far as the native binding, which then fails with the same Node-floor message.

The README, this page, the install banner, and [https://www.npmjs.com/package/shieldcortex](https://www.npmjs.com/package/shieldcortex) all say 5.0 before you update. If one of them does not, file an issue.
