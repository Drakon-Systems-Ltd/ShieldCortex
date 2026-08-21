# ShieldCortex Terminal UX — design lock v2

**Status:** LOCKED v3 (SOL APPROVE_WITH_NITS; Opus MF1-4 folded; implement)  
**Supersedes:** v1 draft in same path  
**Reference pain:** Michael phone SSH screenshots — `update` status soup + `allowlist scan` 40-line source walls

## North star

Crafted TUI feel on mobile SSH (40-col first), pure Node stdlib + ANSI, **no** Ink/Blessed, **no** security-gate regressions.

## Locked principles

1. **Decision first, evidence on demand** — pin card leads with status/basename/progress; source body off by default.
2. **Width-aware** — single width brain; floor 40; content clamp 40–240; frame width `min(content, 72)`.
3. **One glanceable VERDICT** per command close — never mixed into stage spam.
4. **Shared marks** — `[ok] [!] [x] [i]` for pass/warn/fail/info; chips `NEW|CHANGED|CURRENT|MISSING|TOO_LARGE` separate.
5. **Mobile SSH first-class** — design at 40; 80+ is luxury, not an excuse to restore dumps.
6. **No new runtime deps.**
7. **Security copy stays blunt** — never prettify fail-closed / unproven / incomplete into all-clear.
8. **No invented fields** — pin card shows only real `ScanItem` (and derived basename / display path). No `risk`, no generated “hint” prose.

## Module: extract + extend `doctor-report` width brain → `src/cli/term-ui.ts`

Not a parallel system. **Extract** width/colour helpers so one brain exists:

- `getWidth(opts?)` → `clamp(injected || COLUMNS || stdout.columns || 80, 40, 240)`  
  Rendering width never below 40 even if `COLUMNS=1`.
- `supportsColor()` — `NO_COLOR` / `FORCE_COLOR` / TTY / **`TERM=dumb` → false**. **Per call**, not module-load `isTTY`.
- `supportsUnicode()` — **independent** of color. False when `TERM=dumb`, `SHIELDCORTEX_ASCII=1`/`SC_ASCII=1`, or locale not UTF-8.
- `visibleWidth(s)` / strip ANSI for measurement
- `wrapText(s, width, indent?)` — word-boundary; **same behaviour as doctor `wrapLine`**
- `truncatePath(p, width)` — basename preserved; `head…tail`; home→`~` when applicable (**display only**)
- `truncateMiddle(s, width)`
- `hr(width)`, `box(title, lines, width)` — unicode boxes only if `supportsUnicode`; else ASCII `+--+`
- `chip(status)`, `section(title)`, `verdict(kind, summary)`
- injectable `style` / `width` / `unicode` / `color` for tests

**Renderers are pure and return `string[]`.** Callers write line-by-line. No `process.stdout` inside renderers.

`doctor-report.ts` re-exports or imports from `term-ui` (no behaviour change required in v1 beyond shared width if trivial).

### Untrusted field display

- `sanitiseDisplayField(s)` before measure/paint: strip CSI/OSC/C0, `\n`/`\r` → `⏎`, strip bidi/zero-width.  
- **Not** `sanitiseForReport` on pin paths (no env-value redaction of path segments).
- Frames enclose **only** ShieldCortex-generated chrome. Paths, sources, job names, preview: frameless + left gutter.

### Path + SHA visibility (Opus security-visibility, mobile-readable)

- Decision line: **basename** bold + status chip + `i/n`.
- Next lines: **full canonical path**, word-wrapped (not mid-token garbage). Prefer wrap over destructive ellipsis when width is tight; `truncatePath` allowed on secondary summary lists only when full path already shown above or in `--json`.
- SHA: show ≥16 hex always (full 16 on card); never wrap mid-hex without end ellipsis rule on a dedicated sha line.

## Surface A — `allowlist scan`

### Summary header

```
allowlist scan
3 found · 0 current · 3 review
sources: hermes ok · oc-db ok
```

- Compact two-line rows max at 40 cols for the list (chip + basename; dim path/notes).
- Broken/incomplete discovery: **red, exit 1**, never pretty-empty.
- Source short labels (display only): `hermes-cron→hermes`, `openclaw-cron→oc`, `openclaw-cron-db→oc-db`, `glob→glob`. Full ids remain in `--json`.

### Review card (default)

```
── 1/3 · NEW · backup.sh
path  /Users/…/friday/scripts/backup.sh
      (wrapped full path)
sha   a3f1c9e2b4d6f801…
src   oc-db
[! ]  network calls likely (if networkHint)
[! ]  denied note (if deniedNote)

[y] pin  [n] skip  [v]iew  [q] quit
```

**No source body by default.**

### Preview = paging, not a wall

- `[v]` / `view`: show next page of **12** sanitised lines (existing `sanitisePreviewLine` + byte cap 2048).
- Pages through up to existing `PREVIEW_MAX_LINES` (40). Card states `lines 1–12 of 40`.
- Preview exhaustion when pages cover `PREVIEW_MAX_LINES` (or `MAX_VIEW_PAGES=8` cap); then `no more source`. Further `v` counts as **skip** (default-deny), never hang.
- `v` never pins, never advances item index, never increments counters.
- Second path: collapse not required if paging forward-only; document forward-only paging.

### Prompt parser (default-deny untouched)

- Pin **only** if trimmed lower-case is `y` or `yes`.
- `n` / other / empty / EOF → **skip** (never pin).
- `q` / `quit` → quit.
- `v` / `view` → page preview, re-prompt **same** item.
- Optional note prompt after `y` unchanged.
- Gate `isInteractive` / TTY checks stay **before** any card render that could confuse; non-interactive: zero pins, exit 3 when new/changed, refusal copy unchanged.

### `--yes` batch

- **No** N×40 source walls.
- Compact identity list via dedicated `renderBatchIdentity` (not `renderReviewItem`): status, path, short sha, flags.
- Still requires typed `approve` on TTY; non-TTY `--yes` → exit 1.
- First sqlite backfill `--yes` refuse unchanged.
- Full bodies: per-item review without `--yes`.

### Unchanged contracts

- `--json` shape keys/counts; no TUI chrome; no pin
- exit `0 | 3 | 1` matrix
- `pinReviewedScript` + expectedSha256 TOCTOU
- discovery honesty / schema mismatch

## Surface B — `shieldcortex update` closing panel

### Placement

- Build a **step ledger** during `runUpdate`.
- Emit **one** panel as the **last write** of `runUpdate` (after protection self-check, engine remediation, project-key heal, allowlist hook/pointer, **and** 411/dashboard notices — fold those into panel `next` or print them before the panel).
- Mid-flow Action Guard lines still print when they happen.
- `footer()` may stay earlier; the **panel is the final closer** so phone scroll ends on the verdict.
- `update.ts` `paint()` must use `supportsColor()` per call (fix NO_COLOR ignore).

### Panel content (facts only)

```
+-- update 4.54.4 -> 4.54.9 --+
| VERDICT  NEEDS ATTENTION    |
| package  ok                 |
| plugin   ok                 |
| guard    blocked            |
| selfchk  unproven           |
| canary   ok                 |
+-----------------------------+
  detail  guard: Action Guard held a cleanup once
  next    shieldcortex doctor --ai
```

**Framed cells = closed vocabulary only:** status tokens (`ok|warn|blocked|unproven|failed|skipped`), short counts, version strings matching `^[\w.+-]{1,32}$`.
Any free-form child-process/registry reason prints **frameless** under the box (left gutter) after `sanitiseDisplayField`.
**Runnable commands are never ellipsized** — wrap or print frameless below; never `truncateMiddle` a copy-pastable command.

### VERDICT enum (display) + exit coupling

| Kind | When |
|---|---|
| `OK` | no fail, no warn/unproven/blocked residual; **and** exitCode === 0 |
| `NEEDS ATTENTION` | warn / blocked / unproven / remediation-needed; exit may still be 0 |
| `INCOMPLETE` | discovery/source cannot-look class (exit 1) |
| `FAILED` | hard fail / protection verify fail (exit 1) |

**One ledger, one truth:** panel VERDICT and `process.exitCode` derive from the same step ledger.
`exitCode !== 0` implies panel is **never** `OK`.
`stepVerifyProtection` returns a structured outcome; **caller** sets `process.exitCode`.

Unproven self-check **cannot** display as `OK`.

### Stage lines at narrow width (in scope v1)

When `width < 60`: no spinner, no `padEnd` to 24, one compact line per step (no `\r` redraw garbage on phone).  
When `width >= 60`: keep current spinner behaviour if desired.

## Surface C — doctor

Optional adopt shared `getWidth`/`wrapText`. No check-logic change required in v1.

## Non-goals v1

- Full-screen alt buffer, mouse, Ink/Blessed
- Changing pin/hash/TTY/`--yes`/JSON semantics
- Invented risk scores on cards

## Tests (must ship)

**Gates:** non-interactive no write exit 3; `--yes` non-TTY exit 1; `--yes` typed approve; first-backfill refuse; TOCTOU pin refuse; `--json` stable; incomplete discovery exit 1.

**Prompt:** `v,v,y` → one pin; `v`×20 → MAX_VIEW_PAGES then no pin; only `y`/`yes` pins; empty/EOF skip.

**TUI:** width 40/80 snapshots ANSI-stripped; every line ≤ render width; default card no source wall; preview sanitises CSI spoof; path with ESC/newline cannot forge frame; `supportsColor` ⊥ `supportsUnicode`; no new deps.

**Update:** verdict matrix unit from fake ledger; panel after allowlist hook; no credentials in panel if step text poisoned; narrow width no spinner.

## Acceptance

1. Phone 40-col: pin decision without scrolling a code wall  
2. Update finish: verdict panel understandable in <5s  
3. Desktop 80+ intentional, still no default 40-line dump  
4. Design APPROVE from ≥2/3 of Grok, SOL, Opus on **this v2**  
5. Dual code review on implementation PR  

## Implementation order

1. `term-ui.ts` + extract/wire doctor helpers + tests  
2. `allowlist-scan` summary + cards + prompt `v` paging  
3. `update` narrow steps + end panel from ledger  
4. CHANGELOG + PR
