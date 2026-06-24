# ShieldCortex CIC — Terminal Console Design Spec

> **For Claude:** This is the approved design (brainstormed + signed off "Green Light" 2026-06-23).
> Implementation plan lives alongside at `docs/design/2026-06-23-shieldcortex-cic-PLAN.md`.

**Goal:** Replace the dashboards' default look with a "24th-century Combat Information Center" — a
living **memory-cortex** you operate from a **real command line**, that visualises ShieldCortex as the
defence membrane between your **entire agentic ecosystem** (Claude Code, OpenClaw, MCP clients,
sub-agents) and your second brain. Applies to BOTH the local npm dashboard and the cloud SaaS dashboard.

**Identity:** *The second brain you command, shielding your whole agent ecosystem.* The visuals are the
brain thinking, made observable — not decoration.

## Approved decisions (from brainstorming)

1. **Positioning:** Terminal (CIC) is the **new default** on both dashboards. Glass (local) / Shield
   (cloud) are **kept** as selectable alternates — nothing deleted.
2. **Intensity:** **Full immersive** — scanlines, phosphor bloom, boot sequence, character stream-in,
   ambient telemetry, holographic panel depth — gated by a **`calm` toggle + `prefers-reduced-motion`**.
3. **Phosphor:** **Brand multi-spectral** on a near-black void (coral / cyan / amber / violet), keyed to
   meaning — NOT a monochrome CRT.
4. **Command rail is REAL** — a functional command line + `⌘K` palette wired to the API + MCP tools.
   Decorative prompts are explicitly rejected.
5. **Bloom = cortical activation** — the brain is divided into regions that mean something; glow tracks
   real activity (a recall lights the retrieved neurons + their links; a block flares the shield).
6. **Ecosystem defence on screen** — the console tells ECOSYSTEM → SHIELD → CORTEX top to bottom.

## Palette (CIC token set)

```
VOID      --cic-void      #04060c     SURFACE  --cic-surface  #070b14     ELEVATED --cic-surface-2 #0b1120
BORDER    --cic-border    #16203a     GRID     --cic-grid     rgba(0,229,204,.045)

PHOSPHOR (semantic / regional)
  cyan   --cic-cyan   #00e5cc  → MEMORY · live · safe · system · link      glow rgba(0,229,204,.35)
  coral  --cic-coral  #ff4d4d  → DEFENCE · threat · block · danger          glow rgba(255,77,77,.35)
  amber  --cic-amber  #f5a623  → QUARANTINE · warn · pending
  violet --cic-violet #a78bfa  → INTEGRITY · consolidation · links · recall

TEXT  --cic-text #d7e3f4 · -dim #8aa0bf · -muted #51637e · -faint #33415a
```

The colour IS information (matches BLOCK/ALLOW/QUAR semantics already in the product). This semantic,
regional phosphor is the 24th-century leap over a monochrome terminal.

## Cognitive regions (the "second brain" map)

| Region | Colour | Domain |
|---|---|---|
| MEMORY | cyan | vault, recall, the living graph |
| DEFENCE | coral | the shield, threat interception, the 6 layers |
| QUARANTINE | amber | isolation hold, pending review |
| INTEGRITY | violet | consolidation, links, contradictions |

Nav rail items, panels, and graph clusters are coloured by region. **Bloom is activity**: scan → DEFENCE
pulses; recall → MEMORY region + the retrieved neurons + their links glow and trace association; block →
coral flare at the shield. Leverages the EXISTING `ConstellationGraph` `PulseDriver` + energy/recall-pulse
layer (`useGraphPulse`) — made the centrepiece and keyed to the regional colour-map.

## Typography & grid
Geist Mono everywhere (already loaded; `--font-geist-mono`), ligatures `ss01/cv01`. Dense 12–13px base,
larger KPI numerals. Manifest-style leaders (`KEY ····· value`). Monospace column grid.

## Chrome — tactical panels, holographic depth
Real DOM (CSS borders + pseudo-element corner brackets + a header row) evoking box-drawing so it reflows.
**No backdrop-blur** (that is the Glass look). Instead: translucent surface over the void grid, a 1px cyan
top-highlight, a soft phosphor drop-projection → panels read as projected holograms. Header row:
`SYSTEM.NAME ……… [ ● STATUS ]`; corner brackets glow on active/hover.

## The shell
- **Top ops bar** — `ECOSYSTEM ▸ claude-code◉ openclaw◉ mcp:* +N · SHIELD ▣▣▣▣▣▣ · THREATS · CAPTURED · ◉LINK · clock`.
  Live counters + WS pulse (cyan up / coral down). The "defends the whole ecosystem" proof on screen.
- **Left nav rail** — systems list, `▸` active prefix + regional glow, collapsible (`w-60/w-14`), `◉ link.up`
  footer. Recreates the deleted `SidebarTerminal`, adaptive to `data-theme`.
- **Centre** — the CORTEX (regional living graph + activation bloom) as the hero, plus domain panels.
- **Bottom command rail** — real CLI + `⌘K` palette; console log streams above the prompt; blinking block cursor.

## Command system (REAL)
A command registry → thin adapters over existing `:3001` endpoints + MCP tools. Parser, autocomplete, `↑/↓`
history, streamed console output. Initial command set:

```
recall "<q>" [--project x]   scan <path> [--deep]   forget <criteria>   consolidate
quarantine review|approve <id>   irondome on|off|status   go <view>   theme <t>   help
```

Phased by *coverage* (Phase 1 = nav + recall/scan/forget/consolidate), real from line one. Each command is a
small, testable unit (parse → validate → call → render).

## Ecosystem → Shield → Cortex
- **Ecosystem strip**: the active agentic sources (`source` field already classifies user/cli/hook/agent/
  openclaw/api/mcp) with trust score + live throughput — a sensor array.
- **Shield bar** `▣▣▣▣▣▣`: the 6 defence layers, lighting/flaring as they intercept.
- **Cortex**: the protected brain; clean memory becomes neurons; recall flows back to the agents.

## Effects system — `<CicEffects/>` + utilities, all gated
- Scanline + slow vertical sweep over the void.
- Phosphor bloom: `text-shadow: 0 0 8px currentColor` on accent text (tasteful).
- Boot sequence: `SHIELDCORTEX // CIC ONLINE` type-on + staggered panel power-up (~1.2s, skippable).
- Character stream-in on new threat rows / live updates.
- Ambient telemetry: ops bar + edge sparklines breathe with real data.
- **Calm toggle + `prefers-reduced-motion` → instant, no sweep, reduced bloom.** Non-negotiable (paying product).

## Component treatments (primitives already carry terminal branches)
`GlassCard`→**Panel** · `Button`→`[ ACTION ]` · `Badge`→`▎LABEL` severity bar · `TabBar`→glowing underline ·
`StatCard`→dense KPI + sparkline · `Toast`→CLI log line that types in · audit/bulk-review tables→`DenseTable`
monospace rows · `ConstellationGraph`→cluster colours remapped to the regional phosphor (keeps 4.41.0 elegance work).

## Cloud parity (ShieldCortex-internal)
Cloud already has `data-theme` (shield/terminal-green/terminal-amber) + `ThemeContext` + `ThemeSwitcher` + 35
`.terminal.tsx` variants. Port the **same CIC token block**, add `terminal` (CIC) as the **default** theme,
elevate the existing terminal variants with the panel chrome + effects, add `title/statusLine` props to the
cloud `GlassCard`. Green/amber kept as alternates. One canonical token spec, mirrored across the two
independent repos.

## Architecture
- Token-driven; `data-theme="terminal"` default in both `globals.css`.
- Local: recreate the deleted shell as adaptive components; restore a real theme hook + localStorage bootstrap
  (default terminal, Glass kept); replace the `useTheme` no-op shim.
- Effects: one `<CicEffects/>` overlay mounted in layout + `cic-bloom` utility + reduced-motion.
- Command system: a `lib/commands/` registry + a `CommandRail` component.

## Risks / landmines (from recon)
- Canvas graphs (`ConstellationGraph`, `RelationshipGraph`) use hardcoded `CLUSTER_COLOURS` JS constants — recolour
  in JS, not CSS, to hit the regional map.
- Hardcoded hex in `EntityDetail`, `HealthScore`, `MemoryTimeline`, `TrustTimeline` — JS edits.
- Two independent repos — every shared decision mirrored; token spec is the single source of truth.
- Cloud `.terminal.tsx` variants are separate files (not adaptive) — elevate in place; a later refactor to
  adaptive components is out of scope.
- Reduced-motion + contrast (WCAG) must hold — it is a paid product.

## Phasing
| Phase | Deliverable |
|---|---|
| 0 | CIC token system + regional colour-map + `<CicEffects/>` (scanline/bloom/boot) + calm/reduced-motion toggle (both globals.css) |
| 1 | Local: CIC shell + REAL command rail (nav + recall/scan/forget/consolidate) + cortex centre (regional graph + activation bloom) + ecosystem strip + shield bar — a full vertical slice |
| 2 | Local primitives + remaining views re-skinned to CIC |
| 3 | Command coverage expanded (quarantine, irondome, full set) + telemetry rails |
| 4 | Cloud: port tokens + CIC default + elevate 35 terminal variants + GlassCard props + effects |
| 5 | Polish, motion tuning, cross-dashboard consistency, screenshot verification |

## Verification
- Each phase: `cd dashboard && npm run build` clean (ships in the npm tarball) + dashboard jsdom suite green.
- Command system: TDD the parser + each command adapter.
- Manual walkthrough per phase; screenshot the CIC shell + cortex bloom + a real command round-trip.
- Reduced-motion + contrast checks before cloud rollout.
