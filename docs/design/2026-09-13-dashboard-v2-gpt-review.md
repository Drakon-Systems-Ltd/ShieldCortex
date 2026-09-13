# Dashboard v2 — GPT source review

Reviewer: GPT-6 Astra, 13 September 2026. Inspected local worktree at b3e8aafe. Design review only; no built-result approval.

## Required design changes

1. Project scope must cover overview, search, neighbourhood, paths, drawer queries, counts and React Query keys. Existing graph routes/hooks are globally scoped. Define global/unscoped memory treatment explicitly; test cross-project fixtures. requireNotLocked is not record-level authorization.
2. Use namespaced entity/memory IDs. entities is UNIQUE(name,type), while paths currently resolves and returns names. Add ID inputs/outputs while retaining legacy API fields. Preserve predicates, direction, confidence and dispute metadata; no invented triple weight/count. Suspended triples stay absent everywhere. Reverse path traversal is not a reversed assertion.
3. Apply hard node/edge/payload/traversal caps and deterministic ordering. Current neighbourhood caps only related_to fill-in, not all meaningful neighbours. Return edges only with both endpoints present. Strict finite integer bounds must prevent negative SQLite LIMIT or NaN bypass. Show truncation counts.
4. Enforce sensitivity on the server response, not merely hidden drawer fields. Inspect existing disclosure policy before assuming titles/relations are permissible. Synthetic fixtures and isolated runtime only: no real databases, config copies or screenshots containing private data.
5. Single click selects/details; double-click or explicit action enters Focus. Give touch/keyboard equivalents, a navigable list sharing canvas selection and a persistent relationship legend. Specify freeze/drag-pin/release/focus-back/filter/reduced-motion interactions.
6. Entity Map is bounded. Memories and all three edge families appear in capped Focus context (initial 40 memories); any overview overlay shares a total budget. Keep one force-graph instance, stable identities, coordinates and pins. Clone graph objects before d3 mutates them; never mutate React Query cached data. No decorative particles, anchor changes or remount-on-focus. Explain omitted records.
7. Unknown, stale, unavailable, observation-only and enforced are distinct. Fetch errors must not become zero/healthy. Inspect real mutation endpoints before exposing actions; no fictional Boost API or optimistic success. Preserve sensitive-action confirmations/authorization.
8. Migrate consumers before retiring CIC tokens/modules: current graph imports lib/cic/regions. Use accessible native primitives to avoid unapproved dependencies. Retain route/theme/viewport proof, measured bundle/performance baselines, and light/dark canvas/touch inspection. Do not cut verification merely to reduce workload.

## Verdict
APPROVE_WITH_CHANGES for implementation after incorporation. Grok findings are advisory and must be checked against local source; its source came partly from GitHub main, not a full local worktree read. I confirmed local graph clustering, name-only paths, schema confidence, token coupling, and uncapped meaningful neighbours independently.

Sources inspected: full brief, dashboard/package.json, complete useGraphData.ts and graph.ts, schema memory/entity/triple/link definitions, ConstellationGraph import/render/data-selection/force/control excerpts, globals.css token/theme definitions. Full source and mutation contracts must be inspected by implementer before edits.
