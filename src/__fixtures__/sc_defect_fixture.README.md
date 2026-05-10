# sc_defect_fixture.db

Sanitised SQLite fixture extracted from a live ShieldCortex memories.db on host EDITH (project: workspace) on 2026-05-10. Embeddings stripped. No private content beyond what was already in the malformed extractor output.

## Contents

- `memories` — 10 rows showing the auto-extract chunker producing malformed/inverted/imperative-shaped entries (ids 136, 137, 159–163, 171, 192, 206)
- `defence_audit` — 2 rows from CLI self-tests: canonical PASS (id 1) and canonical QUARANTINE for `instruction_injection` / `hidden_instruction` (id 2). Confirms the engine works when invoked.
- `quarantine`, `firewall_rules`, `iron_dome_policies` — all empty, demonstrating that production capture path bypasses defence.

## How to use

Drop into the SC repo at `tests/fixtures/sc_defect_fixture.db`, then point new tests at it:

```python
import sqlite3
db = sqlite3.connect('tests/fixtures/sc_defect_fixture.db')
# assert firewall_rules empty, defence_audit has only 'cli' source rows, etc.
```

## Defects this fixture demonstrates

1. **Pipeline bypass** — every row in `memories` was inserted by the `openclaw-session-end` hook with no corresponding `defence_audit` row.
2. **No rules loaded** — `firewall_rules` and `iron_dome_policies` empty in production despite the engine supporting them.
3. **Malformed extraction** — see id 159 ("commit secrets" — original guidance was *don't* commit secrets, negation dropped) and id 136 (imperative tool-call directive captured as user preference).
