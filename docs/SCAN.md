# How scan results work

The README example is a default install of:

```bash
shieldcortex scan "ignore previous instructions"
```

The report says `QUARANTINE`. The process exits 1.

<a id="exit-codes"></a>

## Exit codes

| Exit | Meaning |
|---|---|
| 0 | Allow |
| 1 | Caught |
| 2 | Bad usage |
| 3 | The scanner itself failed (control is absent) |

0 and 1 are verdicts. 2 is the caller. 3 means the scanner did not run, so a dead tool is not scored as a catch.

<a id="provenance"></a>

## Provenance and the L2 floor

`cli (trusted, L2 not applied)` means you typed the text. The extra floor for untrusted origins (web, email, documents, tool results) is not applied. The injection detector still quarantines this string.

A bare `scan TEXT` stays attested `cli:shieldcortex-scan`. A declared `--source` is a caller label, not host attestation. Untrusted data origins (`web`, `document`, `email`, `tool_result`, `agent_message`, `memory_candidate`) also get the L2 non-authoritative-instruction floor.

<a id="memory-directive"></a>

## Memory candidates: the memory-directive screen

`--source=memory_candidate`, and each memory write the README lists under the memory-directive screen, also runs the memory-directive screen. It fires only when an agent-directed standing frame (an imperative, "you", the agent as subject, an identity or mode change, "from now on" style wording) and evidence about a control sit in the same sentence. A hit adds the threat indicator `memory_directive` and pattern names of the form `memory_directive:<group>` (never the text). The groups are `control_relaxation`, `claimed_authority`, `concealment`, `secret_routing`, `identity_override`, `permissive_default` and `bulk_egress`.

The verdict depends on the defence mode:

| Mode | Verdict on a memory-directive hit |
|---|---|
| `balanced` (default) | `QUARANTINE`, unless another detector already reached `QUARANTINE` or `BLOCK`, which stands |
| `strict` | `BLOCK` (any detection blocks) |
| `permissive` | `ALLOW`, with the indicator still reported |

Persistence wording alone no longer flags a memory candidate. A hit made only of the L2 `non_authoritative:memory_persist` pattern and/or the `memory_manipulation` preference phrasings ("from now on, always use British English spelling") no longer counts under `memory_candidate` when the memory-directive screen ran and did not fire; other detectors still apply. If the screen could not run, the old rules apply. Every other label keeps its verdicts.

This is a deterministic floor, not an intent detector: lexical, English-only, no model call. A reworded instruction with no control words in it gets past it, and a false belief stored without any control in it is not covered.

<a id="what-a-scan-writes"></a>

## What a scan writes

The command stores no memory. It records a local audit row for the verdict. If cloud sync is already configured, it can forward the quarantined text the same way any other pipeline caller can.
