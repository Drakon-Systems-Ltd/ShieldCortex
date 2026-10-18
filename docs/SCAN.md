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

<a id="what-a-scan-writes"></a>

## What a scan writes

The command stores no memory. It records a local audit row for the verdict. If cloud sync is already configured, it can forward the quarantined text the same way any other pipeline caller can.
