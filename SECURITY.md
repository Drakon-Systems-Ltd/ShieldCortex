# Security Policy

Thanks for helping keep ShieldCortex — and the projects that depend on it — safe.

## Reporting a Vulnerability

**Email: [support@drakonsystems.com](mailto:support@drakonsystems.com)**

> `security@drakonsystems.com` is **not** a live mailbox and never was — mail to it
> bounces. It was published here and on the website in error until 6 Aug 2026. If you
> sent a report there, we did not receive it; please resend to the address above.

Please do **not** open a public GitHub issue for security vulnerabilities. For non-security bugs, file an issue as normal.

A PGP key fingerprint is published at <https://shieldcortex.ai/.well-known/security.txt>. Request the full key by reply if you'd like to encrypt the report.

## Response Commitments

| Stage | Target |
|---|---|
| Initial acknowledgement | Within 48 hours |
| Triage + severity assignment | Within 5 business days |
| Critical/High fix or mitigation | Within 30 days of triage |
| Medium/Low fix | Next scheduled release |
| Public disclosure coordination | After fix shipped; default 90-day max embargo |

These are commitments by Drakon Systems Ltd, not contractual SLAs. We will tell you immediately if a target will slip.

## Supported Versions

We support the latest two major versions of the `shieldcortex` npm package. Older majors receive security fixes only at maintainer discretion.

| Version | Status |
|---|---|
| 4.x | ✅ Supported |
| 3.x | ⚠️ Security fixes only, best-effort |
| ≤ 2.x | ❌ End of life |

## In Scope

- The published `shieldcortex` npm package (latest two majors)
- The bundled local dashboard server (port 3838)
- The SaaS API at `api.shieldcortex.ai`
- The dedicated OpenClaw plugin `@drakon-systems/shieldcortex-realtime`
- Defence pipeline correctness issues (false negatives on documented attack classes)
- Credential leak, prompt-injection, and memory-poisoning bypasses against documented detection layers

## Out of Scope

- Findings that require a malicious local user already on the host (the package is designed to run on the user's own machine)
- Denial of service against your own local `memories.db`
- Self-XSS in the local dashboard requiring console paste
- Vulnerabilities in `better-sqlite3`, `@anthropic-ai/sdk`, Node.js, Fly.io, or other upstream software — please report those upstream
- Spam, social engineering of staff, physical attacks
- Issues against pre-release branches or unsupported old versions

## Safe-Harbour

If you act in good faith — staying within the scope above, avoiding privacy violations and service disruption, and giving us reasonable time to remediate before public disclosure — we will not initiate legal action against you. Testing is authorised only against your own machine, your own ShieldCortex Cloud account, or a designated test account you have created.

## Acknowledgements

We do not offer monetary rewards. We do credit every researcher whose report leads to a
fix, by the name and link they ask for.

| Researcher | Report | Shipped in |
|---|---|---|
| [Sarvesh P](https://www.sarvee.in) | Credential-leak detection bypasses (current provider key formats) and prompt-injection detection failures; also surfaced that the published security contact was a dead mailbox | [4.47.31](CHANGELOG.md) |

## Full Policy

Full vulnerability disclosure policy, compliance roadmap, and engineering posture: <https://shieldcortex.ai/security>

---

Drakon Systems Ltd · Company number 16867343 · 34 Lumina Way, Enfield, England, EN1 1FS
