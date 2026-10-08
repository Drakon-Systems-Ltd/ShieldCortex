# ShieldCortex threat model (draft for OSS Scanner)

ShieldCortex is a memory store and defence layer for AI agents. Its job is to sit between untrusted content and an agent's long-term memory and tool calls.

## Adversarial inputs (in scope)
- Any text written to memory: from web pages, emails, tool output or other agents. Assume an attacker controls it fully (prompt injection, credential-shaped strings, poisoning).
- Scanner / firewall inputs (src/defence, memory firewall): bypasses that let hostile content be stored or recalled as trusted are HIGH or CRITICAL.
- Action Guard (hook commands evaluated before an agent runs a shell command): any way to make a destructive or exfiltrating command classify as safe is CRITICAL.
- Local HTTP API and dashboard: assume a malicious local web page or another local user; auth bypass, CSRF, path traversal, SQL injection.
- Approval / lease mechanisms: forging or replaying an approval is CRITICAL.

## Out of scope
- Attacks requiring the attacker to already run code as the same OS user.
- benchmark/, research/, examples/, reports/ — not shipped.
- Denial of service from multi-GB inputs, unless memory/CPU blow-up comes from a tiny input.

## Severity
- CRITICAL: guard/firewall bypass leading to command execution or secret exfiltration; approval forgery.
- HIGH: stored-then-trusted injection; secret leak from memory store; auth bypass on local API.
- MEDIUM: detection gaps needing unusual config; info leaks of non-secret metadata.
- LOW: everything else.

## Reports
Include a minimal reproducer (jest test preferred) and a minimal patch. Deduplicate by root cause.
