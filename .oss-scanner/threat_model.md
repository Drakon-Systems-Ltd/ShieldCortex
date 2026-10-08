# ShieldCortex threat model (OSS Scanner)

ShieldCortex is a local memory store and defence layer for AI agents (Claude Code, OpenClaw, Hermes, MCP hosts). It sits between untrusted content and an agent's long-term memory, and on hosts that can deny it gates tool calls before they run. This file guides the scanner. The published policy in `SECURITY.md` is the scope of record and wins on any conflict.

## What the attacker controls
- Any text an agent reads and may store or recall: web pages, emails, documents, tool output, MCP results, messages from other agents. Treat it as fully attacker-controlled (prompt injection, memory poisoning, credential-shaped strings, invisible-separator and encoding tricks).
- Requests from a hostile web page open in the user's browser, aimed at the local API (port 3001) and dashboard (port 3030): CSRF, DNS rebinding, origin confusion.
- Memory rows already in the store that were written under a different host, agent or project scope.

## In scope (code in this repository)
- **Memory firewall / defence pipeline** (`src/defence`): hostile content stored or recalled as trusted; documented detection classes failing (credential leak, prompt injection, memory poisoning).
- **Action Guard and its policy/approval boundary** (`src/defence/iron-dome`: `tool-action-guard`, `policy-lock`, `protected-root`, `session-guard`; the Claude Code PreToolUse hook; the OpenClaw `before_tool_call` plugin in `plugins/openclaw`; the Hermes `pre_tool_call` plugin in `plugins/hermes`): attacker-origin content that makes a gated agent cross an enforced boundary; forging, replaying or bypassing an approval or lease; defeating the root-pinned policy lock from a non-root context; tampering with the protected root or the audit chain (`src/audit`).
- **Cross-agent and cross-project recall isolation** (`hostId` / `agentId` / `project` scoping, provenance and trust labels on rows; `src/memory`, `src/tools`): reading, ranking in, or injecting across scopes. `CONTRIBUTING.md` names cross-agent contamination as the failure mode we care about most.
- **Local API server and dashboard** (`src/server.ts`, `src/api`, `dashboard/`): auth bypass, CSRF, rebinding, path traversal, SQL injection, reached from a hostile web origin rather than from a local user.
- **Cloud-sync client** (`src/cloud`): what the client sends, verifies or trusts. Test the client code here. Do not probe `api.shieldcortex.ai` or any live service.
- **Host safety of install, repair and hook paths** (`src/setup`, `src/service`): any path that leaves the host agent or gateway broken (`CONTRIBUTING.md`, "The host environment").

## Out of scope
- Anything that needs the attacker to already execute arbitrary code as the same OS user, or a malicious local user on the host (`SECURITY.md`). Pre-existing unrestricted same-user execution is excluded. Attacker-origin content that makes a gated agent cross an enforced boundary is not excluded; that is the product's job.
- Deployments where the relevant control is not enforced: Action Guard off (the default until `sudo shieldcortex protect`), observe-only or shadow posture (enforce-when-ready), and hosts where ShieldCortex is a scanner the model may call rather than a gate (Codex, Cursor, Copilot, generic MCP, LangChain, Python SDK; see `README.md`, "Where it can block"). A miss there is not a bypass. An enabled, supported deployment is valid scope even though enabling it is opt-in.
- `benchmark/`, `research/`, `examples/`, `reports/`: not shipped.
- Upstream bugs in `better-sqlite3`, Node.js, Next.js or hosting providers; report those upstream.
- Denial of service that needs multi-gigabyte input or a hostile local user. Resource blow-up from a small input is in scope.
- The live SaaS (`api.shieldcortex.ai`) and ShieldCortex Cloud accounts.

## Severity: by demonstrated impact and prerequisites
State in every report: the runtime (Claude Code, OpenClaw, Hermes, MCP host, local API), the ShieldCortex version, the configuration or posture (guard on or off, shadow, policy lock pinned, defaults), the attacker's entry point, the boundary crossed, and the observed effect. A component's name does not set the severity; what the finding demonstrably lets happen does.

- **CRITICAL**: a demonstrated severe unauthorised effect under an enforced posture. A gated agent runs a destructive or exfiltrating command the guard would otherwise deny; an approval or lease is forged or replayed; the policy lock or protected root is defeated without root; the audit chain is rewritten without detection.
- **HIGH**: attacker content stored and later recalled as trusted; cross-scope recall or write; secret material leaving the memory store or logs; auth bypass on the local API or dashboard from a web origin; a documented detection class failing broadly.
- **MEDIUM**: a false negative on a documented detection class with a narrow or specific trigger; leaks of non-secret metadata; a control degrading to fail-open where the docs promise fail-closed.
- **LOW**: everything else (hardening, defence in depth, documentation and code disagreeing without an exploit).

Detector false negatives on documented classes stay in scope. Rate them by the demonstrated consequence; do not assume every miss proves command execution or exfiltration.

## Reports
Include a minimal reproducer (a Jest test in the matching `__tests__` directory is preferred; dashboard tests live in `dashboard/src/**/*.test.tsx`) and a minimal patch. Deduplicate by root cause, not by payload variant: many payloads through one gap are one report.
