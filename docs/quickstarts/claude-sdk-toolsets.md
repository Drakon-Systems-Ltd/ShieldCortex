# Claude SDK browser-use / computer-use toolsets (observe-only, P1)

Issue #678. The Python and TypeScript Anthropic SDKs ship abstract classes for the
`browser_toolset_20260801` and `computer_toolset_20260801` toolsets. The SDK runs the
tool loop and hands each `navigate`, `left_click`, `type`, `javascript_exec` and
`file_upload` call to a driver you write. Those calls are actions with real effects, and
the pages and screens they read are untrusted content.

`shieldcortex/toolsets` plugs the Action Guard into the three hook points the SDK
documents (`urlPolicy`, `confirm`, and an `execute` override). It has no runtime
dependency on the SDK: the adapters are typed structurally, and a conformance test
type-checks a driver subclassing the real `@anthropic-ai/sdk` classes through them.

**Phase P1 (this release) is observe-only.** With the default `mode: 'observe'` the guard
never changes what runs: `confirm` returns your own answer (or `true`), `execute` returns
the driver's result unchanged. It classifies each call, scans each page read, taints the
session after the first untrusted read, and emits values-free audit events so you can see
what enforcement *would* do. `mode: 'enforce'` exists so the decision function can be
tested; the bounded-approval and approval-card wiring is phase P2 (see #678).

## TypeScript

```ts
import { ToolsetGuard } from 'shieldcortex/toolsets';
import {
  BetaAbstractBrowserToolset20260801,
  ToolError,
  type BetaBrowserMemberResult,
  type BetaToolsetCallContext,
} from '@anthropic-ai/sdk/helpers/beta/toolsets';
import type { BetaBrowserMemberInput, BetaBrowserMemberName } from '@anthropic-ai/sdk/resources/beta';

const guard = new ToolsetGuard({
  toolset: 'browser',
  urlAllowlist: ['docs.example.com'],
  requestedBy: { band: 'operator', identifier: 'owner-chat' },
  audit: (event) => console.log(JSON.stringify(event)),
  toolError: ToolError,
});

class MyBrowser extends BetaAbstractBrowserToolset20260801 {
  constructor(private backend: Backend) {
    super({
      browserState: guard.browserState(() => ({ tabs: backend.tabs(), state_changes: backend.drainChanges() })),
      urlPolicy: guard.urlPolicy(),
      confirm: guard.confirm(async (ctx, verdict) => askUser(verdict.card)),
    });
  }

  protected override async execute(
    ctx: BetaToolsetCallContext,
    name: BetaBrowserMemberName,
    input: BetaBrowserMemberInput,
  ): Promise<BetaBrowserMemberResult> {
    return guard.execute(ctx, name, input, (c, n, i) => super.execute(c, n, i));
  }

  // ...navigate, screenshot, left_click, read_page against `backend`
}
```

Use `guard.isUrlAllowed(url)` from your driver's request-interception hook (Playwright
`context.route`, CDP `Fetch.requestPaused`) so clicks and redirects get the same URL rule
as `navigate`. The SDK's `urlPolicy` only sees `navigate`.

For the computer toolset pass `toolset: 'computer'`; the class takes `confirm` and the
`execute` override but has no URL or file policy.

## What the guard knows and does not know

| Call | Classification | Why |
|---|---|---|
| `navigate` | scheme, private-range and allowlist check | the SDK checks no scheme; `javascript:` and `file:` are refused |
| click on a `ref` | resolved only from the `read_page` / `find` output of the same tab and page (a full read replaces the tab's refs; navigating drops them); a button labelled pay / send / delete / accept / submit is **irreversible** | the only way to know what a click does |
| click on a coordinate, any desktop click | **unclassified**: allowed untainted, held once tainted | Anthropic: `confirm` "receives the tool and its input, not the screen" |
| `type`, `form_input`, `key` | typed text scanned for secrets → **denied**; Enter after typing = submit | credentials must never be typed into a page |
| `javascript_exec`, `file_upload` | held; an upload from `.ssh`, `.aws`, `.env`, … is denied | runs with the page's authority / exfiltrates files |
| `get_page_text`, `read_page`, `find`, console, network | scanned with the tool-response scanner (injection, hidden HTML, credentials, markdown-image exfil) | page content is untrusted |
| `screenshot`, `zoom` | taints the session; not scanned (no OCR in P1) | — |
| `navigate`, `new_tab`, `switch_tab`, `list_tabs` results; the `browserState` report | tab titles, URLs and dialog messages taint the session and are scanned | page-supplied text the model reads with every result |

Wrap the required `browserState` option with `guard.browserState(...)`: the SDK attaches
that report to every tool result, so a page title is content the model reads.

**Session taint**: after the first page or screen read (including a page title), every irreversible or
unclassified action is `require_approval`. That is the point: the agent is now acting on
content an attacker may have written (ADR-002 §2.2).

## Audit events

One event per call and one per scanned result. Fields: toolset, member, mode, decision,
effect kinds, signal names, taint, `requestedBy`, host (never path or query), element role
and a bounded escaped label, input hash, outcome, host answer, scan indicators. Never the
typed text, never a URL query string, never page content.

## Not covered

Container egress rules, desktop isolation and request interception are deployment
concerns the SDK docs list; the guard cannot see what the browser's network does. The
server-side prompt-injection classifier is Anthropic's and is not host-controllable.
