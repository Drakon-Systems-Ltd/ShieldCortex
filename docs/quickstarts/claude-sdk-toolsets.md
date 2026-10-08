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

**Required driver duty: request interception.** Call `guard.interceptRequest(url)` from
your driver's request-interception hook (Playwright `context.route`, CDP
`Fetch.requestPaused`), so link clicks, form posts and redirects get the same URL rule as
`navigate`. The SDK's `urlPolicy` only sees `navigate`, and the ref catalogue records a
link's label, not its href: without interception the guard cannot see where a click goes.
As a backstop, once the session is tainted every link click and every click on a ref it
cannot resolve is `require_approval`.

`interceptRequest` follows the guard's mode. A request the URL rule rejects emits one
values-free `call` event (member `request`, host only, signal `request-interception`).
In `observe` it then answers `continue`, so the request goes ahead and the page behaves
as it would without ShieldCortex; only in `enforce` does it answer `abort`. A request the
rule accepts is not audited.

```ts
await context.route('**/*', (route) =>
  guard.interceptRequest(route.request().url()) === 'abort' ? route.abort('blockedbyclient') : route.continue());
```

`guard.isUrlAllowed(url)` is the same URL rule as a plain predicate: it does not depend
on the mode and records nothing. If your deployment blocks requests on its own (a
`context.route` that aborts on `!guard.isUrlAllowed(url)`, a proxy, container egress
rules), that is **your own control**, enforced whatever the guard's mode. It is not
ShieldCortex observe, and ShieldCortex does not audit what it blocks.

For the computer toolset pass `toolset: 'computer'`; the class takes `confirm` and the
`execute` override but has no URL or file policy.

## What the guard knows and does not know

| Call | Classification | Why |
|---|---|---|
| `navigate` | scheme, private-range and allowlist check | the SDK checks no scheme; `javascript:` and `file:` are refused |
| click on a `ref` | resolved only from the `read_page` / `find` output of the same tab and page (a full read replaces the tab's refs; navigating drops them); a button labelled pay / send / delete / accept / submit is **irreversible**; a link click (the catalogue has no href) is held once tainted | the only way to know what a click does |
| click on a coordinate, any desktop click | **unclassified**: allowed untainted, held once tainted | Anthropic: `confirm` "receives the tool and its input, not the screen" |
| `type`, `form_input`, `key` | typed text scanned for secrets → **denied**; Enter after typing = submit | credentials must never be typed into a page |
| `javascript_exec`, `file_upload` | held; an upload from `.ssh`, `.aws`, `.env`, … is denied | runs with the page's authority / exfiltrates files |
| `get_page_text`, `read_page`, `find`, console, network | scanned with the tool-response scanner (injection, hidden HTML, credentials, markdown-image exfil); a non-string result has every string leaf scanned, and one that cannot be fully walked is never reported clean | page content is untrusted |
| `screenshot`, `zoom` | taints the session; not scanned (no OCR in P1), so the result event carries `not-scanned:image` and never `scanClean: true` | — |
| `navigate`, `new_tab`, `switch_tab`, `list_tabs` results; the `browserState` report | tab titles, URLs and dialog messages taint the session and are scanned | page-supplied text the model reads with every result |

**Driver errors are page content.** The SDK relays the text of an error your driver
throws to the model as the tool result, and an action's error can quote the page (a
click's "element `<div>…</div>` intercepts pointer events"). So the guard scans the error
text of every member the same way as a result (one `result` event, indicator
`driver-error`) and rethrows. The error taints the session when the member is a reading
or tab member (`navigate`, `new_tab`, `switch_tab`, `list_tabs`, `read_page`,
`get_page_text`, `find`, console, network, `javascript_exec`, `screenshot`, `zoom`), or
when the scan does not report it clean, whatever the member. A clean error from an
action member (`left_click`, `type`, `wait`, …) does not taint. In `observe` the guard
rethrows the same error object. In `enforce` a clean error is rethrown unchanged; an
error the scan flags is replaced by a new `toolError` carrying only the scanner's
neutralised text.

Wrap the required `browserState` option with `guard.browserState(...)`: the SDK attaches
that report to every tool result, so a page title is content the model reads.

**Session taint**: after the first page or screen read (including a page title), every irreversible or
unclassified action is `require_approval`. That is the point: the agent is now acting on
content an attacker may have written (ADR-002 §2.2).

`execute` binds to what `confirm` saw for the same call (by tool_use id, else by member
name, never by the input): an input that changed after `confirm` is recorded as
`mutated_input`, and an `execute` with no `confirm` record as `unconfirmed`. In
`enforce` mode both are refused. `enforce` also re-applies the DENY set (typed secrets,
credential uploads, blocked URLs) to the exact bytes in `execute`, and refuses a call
that `confirm` answered `false`, so a driver that skips or ignores `confirm` cannot run it.

## Audit events

One event per call and one per scanned result. `urlPolicy` records one `call` event per URL it checks (signal `url-policy`), in observe mode as well. Fields: toolset, member, mode, decision,
effect kinds, signal names, taint, `requestedBy`, host (never path or query), element role
and a bounded, escaped label with secret-shaped text redacted, input hash, outcome, host answer, scan indicators. Never the
typed text, never a URL query string, never page content.

## Known limits (P1)

Both are tracked for P2 (#678).

- **N1 — input binding skips three field names.** The input hash that binds `execute`
  to `confirm` does not include own JSON fields named `constructor`, `prototype` or
  `__proto__`. A change to only those fields after `confirm` is not detected as
  `mutated_input`. No standard SDK member reads them.
- **N2 — a newline in `type` after a read.** A `type` call whose text contains a newline
  after a read is classified as a submit but is still allowed without approval unless the
  previous member was typing; the gap is the approval, not the classification. P2 item.

## Not covered

Container egress rules and desktop isolation are deployment concerns the SDK docs list.
The guard sees only the requests your interception hook passes to `interceptRequest`;
it cannot see the rest of the browser's network. The
server-side prompt-injection classifier is Anthropic's and is not host-controllable.
