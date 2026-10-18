# Claude SDK browser-use / computer-use toolsets (observe by default; enforce with approvals)

Issue #678. The Python and TypeScript Anthropic SDKs ship abstract classes for the
`browser_toolset_20260801` and `computer_toolset_20260801` toolsets. The SDK runs the
tool loop and hands each `navigate`, `left_click`, `type`, `javascript_exec` and
`file_upload` call to a driver you write. Those calls are actions with real effects, and
the pages and screens they read are untrusted content.

`shieldcortex/toolsets` plugs the Action Guard into the three hook points the SDK
documents (`urlPolicy`, `confirm`, and an `execute` override). It has no runtime
dependency on the SDK: the adapters are typed structurally, and a conformance test
type-checks a driver subclassing the real `@anthropic-ai/sdk` classes through them.

**The default is observe-only.** With the default `mode: 'observe'` the guard never
changes what runs: `confirm` returns your own answer (or `true`), `execute` returns the
driver's result unchanged. It classifies each call, scans each page read, taints the
session after the first untrusted read, and emits values-free audit events so you can see
what enforcement *would* do.

**`mode: 'enforce'` (phase P2, first slice)** refuses the DENY set without asking, and
routes every `require_approval` call through the Action Guard's bounded-approval store
with a readable, values-free card. See [Enforce mode](#enforce-mode). The #673 digest
and the Python port are not in this release.

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
      confirm: guard.confirm(async (ctx, card) => askUser(card.card)),
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

**The URL rule does no DNS.** `checkUrl`, the rule behind `urlPolicy`, `interceptRequest`
and `isUrlAllowed`, is pure: it reads the URL text and never resolves a name. It refuses
private and loopback IP literals, but a hostname that resolves to one passes the check.
That covers wildcard-DNS names such as `127.0.0.1.nip.io` and DNS-rebinding names, which
can resolve to a public address first and a private one later. What stops those names is
request interception or host egress controls that act on the address the connection
actually uses, for example a proxy or firewall that refuses private ranges.
`guard.interceptRequest` applies the same DNS-free rule, so on its own it lets these names
through too. A `urlAllowlist` narrows the exposure to the hosts you list.

For the computer toolset pass `toolset: 'computer'`; the class takes `confirm` and the
`execute` override but has no URL or file policy.

## What the guard knows and does not know

| Call | Classification | Why |
|---|---|---|
| `navigate` | scheme, private-range and allowlist check | the SDK checks no scheme; `javascript:` and `file:` are refused |
| click on a `ref` | resolved only from the `read_page` / `find` output of the same tab and page (a full read replaces the tab's refs; navigating drops them); a button labelled pay / send / delete / accept / submit is **irreversible**; a link click (the catalogue has no href) is held once tainted | the only way to know what a click does |
| click on a coordinate, any desktop click | **unclassified**: allowed untainted, held once tainted | Anthropic: `confirm` "receives the tool and its input, not the screen" |
| `type`, `form_input`, `key` | typed text scanned for secrets → **denied** (by `enforce`); Enter after typing = submit | credentials must never be typed into a page |
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
`mutated_input`, and an `execute` with no `confirm` record as `unconfirmed`. The input
hash covers every own enumerable key, including keys named `constructor`, `prototype`
and `__proto__`. In `enforce` mode both are refused. `enforce` also re-applies the DENY
set (typed secrets, credential uploads, blocked URLs) to the exact bytes in `execute`, and
refuses a call that `confirm` answered `false`, so a driver that skips or ignores
`confirm` cannot run it.

## Enforce mode

```ts
const guard = new ToolsetGuard({
  toolset: 'browser',
  mode: 'enforce',
  urlAllowlist: ['docs.example.com'],
  requestedBy: { band: 'operator', identifier: 'owner-chat' },
  audit: (event) => sink.write(event),
  toolError: ToolError,
  approvalTimeoutMs: 120_000, // default 5 minutes
});

confirm: guard.confirm(async (ctx, card) => askUser(card.card) /* must resolve to exactly true */),
```

What `confirm` does per decision:

| Decision | `confirm` | `inner` asked? |
|---|---|---|
| `allow` | `true` | no |
| `block` (typed secret, credential upload, `javascript:` / `file:` / private-range URL) | `false` | **never**; there is no approval path |
| `require_approval` | `true` only if `inner(ctx, card)` returned exactly `true` within `approvalTimeoutMs` | yes |

Hosts switching from observe to enforce lose their own `inner` refusals on actions ShieldCortex classifies as `allow`, because enforce approves those actions without calling `inner`.

For a `require_approval` call the guard records a pending request in the same store as
every other Action Guard approval (`~/.shieldcortex/approvals/`, `action-approvals.ts`;
`approvalsHome` moves it). The key is the store's hash of (toolset, member, host of
`tabURL`, input hash). `card.approvalKey` carries it. When `inner` returns exactly `true`
the request is marked approved with the store's lifetime (`approvalTtlMs`, default 10
minutes). The timeout is an elapsed deadline, including time spent in a blocking host callback. Any other value (`'yes'`, `1`, an object), an exception, a timeout or an aborted
call refuses, and the pending request is removed. With no `inner`, every held call is
refused.

`execute` then runs a held call only by spending that approval: the bytes it receives must
hash to the key `confirm` approved, on the same tab host, and the approval must still be
live. It is single-use, so the same approval cannot run a second call, and the next
identical call goes back to `inner`. If `confirm` was never called for a call, `execute`
still applies the DENY set and HOLD to the bytes it receives (audit signals
`denied-at-execute` / `held-at-execute`) and refuses the call.

Audit signals added on `call` events in enforce: `approval-granted`, `approval-not-true`,
`approval-error`, `approval-timeout`, `approval-aborted`, `approval-no-approver`,
`approval-store-error`, `approval-not-live` (expired or already spent at `execute`),
`held-at-execute`.

**Session taint and submits.** Pending text is tracked per tab; text from an unknown tab counts as pending on every tab. Text typed after a submit was confirmed but before it runs still holds that submit unless the submit already has the needed approval. A successful approved submit clears its tab's pending text only when no more text arrived there in the meantime. A failed or refused dispatch leaves it pending. In a tainted session a `type` whose text contains a
newline (`\n` or `\r`) is a submit: `require_approval`, effects `submit` +
`irreversible-ui-action`, signal `typed-newline`, whatever the previous member was.

### Approval cards

`inner` receives the verdict as its second argument; `card.card` is the readable card.
Cards are plain English, at most 200 characters and printable ASCII only (anything else
is shown as `\uXXXX`). A page label is redacted with the credential patterns, withheld
whole if any residual text still looks like a secret or the page itself wrote a redaction-shaped marker, and bounded to 60 characters. Only the host of
`tabURL` is shown, at most 32 characters, keeping its end (the registrable domain). A card
never contains the typed text, a URL path or query string, an upload path, or page body.
When the card would pass 200 characters the taint and requester sentences are dropped
first; `Approve once / Deny.` is always kept.

```
Click the button labelled "Place order" on checkout.example.com? This could spend money, send something or delete something. The agent is acting on web or screen content it read. Approve once / Deny.
Type into a field on checkout.example.com? The text looks like a secret (api key). ShieldCortex does not allow secrets to be typed into pages or apps. Denied; nothing was typed.
Run page script on checkout.example.com? Scripts run with the page's own cookies and logins. The agent is acting on web or screen content it read. Requested by: operator. Approve once / Deny.
Click on the screen (desktop)? ShieldCortex cannot tell what this click does. The agent is acting on web or screen content it read. Requested by: unknown. Approve once / Deny.
Upload 1 file(s) from this machine to checkout.example.com? The page receives a copy of the file. The agent is acting on web or screen content it read. Requested by: operator. Approve once / Deny.
```

A DENY card (the typed-secret one above) is only on the verdict `classify` returns; `inner` is never asked for a DENY.

In `observe` the same call is not stopped, and `inner` is asked with the card as usual.
The card then ends "In enforce mode this would be denied." instead of "Denied; nothing was
typed / uploaded / opened."

### Not in this release

- The #673 digest (unanswered cards collected as "skipped" entries).
- The Python port (`shieldcortex.toolsets` under `plugins/`).
- Screenshot OCR, per-site policy files, and a `doctor` row (phase P3).

## Audit events

One event per call and one per scanned result. `urlPolicy` records one `call` event per URL it checks (signal `url-policy`), in observe mode as well. Fields: toolset, member, mode, decision,
effect kinds, signal names, taint, `requestedBy`, host (never path or query), element role
and a bounded, escaped label with secret-shaped text redacted, input hash, outcome, host answer, scan indicators. Never the
typed text, never a URL query string, never page content. Signal names are fixed
diagnostics (an unrecognised scheme is `url-scheme-unknown`, without the scheme). A host
whose text trips ShieldCortex's credential recognisers, as written, percent-decoded, or
as the URL parser maps it (fullwidth or soft-hyphenated text becomes ASCII; this mapped
text is checked with its case kept, and the parser's lowercased host is checked against
the recognisers too), is shown as `redacted-host` on cards and audit rows. A long
internationalised name is still shown as its punycode, unless it trips them. An unknown member
name that trips them is audited as `other`; the policy and the driver still get the real
URL. A secret in a shape the recognisers do not know is not guaranteed to be caught.

## Known limits

The two P1 known limits are closed: the input hash now covers own `constructor`,
`prototype` and `__proto__` fields (N1), and a `type` with a newline in a tainted session
is `require_approval` whatever the previous member was (N2). Navigation does not reset pending text. Drivers that call `confirm` without wrapping `execute` never retire pending text, so later Enter calls remain held after typing.

- An approval is bound to the host of the tab URL in the SDK's **last state report**, not
  the live browser; Anthropic notes the page can change after that report.
- Before the first page or screen read, a `type` with a newline in the browser toolset is
  still `allow` (the session is not tainted yet).
- A `key Return` with no text typed since the last executed submit keeps its ordinary verdict.
- Text entered through `key` members (single keys or paste shortcuts) does not mark text as pending, so a later Enter keeps its ordinary verdict.

## Not covered

Container egress rules and desktop isolation are deployment concerns the SDK docs list.
The guard sees only the requests your interception hook passes to `interceptRequest`;
it cannot see the rest of the browser's network. The
server-side prompt-injection classifier is Anthropic's and is not host-controllable.
