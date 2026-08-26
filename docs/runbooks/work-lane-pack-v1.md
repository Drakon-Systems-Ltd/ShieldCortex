# Runbook — Work-lane pack v1 (#401)

**Audience:** operators of a ShieldCortex-guarded host whose agent keeps getting
held on a known class of work (the post-Edith stop-bleed: LAN diagnostics with
no door).

**Design:** `docs/design/2026-08-24-memory-sota-defence-work-not-frustration.md`
§5–6 — *no deny without a door*. A repeated hold class without a lane is a
product defect, not an operator-skill issue.

## What ships

| Lane id | Script | Trigger (hint) |
|---|---|---|
| `vita-ci` | operator's own `gh-ci.sh` | pin + vita-shaped cwd + `external-egress` |
| `jotform` | operator's own jotform toolkit | pin + jotform cwd/signal + `external-egress` |
| `lan-diag` | `templates/work-lanes/lan-diag.sh` (this package) | pin + (lan/diag/network/connectivity/wifi cwd **or** a network tool such as ping/traceroute/ip/dig) + `external-egress` |

Hints are advisory copy on the denial digest. They never approve anything, and
they never name a path that is not actually pinned on the host (#399 law).

`lan-diag.sh` is read-mostly and fails closed:

- no args / `status` — `ip -br addr` + `ip route` (read-only)
- `<host-or-ip>` — `ping -c 2 -W 2`, **only** loopback, link-local, or RFC1918
- `GET <url>` — http(s) GET, `--max-time 3`, same private-only destination rule,
  no redirects, no request body
- everything else refuses (exit 2): public or global-IPv6 destinations,
  hostnames with any public address, nmap/tcpdump/ssh/sudo/writes/captures

## Install the lan-diag lane

All three steps happen on the target host, **from a real TTY** — the allowlist
CLI refuses non-interactive callers by design.

1. Copy the template out of the installed package onto a stable path:

   ```bash
   mkdir -p ~/.shieldcortex/work-lanes
   cp "$(npm root -g)/shieldcortex/templates/work-lanes/lan-diag.sh" \
      ~/.shieldcortex/work-lanes/lan-diag.sh
   chmod 0755 ~/.shieldcortex/work-lanes/lan-diag.sh
   ```

2. Pin it (review it first — the pin is the operator saying *I read this*):

   ```bash
   shieldcortex allowlist add ~/.shieldcortex/work-lanes/lan-diag.sh
   ```

3. Retry the held job through the pin instead of freehand curl/nmap:

   ```bash
   ~/.shieldcortex/work-lanes/lan-diag.sh status
   ~/.shieldcortex/work-lanes/lan-diag.sh 192.168.1.1
   ~/.shieldcortex/work-lanes/lan-diag.sh GET http://192.168.1.1/health
   ```

Once pinned, the next `external-egress` denial from lan-shaped work carries a
`Lane:` line pointing at exactly this path. Shipping the template does **not**
pre-approve it — a host with no pin gets no hint and no allowlist entry.

## Verifying the doors

The denial→door matrix is locked by
`src/defence/iron-dome/__tests__/denial-doors-401.test.ts`:

- `catastrophic` — hard stop; no retry, no `approve --denial` in its copy
- `denied_no_prompt_surface` — always `shieldcortex approve --denial <actionId>`
  + honest-TTY copy; plus the `Lane:` line when a pin matches
- `approval_requested` — Approve/Deny one-shot commands

## Non-goals

- **`enforce: false`** — degrading the guard is not a door.
- **Fleet-wide `retryCards`** — stays off until Approve/Deny spend is proven on
  that host class (design §5 defaults).
- **Invented paths** — a hint may only name a path that exists in the pin list.
  No pin, no lane line, ever.
- **memories.db salvage** — separate runbook, separate concern.
