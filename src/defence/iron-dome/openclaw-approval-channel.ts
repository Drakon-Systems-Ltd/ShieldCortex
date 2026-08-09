/**
 * ShieldCortex — the OpenClaw native-approval notify channel (#143).
 *
 * The channel the design doc actually wanted: when the guard holds for a
 * human, raise a NATIVE OpenClaw plugin approval (`plugin.approval.request`)
 * so the card — with real Approve/Deny buttons — lands on whatever channel
 * the operator already uses (Telegram, WhatsApp, Discord, Slack, the TUI…).
 * OpenClaw owns delivery, approver authentication, and button rendering;
 * this module owns none of that.
 *
 * Like every `NotifyChannel`, this one only DELIVERS. The invariant from
 * operator-notify.ts — delivering a notification is not consent — holds
 * structurally: this module does not import the approval store, and the
 * gateway's response to `plugin.approval.request` (two-phase: an id and a
 * pending status, never a decision) is read for exactly two things — "did a
 * request get created" and its id. The operator's actual answer travels a
 * separate, later path: the detached waiter process this channel spawns
 * (openclaw-approval-waiter.ts) blocks on `plugin.approval.waitDecision`,
 * and only a decision the GATEWAY authenticated — a tap from a resolved
 * approver, the same trust bar as `/approve` in the operator's own chat —
 * is translated onto the #118 store. A gateway that is itself compromised
 * is outside this threat model: it already runs the agent.
 *
 * Why shell out to the `openclaw` CLI instead of speaking the gateway
 * WebSocket protocol directly? The same reason cli-invoker.ts shells out to
 * a model CLI: the binary already holds the auth material and the transport
 * details, and a child process gets a hard kill deadline — no client library
 * to keep in lockstep with the gateway's protocol, no credential handling
 * in guard code.
 */
import { execFile, spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import type { NotifyChannel, OperatorNotification } from './operator-notify.js';

/** Mirrors `resolveOpenClawBinary` in src/setup/openclaw.ts, minus the
 *  synchronous `which` call — the hook path loads this module on every held
 *  tool call, and a PATH probe that blocks is a probe that slows the guard.
 *  Env override first (tests, unusual installs), then the known roots. */
export function resolveOpenClawBinaryLite(home: string = homedir()): string | null {
  const fromEnv = process.env.SHIELDCORTEX_OPENCLAW_BIN;
  if (fromEnv && existsSync(fromEnv)) return fromEnv;
  const candidates = [
    join(home, '.npm-global', 'bin', 'openclaw'),
    '/usr/local/bin/openclaw',
    '/opt/homebrew/bin/openclaw',
    join(home, '.local', 'bin', 'openclaw'),
  ];
  for (const c of candidates) {
    if (existsSync(c)) return c;
  }
  return null;
}

/** OpenClaw caps title at 80 and description at 256 — enforced gateway-side,
 *  but a request rejected for length is a card that never reached the
 *  operator, so we stay inside the caps rather than discover them. */
const TITLE_MAX = 80;
const DESCRIPTION_MAX = 256;

/** The card's pending window. OpenClaw clamps to its own 10-minute ceiling
 *  (MAX_PLUGIN_APPROVAL_TIMEOUT_MS); the #118 pending record outlives it
 *  (60-minute retention), so an expired card degrades to the terminal-hash
 *  floor rather than to a dangling approval. */
const CARD_TIMEOUT_MS = 600_000;
/** The waiter must outlast the card's own expiry to observe it. */
export const WAIT_DECISION_TIMEOUT_MS = CARD_TIMEOUT_MS + 15_000;

function clip(text: string, max: number): string {
  return text.length <= max ? text : `${text.slice(0, max - 1)}…`;
}

/** A held command can itself contain the credential that tripped the guard.
 *  A secret-egress hold must never copy that credential onto a chat surface —
 *  same discipline as #192, where secret-egress spans are excluded from audit
 *  rows. The operator still gets the tool name, the signals, and the hash;
 *  what they lose is exactly the thing that must not be forwarded. */
function isSecretEgress(signals: string[]): boolean {
  return signals.some((s) => s.toLowerCase().includes('secret') || s.toLowerCase().includes('credential'));
}

export function buildCardFields(n: OperatorNotification): { title: string; description: string } {
  const title = clip(`ShieldCortex: approve ${n.tool}? [${n.shortHash}]`, TITLE_MAX);
  const commandPart = isSecretEgress(n.signals)
    ? '(command withheld — contains credential material)'
    : n.command;
  const description = clip(
    `${commandPart}\nTripped: ${n.signals.join(', ') || 'none'} (${n.severity})`,
    DESCRIPTION_MAX,
  );
  return { title, description };
}

export interface OpenClawApprovalChannelOptions {
  /** Absolute path to the `openclaw` binary. Callers resolve it (or fail to)
   *  BEFORE constructing the channel — a channel with no binary should be a
   *  channel that was never built, indistinguishable from "not configured". */
  openclawBin: string;
  /** Absolute path to the compiled waiter entry
   *  (dist/defence/iron-dome/openclaw-approval-waiter.js). */
  waiterEntry: string;
  /** Injected for tests. */
  execFileImpl?: typeof execFile;
  spawnImpl?: typeof spawn;
}

interface RequestResponse {
  id?: unknown;
}

/**
 * Build a `NotifyChannel` that delivers via a native OpenClaw plugin
 * approval. Every failure mode — no gateway, bad params, unparseable
 * response, kill on timeout — resolves to `{ delivered: false, reason }`,
 * never a throw, so operator-notify.ts can fall through to the next channel
 * and ultimately to the unchanged hash-in-terminal floor.
 */
export function createOpenClawApprovalChannel(opts: OpenClawApprovalChannelOptions): NotifyChannel {
  const execFileImpl = opts.execFileImpl ?? execFile;
  const spawnImpl = opts.spawnImpl ?? spawn;

  return {
    name: 'openclaw-approval',
    async send(notification, { timeoutMs }) {
      const { title, description } = buildCardFields(notification);
      const params = {
        pluginId: 'shieldcortex',
        title,
        description,
        // The guard's tier vocabulary is not OpenClaw's. Everything that
        // reaches an approval card is the dangerous tier (catastrophic
        // blocked long before any notify path) — "warning" on every card,
        // and "critical" deliberately unused so it stays meaningful if a
        // future tier ever earns it.
        severity: 'warning',
        // One-shot by construction. `allow-always` is deliberately not
        // offered: durable trust is a config decision (the reviewed-script
        // allowlist), not a chat tap, and a decision OpenClaw remembers but
        // the #118 store does not would be a standing lie.
        allowedDecisions: ['allow-once', 'deny'],
        timeoutMs: CARD_TIMEOUT_MS,
        // Two-phase: respond as soon as the card is accepted for delivery.
        // The decision is collected separately by the waiter — this send()
        // must fit the notify transport's own delivery deadline.
        twoPhase: true,
      };

      let stdout: string;
      try {
        stdout = await new Promise<string>((resolvePromise, rejectPromise) => {
          execFileImpl(
            opts.openclawBin,
            ['gateway', 'call', 'plugin.approval.request', '--json', '--params', JSON.stringify(params)],
            { timeout: timeoutMs, killSignal: 'SIGKILL', maxBuffer: 256 * 1024 },
            (err, out) => (err ? rejectPromise(err) : resolvePromise(String(out))),
          );
        });
      } catch (err) {
        return { delivered: false, reason: `gateway call failed: ${err instanceof Error ? err.message : String(err)}` };
      }

      // The response is read for the request id and NOTHING else. A gateway
      // (or a process impersonating one) that echoes {"decision":"allow-once"}
      // here gets nothing for it — decisions only count when the waiter hears
      // them on plugin.approval.waitDecision, and even then only land as a
      // one-shot #118 record the guard re-checks itself.
      let id: string | null = null;
      try {
        const parsed = JSON.parse(stdout) as RequestResponse;
        if (typeof parsed?.id === 'string' && parsed.id.length > 0) id = parsed.id;
      } catch {
        id = null;
      }
      if (!id) {
        return { delivered: false, reason: 'gateway response carried no approval id' };
      }

      // Hand the long wait to a detached process and get out of the guard's
      // way. If the spawn fails the card is still on the operator's screen —
      // their tap will die unheard, so report NOT delivered and let the
      // terminal-hash floor stand as the honest path.
      try {
        const child = spawnImpl(
          process.execPath,
          [opts.waiterEntry, '--id', id, '--hash', notification.hash, '--openclaw-bin', opts.openclawBin],
          { detached: true, stdio: 'ignore' },
        );
        child.unref();
      } catch (err) {
        return { delivered: false, reason: `card sent but waiter failed to start: ${err instanceof Error ? err.message : String(err)}` };
      }

      return { delivered: true };
    },
  };
}
