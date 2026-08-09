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
 * Topology, learned the empirical way: the gateway scopes a pending approval
 * to the CONNECTION that requested it — a second connection (a later CLI
 * invocation) cannot `waitDecision` on it, and the record dies with the
 * requester's socket. So request and wait must share one connection, and
 * that one long-lived call cannot live in this hook (one process per tool
 * call, exits immediately). It lives in the detached WAITER
 * (openclaw-approval-waiter.ts); this channel only launches it and reports
 * whether the launch took.
 *
 * Delivery semantics, honestly stated: the waiter writes a receipt file
 * before dialling and rewrites it on any fast failure (gateway down, no
 * approval route, bad params — all of which surface within a couple of
 * seconds). This channel polls that receipt inside its own send deadline:
 * a fast failure reports `delivered: false`; a request still standing after
 * the poll window means the gateway accepted it and routed it to an
 * approval surface. That is a launch-and-negative-check, not an
 * end-to-end render receipt — the floor beneath it (the hash in the
 * terminal refusal) is unchanged either way.
 *
 * Like every `NotifyChannel`, this one only DELIVERS. The invariant from
 * operator-notify.ts — delivering a notification is not consent — holds
 * structurally: this module does not import the approval store, and nothing
 * it reads (a receipt file it created the name of, with two known phases)
 * can encode a decision. The operator's actual answer travels only through
 * the waiter, and only a decision the GATEWAY authenticated — a tap from a
 * resolved approver, the same trust bar as `/approve` in the operator's own
 * chat — is translated onto the #118 store. A gateway that is itself
 * compromised is outside this threat model: it already runs the agent.
 */
import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
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
export const CARD_TIMEOUT_MS = 600_000;
/** The waiter's own call deadline must outlast the card's expiry to hear it. */
export const WAIT_DECISION_TIMEOUT_MS = CARD_TIMEOUT_MS + 15_000;

/** How long send() watches the receipt for a fast failure before calling the
 *  launch good. Bounded additionally by the caller's own timeoutMs. */
const RECEIPT_POLL_WINDOW_MS = 4_000;
const RECEIPT_POLL_INTERVAL_MS = 200;

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

/** The exact request the waiter will place — built HERE so tests can pin
 *  what the operator is offered without spawning anything. One-shot by
 *  construction: `allow-always` is deliberately not offered, because durable
 *  trust is a config decision (the #189 reviewed-script allowlist), not a
 *  chat tap, and a decision OpenClaw remembers but the #118 store does not
 *  would be a standing lie. */
export function buildCardRequestParams(n: OperatorNotification): Record<string, unknown> {
  const { title, description } = buildCardFields(n);
  return {
    pluginId: 'shieldcortex',
    title,
    description,
    // The guard's tier vocabulary is not OpenClaw's. Everything that reaches
    // an approval card is the dangerous tier (catastrophic blocked long
    // before any notify path) — "warning" on every card, "critical" left
    // unused so it stays meaningful if a future tier ever earns it.
    severity: 'warning',
    allowedDecisions: ['allow-once', 'deny'],
    timeoutMs: CARD_TIMEOUT_MS,
  };
}

export type WaiterReceipt =
  | { phase: 'requesting' }
  | { phase: 'failed'; reason: string };

export interface OpenClawApprovalChannelOptions {
  /** Absolute path to the `openclaw` binary. Callers resolve it (or fail to)
   *  BEFORE constructing the channel — a channel with no binary should be a
   *  channel that was never built, indistinguishable from "not configured". */
  openclawBin: string;
  /** Absolute path to the compiled waiter entry
   *  (dist/defence/iron-dome/openclaw-approval-waiter.js). */
  waiterEntry: string;
  /** Injected for tests. */
  spawnImpl?: typeof spawn;
  readReceipt?: (path: string) => WaiterReceipt | null;
  sleepImpl?: (ms: number) => Promise<void>;
  receiptDir?: string;
}

function defaultReadReceipt(path: string): WaiterReceipt | null {
  try {
    const parsed = JSON.parse(readFileSync(path, 'utf8')) as WaiterReceipt;
    if (parsed && (parsed.phase === 'requesting' || parsed.phase === 'failed')) return parsed;
    return null;
  } catch {
    return null;
  }
}

const defaultSleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

/**
 * Build a `NotifyChannel` that delivers via a native OpenClaw plugin
 * approval. Every failure mode — no gateway, a waiter that dies on launch,
 * a fast "no approval route" refusal — resolves to `{ delivered: false,
 * reason }`, never a throw, so operator-notify.ts can fall through to the
 * next channel and ultimately to the unchanged hash-in-terminal floor.
 */
export function createOpenClawApprovalChannel(opts: OpenClawApprovalChannelOptions): NotifyChannel {
  const spawnImpl = opts.spawnImpl ?? spawn;
  const readReceipt = opts.readReceipt ?? defaultReadReceipt;
  const sleepImpl = opts.sleepImpl ?? defaultSleep;

  return {
    name: 'openclaw-approval',
    async send(notification, { timeoutMs }) {
      const params = buildCardRequestParams(notification);
      const receiptDir = opts.receiptDir ?? join(tmpdir(), 'shieldcortex-approval-receipts');
      const receiptPath = join(receiptDir, `${randomUUID()}.json`);

      try {
        mkdirSync(receiptDir, { recursive: true, mode: 0o700 });
      } catch {
        /* the waiter re-tries; a missing dir surfaces as a failed receipt */
      }

      // The waiter owns the request end-to-end (one connection — see module
      // doc). It gets the card params, the store hash, and the receipt path;
      // it writes the receipt BEFORE dialling, so "no receipt appears" below
      // means the waiter itself never started.
      try {
        const child = spawnImpl(
          process.execPath,
          [
            opts.waiterEntry,
            '--params-b64', Buffer.from(JSON.stringify(params), 'utf8').toString('base64'),
            '--hash', notification.hash,
            '--openclaw-bin', opts.openclawBin,
            '--receipt', receiptPath,
          ],
          { detached: true, stdio: 'ignore' },
        );
        child.unref();
      } catch (err) {
        return { delivered: false, reason: `waiter failed to start: ${err instanceof Error ? err.message : String(err)}` };
      }

      // Watch for a fast failure. A gateway that is down, refuses the params,
      // or has no approval route fails within this window; a request still
      // standing at the end of it has been accepted and routed.
      const deadline = Math.min(RECEIPT_POLL_WINDOW_MS, Math.max(0, timeoutMs - 500));
      let sawRequesting = false;
      let waited = 0;
      while (waited < deadline) {
        await sleepImpl(RECEIPT_POLL_INTERVAL_MS);
        waited += RECEIPT_POLL_INTERVAL_MS;
        const receipt = readReceipt(receiptPath);
        if (receipt?.phase === 'failed') {
          return { delivered: false, reason: `card not raised: ${receipt.reason}` };
        }
        if (receipt?.phase === 'requesting') sawRequesting = true;
      }
      if (!sawRequesting && readReceipt(receiptPath) === null) {
        return { delivered: false, reason: 'waiter never reported in — card was not raised' };
      }

      return { delivered: true };
    },
  };
}
