/**
 * #815 B — which denials a one-tap approve may answer.
 *
 * One predicate, used three times: by the tap path's read-only preview (mint
 * and verify), again by `grantRetry` on the CURRENT row inside the retry
 * store's own locked transaction, so a denial that became terminal-only
 * between the preview and the grant is still refused, and by
 * `consumeRetryGrant` on the guard's current verdict for the call that would
 * spend a tap grant.
 *
 * A tap may answer a denial only when EVERY signal on it is in the reviewed
 * registry below. Anything else — catastrophic, the self-protection floor,
 * an action the guard could not fully read, a redacted or cut-off signal
 * list, or a name nobody has reviewed for taps yet — is terminal-only.
 */

import { CATASTROPHIC_SIGNALS, GUARD_SELF_PROTECTION_SIGNALS } from './tool-action-guard.js';

/**
 * The reviewed tap-eligible signals: recognised-dangerous actions whose whole
 * effect is visible in the bound call itself (the exact call digest covers
 * every byte the card describes). Adding a name here is a review decision.
 *
 * Deliberately NOT here, so terminal-only:
 *   - `opaque-script-invocation`, `opaque-command-substitution`: the guard
 *     could not read the script or file that would run, so a phone card
 *     cannot describe it;
 *   - `pipe-download-to-shell`, `pipe-download-stdin-exec`,
 *     `pipe-download-module-exec`, `decode-pipe-to-shell`: the bytes that
 *     would run are fetched or decoded at run time and were never scanned;
 *   - `oversized-command`, `command-evidence-unscannable`: not fully read;
 *   - every `openclaw-process-*` signal: OpenClaw keeps its own approval
 *     channel (#220), taps never answer it.
 */
export const TAP_ELIGIBLE_SIGNALS: readonly string[] = Object.freeze([
  'change-permissions',
  'dd-overwrite',
  'destroy-data-or-infra',
  'external-egress',
  'file-delete',
  'git-delete-branch',
  'git-force-push',
  'git-mutate',
  'install-package',
  'install-package-global',
  'local-package-install',
  'modify-network-firewall',
  'modify-scheduler',
  'modify-shell-startup',
  'move-or-copy',
  'privilege-escalation',
  'recursive-perms-system-dir',
  'registry-code-exec',
  'stop-process-or-service',
  'touch-sensitive-path',
  'truncate-to-zero',
  'wipe-history-or-logs',
  'write-content-dangerous',
]);

/** A tool call the guard could not fully read. */
const UNSCANNED_SIGNALS: readonly string[] = Object.freeze([
  'fallback-scan', 'invalid-tool-input', 'unknown-keys', 'not-object', 'nested-invalid',
  'type-coercion', 'missing-handle', 'command-evidence-unscannable', 'oversized-command',
  'opaque-script-invocation', 'opaque-command-substitution',
]);

/** The retry store keeps at most this many signals per row; a full list may
 *  have been cut, so it cannot prove the floor is absent. */
const RETRY_ROW_SIGNAL_CAP = 8;

export type TerminalOnlyReason = 'self-protection-floor' | 'catastrophic' | 'unscanned' | 'unknown-signal' | 'signals-incomplete';

/**
 * Why a denial with these signals may only be approved from a terminal, or
 * null when a tap may answer it. Null only when the list is complete and
 * every entry is in `TAP_ELIGIBLE_SIGNALS`.
 */
export function tapTerminalOnlyReason(signals: readonly unknown[] | undefined): TerminalOnlyReason | null {
  if (!Array.isArray(signals) || signals.length === 0 || signals.length >= RETRY_ROW_SIGNAL_CAP) {
    return 'signals-incomplete';
  }
  const list = signals.map((s) => (typeof s === 'string' ? s : ''));
  if (list.some((s) => GUARD_SELF_PROTECTION_SIGNALS.includes(s))) return 'self-protection-floor';
  if (list.some((s) => CATASTROPHIC_SIGNALS.includes(s))) return 'catastrophic';
  if (list.some((s) => UNSCANNED_SIGNALS.includes(s))) return 'unscanned';
  if (list.some((s) => !TAP_ELIGIBLE_SIGNALS.includes(s))) return 'unknown-signal';
  return null;
}
