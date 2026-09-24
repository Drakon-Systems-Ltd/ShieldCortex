/**
 * ADR-002 measurement harness — the three enforcement policies under
 * comparison, expressed as sets of Action Guard SIGNAL NAMES (#555, #556).
 *
 * Shared by both halves of the harness so they cannot drift:
 *   - `scripts/guard-policy-replay.mjs`      (Half A: logged-signal comparison)
 *   - `scripts/guard-effect-fixtures/run.mjs` (Half B: synthetic effect fixtures)
 *
 * A policy is a predicate over the signal set of ONE event. `gates(signals)`
 * answers "would this policy stop the action" — it never answers "would the
 * classifier have emitted these signals", which is a different question the
 * classifier itself answers (Half B runs it; Half A trusts the log).
 *
 * Signal names are the guard's own, as spelled in
 * `src/defence/iron-dome/tool-action-guard.ts` at the commit this file was
 * written against. Every set below is enumerated in full — nothing is derived
 * by pattern — so a reviewer can diff the membership against the guard source.
 * `ALL_KNOWN_SIGNALS` is the union; the replay reports any logged signal that
 * is NOT in it as "unclassified", never silently dropped (defect 1 of the
 * original aggregation script: a hand-picked set with no report of the rest).
 *
 * Style note: dangerous shapes are referred to by SIGNAL NAME here, never by
 * their shell spelling, so this file is not itself an evidence hit when the
 * guard folds it (same convention as `guard-precision-corpus.ts`).
 */

/** Signals the guard's own CATASTROPHIC table emits (block, no prompt). */
export const CATASTROPHIC_TIER = Object.freeze([
  'recursive-force-delete',
  'delete-root-or-home',
  'fork-bomb',
  'format-filesystem',
  'raw-disk-write',
  'redirect-to-block-device',
  'disk-partition-tool',
  'pipe-download-to-shell',
  'pipe-download-stdin-exec',
  'pipe-download-module-exec',
  'recursive-perms-on-root',
  'shred-device',
  'delete-critical-path',
  'write-content-catastrophic',
  'secret-egress',
]);

/** Signals the guard's DANGEROUS table emits (require_approval). */
export const DANGEROUS_TIER = Object.freeze([
  'file-delete',
  'recursive-find-delete',
  'truncate-to-zero',
  'wipe-history-or-logs',
  'dd-overwrite',
  'stop-process-or-service',
  'privilege-escalation',
  'modify-scheduler',
  'modify-network-firewall',
  'modify-shell-startup',
  'install-package',
  'install-package-global',
  'registry-code-exec',
  'decode-pipe-to-shell',
  'external-egress',
  'git-force-push',
  'git-delete-branch',
  'touch-sensitive-path',
  'touch-approval-store',
  'touch-decisions-ledger',
  'touch-guard-config',
  'disable-action-guard',
  'session-lease',
  'recursive-perms-system-dir',
  'write-content-dangerous',
  'opaque-script-invocation',
  'oversized-command',
]);

/** Signals the guard's SENSITIVE table emits (allowed, audited). */
export const SENSITIVE_TIER = Object.freeze([
  'change-permissions',
  'move-or-copy',
  'git-mutate',
  'local-package-install',
  'opaque-command-substitution',
]);

/**
 * Reason codes that record a scan/schema problem rather than a recognised
 * operation. They are denials on the current tiers (a call the guard could not
 * read is not allowed through) but they carry no effect class, so no floor
 * policy can key on them.
 */
export const SCHEMA_OR_SCAN_GAP = Object.freeze([
  'invalid-tool-input',
  'unknown-keys',
  'not-object',
  'nested-invalid',
  'type-coercion',
  'missing-handle',
  'command-evidence-unscannable',
]);

/**
 * Signals the guard emits that the notify/denial writer does NOT keep
 * (`SAFE_ACTION_GUARD_SIGNALS` in `operator-notify.ts`). A row that carried
 * one of these shows `redacted-signal` in its place. Listed so the replay can
 * say WHICH classes are structurally invisible in the log — in particular the
 * two security-config-write signals, which means Half A can never count a
 * security-config write directly.
 */
export const NEVER_LOGGED_SIGNALS = Object.freeze([
  'touch-guard-config',
  'disable-action-guard',
  'command-evidence-unscannable',
]);

/** The marker the denial writer substitutes for any redacted signal. */
export const REDACTED_MARKER = 'redacted-signal';

// ── Policy 2: destruction-only floor (ADR-002 §3 as written) ────────────────

/**
 * ADR-002 §3 names four classes: recursive delete of root/home, fork bomb,
 * raw write to a block device, filesystem format / partition tooling. This
 * is strictly the signals for those four.
 *
 * Deliberately NOT on this floor, so the reader sees what falls off:
 *   recursive-force-delete (a recursive delete of a NON-root path),
 *   dd-overwrite (a dd whose target is a regular file), recursive-find-delete,
 *   truncate-to-zero, wipe-history-or-logs, delete-critical-path (a top-level
 *   system dir — arguably root-equivalent; kept off because the ADR text does
 *   not name it), write-content-catastrophic (a Write payload marker; the
 *   specific class rides alongside it as its own signal and is what decides).
 */
export const DESTRUCTION_FLOOR = Object.freeze([
  'delete-root-or-home',
  'fork-bomb',
  'raw-disk-write',
  'redirect-to-block-device',
  'shred-device',
  'format-filesystem',
  'disk-partition-tool',
]);

// ── Policy 3: broad floor (Jarvis's #556 counter-proposal) ──────────────────

/** Credential / secret leaving the host. */
export const CREDENTIAL_EGRESS = Object.freeze([
  'secret-egress',
  'secret-egress-fold',
  'credential-exfil',
  'credential-access',
  'data-exfiltration',
]);

/** A one-shot action becoming a standing one: scheduler, shell rc, hook/agent config. */
export const PERSISTENCE_SINKS = Object.freeze([
  'modify-scheduler',
  'modify-shell-startup',
  'persistence-risk',
]);

/** Writes to the guard's own configuration, approvals, ledger, lease, firewall. */
export const SECURITY_CONFIG_WRITES = Object.freeze([
  'touch-guard-config',
  'disable-action-guard',
  'touch-approval-store',
  'touch-decisions-ledger',
  'session-lease',
  'modify-network-firewall',
]);

export const BROAD_FLOOR = Object.freeze([
  ...DESTRUCTION_FLOOR,
  ...CREDENTIAL_EGRESS,
  ...PERSISTENCE_SINKS,
  ...SECURITY_CONFIG_WRITES,
]);

/**
 * Injection-flavoured signals: the payoff shapes of a successful injection
 * (secrets out, remote code in) as opposed to the agent's own workaday
 * operations. The original aggregation script omitted `pipe-download-to-shell`
 * (defect 2); this list is what #555's "26 of 837" figure should have counted.
 */
export const INJECTION_FLAVOURED = Object.freeze([
  'prompt-injection',
  'injection',
  'shell-injection',
  'untrusted-instruction',
  'untrusted-script',
  ...CREDENTIAL_EGRESS,
  'external-egress',
  'network-egress',
  'pipe-download-to-shell',
  'pipe-download-stdin-exec',
  'pipe-download-module-exec',
  'decode-pipe-to-shell',
]);

/**
 * Family label per signal, for the per-signal table. Every signal the guard
 * can emit appears exactly once; a logged signal outside this map is reported
 * as `unclassified` and listed by name.
 */
export const SIGNAL_FAMILY = Object.freeze(Object.fromEntries([
  ...DESTRUCTION_FLOOR.map(s => [s, 'destruction-floor']),
  ...['recursive-force-delete', 'delete-critical-path', 'write-content-catastrophic',
      'recursive-perms-on-root', 'recursive-perms-system-dir', 'dd-overwrite',
      'file-delete', 'recursive-find-delete', 'truncate-to-zero', 'wipe-history-or-logs',
      'filesystem-destructive', 'destructive-filesystem'].map(s => [s, 'destruction-other']),
  ...CREDENTIAL_EGRESS.map(s => [s, 'credential-egress']),
  ...['external-egress', 'network-egress'].map(s => [s, 'external-egress']),
  ...['pipe-download-to-shell', 'pipe-download-stdin-exec', 'pipe-download-module-exec',
      'decode-pipe-to-shell', 'registry-code-exec', 'untrusted-script',
      'shell-injection', 'prompt-injection', 'injection', 'untrusted-instruction'].map(s => [s, 'remote-code']),
  ...PERSISTENCE_SINKS.map(s => [s, 'persistence-sink']),
  ...SECURITY_CONFIG_WRITES.map(s => [s, 'security-config-write']),
  ...['touch-sensitive-path'].map(s => [s, 'sensitive-path']),
  ...['stop-process-or-service', 'service-restart', 'privilege-escalation',
      'install-package', 'install-package-global', 'local-package-install',
      'git-force-push', 'force-push', 'force-push-invocation', 'git-delete-branch', 'git-mutate',
      'change-permissions', 'move-or-copy', 'write-content-dangerous',
      'dangerous-shell', 'command-exec', 'exec-like'].map(s => [s, 'agent-operation']),
  ...['opaque-script-invocation', 'opaque-script', 'opaque-command-substitution',
      'oversized-command', 'reviewed-script', 'fallback-scan', 'approval-required'].map(s => [s, 'scan-gap-or-meta']),
  ...SCHEMA_OR_SCAN_GAP.map(s => [s, 'schema-reject']),
]));

export const ALL_KNOWN_SIGNALS = Object.freeze(Object.keys(SIGNAL_FAMILY));

/**
 * The three policies. `gates` is the whole contract: given the signal names on
 * one event, would this policy stop the action.
 *
 * `current-tiers` gates on any catastrophic/dangerous-tier signal or a schema
 * reject — i.e. the signal set the guard's tiers key on today. In Half A this
 * is a HYPOTHETICAL signal-set match like the other two policies — the log
 * holds denials, warnings (which stopped nothing) and retry lifecycle rows, so
 * it is NOT "everything in the log was stopped" and no 100% baseline exists;
 * the ACTUAL outcome is accounted separately. On the synthetic fixtures it is
 * the live guard's own decision.
 */
export const POLICIES = Object.freeze([
  {
    id: 'current-tiers',
    label: 'Current tiers (catastrophic=block, dangerous=approve)',
    gateSet: new Set([...CATASTROPHIC_TIER, ...DANGEROUS_TIER, ...SCHEMA_OR_SCAN_GAP]),
  },
  {
    id: 'destruction-floor',
    label: 'Destruction-only floor (ADR-002 §3 as written)',
    gateSet: new Set(DESTRUCTION_FLOOR),
  },
  {
    id: 'broad-floor',
    label: 'Broad floor (destruction + credential egress + persistence + security-config)',
    gateSet: new Set(BROAD_FLOOR),
  },
]);

/** Would `policy` gate an event carrying `signals`? Pure. */
export function gates(policy, signals) {
  for (const s of signals) if (policy.gateSet.has(s)) return true;
  return false;
}

/** The signals on `signals` that made `policy` gate — for the per-signal table. */
export function gatingSignals(policy, signals) {
  return signals.filter(s => policy.gateSet.has(s));
}
