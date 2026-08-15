/**
 * ShieldCortex — approval broker configuration (#143).
 *
 * Design: docs/design/2026-07-31-ai-approval-broker.md
 *
 * `approval-broker.ts` is the policy; this is the only thing allowed to move it.
 * That makes this file a trust boundary: a config lives on disk, and on a box
 * the agent has already been talked into misusing, "on disk" means "reachable".
 * So the normaliser is written the way a parser for hostile input is written —
 * allowlist the fields, bound the numbers, and treat anything it does not
 * recognise as absent rather than as intent.
 *
 * One rule governs every knob here:
 *
 *   **Config may TIGHTEN. Config may never LOOSEN.**
 *
 * Concretely, and pinned by __tests__/broker-config.test.ts:
 *   - `enabled` is false unless the file says exactly `true`. The broker is new
 *     security-critical behaviour; nothing changes for anyone until they opt in.
 *   - `preClearConfidence` has a FLOOR, not a range. You may demand more of the
 *     judge than the default; you may not accept less.
 *   - There is no field for the pre-clear signal allowlist, and no field for the
 *     severity set. Widening either is a code change with corpus evidence behind
 *     it — never a line in someone's JSON.
 *   - `model` is handed to a CLI as an argv element, so it is validated as a
 *     model *name* (no leading dash, no shell metacharacters) and dropped
 *     otherwise. A rejected override falls back to the host's default model,
 *     never to an attacker's flag.
 */
import { DEFAULT_BROKER_POLICY, type BrokerPolicy } from './approval-broker.js';

/** The tiers that can actually reach an approval gate. Benign never gates;
 *  catastrophic hard-blocks at the guard and is never brokered. */
export type BrokerGatedSeverity = 'sensitive' | 'dangerous';

export interface BrokerConfig {
  /** Master switch. FALSE by default — the whole feature is opt-in. */
  enabled: boolean;
  /** Allow the pre-clear outcome at all. `false` sends every gate to a human. */
  allowPreClear: boolean;
  /** Minimum judge confidence for a pre-clear. Floored at the built-in default. */
  preClearConfidence: number;
  /** Hard ceiling on the judge call. The operator is waiting. */
  judgeTimeoutMs: number;
  /** How long to wait for a human before applying `timeoutOutcome`, per tier. */
  approvalTimeoutMs: Record<BrokerGatedSeverity, number>;
  /** Optional judge-model override, resolved by the host's own model pool. */
  model?: string;
}

// Bounds. Deliberately generous at the edges and strict where it matters: a
// silly-but-harmless number (a 3-second judge timeout) is the operator's
// business; a number that changes what gets released is not.
const JUDGE_TIMEOUT_MIN_MS = 500;
const JUDGE_TIMEOUT_MAX_MS = 60_000;
const APPROVAL_TIMEOUT_MIN_MS = 1_000;
const APPROVAL_TIMEOUT_MAX_MS = 3_600_000;
const MODEL_MAX_LENGTH = 64;

/** A model id or alias — letters, digits and the punctuation real ids use.
 *  Anchored, and forced to start alphanumeric so `-p` can never be an override. */
const MODEL_NAME = /^[A-Za-z0-9][A-Za-z0-9._:@/-]*$/;

export const DEFAULT_BROKER_CONFIG: BrokerConfig = {
  enabled: false,
  allowPreClear: DEFAULT_BROKER_POLICY.allowPreClear,
  preClearConfidence: DEFAULT_BROKER_POLICY.preClearConfidence,
  // 15s, raised from 8s in the #143 residual. Field latency on the Jarvis box
  // reached ~6s, and an 8s ceiling turned an answered judge into a silent null
  // often enough to matter. A null holds for a human, so the old value was safe
  // but wasteful; the ceiling exists to bound the operator's wait, not to race
  // the model. Still well inside the 60s bound.
  judgeTimeoutMs: 15_000,
  approvalTimeoutMs: {
    // The more dangerous the action, the sooner we stop waiting — because
    // "stop waiting" resolves to DENY for everything the broker did not
    // pre-clear. A shorter window is the stricter setting, not the looser one.
    sensitive: 600_000,
    dangerous: 300_000,
  },
};

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/** A finite number inside [min, max], or undefined. No clamping: a value we do
 *  not understand is not silently reinterpreted as the nearest one we do. */
function boundedNumber(v: unknown, min: number, max: number): number | undefined {
  if (typeof v !== 'number' || !Number.isFinite(v)) return undefined;
  if (v < min || v > max) return undefined;
  return v;
}

/** The model override, or undefined. See MODEL_NAME for why this is strict. */
export function normaliseBrokerModel(v: unknown): string | undefined {
  if (typeof v !== 'string') return undefined;
  const trimmed = v.trim();
  if (!trimmed || trimmed.length > MODEL_MAX_LENGTH) return undefined;
  if (!MODEL_NAME.test(trimmed)) return undefined;
  return trimmed;
}

function normaliseApprovalTimeouts(v: unknown): Record<BrokerGatedSeverity, number> {
  const out = { ...DEFAULT_BROKER_CONFIG.approvalTimeoutMs };
  if (!isPlainObject(v)) return out;
  // Allowlisted keys only. A `catastrophic` entry is not "supported but
  // ignored" — it is dropped, so it can never grow a meaning later by accident.
  for (const key of ['sensitive', 'dangerous'] as const) {
    const ms = boundedNumber(v[key], APPROVAL_TIMEOUT_MIN_MS, APPROVAL_TIMEOUT_MAX_MS);
    if (ms !== undefined) out[key] = ms;
  }
  return out;
}

/**
 * Turn whatever was on disk into a config the broker can be trusted with.
 * Total: every input, including junk, yields a valid BrokerConfig.
 */
export function normaliseBrokerConfig(raw: unknown): BrokerConfig {
  if (!isPlainObject(raw)) return { ...DEFAULT_BROKER_CONFIG, approvalTimeoutMs: { ...DEFAULT_BROKER_CONFIG.approvalTimeoutMs } };

  const cfg: BrokerConfig = {
    // Strict true. Not truthy — a stray "false" string must not arm the broker.
    enabled: raw.enabled === true,
    // Strict false, mirroring the above: only an explicit `false` disables
    // pre-clear, and only an explicit boolean is honoured at all.
    allowPreClear: typeof raw.allowPreClear === 'boolean' ? raw.allowPreClear : DEFAULT_BROKER_CONFIG.allowPreClear,
    // FLOOR, not range: the built-in threshold is the loosest this can ever be.
    preClearConfidence:
      boundedNumber(raw.preClearConfidence, DEFAULT_BROKER_CONFIG.preClearConfidence, 1)
      ?? DEFAULT_BROKER_CONFIG.preClearConfidence,
    judgeTimeoutMs:
      boundedNumber(raw.judgeTimeoutMs, JUDGE_TIMEOUT_MIN_MS, JUDGE_TIMEOUT_MAX_MS)
      ?? DEFAULT_BROKER_CONFIG.judgeTimeoutMs,
    approvalTimeoutMs: normaliseApprovalTimeouts(raw.approvalTimeoutMs),
  };

  // Only present when it survived validation — an absent key means "use the
  // host's default model", which is the safe fallback for a rejected override.
  const model = normaliseBrokerModel(raw.model);
  if (model !== undefined) cfg.model = model;

  return cfg;
}

/** The two knobs the pure decision core exposes. Nothing else crosses over. */
export function toBrokerPolicy(cfg: BrokerConfig): BrokerPolicy {
  return {
    allowPreClear: cfg.allowPreClear,
    preClearConfidence: cfg.preClearConfidence,
  };
}

/**
 * How long to wait for the human, given a guard severity.
 *
 * An unrecognised tier gets the STRICTEST configured window rather than the
 * most generous one. Catastrophic never arrives here (it hard-blocks at the
 * guard), but if it ever did, it would wait the shortest time and then take the
 * deny branch — the same answer, reached twice.
 */
export function approvalTimeoutMs(cfg: BrokerConfig, severity: string): number {
  if (severity === 'sensitive') return cfg.approvalTimeoutMs.sensitive;
  if (severity === 'dangerous') return cfg.approvalTimeoutMs.dangerous;
  return Math.min(cfg.approvalTimeoutMs.sensitive, cfg.approvalTimeoutMs.dangerous);
}
