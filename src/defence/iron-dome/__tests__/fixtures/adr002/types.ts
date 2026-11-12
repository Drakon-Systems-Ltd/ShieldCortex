/**
 * ADR-002 build epic (#1065), Phase 0: the frozen corpus.
 *
 * Every open Guard issue the epic folds in gets at least one NAMED fixture
 * here: the call, the effect and targets the command model is expected to
 * derive from it, the decision the proposed ADR-002 v3 gives it, and the
 * verdict today's classifier (`evaluateToolCall`) must return for the fixture
 * to count as fixed.
 *
 * This directory is test data. It sits under `__tests__/`, which
 * `tsconfig.build.json` excludes, so nothing here reaches the published
 * package and no runtime module imports it.
 *
 * Conventions (same as `guard-precision-corpus.ts` and
 * `scripts/lib/guard-policy-sets.mjs`):
 *   - Catastrophic shapes are named by signal or composed from the shared
 *     tokens in `tokens.ts`; they are never spelled out.
 *   - Credentials are synthetic and hosts are reserved example names or
 *     documentation address ranges.
 *   - Fixtures are classifier inputs. Nothing in this corpus is executed, and
 *     the corpus runs in CI or an isolated evaluator only (#629, 5 Oct rule).
 */

/**
 * Effect kinds. The first eleven are ADR-002 §2.4's minimum privileged-effect
 * taxonomy, by the ADR's own names. The last five are the kinds the corpus
 * also has to name: two non-privileged ones the false-positive rows resolve
 * to, a resolved execution, and the two block-list kinds the 20 Oct contract
 * adds (they are part of the v3 PROPOSAL, not of the accepted v2 text).
 */
export type EffectKind =
  | 'destroy'
  | 'credential-read'
  | 'egress'
  | 'persistence-write'
  | 'security-config-write'
  | 'privilege-change'
  | 'process-control'
  | 'file-mutate'
  | 'package-install'
  | 'code-exec-opaque'
  | 'network-fetch'
  | 'none'            // prints, help text, pure computation
  | 'read'            // reads local, non-credential state
  | 'code-exec'       // runs a program whose own effects were resolved and are listed beside it
  | 'history-rewrite' // force push or history rewrite (v3 proposal)
  | 'payment';        // payments or money movement (v3 proposal)

/**
 * Decision under the PROPOSED ADR-002 v3 (see
 * `docs/architecture/ADR-002-v3-amendment-proposed.md`). It is recorded for
 * the reviewer and for Phases 2 to 4; it is not asserted by the Phase 0 test,
 * because v3 is not accepted and no default has changed.
 *   BLOCK      on the fixed published list
 *   LOG        everything else by default
 *   UNRESOLVED the model cannot classify it: logged with a marker by default,
 *              held only where the owner has opted the box into enforce
 */
export type AdrDecision = 'BLOCK' | 'LOG' | 'UNRESOLVED';

/**
 * What the Phase 0 test asserts against `evaluateToolCall` at default config.
 *   allow      decision === 'allow'
 *   not-block  decision !== 'block'
 *   gate       decision !== 'allow'
 *   block      decision === 'block'
 *   any        the decision is not asserted (signals only)
 */
export type ExpectedVerdict = 'allow' | 'not-block' | 'gate' | 'block' | 'any';

/**
 *   settled           the expectation holds on main today and must keep holding
 *   known-gap         the expectation is agreed and FAILS on main today; run as
 *                     `it.failing`, so CI goes red the moment it starts passing
 *                     until the marker is removed and the epic line is ticked
 *   pending-decision  the correct verdict is not settled (owner or design
 *                     decision outstanding); `expect` pins TODAY's verdict so
 *                     any movement is deliberate and shows in the moved list
 *   note              a recorded constraint or classification with no call to
 *                     evaluate; never executed
 */
export type FixtureStatus = 'settled' | 'known-gap' | 'pending-decision' | 'note';

export type FixtureClass =
  | 'false-positive' // routine work the guard misreads
  | 'miss'           // a dangerous shape the guard does not stop
  | 'control'        // the paired case that must not move when its sibling is fixed
  | 'cost'           // scan cost grows faster than linearly
  | 'note';

export interface FixtureExpectation {
  verdict: ExpectedVerdict;
  /** Signals that must not appear on the verdict. */
  forbidSignals?: string[];
  /** Signals that must appear on the verdict. */
  requireSignals?: string[];
  /** Paths the script resolver must have been asked for (#738). */
  asksFor?: string[];
  /**
   * `cost` fixtures: the largest allowed time ratio between input size n and
   * 2n. Linear is about 2; quadratic is about 4. Measured as a best-of ratio,
   * never as wall clock against a budget (#519, #1040).
   */
  maxGrowthPerDoubling?: number;
}

export interface FrozenFixture {
  /** Stable id, `<issue>/<slug>`. Epic lines and PR moved-lists refer to this. */
  id: string;
  /** The epic line this fixture answers. */
  issue: number;
  /** The epic phase that is expected to make it pass. */
  phase: 1 | 2 | 3 | 4;
  class: FixtureClass;
  status: FixtureStatus;
  /** One line a reviewer can check against the issue. */
  what: string;
  /** Tool call as an enforcement plane sees it. Absent on `note` fixtures. */
  tool?: string;
  args?: Record<string, unknown>;
  /** `cost` fixtures build their call from a size. */
  build?: (n: number) => { tool: string; args: Record<string, unknown> };
  /** Input sizes for a `cost` fixture; consecutive entries double. */
  sizes?: number[];
  /** Stub resolver contents, keyed by the path the command names. */
  files?: Record<string, string>;
  /** Effect kinds the command model is expected to derive. */
  effects: EffectKind[];
  /** Targets the command model is expected to resolve. */
  targets: string[];
  /** Decision under the proposed ADR-002 v3. */
  adr: AdrDecision;
  expect?: FixtureExpectation;
  /** Why the status is what it is: the mechanism, or the open decision. */
  why: string;
}

/** Bash fixture shorthand. */
export const bash = (command: string): { tool: string; args: Record<string, unknown> } => ({
  tool: 'Bash',
  args: { command },
});
