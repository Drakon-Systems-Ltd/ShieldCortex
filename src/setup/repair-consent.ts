/**
 * ShieldCortex — what `shieldcortex repair` is allowed to do, and who said so (#156).
 *
 * Field report, 1 Aug 2026: an operator fixing his own install had to discover
 * and combine THREE environment variables, and omitting one bought him a
 * paragraph explaining why enforcement could not be proven. His words: "I had
 * to jump through 50 hoops … anyone experiencing this is going to think our
 * software is a piece of shit."
 *
 * He is right, and the inconsistency was ours: the RESTART gate already treated
 * an interactive terminal as consent, while RECONCILE and CANARY did not. Three
 * gates guarding related actions, with two different rules about what counts as
 * a human saying yes.
 *
 * The principle, stated once here: **typing `shieldcortex repair` at a terminal
 * IS the consent.** That is what the command means. A person at a TTY has asked
 * for exactly the thing the gates are gating.
 *
 * What this does NOT change — and these are the reasons the gates exist:
 *   - Headless, agent, cron and CI runs still require the explicit env vars.
 *     Those are the contexts the zeroth law is about: an agent running INSIDE
 *     the gateway must never restart it out from under itself and every
 *     in-flight turn on the host.
 *   - No gate is removed. `SHIELDCORTEX_ALLOW_GATEWAY_*` keeps working exactly
 *     as before for deliberate automation.
 *   - Under Jest, nothing is ever consented. Tests never touch a live gateway.
 *
 * So this is a consistency fix, not a loosening: it applies the RESTART gate's
 * existing rule to its two siblings.
 */

export interface ConsentEnvironment {
  /** The process env to read gates from. */
  env: NodeJS.ProcessEnv;
  /** Whether stdin is a TTY — i.e. a human is present. */
  isTty: boolean;
}

export interface RepairConsent {
  /** May apply the remediation plan (was SHIELDCORTEX_ALLOW_GATEWAY_RECONCILE). */
  reconcile: boolean;
  /** May restart the gateway (was SHIELDCORTEX_ALLOW_GATEWAY_RESTART). */
  restart: boolean;
  /** May drive the live enforcement canary (was SHIELDCORTEX_ALLOW_GATEWAY_CANARY). */
  canary: boolean;
  /** How consent was obtained, for the operator-facing summary. */
  source: 'interactive' | 'env' | 'none';
}

/**
 * Resolve what this invocation may do.
 *
 * An interactive terminal grants all three. Headless grants only what the
 * environment explicitly asks for, per-capability, exactly as before.
 */
export function resolveRepairConsent(ctx: ConsentEnvironment): RepairConsent {
  // A test runner is never a consenting human, whatever the TTY says.
  if (ctx.env.JEST_WORKER_ID !== undefined) {
    return { reconcile: false, restart: false, canary: false, source: 'none' };
  }

  const envReconcile = ctx.env.SHIELDCORTEX_ALLOW_GATEWAY_RECONCILE === '1';
  const envRestart = ctx.env.SHIELDCORTEX_ALLOW_GATEWAY_RESTART === '1';
  const envCanary = ctx.env.SHIELDCORTEX_ALLOW_GATEWAY_CANARY === '1';

  if (ctx.isTty) {
    return { reconcile: true, restart: true, canary: true, source: 'interactive' };
  }
  const any = envReconcile || envRestart || envCanary;
  return {
    reconcile: envReconcile,
    restart: envRestart,
    canary: envCanary,
    source: any ? 'env' : 'none',
  };
}

/**
 * The one line to print when a headless run can do nothing — naming every
 * capability at once, so an operator never discovers the gates one failed run
 * at a time.
 */
export const HEADLESS_CONSENT_HINT =
  'Run `shieldcortex repair` from a terminal and it will do all of this without flags. ' +
  'For automation, set SHIELDCORTEX_ALLOW_GATEWAY_RECONCILE=1 SHIELDCORTEX_ALLOW_GATEWAY_RESTART=1 SHIELDCORTEX_ALLOW_GATEWAY_CANARY=1.';
