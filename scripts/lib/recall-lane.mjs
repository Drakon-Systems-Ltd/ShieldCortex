/**
 * Lane detection + lane recall policy for the prompt-recall hook (#718).
 *
 * Recall used to be scoped by project key only. On a single-workspace host
 * every lane — the owner's chat, cron workers, a 15-minute watchdog liveness
 * probe — shares one project, so a personal memory was a recall candidate in
 * every unattended run. Two questions the hook now asks before injecting:
 *
 *   detectLane()        which lane is this turn?  interactive | cron | automation | subagent
 *   resolveLanePolicy() what may that lane see?   nothing | some categories | everything
 *
 * and applyLanePolicy() filters a candidate set accordingly.
 *
 * WHAT THE HOOK CAN SEE. The OpenClaw CLI backend gives the `claude` child no
 * lane: the session key (`agent:<id>:cron:<job>`, `…:subagent:<uuid>`, …)
 * stays in the gateway, and the env it passes is the gateway's own on every
 * turn. What does differ is the PROMPT, which OpenClaw builds per lane — so
 * detection keys on the markers below (literal strings from OpenClaw
 * 2026.9.x), plus an operator pin, SHIELDCORTEX_RECALL_LANE, for jobs that
 * run outside OpenClaw's own builders (e.g. a systemd probe).
 *
 * Markers can only ever RESTRICT recall: an owner who happens to type one
 * gets less recall on that turn, never more anywhere. An unrecognised turn
 * is `interactive`, because plain Claude Code use carries no lane signal at
 * all and must keep today's recall. A pin that is set but names no lane is
 * NOT unrecognised: it resolves to `automation` (#722 review R4).
 *
 * Safe defaults (override per lane in ~/.shieldcortex/config.json
 * `recallLanes: { cron: { recall, categories } }`):
 *   automation  → no recall (opt in with recallLanes.automation.recall = true)
 *   cron        → category IN (error, pattern, decision)
 *   subagent    → category IN (error, pattern, decision)
 *   interactive → everything
 *
 * One rule is NOT configurable: a non-interactive lane only ever receives
 * PUBLIC rows. INTERNAL / PERSONAL / CONFIDENTIAL / RESTRICTED rows — and
 * unlabelled rows, INTERNAL by convention — are interactive-owner only.
 */

import { dirname, resolve } from 'path';
import { fileURLToPath, pathToFileURL } from 'url';

export const LANES = Object.freeze({
  INTERACTIVE: 'interactive',
  CRON: 'cron',
  AUTOMATION: 'automation',
  SUBAGENT: 'subagent',
});

const VALID_LANES = new Set(Object.values(LANES));

/** detectLane()'s signal when SHIELDCORTEX_RECALL_LANE is set to something that is not a lane. */
export const INVALID_PIN_SIGNAL = 'env:SHIELDCORTEX_RECALL_LANE:invalid';

const NON_INTERACTIVE_CATEGORIES = Object.freeze(['error', 'pattern', 'decision']);

export const DEFAULT_LANE_POLICY = Object.freeze({
  interactive: Object.freeze({ recall: true, categories: null }),
  cron: Object.freeze({ recall: true, categories: NON_INTERACTIVE_CATEGORIES }),
  subagent: Object.freeze({ recall: true, categories: NON_INTERACTIVE_CATEGORIES }),
  automation: Object.freeze({ recall: false, categories: NON_INTERACTIVE_CATEGORIES }),
});

// Checked in this order — most restrictive lane first, so a prompt carrying
// two lanes' markers gets the narrower policy. Every pattern is anchored to a
// line start so a marker quoted mid-sentence does not count.
//
// The leading indent is horizontal whitespace only — `\s` minus every JS line
// terminator (\n \r \u2028 \u2029) — never `\s*`: with the m flag each of
// those starts a line, so an indent class that spans one re-scans the whole
// run from every line start. Quadratic: 30 s+ on 100 KB of blank lines against
// a 5 s hook budget (#722 review B1). The cron row's classes are disjoint and
// stop at the line end for the same reason. Keep both properties in any new row.
export const LANE_MARKERS = Object.freeze([
  // Liveness probes / heartbeats: unattended, nothing to recall for.
  { lane: LANES.AUTOMATION, signal: 'marker:liveness-check', pattern: /^[^\S\n\r\u2028\u2029]*Automated liveness check\b/im },
  { lane: LANES.AUTOMATION, signal: 'marker:heartbeat', pattern: /^[^\S\n\r\u2028\u2029]*Follow the heartbeat monitor scratch context\b/im },
  { lane: LANES.AUTOMATION, signal: 'marker:heartbeat', pattern: /^[^\S\n\r\u2028\u2029]*\[OpenClaw heartbeat poll\]/im },
  { lane: LANES.AUTOMATION, signal: 'marker:heartbeat', pattern: /^[^\S\n\r\u2028\u2029]*Read HEARTBEAT\.md\b/im },
  // Cron: isolated cron runs, cron events delivered to the main session.
  { lane: LANES.CRON, signal: 'marker:cron', pattern: /^[^\S\n\r\u2028\u2029]*\[cron:[^\]\s][^\]\n\r\u2028\u2029]*\]/im },
  { lane: LANES.CRON, signal: 'marker:cron', pattern: /^[^\S\n\r\u2028\u2029]*This is an unattended scheduled run\b/im },
  { lane: LANES.CRON, signal: 'marker:cron', pattern: /^[^\S\n\r\u2028\u2029]*A scheduled (?:reminder|cron event) (?:has been|was) triggered\b/im },
  { lane: LANES.CRON, signal: 'marker:cron', pattern: /^[^\S\n\r\u2028\u2029]*\[(?:Scheduled Run|OpenClaw cron wake)\]/im },
  // Subagents spawned by sessions_spawn.
  { lane: LANES.SUBAGENT, signal: 'marker:subagent', pattern: /^[^\S\n\r\u2028\u2029]*\[Subagent (?:Task|Context)\]/im },
]);

/**
 * @param {{ text?: string, env?: Record<string, string | undefined> }} input
 *   text — the prompt to inspect. Pass the SANITISED prompt: envelope history
 *   can quote another lane's markers.
 * @returns {{ lane: string, signal: string }}
 */
export function detectLane({ text = '', env = {} } = {}) {
  const pinned = String(env.SHIELDCORTEX_RECALL_LANE ?? '').trim().toLowerCase();
  if (VALID_LANES.has(pinned)) return { lane: pinned, signal: 'env:SHIELDCORTEX_RECALL_LANE' };
  // A pin that is SET but names no lane is a typo in a job someone meant to
  // pin — and the jobs that need a pin are exactly the ones whose prompts
  // carry no marker. Treating it like an absent pin let those turns fall
  // through to interactive and the owner's full recall (#722 review R4).
  // Fail safe: the most restrictive lane, with a signal the recall log shows.
  // Unset or blank stays "no pin" — that is how plain Claude Code runs.
  if (pinned !== '') return { lane: LANES.AUTOMATION, signal: INVALID_PIN_SIGNAL };
  const body = typeof text === 'string' ? text : '';
  for (const m of LANE_MARKERS) {
    if (m.pattern.test(body)) return { lane: m.lane, signal: m.signal };
  }
  return { lane: LANES.INTERACTIVE, signal: 'default' };
}

/**
 * Lane policy = defaults overlaid with config.recallLanes[lane]. Malformed
 * overrides are ignored field by field, never widened by accident.
 *
 * @returns {{ recall: boolean, categories: string[] | null }}
 */
export function resolveLanePolicy(lane, config = {}) {
  const base = DEFAULT_LANE_POLICY[lane] ?? DEFAULT_LANE_POLICY.automation;
  const override = config && typeof config.recallLanes === 'object' && config.recallLanes
    ? config.recallLanes[lane]
    : undefined;
  let { recall, categories } = base;
  if (override && typeof override === 'object') {
    if (typeof override.recall === 'boolean') recall = override.recall;
    if (override.categories === null) categories = null;
    else if (Array.isArray(override.categories)) {
      categories = override.categories.filter((c) => typeof c === 'string' && c.trim()).map((c) => c.trim().toLowerCase());
    }
  }
  return { recall, categories: categories ? [...categories] : null };
}

/**
 * The label normaliser the PUBLIC-only rule compares with (#722 review R1).
 *
 * It must be the one the read-side isolation gate uses —
 * `normaliseSensitivityLabel` in src/defence/sensitivity/isolation.ts: trim,
 * ASCII-only upper-casing, `null` for an absent/blank label. Unicode
 * `toUpperCase` (what this file used to call) folds `publıc` (dotless i) to
 * `PUBLIC` and admitted a label every other reader treats as unknown, i.e.
 * isolated. The helper is loaded from the build rather than copied, so the two
 * can never drift.
 *
 * Without a build there is no helper, and the fallback is the strictest
 * reading that cannot admit anything isolation.ts would not: only a string
 * that is exactly `PUBLIC` passes. A lower-case `public` row is withheld from
 * automated lanes until dist exists — fail closed, never wider.
 */
export function strictLabelNormaliser(level) {
  return level === 'PUBLIC' ? 'PUBLIC' : null;
}

let _labelNormaliser = null;
let _labelNormaliserKey = null;

/**
 * @param {string} [distRootOverride] test seam — point at an empty dir to get the fallback.
 * @returns {Promise<(level: unknown) => string | null>}
 */
export async function loadLabelNormaliser(distRootOverride) {
  const here = dirname(fileURLToPath(import.meta.url));
  const distRoot = distRootOverride ?? resolve(here, '..', '..', 'dist');
  if (_labelNormaliser && _labelNormaliserKey === distRoot) return _labelNormaliser;
  try {
    const mod = await import(pathToFileURL(resolve(distRoot, 'defence', 'sensitivity', 'isolation.js')).href);
    if (typeof mod.normaliseSensitivityLabel !== 'function') return strictLabelNormaliser;
    _labelNormaliser = mod.normaliseSensitivityLabel;
    _labelNormaliserKey = distRoot;
    return _labelNormaliser;
  } catch {
    return strictLabelNormaliser;
  }
}

/**
 * Split candidate rows into what this lane may receive and what it may not.
 * An absent or blank label is withheld (INTERNAL by convention), and so is
 * any label the normaliser does not turn into exactly `PUBLIC`.
 *
 * @param {(level: unknown) => string | null} [normaliseLabel] from loadLabelNormaliser();
 *   defaults to the fail-closed strictLabelNormaliser.
 * @returns {{ kept: object[], withheld: Array<{ row: object, reason: string }> }}
 */
export function applyLanePolicy(rows, lane, policy, normaliseLabel = strictLabelNormaliser) {
  const kept = [];
  const withheld = [];
  const list = Array.isArray(rows) ? rows : [];
  if (lane === LANES.INTERACTIVE) return { kept: [...list], withheld };
  const categories = policy && Array.isArray(policy.categories) ? new Set(policy.categories) : null;
  for (const row of list) {
    if (normaliseLabel(row?.sensitivity_level) !== 'PUBLIC') {
      withheld.push({ row, reason: 'lane_policy:sensitivity' });
    } else if (categories && !categories.has(String(row?.category ?? '').toLowerCase())) {
      withheld.push({ row, reason: 'lane_policy:category' });
    } else {
      kept.push(row);
    }
  }
  return { kept, withheld };
}
