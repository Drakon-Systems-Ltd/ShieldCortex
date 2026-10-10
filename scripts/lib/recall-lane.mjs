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
 * all and must keep today's recall.
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

export const LANES = Object.freeze({
  INTERACTIVE: 'interactive',
  CRON: 'cron',
  AUTOMATION: 'automation',
  SUBAGENT: 'subagent',
});

const VALID_LANES = new Set(Object.values(LANES));

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
export const LANE_MARKERS = Object.freeze([
  // Liveness probes / heartbeats: unattended, nothing to recall for.
  { lane: LANES.AUTOMATION, signal: 'marker:liveness-check', pattern: /^\s*Automated liveness check\b/im },
  { lane: LANES.AUTOMATION, signal: 'marker:heartbeat', pattern: /^\s*Follow the heartbeat monitor scratch context\b/im },
  { lane: LANES.AUTOMATION, signal: 'marker:heartbeat', pattern: /^\s*\[OpenClaw heartbeat poll\]/im },
  { lane: LANES.AUTOMATION, signal: 'marker:heartbeat', pattern: /^\s*Read HEARTBEAT\.md\b/im },
  // Cron: isolated cron runs, cron events delivered to the main session.
  { lane: LANES.CRON, signal: 'marker:cron', pattern: /^\s*\[cron:[^\]\s]+[^\]]*\]/im },
  { lane: LANES.CRON, signal: 'marker:cron', pattern: /^\s*This is an unattended scheduled run\b/im },
  { lane: LANES.CRON, signal: 'marker:cron', pattern: /^\s*A scheduled (?:reminder|cron event) (?:has been|was) triggered\b/im },
  { lane: LANES.CRON, signal: 'marker:cron', pattern: /^\s*\[(?:Scheduled Run|OpenClaw cron wake)\]/im },
  // Subagents spawned by sessions_spawn.
  { lane: LANES.SUBAGENT, signal: 'marker:subagent', pattern: /^\s*\[Subagent (?:Task|Context)\]/im },
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

function normaliseLabel(level) {
  if (level == null) return 'INTERNAL';
  const s = String(level).trim().toUpperCase();
  return s === '' ? 'INTERNAL' : s;
}

/**
 * Split candidate rows into what this lane may receive and what it may not.
 *
 * @returns {{ kept: object[], withheld: Array<{ row: object, reason: string }> }}
 */
export function applyLanePolicy(rows, lane, policy) {
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
