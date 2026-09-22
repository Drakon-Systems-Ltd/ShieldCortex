#!/usr/bin/env node
/**
 * ADR-002 measurement harness, Half A — logged-signal policy comparison
 * (#555, #556).
 *
 *   node scripts/guard-policy-replay.mjs <denials.jsonl> [--json out.json] [--md out.md] [--quiet]
 *
 * Reads an Action Guard log and, per policy, reports the HYPOTHETICAL tier match
 * (would this policy's signal set match the reconstructable signals) SEPARATELY
 * from the ACTUAL outcome the guard recorded (auto_denied / denied_no_prompt_
 * surface / warned / retry_granted / other). The two are never conflated:
 *
 *   - "actually stopped"   = events whose FINAL enforcement outcome stopped the
 *                            call (auto_denied or denied_no_prompt_surface, and
 *                            not later lifted by a retry grant). A `warned`
 *                            record emits NO permission decision and did NOT
 *                            stop anything (finding 4). A denials FILENAME does
 *                            not make every record a denial.
 *   - "hypothetical match" = of the reconstructable-signal events, how many a
 *                            policy's SIGNAL SET would match. This is NOT an
 *                            enforcement rate and there is no 100% baseline.
 *
 * Record contracts (round-2 finding 4, round-3, round-4 M1): a row is
 * classified by its DECLARED event + outcome pair
 * (`scripts/lib/guard-log-schema.mjs`), never by the presence of a signals
 * array. A row whose event and outcome agree on a denial or warning but lacks
 * signals is MALFORMED; a non-string `event`, a numeric notify status or an
 * array channel is MALFORMED; an event/outcome pair that disagrees is
 * CONTRADICTORY (`event-outcome-mismatch`, or `retry-event-mismatch` for a
 * retry outcome under the wrong event — two separate counters, never summed);
 * an event whose signals are redacted, empty, or outside the writer's
 * vocabulary is UNKNOWN. A `deliveredVia` of whitespace is not a channel; a
 * `delivered` status with no channel is a contradictory claim, not a validated
 * delivery — and a validated delivery is a transport report, never proof a
 * person saw it.
 *
 * Round-4 M1 — only VALIDATED ENFORCEMENT signals classify an event. A
 * malformed JSON row is never discarded before grouping: it is retained as a
 * `malformed` record of its event (by actionId / correlationId, or its own
 * line) and the whole event lands in the MALFORMED bucket. Signals carried on
 * a retry row or on a row with an outcome outside the writer's enum are
 * counted as STRAY, never unioned into the event's signal set, and make the
 * event UNKNOWN. Four event buckets — known / unknown / contradictory /
 * malformed — partition the events; none but known enters a denominator.
 *
 * Round-4 M2 — three independent lifecycles per actionId, each with its own
 * final state: ENFORCEMENT (the last DECISION row; the writer's final
 * notification copy of a denial — same event, outcome and signals, only the
 * notify object differs — is NEVER a new decision), RETRY (see round-5 M2
 * below) and NOTIFICATION (the last row that CARRIES a notify object; a retry
 * row without one does not reset it). A retry GRANT is NOT proof of execution
 * (finding 5).
 *
 * Round-5 M1 — INPUT ACCOUNTING and the declared-pair rule.
 *   (a) One input row is counted exactly once: `rows.total` is the number of
 *       non-blank lines and equals `rows.parsed + rows.malformed`; blank lines
 *       are counted separately (`rows.lines = total + blankLines`). Retaining a
 *       malformed object as a `malformed` record for correlation never adds a
 *       second count.
 *   (b) There is NO declared-pair shortcut. A retry row is validated against
 *       the SAME pinned schema as an enforcement row: `event` must be present,
 *       a string, and exactly `action_guard_denial` (the only event the retry
 *       writer emits). A retry row with a missing event is MALFORMED
 *       (`missing-event`); with a warning or any other event it is
 *       CONTRADICTORY (`retry-event-mismatch`). Neither is a `dnp_retry`
 *       record, so neither can set the retry lifecycle or make the event
 *       known. An event with no validated enforcement DECISION is never known
 *       and never "actually stopped", whatever its retry rows say.
 *   (c) LEGACY ACCEPTANCE (explicit, closed). Every shipped writer since the
 *       first `denials.jsonl` writer (#247, 12 Aug 2026) has written `event`,
 *       `outcome`, `signals`, `severity`, `tool` and `detectedAt` on every
 *       enforcement row. Rows written before #284 (12–14 Aug 2026) lack
 *       `origin`, `actionId`, `sessionId` and `notify`; `correlationId` was
 *       optional. The ONLY pre-schema tolerance this tool grants is therefore:
 *         - no `notify` object        → accepted; notification lifecycle `none`;
 *         - no `actionId`             → accepted; grouped by `correlationId`,
 *                                       else by its own line;
 *         - no `origin` / `sessionId` → accepted; never read.
 *       The pinned schema the validator enforces covers FOUR fields — `event`,
 *       `outcome`, `signals`, `notify` — and nothing else. Within those, every
 *       departure is rejected as MALFORMED with a named reason: no `event`, no
 *       `outcome` (absent, empty or non-string), a non-string `event`, an
 *       agreeing denial/warning pair without `signals`, a non-array or
 *       non-string signal member, a non-object notify, a non-string notify
 *       status or channel. No missing field is inferred from another. The
 *       reported reason is the first failing check in this order:
 *       `missing-outcome`, `event-not-string`, signals problems, notify
 *       problems, `missing-event`.
 *       The other fields are READ PERMISSIVELY and never validated: a missing
 *       or non-string `severity` / `tool` projects to `other`; a missing or
 *       non-string `detectedAt` is an empty timestamp; a missing or non-string
 *       `actionId` / `correlationId` falls through to the next grouping key.
 *       A string `event` / `outcome` outside the enum on a non-retry row is
 *       an unrecognised-outcome record (UNKNOWN bucket), not malformed.
 *
 * Round-5 M2 — the RETRY lifecycle is a HISTORY, not last-row-wins. Over the
 * validated retry rows of an event, in time order:
 *   - `grantSeen`  becomes true once ANY validated `retry_granted` is observed
 *                  and never goes back to false;
 *   - `effective`  is the current retry state in
 *                  { none, granted, denied, revoked, failed, unknown }:
 *                    retry_granted      → granted
 *                    retry_denied       → denied   (a grant, if any, is spent/withdrawn)
 *                    retry_revoked      → revoked  (reserved: the writer records a
 *                                         revocation only inside `reason` text,
 *                                         which this tool never reads → 0 today)
 *                    retry_grant_failed → failed when no grant has been seen;
 *                                         UNKNOWN when a grant HAS been seen — a
 *                                         failed re-issue after a grant is not a
 *                                         revocation and does not restore the stop;
 *   - `history`    is the ordered list of validated retry states.
 * "Actually stopped" = enforcement final is a stop outcome AND the effective
 * retry state is neither `granted` nor `unknown`. The public projection carries
 * the effective-state distribution, the number of events with a grant seen, and
 * the distribution of compact history patterns (state sequences), so an earlier
 * grant is never dropped from the output — while actionIds themselves never
 * leave the tool.
 *
 * NOT a classifier replay (the command surface is redacted, so no command is
 * re-run) and NOT an effect measurement (Half B does that).
 *
 * Privacy (finding 3, round-3): ONE export projection (`projectPublic`) feeds
 * both the JSON and the Markdown. It copies counts, and strings ONLY through
 * the closed sets in `guard-log-schema.mjs`: a signal name is printed only by
 * MEMBERSHIP in the writer's vocabulary (not by matching a pattern) and every
 * other signal is counted under one redacted bucket; event / outcome / notify
 * status / channel / severity / tool are each mapped to their enum or `other`.
 * No `reason`, `surface`, session/correlation ids, payloads or command text are
 * ever read into the summary at all.
 *
 * Node core only. Exports its functions for the harness test; runs `main` only
 * when invoked directly.
 */
import { readFileSync, writeFileSync, realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  POLICIES, gates, gatingSignals, SIGNAL_FAMILY, INJECTION_FLAVOURED,
  NEVER_LOGGED_SIGNALS, REDACTED_MARKER, SCHEMA_OR_SCAN_GAP,
} from './lib/guard-policy-sets.mjs';
import {
  DENIAL_OUTCOMES, WARNING_OUTCOMES, RETRY_OUTCOMES, EVENT_ENUM, DELIVERY_CLAIM_STATUSES,
  publicEvent, publicOutcome, publicNotifyStatus, publicChannel, publicSeverity, publicTool,
  isVocabularySignal, publicSignalName, validateNotify, REDACTED_SIGNAL_LABEL, OTHER,
} from './lib/guard-log-schema.mjs';

export const BANNER = [
  '=== LOGGED-SIGNAL POLICY COMPARISON ===',
  'NOT a classifier replay and NOT an effect-achieved measurement.',
  'Two axes are reported SEPARATELY and never conflated: (1) ACTUAL outcome the guard recorded',
  '(auto_denied / denied_no_prompt_surface actually stopped the call; warned did NOT — it emits',
  'no permission decision; retry_granted re-offered one scoped attempt), and (2) HYPOTHETICAL',
  'signal-set match per policy, which is NOT an enforcement rate. A denials filename does not',
  'make every record a denial. Known, unknown, contradictory and malformed are four separate event',
  'buckets; all but known are excluded from every %. Only validated enforcement signals classify an',
  'event, and only vocabulary signal names are printed.',
].join('\n');

const INJECTION_SET = new Set(INJECTION_FLAVOURED);
const SCHEMA_SET = new Set(SCHEMA_OR_SCAN_GAP);
const DENIAL_SET = new Set(DENIAL_OUTCOMES);
const WARNING_SET = new Set(WARNING_OUTCOMES);
const RETRY_SET = new Set(RETRY_OUTCOMES);
const EVENT_SET = new Set(EVENT_ENUM);
const STOPPED_OUTCOMES = new Set(['auto_denied', 'denied_no_prompt_surface', 'failure_denied']);
const CLAIM_SET = new Set(DELIVERY_CLAIM_STATUSES);

/** Public-safe signal name (kept as an export for the tests): membership, not syntax. */
export const safeSignalName = publicSignalName;

// ── 1. Parse + classify: every line accounted for, record kinds discriminated ─

/**
 * Classify a row by its DECLARED event + outcome contract. Round-5 M1(b):
 * there is no shortcut for any outcome — a retry outcome needs a present,
 * string `event` equal to `action_guard_denial` exactly as a denial does; a
 * missing event is never classified into a lifecycle (it is malformed, see
 * `rowProblem`), and a retry outcome under any other event is contradictory.
 * @param {object} row
 * @returns {{ kind: 'denial'|'warning'|'dnp_retry'|'contradictory'|'other', retry?: string, reason?: string }}
 */
export function classifyRecord(row) {
  const outcome = typeof row.outcome === 'string' ? row.outcome : '';
  const event = typeof row.event === 'string' ? row.event : null;
  if (event === null) return { kind: 'other', reason: 'missing-event' };
  if (RETRY_SET.has(outcome)) {
    return event === 'action_guard_denial'
      ? { kind: 'dnp_retry', retry: outcome }
      : { kind: 'contradictory', reason: 'retry-event-mismatch' };
  }
  if (!EVENT_SET.has(event)) return { kind: 'other', reason: 'unknown-event' };
  const byOutcome = DENIAL_SET.has(outcome) ? 'denial' : WARNING_SET.has(outcome) ? 'warning' : null;
  if (!byOutcome) return { kind: 'other', reason: 'unknown-outcome' };
  const byEvent = event === 'action_guard_denial' ? 'denial' : 'warning';
  if (byEvent !== byOutcome) return { kind: 'contradictory', reason: 'event-outcome-mismatch' };
  return { kind: byOutcome };
}

/**
 * A signals member, when present, must be an array of strings; a denial or
 * warning REQUIRES it. Returns the malformed reason or null.
 */
function signalsProblem(row, kind) {
  if (row.signals === undefined || row.signals === null) {
    return kind === 'denial' || kind === 'warning' ? 'missing-signals' : null;
  }
  if (!Array.isArray(row.signals)) return 'signals-not-array';
  if (!row.signals.every(s => typeof s === 'string')) return 'signal-member-not-string';
  return null;
}

const NO_NOTIFY = Object.freeze({ present: false, status: null, claimsDelivery: false, channel: null, channelPresent: false });

/** The fields a record carries; ids are grouping keys only and never leave the tool. */
function baseRecord(row, lineNo) {
  return {
    lineNo,
    actionId: typeof row.actionId === 'string' ? row.actionId : '',
    correlationId: typeof row.correlationId === 'string' ? row.correlationId : '',
    detectedAt: typeof row.detectedAt === 'string' ? row.detectedAt : '',
    severity: publicSeverity(row.severity), tool: publicTool(row.tool),
    event: publicEvent(row.event), outcome: publicOutcome(row.outcome),
  };
}

/**
 * Validate one JSON object row against the writer's schema. Returns the
 * malformed reason, or null when the row conforms to its declared contract.
 * The same checks apply to every row kind (M1(b)): a retry row is not exempt
 * from any of them. Check order (first failure is the reported reason):
 * missing-outcome, event-not-string, signals, notify, missing-event.
 * The legacy tolerances (M1(c)) are exactly: no notify object, no actionId,
 * no origin / sessionId. A missing `event` is NOT legacy — no shipped writer
 * ever omitted it — so it is malformed. Only `event`, `outcome`, `signals`
 * and `notify` are checked here; `severity`, `tool`, `detectedAt` and the ids
 * are read permissively in `baseRecord` and never produce a malformed reason.
 */
function rowProblem(row, cls) {
  if (typeof row.outcome !== 'string' || row.outcome === '') return 'missing-outcome';
  if (row.event !== undefined && row.event !== null && typeof row.event !== 'string') return 'event-not-string';
  const sp = signalsProblem(row, cls.kind);
  if (sp) return sp;
  const nv = validateNotify(row);
  if (!nv.ok) return nv.reason;
  if (row.event === undefined || row.event === null) return 'missing-event';
  return null;
}

/**
 * @param {string} text
 */
export function parseDenials(text) {
  const records = [];
  const malformed = [];
  let blankLines = 0;
  // Round-5 M1(a): every non-blank line is counted ONCE, here, as it is read.
  // `parsed` counts rows that conformed to their declared contract; every
  // other non-blank line is in `malformed`. total === parsed + malformed by
  // construction — retaining a malformed object as a record below adds
  // nothing to any count.
  let total = 0, parsed = 0;
  const lines = text.split(/\r?\n/);
  lines.forEach((line, i) => {
    const lineNo = i + 1;
    if (line.trim() === '') { blankLines++; return; }
    total++;
    let row;
    try { row = JSON.parse(line); } catch { malformed.push({ lineNo, reason: 'not-json' }); return; }
    if (row === null || typeof row !== 'object' || Array.isArray(row)) { malformed.push({ lineNo, reason: 'not-object' }); return; }
    const cls = classifyRecord(row);
    const problem = rowProblem(row, cls);
    if (problem) {
      // M1: a malformed JSON row is counted (once, in `malformed`) AND
      // retained as a `malformed` record so it stays part of its event (same
      // actionId / correlationId) and marks that event malformed. Nothing
      // else is read from it: no signals, no notify — a row that failed its
      // contract carries no evidence, only the fact that it exists.
      malformed.push({ lineNo, reason: problem });
      records.push({ ...baseRecord(row, lineNo), kind: 'malformed', retry: null, reason: problem, signals: [], straySignals: 0, notify: NO_NOTIFY });
      return;
    }
    parsed++;
    const nv = validateNotify(row);
    const raw = Array.isArray(row.signals) ? [...new Set(row.signals.map(s => s.trim()).filter(Boolean))] : [];
    // M1: only a validated ENFORCEMENT row (denial / warning by declared
    // contract) contributes signals. A retry row or an unknown-outcome row
    // that carries signals has them counted as STRAY and dropped.
    const enforcement = cls.kind === 'denial' || cls.kind === 'warning';
    const signals = enforcement ? raw : [];
    const straySignals = enforcement ? 0 : raw.length;
    // Only these fields ever leave the row; every label is enum-mapped here, once.
    records.push({
      ...baseRecord(row, lineNo),
      kind: cls.kind, retry: cls.retry ?? null, reason: cls.reason ?? null,
      signals, straySignals,
      notify: {
        present: nv.status !== null || nv.channel !== null,
        status: nv.status === null ? null : publicNotifyStatus(nv.status),
        claimsDelivery: nv.status !== null && CLAIM_SET.has(nv.status),
        channel: nv.channel === null ? null : publicChannel(nv.channel),
        channelPresent: nv.channel !== null,
      },
    });
  });
  if (lines.length && lines[lines.length - 1] === '') blankLines--;
  const rows = { total, parsed, malformed: malformed.length, blankLines, lines: total + blankLines };
  return { records, malformed, blankLines, rows };
}

// ── 2. Group: full lifecycle per event, nothing wins by position ─────────────

/**
 * @param {ReturnType<typeof parseDenials>['records']} records
 */
export function groupEvents(records) {
  const byKey = new Map();
  for (const r of records) {
    const key = r.actionId ? `aid:${r.actionId}` : r.correlationId ? `corr:${r.correlationId}` : `line:${r.lineNo}`;
    const keyKind = r.actionId ? 'actionId' : r.correlationId ? 'correlationId' : 'line';
    if (!byKey.has(key)) byKey.set(key, { key, keyKind, records: [] });
    byKey.get(key).records.push(r);
  }
  const events = [];
  for (const ev of byKey.values()) {
    ev.records.sort((a, b) => (a.detectedAt < b.detectedAt ? -1 : a.detectedAt > b.detectedAt ? 1 : a.lineNo - b.lineNo));
    const enforcement = ev.records.filter(r => r.kind === 'denial' || r.kind === 'warning');
    const retries = ev.records.filter(r => r.kind === 'dnp_retry');
    const malformedRowReasons = ev.records.filter(r => r.kind === 'malformed').map(r => r.reason);
    const malformedRows = malformedRowReasons.length;
    const unrecognisedOutcomeRows = ev.records.filter(r => r.kind === 'other').length;
    const straySignals = ev.records.reduce((n, r) => n + r.straySignals, 0);
    // M1: the signal set is the union over VALIDATED ENFORCEMENT rows only.
    const union = [...new Set(enforcement.flatMap(x => x.signals))];

    // M2 — ENFORCEMENT lifecycle. The writer re-emits a denial/warning row with
    // the same event, outcome and signals once notification settles ("were
    // they told"); that copy is NOT a new decision. A row is a DECISION unless
    // an earlier enforcement row of the event already carries the same
    // (event, outcome, signal set).
    const decisions = [];
    let notifyCopies = 0;
    for (const r of enforcement) {
      const dup = decisions.some(d => d.event === r.event && d.outcome === r.outcome && sameSet(d.signals, r.signals));
      if (dup) notifyCopies++; else decisions.push(r);
    }
    const firstDecision = decisions.length ? decisions[0] : null;
    const lastDecision = decisions.length ? decisions[decisions.length - 1] : null;
    const enfOutcomes = [...new Set(decisions.map(x => x.outcome))];
    const enforcementFinal = lastDecision ? enforcementState(lastDecision.outcome) : 'none';

    // M2 (round 4 + round 5) — RETRY / REVOCATION lifecycle: a HISTORY over
    // the VALIDATED retry rows only (`dnp_retry` kind — a retry row that
    // failed the schema or carried the wrong event is malformed /
    // contradictory and never reaches here). `grantSeen` latches on the first
    // validated grant; `effective` is the current state; a grant_failed AFTER
    // a grant is a failed re-issue (effective UNKNOWN), never a revocation.
    const retryOutcomes = retries.map(r => r.retry);
    const retry = retryLifecycle(retryOutcomes);
    const retryGranted = retry.effective === 'granted';

    // M2 — NOTIFICATION lifecycle: the LAST row that carries a notify object.
    // A retry row (which never carries one) does not reset it to none.
    const notifyRows = ev.records.filter(r => r.notify.present);
    const lastNotify = notifyRows.length ? notifyRows[notifyRows.length - 1].notify : NO_NOTIFY;
    const anyValidatedDelivery = ev.records.some(r => r.notify.claimsDelivery && r.notify.channelPresent);
    const notificationFinal = notificationState(lastNotify);

    // Actually stopped: a validated enforcement DECISION ended in a stop AND
    // the effective retry state is neither granted nor unknown (M1(b): no
    // decision → never stopped; M2: a grant followed by a failed re-issue is
    // unresolved, not a restored stop) AND every row of the event validated
    // (M1(b): a malformed or contradictory row — e.g. an unvalidated retry
    // row — is not accepted as a grant, but it is not ignored either: the stop
    // is then UNCONFIRMED, never counted as stopped). A grant is still not
    // execution proof.
    const stopDecided = STOPPED_OUTCOMES.has(enforcementFinal);
    const evidenceIntact = malformedRows === 0 && !ev.records.some(r => r.kind === 'contradictory');
    const actuallyStopped = stopDecided && evidenceIntact && retry.effective !== 'granted' && retry.effective !== 'unknown';
    const stopUnconfirmed = stopDecided && !evidenceIntact;
    const finalEnfOutcome = lastDecision ? lastDecision.outcome : (retries.length ? 'retry-only' : 'none');

    // Contradictions (finding 4): the evidence disagrees with itself. Each
    // row-level contradiction reason is its OWN entry (#559 follow-up): a
    // retry outcome under the wrong event (`retry-event-mismatch`) is never
    // folded into a disagreeing enforcement pair (`event-outcome-mismatch`).
    const contradictions = [];
    const rowReasons = new Set(ev.records.filter(r => r.kind === 'contradictory').map(r => r.reason));
    for (const reason of CONTRADICTORY_ROW_REASONS) if (rowReasons.delete(reason)) contradictions.push(reason);
    for (const reason of rowReasons) contradictions.push(typeof reason === 'string' && reason ? reason : 'contradictory-row');
    if (enfOutcomes.length > 1) contradictions.push('conflicting-enforcement-outcomes');
    if (ev.records.some(r => r.notify.claimsDelivery && !r.notify.channelPresent)) contradictions.push('delivery-claimed-without-channel');

    const firstRec = ev.records[0];
    const lastRec = ev.records[ev.records.length - 1];
    events.push({
      key: ev.key, keyKind: ev.keyKind,
      recordCount: ev.records.length,
      kinds: [...new Set(ev.records.map(r => r.kind))],
      malformedRows, malformedRowReasons, unrecognisedOutcomeRows, straySignals,
      hasEnforcement: decisions.length > 0,
      finalEnfOutcome, enfOutcomes,
      conflictingOutcome: enfOutcomes.length > 1,
      contradictions,
      lifecycle: {
        enforcement: { final: enforcementFinal, decisions: decisions.length, notifyCopies },
        retry,
        notification: { final: notificationFinal, anyValidatedDelivery },
      },
      retryOutcomes, retryGranted, actuallyStopped, stopUnconfirmed,
      signals: union,
      unrecognisedSignals: union.filter(s => !isVocabularySignal(s)).length,
      signalDrift: !sameSet(firstDecision ? firstDecision.signals : [], lastDecision ? lastDecision.signals : []),
      redacted: union.includes(REDACTED_MARKER),
      severity: (lastDecision ?? lastRec).severity,
      tool: (lastDecision ?? lastRec).tool,
      event: (lastDecision ?? lastRec).event,
      // Delivery across ALL records: a validated delivery is a claim status WITH a channel.
      anyValidatedDelivery,
      finalNotify: lastNotify,
      firstNotify: firstRec.notify,
      coalescedEver: ev.records.some(r => r.notify.status === 'coalesced'),
      suppressedEver: ev.records.some(r => r.notify.status === 'suppressed'),
      detectedAt: lastRec.detectedAt,
    });
  }
  return events;
}

const sameSet = (a, b) => a.length === b.length && a.every(s => b.includes(s));

/**
 * Row-level contradiction reasons `classifyRecord` can emit, in the order they
 * are listed on an event (the first is the event's bucket reason). Each is
 * reported under its own name in `contradictoryReasons`; the event-level
 * `conflicting-enforcement-outcomes` and `delivery-claimed-without-channel`
 * follow them.
 */
export const CONTRADICTORY_ROW_REASONS = Object.freeze(['event-outcome-mismatch', 'retry-event-mismatch']);

/** Closed lifecycle states (M2). Each is projected verbatim; anything else is `other`. */
export const ENFORCEMENT_STATES = Object.freeze(['none', ...DENIAL_OUTCOMES, ...WARNING_OUTCOMES, 'other']);
export const RETRY_STATES = Object.freeze(['none', 'granted', 'denied', 'failed', 'revoked', 'unknown']);
export const NOTIFICATION_STATES = Object.freeze(['none', 'delivered', 'failed', 'suppressed', 'unknown']);
/** Longest retry history pattern printed verbatim; longer ones end in `more`. */
export const RETRY_HISTORY_MAX = 8;

/**
 * Round-5 M2 — project the ordered VALIDATED retry outcomes of one event into
 * its retry lifecycle: `{ effective, grantSeen, history }`.
 *   none    — no validated retry row;
 *   granted — the latest state is a grant;
 *   denied  — the latest state is a denial (a prior grant, if any, is withdrawn);
 *   revoked — reserved (see `retryState`);
 *   failed  — a grant_failed with NO grant ever seen;
 *   unknown — a grant_failed AFTER a grant was seen (a failed re-issue; the
 *             earlier grant is neither confirmed nor revoked), or a retry
 *             outcome the state mapper does not recognise.
 * `grantSeen` is true once any validated grant is observed and never resets.
 */
export function retryLifecycle(retryOutcomes) {
  let effective = 'none', grantSeen = false;
  const history = [];
  for (const o of retryOutcomes ?? []) {
    const st = retryState(o);
    history.push(st);
    if (st === 'granted') { grantSeen = true; effective = 'granted'; }
    else if (st === 'denied') effective = 'denied';
    else if (st === 'revoked') effective = 'revoked';
    else if (st === 'failed') effective = grantSeen ? 'unknown' : 'failed';
    else effective = 'unknown';
  }
  return { effective, grantSeen, history };
}

/** Compact, closed pattern key for a retry history: states joined by ' -> ', capped. */
export function retryHistoryKey(history) {
  const states = (history ?? []).map(s => (RETRY_STATES.includes(s) ? s : OTHER));
  if (states.length === 0) return 'none';
  const shown = states.slice(0, RETRY_HISTORY_MAX);
  if (states.length > RETRY_HISTORY_MAX) shown.push('more');
  return shown.join(' -> ');
}

/** Enforcement final state from the last DECISION row's outcome. */
export function enforcementState(outcome) {
  return DENIAL_SET.has(outcome) || WARNING_SET.has(outcome) ? outcome : 'other';
}

/**
 * Retry state of ONE validated retry row. `revoked` is reserved: the current
 * writer records a revocation only inside the `reason` text of a
 * `retry_denied` row, which this tool never reads, so it is 0 by construction.
 * Anything outside the retry enum maps to `none` (it cannot be a `dnp_retry`
 * record in the first place, see `classifyRecord`).
 */
export function retryState(retryOutcome) {
  if (retryOutcome === 'retry_granted') return 'granted';
  if (retryOutcome === 'retry_denied') return 'denied';
  if (retryOutcome === 'retry_grant_failed') return 'failed';
  if (retryOutcome === 'retry_revoked') return 'revoked';
  return 'none';
}

/**
 * Notification final state from the last notify-bearing row:
 *   none       — no row carried a notify object, or nothing was attempted
 *                (`not_configured`, `no_channel`);
 *   delivered  — a delivery claim WITH a channel (validated transport report);
 *   failed     — `error`;
 *   suppressed — `suppressed` or `coalesced` (folded into another alert);
 *   unknown    — `pending`, a delivery claim without a channel, or a status
 *                outside the writer's enum.
 */
export function notificationState(notify) {
  if (!notify || !notify.present || notify.status === null) return notify && notify.channelPresent ? 'unknown' : 'none';
  const st = notify.status;
  if (st === 'not_configured' || st === 'no_channel') return 'none';
  if (notify.claimsDelivery) return notify.channelPresent ? 'delivered' : 'unknown';
  if (st === 'error') return 'failed';
  if (st === 'suppressed' || st === 'coalesced') return 'suppressed';
  return 'unknown';
}

// ── 3. Analyse ────────────────────────────────────────────────────────────────

const counter = () => new Map();
const bump = (m, k, n = 1) => m.set(k, (m.get(k) ?? 0) + n);
const sortedObj = (m) => Object.fromEntries([...m.entries()].sort((a, b) => b[1] - a[1] || String(a[0]).localeCompare(String(b[0]))));

/**
 * Which of the FOUR evidence buckets an event lands in, with the reason.
 * malformed > contradictory > unknown > known: a schema failure anywhere in
 * the event outranks a semantic reading of the rest of it.
 */
export function bucketOf(e) {
  if (e.malformedRows > 0) return { bucket: 'malformed', reason: 'malformed-row-in-event' };
  if (e.contradictions.length) return { bucket: 'contradictory', reason: e.contradictions[0] };
  if (!e.hasEnforcement) return { bucket: 'unknown', reason: 'retry-or-other-only' };
  if (e.straySignals > 0) return { bucket: 'unknown', reason: 'signals-on-non-enforcement-row' };
  if (e.unrecognisedOutcomeRows > 0) return { bucket: 'unknown', reason: 'unrecognised-outcome-row' };
  if (e.signals.length === 0) return { bucket: 'unknown', reason: 'empty-signals' };
  if (e.redacted) return { bucket: 'unknown', reason: e.signals.length === 1 ? 'redacted-only' : 'redacted-plus-partial' };
  if (e.unrecognisedSignals > 0) return { bucket: 'unknown', reason: 'signal-outside-vocabulary' };
  return { bucket: 'known', reason: null };
}

/**
 * @param {ReturnType<typeof groupEvents>} events
 * @param {ReturnType<typeof parseDenials>} parse — the parser's own result; its
 *   `rows` accounting is the ONLY source of the row counts (M1(a)). A caller
 *   that re-derives a total from record arrays is refused.
 */
export function analyse(events, parse) {
  if (!parse || !parse.rows || !Array.isArray(parse.malformed)) {
    throw new Error('analyse: pass the parseDenials() result; row counts are never re-derived from record arrays (round-5 M1a)');
  }
  const buckets = events.map(e => ({ e, ...bucketOf(e) }));
  const known = buckets.filter(b => b.bucket === 'known').map(b => b.e);
  const unknown = buckets.filter(b => b.bucket === 'unknown').map(b => b.e);
  const contradictory = buckets.filter(b => b.bucket === 'contradictory').map(b => b.e);
  const malformedEvents = buckets.filter(b => b.bucket === 'malformed').map(b => b.e);
  const signalless = events.filter(e => e.signals.length === 0);

  const unknownReasons = counter(), contradictoryReasons = counter(), malformedReasons = counter(), malformedEventReasons = counter();
  for (const b of buckets) if (b.bucket === 'unknown') bump(unknownReasons, b.reason);
  for (const e of contradictory) for (const c of e.contradictions) bump(contradictoryReasons, c);
  for (const m of parse.malformed) bump(malformedReasons, m.reason);
  // Event-level malformed reasons: the reasons of the malformed rows retained inside each malformed event.
  for (const e of malformedEvents) for (const r of e.malformedRowReasons) bump(malformedEventReasons, r);

  // M2: the three lifecycles, aggregated. Each final-state distribution is
  // over ALL events (a lifecycle exists for every event; `none` is a state).
  const lifecycles = {
    enforcement: { final: counter(), decisions: counter(), notifyCopies: 0 },
    // Round-5 M2: effective-state distribution, events with a grant seen, and
    // the distribution of compact history patterns — the earlier grant of a
    // grant → grant_failed event survives here as `granted -> failed`.
    retry: { effective: counter(), grantSeen: 0, histories: counter() },
    notification: { final: counter(), anyValidatedDelivery: 0 },
  };
  for (const e of events) {
    bump(lifecycles.enforcement.final, e.lifecycle.enforcement.final);
    bump(lifecycles.enforcement.decisions, String(e.lifecycle.enforcement.decisions));
    lifecycles.enforcement.notifyCopies += e.lifecycle.enforcement.notifyCopies;
    bump(lifecycles.retry.effective, e.lifecycle.retry.effective);
    if (e.lifecycle.retry.grantSeen) lifecycles.retry.grantSeen++;
    bump(lifecycles.retry.histories, retryHistoryKey(e.lifecycle.retry.history));
    bump(lifecycles.notification.final, e.lifecycle.notification.final);
    if (e.lifecycle.notification.anyValidatedDelivery) lifecycles.notification.anyValidatedDelivery++;
  }

  const keyKinds = counter(), recordsPerEvent = counter(), outcomeTransitions = counter();
  let multiRecord = 0, conflicting = 0, drift = 0;
  for (const e of events) {
    bump(keyKinds, e.keyKind);
    bump(recordsPerEvent, String(e.recordCount));
    if (e.recordCount > 1) multiRecord++;
    if (e.conflictingOutcome) { conflicting++; bump(outcomeTransitions, e.enfOutcomes.join(' -> ')); }
    if (e.signalDrift) drift++;
  }

  // ACTUAL outcome accounting (finding 4) — what the guard truly did, read
  // from the lifecycle finals (M2), never from row position.
  const actual = { actuallyStopped: 0, stopUnconfirmed: 0, warnedOnly: 0, retryGranted: 0, retryDeniedOrFailed: 0, retryUnresolved: 0, other: 0 };
  const finalEnfDist = counter();
  for (const e of events) {
    bump(finalEnfDist, e.finalEnfOutcome);
    const enf = e.lifecycle.enforcement.final, retry = e.lifecycle.retry.effective;
    if (e.actuallyStopped) actual.actuallyStopped++;
    else if (e.stopUnconfirmed) actual.stopUnconfirmed++;
    else if (retry === 'granted') actual.retryGranted++;
    else if (retry === 'denied' || retry === 'failed' || retry === 'revoked') actual.retryDeniedOrFailed++;
    else if (retry === 'unknown') actual.retryUnresolved++;
    else if (enf === 'warned' || enf === 'failure_allowed') actual.warnedOnly++;
    else actual.other++;
  }

  const severityAll = counter(), toolAll = counter(), eventKindAll = counter(), recordKindAll = counter();
  for (const e of events) { bump(severityAll, e.severity); bump(toolAll, e.tool); bump(eventKindAll, e.event); for (const k of e.kinds) bump(recordKindAll, k); }

  // Delivery across ALL records (finding 7) — a transport report, never "person reached".
  const delivery = { anyValidatedDelivery: 0, coalescedEver: 0, suppressedEver: 0, finalStatus: counter(), unknownFinal: 0, claimedWithoutChannel: 0 };
  for (const e of events) {
    if (e.anyValidatedDelivery) delivery.anyValidatedDelivery++;
    if (e.coalescedEver) delivery.coalescedEver++;
    if (e.suppressedEver) delivery.suppressedEver++;
    if (e.contradictions.includes('delivery-claimed-without-channel')) delivery.claimedWithoutChannel++;
    const st = e.finalNotify.status ?? 'none';
    bump(delivery.finalStatus, `${st} via=${e.finalNotify.channel ?? 'none'}`);
    if (st === 'none' || st === 'pending') delivery.unknownFinal++;
  }

  const isInjection = (e) => e.signals.some(s => INJECTION_SET.has(s));
  const injection = known.filter(isInjection);
  const rest = known.filter(e => !isInjection(e));

  // Policy comparison: HYPOTHETICAL signal-set match over KNOWN events only.
  const policies = POLICIES.map(p => {
    const matched = known.filter(e => gates(p, e.signals));
    const matchedInj = injection.filter(e => gates(p, e.signals)).length;
    const matchedRest = rest.filter(e => gates(p, e.signals)).length;
    const matchedAndStopped = matched.filter(e => e.actuallyStopped).length;
    const matchedBy = counter();
    for (const e of matched) for (const s of gatingSignals(p, e.signals)) bump(matchedBy, s);
    const unknownLowerBound = unknown.filter(e => gates(p, e.signals.filter(s => s !== REDACTED_MARKER))).length;
    return {
      id: p.id, label: p.label,
      hypotheticalMatch: matched.length,
      hypotheticalNoMatch: known.length - matched.length,
      matchedAndActuallyStopped: matchedAndStopped,
      injectionMatched: matchedInj, injectionNoMatch: injection.length - matchedInj,
      restMatched: matchedRest, restNoMatch: rest.length - matchedRest,
      matchedBySignal: sortedObj(matchedBy),
      unknownLowerBoundMatch: unknownLowerBound,
    };
  });

  const broad = POLICIES.find(p => p.id === 'broad-floor');
  const broadPlusEgress = { gateSet: new Set([...broad.gateSet, 'external-egress', 'network-egress']) };
  const broadMatched = known.filter(e => gates(broad, e.signals)).length;
  const broadPlusEgressMatched = known.filter(e => gates(broadPlusEgress, e.signals)).length;

  // Per-signal table over KNOWN events: every name here is a vocabulary member
  // by construction (an event with any other name is in the unknown bucket).
  const perSignal = new Map();
  for (const e of known) {
    for (const s of e.signals) {
      if (!perSignal.has(s)) {
        perSignal.set(s, {
          signal: s,
          family: SIGNAL_FAMILY[s] ?? 'unclassified',
          events: 0,
          injectionFlavoured: INJECTION_SET.has(s),
          policies: Object.fromEntries(POLICIES.map(p => [p.id, { matched: 0, noMatch: 0, gatesByItself: p.gateSet.has(s) }])),
        });
      }
      const slot = perSignal.get(s);
      slot.events++;
      for (const p of POLICIES) { if (gates(p, e.signals)) slot.policies[p.id].matched++; else slot.policies[p.id].noMatch++; }
    }
  }
  const perSignalRows = [...perSignal.values()].sort((a, b) => b.events - a.events || a.signal.localeCompare(b.signal));
  const unclassified = perSignalRows.filter(r => r.family === 'unclassified').map(r => r.signal);
  const schemaOnlyKnown = known.filter(e => e.signals.every(s => SCHEMA_SET.has(s))).length;
  const dates = events.map(e => e.detectedAt.slice(0, 10)).filter(d => /^\d{4}-\d{2}-\d{2}$/.test(d)).sort();

  // Signals outside the vocabulary: counted, never named.
  let outsideVocabOccurrences = 0, outsideVocabEvents = 0;
  for (const e of events) { if (e.unrecognisedSignals) { outsideVocabEvents++; outsideVocabOccurrences += e.unrecognisedSignals; } }

  return {
    banner: BANNER,
    scope: 'logged-signal comparison; actual outcome and hypothetical match reported separately; malformed, contradictory and unknown evidence excluded from every percentage',
    dateRange: dates.length ? { from: dates[0], to: dates[dates.length - 1] } : null,
    // Round-5 M1(a): counts come straight from the parser's single pass
    // (`parse.rows`); nothing here re-derives a total from record arrays.
    rows: {
      total: parse.rows.total, parsed: parse.rows.parsed, malformed: parse.rows.malformed,
      blankLines: parse.rows.blankLines, lines: parse.rows.lines,
    },
    malformed: parse.malformed.slice(0, 50),
    evidence: {
      validKnown: known.length,
      unknown: unknown.length, unknownReasons: sortedObj(unknownReasons),
      contradictory: contradictory.length, contradictoryReasons: sortedObj(contradictoryReasons),
      malformed: malformedEvents.length, malformedEventReasons: sortedObj(malformedEventReasons),
      malformedRows: parse.malformed.length, malformedReasons: sortedObj(malformedReasons),
    },
    events: {
      total: events.length, keyedBy: sortedObj(keyKinds), recordsPerEvent: sortedObj(recordsPerEvent),
      recordKinds: sortedObj(recordKindAll), multiRecord, conflictingOutcome: conflicting,
      outcomeTransitions: sortedObj(outcomeTransitions), signalDriftBetweenFirstAndLast: drift,
      straySignals: events.reduce((n, e) => n + e.straySignals, 0),
    },
    actual: { ...actual, finalEnforcementOutcome: sortedObj(finalEnfDist) },
    lifecycles: {
      enforcement: { final: sortedObj(lifecycles.enforcement.final), decisionsPerEvent: sortedObj(lifecycles.enforcement.decisions), notifyCopies: lifecycles.enforcement.notifyCopies },
      retry: {
        effective: sortedObj(lifecycles.retry.effective),
        grantSeen: lifecycles.retry.grantSeen,
        histories: sortedObj(lifecycles.retry.histories),
        total: events.length,
        note: 'effective is the current retry state over the validated retry history; grantSeen counts events where any validated grant was observed; a grant_failed after a grant is a failed re-issue (unknown), not a revocation; revoked is reserved: the writer records a revocation only inside reason text, which this tool never reads',
      },
      notification: { final: sortedObj(lifecycles.notification.final), anyValidatedDelivery: lifecycles.notification.anyValidatedDelivery, total: events.length },
    },
    unknown: {
      total: unknown.length, signalless: signalless.length, reasons: sortedObj(unknownReasons),
      neverLoggedSignals: [...NEVER_LOGGED_SIGNALS],
      note: 'Signals outside the notify allowlist are written as redacted-signal; security-config-write signals are among them, so they are structurally invisible here.',
    },
    redactedSignals: { label: REDACTED_SIGNAL_LABEL, occurrences: outsideVocabOccurrences, events: outsideVocabEvents },
    known: { total: known.length, schemaRejectOnly: schemaOnlyKnown },
    severity: sortedObj(severityAll), tools: sortedObj(toolAll), eventKinds: sortedObj(eventKindAll),
    delivery: {
      anyValidatedDelivery: delivery.anyValidatedDelivery, coalescedEver: delivery.coalescedEver,
      suppressedEver: delivery.suppressedEver, unknownFinal: delivery.unknownFinal,
      claimedWithoutChannel: delivery.claimedWithoutChannel,
      finalStatus: sortedObj(delivery.finalStatus), total: events.length,
    },
    injection: { set: [...INJECTION_FLAVOURED], withSignal: injection.length, without: rest.length },
    policies,
    sensitivity: { broadFloorPlusExternalEgress: { matched: broadPlusEgressMatched, delta: broadPlusEgressMatched - broadMatched } },
    perSignal: perSignalRows,
    unclassifiedSignals: unclassified,
  };
}

// ── 4. The ONE public export projection (finding 3) ─────────────────────────

const num = (v) => (typeof v === 'number' && Number.isFinite(v) ? v : 0);
const isIdent = (k) => /^[A-Za-z0-9_.:>\-\s]{1,80}$/.test(k);
/** Copy a {label: count} distribution, re-keying every label through `mapKey`. */
function projectDist(obj, mapKey) {
  const m = counter();
  for (const [k, v] of Object.entries(obj ?? {})) bump(m, mapKey(k), num(v));
  return sortedObj(m);
}
const identOrOther = (k) => (isIdent(k) ? k : OTHER);
/** A retry history pattern key: each step a closed retry state or the `more` cap marker, else `other`. */
function projectRetryHistoryKey(k) {
  return String(k).split(' -> ').slice(0, RETRY_HISTORY_MAX + 1)
    .map(x => (RETRY_STATES.includes(x) || x === 'more' ? x : OTHER)).join(' -> ');
}
const signalsToPublic = (list) => (list ?? []).map(publicSignalName);
function projectNotifyKey(k) {
  // "<status> via=<channel>" — both halves through their enum.
  const m = /^(.*) via=(.*)$/.exec(k);
  if (!m) return OTHER;
  const st = m[1] === 'none' ? 'none' : publicNotifyStatus(m[1]);
  const ch = m[2] === 'none' ? 'none' : publicChannel(m[2]);
  return `${st} via=${ch}`;
}

/**
 * Build the public summary. Every string that reaches JSON or Markdown passes
 * through here: counts are copied as numbers; signal names only by vocabulary
 * membership (everything else collapses to one redaction label); metadata
 * labels only through their closed enums (everything else is `other`).
 * Pure; both renderers consume ONLY its output.
 */
export function projectPublic(s) {
  const policyIds = new Set(POLICIES.map(p => p.id));
  const policyId = (id) => (policyIds.has(id) ? id : OTHER);
  const outcomeOrLifecycle = (k) => (k === 'none' || k === 'retry-only' ? k : publicOutcome(k));
  return {
    banner: BANNER,
    scope: s.scope,
    dateRange: s.dateRange ? { from: String(s.dateRange.from).slice(0, 10), to: String(s.dateRange.to).slice(0, 10) } : null,
    rows: { total: num(s.rows.total), parsed: num(s.rows.parsed), malformed: num(s.rows.malformed), blankLines: num(s.rows.blankLines), lines: num(s.rows.lines) },
    malformed: (s.malformed ?? []).map(m => ({ lineNo: num(m.lineNo), reason: identOrOther(String(m.reason)) })),
    evidence: {
      validKnown: num(s.evidence.validKnown),
      unknown: num(s.evidence.unknown), unknownReasons: projectDist(s.evidence.unknownReasons, identOrOther),
      contradictory: num(s.evidence.contradictory), contradictoryReasons: projectDist(s.evidence.contradictoryReasons, identOrOther),
      malformed: num(s.evidence.malformed), malformedEventReasons: projectDist(s.evidence.malformedEventReasons, identOrOther),
      malformedRows: num(s.evidence.malformedRows), malformedReasons: projectDist(s.evidence.malformedReasons, identOrOther),
    },
    events: {
      total: num(s.events.total),
      keyedBy: projectDist(s.events.keyedBy, k => (['actionId', 'correlationId', 'line'].includes(k) ? k : OTHER)),
      recordsPerEvent: projectDist(s.events.recordsPerEvent, k => (/^\d{1,6}$/.test(k) ? k : OTHER)),
      recordKinds: projectDist(s.events.recordKinds, k => (['denial', 'warning', 'dnp_retry', 'contradictory', 'malformed', 'other'].includes(k) ? k : OTHER)),
      multiRecord: num(s.events.multiRecord), conflictingOutcome: num(s.events.conflictingOutcome),
      outcomeTransitions: projectDist(s.events.outcomeTransitions, k => k.split(' -> ').map(publicOutcome).join(' -> ')),
      signalDriftBetweenFirstAndLast: num(s.events.signalDriftBetweenFirstAndLast),
      straySignals: num(s.events.straySignals),
    },
    actual: {
      actuallyStopped: num(s.actual.actuallyStopped), stopUnconfirmed: num(s.actual.stopUnconfirmed), warnedOnly: num(s.actual.warnedOnly),
      retryGranted: num(s.actual.retryGranted), retryDeniedOrFailed: num(s.actual.retryDeniedOrFailed),
      retryUnresolved: num(s.actual.retryUnresolved), other: num(s.actual.other),
      finalEnforcementOutcome: projectDist(s.actual.finalEnforcementOutcome, outcomeOrLifecycle),
    },
    lifecycles: {
      enforcement: {
        final: projectDist(s.lifecycles.enforcement.final, k => (ENFORCEMENT_STATES.includes(k) ? k : OTHER)),
        decisionsPerEvent: projectDist(s.lifecycles.enforcement.decisionsPerEvent, k => (/^\d{1,6}$/.test(k) ? k : OTHER)),
        notifyCopies: num(s.lifecycles.enforcement.notifyCopies),
      },
      retry: {
        effective: projectDist(s.lifecycles.retry.effective, k => (RETRY_STATES.includes(k) ? k : OTHER)),
        grantSeen: num(s.lifecycles.retry.grantSeen),
        // history patterns: every step re-mapped through the closed state set (+ the `more` cap marker)
        histories: projectDist(s.lifecycles.retry.histories, projectRetryHistoryKey),
        total: num(s.lifecycles.retry.total),
        note: s.lifecycles.retry.note,
      },
      notification: {
        final: projectDist(s.lifecycles.notification.final, k => (NOTIFICATION_STATES.includes(k) ? k : OTHER)),
        anyValidatedDelivery: num(s.lifecycles.notification.anyValidatedDelivery), total: num(s.lifecycles.notification.total),
      },
    },
    unknown: {
      total: num(s.unknown.total), signalless: num(s.unknown.signalless), reasons: projectDist(s.unknown.reasons, identOrOther),
      neverLoggedSignals: [...NEVER_LOGGED_SIGNALS], note: s.unknown.note,
    },
    redactedSignals: { label: REDACTED_SIGNAL_LABEL, occurrences: num(s.redactedSignals.occurrences), events: num(s.redactedSignals.events) },
    known: { total: num(s.known.total), schemaRejectOnly: num(s.known.schemaRejectOnly) },
    severity: projectDist(s.severity, publicSeverity),
    tools: projectDist(s.tools, publicTool),
    eventKinds: projectDist(s.eventKinds, publicEvent),
    delivery: {
      anyValidatedDelivery: num(s.delivery.anyValidatedDelivery), coalescedEver: num(s.delivery.coalescedEver),
      suppressedEver: num(s.delivery.suppressedEver), unknownFinal: num(s.delivery.unknownFinal),
      claimedWithoutChannel: num(s.delivery.claimedWithoutChannel),
      finalStatus: projectDist(s.delivery.finalStatus, projectNotifyKey), total: num(s.delivery.total),
    },
    injection: { set: signalsToPublic(s.injection.set), withSignal: num(s.injection.withSignal), without: num(s.injection.without) },
    policies: (s.policies ?? []).map(p => ({
      id: policyId(p.id), label: POLICIES.find(x => x.id === p.id)?.label ?? OTHER,
      hypotheticalMatch: num(p.hypotheticalMatch), hypotheticalNoMatch: num(p.hypotheticalNoMatch),
      matchedAndActuallyStopped: num(p.matchedAndActuallyStopped),
      injectionMatched: num(p.injectionMatched), injectionNoMatch: num(p.injectionNoMatch),
      restMatched: num(p.restMatched), restNoMatch: num(p.restNoMatch),
      matchedBySignal: projectDist(p.matchedBySignal, publicSignalName),
      unknownLowerBoundMatch: num(p.unknownLowerBoundMatch),
    })),
    sensitivity: { broadFloorPlusExternalEgress: { matched: num(s.sensitivity.broadFloorPlusExternalEgress.matched), delta: num(s.sensitivity.broadFloorPlusExternalEgress.delta) } },
    perSignal: (s.perSignal ?? []).map(r => ({
      signal: publicSignalName(r.signal),
      family: identOrOther(String(r.family)),
      events: num(r.events),
      injectionFlavoured: !!r.injectionFlavoured,
      policies: Object.fromEntries(Object.entries(r.policies ?? {}).map(([id, c]) => [policyId(id), { matched: num(c.matched), noMatch: num(c.noMatch), gatesByItself: !!c.gatesByItself }])),
    })),
    unclassifiedSignals: signalsToPublic(s.unclassifiedSignals),
  };
}

// ── 5. Render (consumes ONLY the public projection) ─────────────────────────

const pct = (n, d) => (d > 0 ? `${((100 * n) / d).toFixed(1)}%` : 'n/a');
const kv = (obj) => Object.entries(obj).map(([k, v]) => `${k}=${v}`).join(', ') || '(none)';

export function renderMarkdown(s) {
  const K = s.known.total;
  const out = [];
  out.push('```', s.banner, '```', '');
  out.push(`**Window:** ${s.dateRange ? `${s.dateRange.from} to ${s.dateRange.to}` : 'n/a'} (dates from the log's own timestamps; no host named)`, '');
  out.push('### Input accounting', '');
  out.push('| rows (= parsed + malformed) | parsed | malformed | blank | lines (= rows + blank) | events | multi-record | conflicting | signal drift |');
  out.push('|---|---|---|---|---|---|---|---|---|');
  out.push(`| ${s.rows.total} | ${s.rows.parsed} | **${s.rows.malformed}** | ${s.rows.blankLines} | ${s.rows.lines} | ${s.events.total} | ${s.events.multiRecord} | ${s.events.conflictingOutcome} | ${s.events.signalDriftBetweenFirstAndLast} |`, '');
  out.push(`- events keyed by: ${kv(s.events.keyedBy)}`);
  out.push(`- records per event: ${kv(s.events.recordsPerEvent)}`);
  out.push(`- record kinds present: ${kv(s.events.recordKinds)}`);
  if (s.events.conflictingOutcome) out.push(`- enforcement outcome transitions: ${kv(s.events.outcomeTransitions)}`);
  if (s.rows.malformed) out.push(`- malformed lines (first 50): ${s.malformed.map(m => `${m.lineNo}:${m.reason}`).join(', ')}`);
  out.push('');

  out.push('### Evidence buckets (four separate event buckets; only known enters a denominator)', '');
  out.push('| bucket | count | reasons |');
  out.push('|---|---|---|');
  out.push(`| valid known events | **${s.evidence.validKnown}** | validated enforcement signals in the vocabulary, consistent event/outcome, no stray or malformed rows |`);
  out.push(`| unknown events | ${s.evidence.unknown} | ${kv(s.evidence.unknownReasons)} |`);
  out.push(`| contradictory events | ${s.evidence.contradictory} | ${kv(s.evidence.contradictoryReasons)} |`);
  out.push(`| malformed events | ${s.evidence.malformed} | ${kv(s.evidence.malformedEventReasons)} |`);
  out.push(`| malformed rows (row level; JSON rows are retained inside their event) | ${s.evidence.malformedRows} | ${kv(s.evidence.malformedReasons)} |`);
  out.push('');
  out.push(`- signals outside the writer's vocabulary: ${s.redactedSignals.occurrences} occurrence(s) across ${s.redactedSignals.events} event(s); printed only as \`${s.redactedSignals.label}\``);
  out.push(`- stray signals (carried on a retry or unknown-outcome row; never used for matching): ${s.events.straySignals}`, '');

  out.push('### ACTUAL outcome (what the guard did — separate from any policy hypothesis)', '');
  out.push('| category | events | note |');
  out.push('|---|---|---|');
  out.push(`| actually stopped | ${s.actual.actuallyStopped} | a validated enforcement DECISION of auto_denied / denied_no_prompt_surface, every row of the event validated, AND effective retry state neither granted nor unknown |`);
  out.push(`| stop unconfirmed | ${s.actual.stopUnconfirmed} | a stop decision exists but the event also carries a malformed or contradictory row (e.g. an unvalidated retry row): not accepted as a grant, not counted as stopped |`);
  out.push(`| warned only | ${s.actual.warnedOnly} | advisory; NO permission decision emitted — did not stop the call |`);
  out.push(`| retry granted | ${s.actual.retryGranted} | effective retry state is a scoped one-shot grant; NOT proof of execution |`);
  out.push(`| retry denied / grant failed | ${s.actual.retryDeniedOrFailed} | effective retry state denied, revoked, or failed with no grant ever seen |`);
  out.push(`| retry unresolved | ${s.actual.retryUnresolved} | a grant was seen, then a grant_failed: a failed re-issue, NOT a revocation — the stop is not restored |`);
  out.push(`| other | ${s.actual.other} | |`);
  out.push('');
  out.push(`- final enforcement outcome distribution: ${kv(s.actual.finalEnforcementOutcome)}`, '');

  out.push('### Lifecycles per event (three independent observations, each with its own final state)', '');
  out.push('| lifecycle | final-state distribution | note |');
  out.push('|---|---|---|');
  out.push(`| enforcement | ${kv(s.lifecycles.enforcement.final)} | last DECISION row; ${s.lifecycles.enforcement.notifyCopies} notify-copy row(s) (same event/outcome/signals, only notify differs) were NOT counted as new decisions; decisions per event: ${kv(s.lifecycles.enforcement.decisionsPerEvent)} |`);
  out.push(`| retry / revocation (effective) | ${kv(s.lifecycles.retry.effective)} | grant seen on ${s.lifecycles.retry.grantSeen} of ${s.lifecycles.retry.total} event(s); validated retry histories: ${kv(s.lifecycles.retry.histories)}; ${s.lifecycles.retry.note} |`);
  out.push(`| notification | ${kv(s.lifecycles.notification.final)} | last row that CARRIES a notify object; validated delivery on any row: ${s.lifecycles.notification.anyValidatedDelivery} of ${s.lifecycles.notification.total} |`);
  out.push('');

  out.push('### Unknown bucket (excluded from every percentage)', '');
  out.push(`- unknown events: **${s.unknown.total}** of ${s.events.total} (${kv(s.unknown.reasons)}); signal-less events (incl. retry-only): ${s.unknown.signalless}`);
  out.push(`- known (reconstructable-signal) events: **${K}** (schema-reject only: ${s.known.schemaRejectOnly})`);
  out.push(`- structurally never logged (redacted at write): ${s.unknown.neverLoggedSignals.join(', ')} — ${s.unknown.note}`, '');

  out.push('### Notify delivery — across ALL records (a transport report; never "person reached")', '');
  out.push('| measure | events |');
  out.push('|---|---|');
  out.push(`| validated delivery (a delivery-claim status WITH a channel) | **${s.delivery.anyValidatedDelivery}** of ${s.delivery.total} |`);
  out.push(`| delivery claimed WITHOUT a channel (contradictory, not validated) | ${s.delivery.claimedWithoutChannel} |`);
  out.push(`| coalesced at some point | ${s.delivery.coalescedEver} |`);
  out.push(`| suppressed at some point | ${s.delivery.suppressedEver} |`);
  out.push(`| final status none/pending (unknown) | ${s.delivery.unknownFinal} |`);
  out.push('');
  out.push(`- final status distribution (enum or other): ${kv(s.delivery.finalStatus)}`, '');

  out.push('### Policy comparison — HYPOTHETICAL signal-set match (NOT an enforcement rate)', '');
  out.push(`- injection-flavoured set: ${s.injection.set.join(', ')}`);
  out.push(`- known events carrying an injection-flavoured signal: **${s.injection.withSignal}** (${pct(s.injection.withSignal, K)}); without: **${s.injection.without}**`, '');
  out.push('| policy | hypothetical match | no match | of matched, actually stopped | injection m/n | rest m/n | unknown lower bound |');
  out.push('|---|---|---|---|---|---|---|');
  for (const p of s.policies) {
    out.push(`| ${p.id} | ${p.hypotheticalMatch} | ${p.hypotheticalNoMatch} | ${p.matchedAndActuallyStopped} | ${p.injectionMatched} / ${p.injectionNoMatch} | ${p.restMatched} / ${p.restNoMatch} | ${p.unknownLowerBoundMatch} |`);
  }
  out.push('');
  out.push(`- sensitivity: adding plain \`external-egress\` to the broad floor would match ${s.sensitivity.broadFloorPlusExternalEgress.matched} (+${s.sensitivity.broadFloorPlusExternalEgress.delta}).`);
  for (const p of s.policies) out.push(`- ${p.id} matched by signal: ${kv(p.matchedBySignal)}`);
  out.push('');
  out.push('### Per signal (known events; hypothetical match / no-match under each policy)', '');
  const ids = s.policies.map(p => p.id);
  out.push(`| signal | family | events | ${ids.join(' | ')} |`);
  out.push(`|---|---|---|${ids.map(() => '---').join('|')}|`);
  for (const r of s.perSignal) {
    const cells = ids.map(id => { const c = r.policies[id]; return c ? `${c.matched} / ${c.noMatch}${c.gatesByItself ? '' : ' ⁽ᶜ⁾'}` : 'n/a'; });
    out.push(`| ${r.signal}${r.injectionFlavoured ? ' ⚑' : ''} | ${r.family} | ${r.events} | ${cells.join(' | ')} |`);
  }
  out.push('');
  out.push('⁽ᶜ⁾ signal not in that policy\'s gate set; any match there comes from a co-occurring signal. ⚑ injection-flavoured.');
  out.push(`- unclassified signals (in the vocabulary but absent from the policy family map — fix the map): ${s.unclassifiedSignals.length ? s.unclassifiedSignals.join(', ') : 'none'}`);
  return out.join('\n');
}

// ── 6. Main ────────────────────────────────────────────────────────────────

export function run(text) {
  const parsed = parseDenials(text);
  const events = groupEvents(parsed.records);
  // M1(a): the parser's own accounting is passed through untouched.
  const internal = analyse(events, parsed);
  const summary = projectPublic(internal);
  return { summary, markdown: renderMarkdown(summary) };
}

function main(argv) {
  const args = argv.slice(2);
  const file = args.find(a => !a.startsWith('--'));
  const flag = (name) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : null; };
  if (!file) {
    process.stderr.write('usage: guard-policy-replay.mjs <denials.jsonl> [--json out.json] [--md out.md] [--quiet]\n');
    process.exit(2);
  }
  const { summary, markdown } = run(readFileSync(file, 'utf8'));
  const jsonOut = flag('--json'), mdOut = flag('--md');
  if (jsonOut) writeFileSync(jsonOut, JSON.stringify(summary, null, 2) + '\n');
  if (mdOut) writeFileSync(mdOut, markdown + '\n');
  if (!args.includes('--quiet')) process.stdout.write(markdown + '\n');
  if (summary.rows.malformed) process.stderr.write(`[guard-policy-replay] ${summary.rows.malformed} malformed row(s) counted, not skipped.\n`);
}

const invokedDirectly = (() => {
  try { return process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url)); } catch { return false; }
})();
if (invokedDirectly) main(process.argv);
