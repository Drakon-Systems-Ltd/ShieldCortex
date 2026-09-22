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
 * Record kinds (finding 5): the log interleaves `action_guard_denial`,
 * `action_guard_warning`, and RETRY lifecycle rows (`retry_granted` /
 * `retry_denied` / `retry_grant_failed`) that carry the SAME actionId and NO
 * signals. Retry rows are first-class records kept in the event lifecycle, never
 * malformed. A retry GRANT is NOT proof of execution — it is a scoped one-shot
 * re-offer; it is tracked as its own lifecycle state.
 *
 * NOT a classifier replay (the command surface is redacted, so no command is
 * re-run) and NOT an effect measurement (Half B does that). Rows whose signals
 * cannot be reconstructed (redacted/empty) are bucketed *unknown* and excluded
 * from every percentage.
 *
 * Privacy (finding 7): output is a field ALLOWLIST — counts, outcome enums, tool
 * names, notify statuses, and signal names that conform to the guard's own
 * `[a-z][a-z0-9-]*` vocabulary. A non-conforming or non-string signal member is
 * never echoed verbatim; it is redacted and counted. No `reason`, `surface`,
 * session/correlation ids, payloads or command text are ever printed.
 *
 * Node core only. Exports its functions for the harness test; runs `main` only
 * when invoked directly.
 */
import { readFileSync, writeFileSync, realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  POLICIES, gates, gatingSignals, SIGNAL_FAMILY, INJECTION_FLAVOURED,
  NEVER_LOGGED_SIGNALS, REDACTED_MARKER, SCHEMA_OR_SCAN_GAP, ALL_KNOWN_SIGNALS,
} from './lib/guard-policy-sets.mjs';

export const BANNER = [
  '=== LOGGED-SIGNAL POLICY COMPARISON ===',
  'NOT a classifier replay and NOT an effect-achieved measurement.',
  'Two axes are reported SEPARATELY and never conflated: (1) ACTUAL outcome the guard recorded',
  '(auto_denied / denied_no_prompt_surface actually stopped the call; warned did NOT — it emits',
  'no permission decision; retry_granted re-offered one scoped attempt), and (2) HYPOTHETICAL',
  'signal-set match per policy, which is NOT an enforcement rate. A denials filename does not',
  'make every record a denial. Redacted/empty-signal rows are "unknown" and excluded from every %.',
].join('\n');

const INJECTION_SET = new Set(INJECTION_FLAVOURED);
const SCHEMA_SET = new Set(SCHEMA_OR_SCAN_GAP);
const KNOWN_SIGNAL_SET = new Set(ALL_KNOWN_SIGNALS);
const RETRY_OUTCOMES = new Set(['retry_granted', 'retry_denied', 'retry_grant_failed']);
const STOPPED_OUTCOMES = new Set(['auto_denied', 'denied_no_prompt_surface', 'failure_denied']);
const OUTCOME_SPLIT = ['warned', 'auto_denied', 'denied_no_prompt_surface', 'retry_granted', 'retry_denied', 'retry_grant_failed'];
const DELIVERED_STATUSES = new Set(['delivered', 'sent']);

/** Public-safe signal name: the guard's own vocabulary only, else redacted. */
export function safeSignalName(s) {
  return typeof s === 'string' && /^[a-z][a-z0-9-]{0,63}$/.test(s) ? s : '<non-conforming-signal-redacted>';
}

// ── 1. Parse + classify: every line accounted for, record kinds discriminated ─

/**
 * @param {object} row
 * @returns {{ kind: 'denial'|'warning'|'dnp_retry'|'other', retry?: string }}
 */
export function classifyRecord(row) {
  const outcome = typeof row.outcome === 'string' ? row.outcome : '';
  const event = typeof row.event === 'string' ? row.event : '';
  if (RETRY_OUTCOMES.has(outcome)) return { kind: 'dnp_retry', retry: outcome };
  if (event === 'action_guard_warning' || outcome === 'warned') return { kind: 'warning' };
  if (Array.isArray(row.signals)) return { kind: 'denial' };
  return { kind: 'other' };
}

/**
 * A signals member must be an array of strings. Returns the reason a row is
 * malformed on its signals, or null if the signals are acceptable / absent.
 */
function signalsProblem(row, kind) {
  if (row.signals == null) {
    // Only denial/warning kinds REQUIRE signals; retry/other may omit them.
    return kind === 'denial' || kind === 'warning' ? 'missing-signals' : null;
  }
  if (!Array.isArray(row.signals)) return 'signals-not-array';
  if (!row.signals.every(s => typeof s === 'string')) return 'signal-member-not-string';
  return null;
}

/**
 * @param {string} text
 */
export function parseDenials(text) {
  const records = [];
  const malformed = [];
  let blankLines = 0;
  const lines = text.split(/\r?\n/);
  lines.forEach((line, i) => {
    const lineNo = i + 1;
    if (line.trim() === '') { blankLines++; return; }
    let row;
    try { row = JSON.parse(line); } catch { malformed.push({ lineNo, reason: 'not-json' }); return; }
    if (row === null || typeof row !== 'object' || Array.isArray(row)) { malformed.push({ lineNo, reason: 'not-object' }); return; }
    if (typeof row.outcome !== 'string' || row.outcome === '') { malformed.push({ lineNo, reason: 'missing-outcome' }); return; }
    const cls = classifyRecord(row);
    const sp = signalsProblem(row, cls.kind);
    if (sp) { malformed.push({ lineNo, reason: sp }); return; }
    records.push({ lineNo, row, kind: cls.kind, retry: cls.retry ?? null });
  });
  if (lines.length && lines[lines.length - 1] === '') blankLines--;
  return { records, malformed, blankLines };
}

// ── 2. Group: full lifecycle per event, nothing wins by position ─────────────

const str = (v) => (typeof v === 'string' ? v : '');
const notifyOf = (row) => {
  const n = row.notify && typeof row.notify === 'object' && !Array.isArray(row.notify) ? row.notify : null;
  return { status: n ? str(n.status) || 'none' : 'none', deliveredVia: n ? str(n.deliveredVia) || null : null };
};

/**
 * @param {Array<{lineNo:number,row:object,kind:string,retry:string|null}>} records
 */
export function groupEvents(records) {
  const byKey = new Map();
  for (const r of records) {
    const aid = str(r.row.actionId);
    const cid = str(r.row.correlationId);
    const key = aid ? `aid:${aid}` : cid ? `corr:${cid}` : `line:${r.lineNo}`;
    const keyKind = aid ? 'actionId' : cid ? 'correlationId' : 'line';
    if (!byKey.has(key)) byKey.set(key, { key, keyKind, records: [] });
    byKey.get(key).records.push(r);
  }
  const events = [];
  for (const ev of byKey.values()) {
    ev.records.sort((a, b) => {
      const ta = str(a.row.detectedAt), tb = str(b.row.detectedAt);
      return ta < tb ? -1 : ta > tb ? 1 : a.lineNo - b.lineNo;
    });
    const enforcement = ev.records.filter(r => r.kind === 'denial' || r.kind === 'warning');
    const retries = ev.records.filter(r => r.kind === 'dnp_retry');
    const sigs = (row) => (Array.isArray(row.signals) ? row.signals.map(s => String(s ?? '').trim()).filter(Boolean) : []);
    const union = [...new Set(ev.records.flatMap(x => sigs(x.row)))];

    const firstRec = ev.records[0];
    const lastRec = ev.records[ev.records.length - 1];
    const lastEnf = enforcement.length ? enforcement[enforcement.length - 1] : null;
    const firstEnf = enforcement.length ? enforcement[0] : null;
    const enfOutcomes = [...new Set(enforcement.map(x => x.row.outcome))];

    const firstSigs = firstEnf ? sigs(firstEnf.row) : [];
    const lastSigs = lastEnf ? sigs(lastEnf.row) : [];
    const sameSet = (a, b) => a.length === b.length && a.every(s => b.includes(s));

    const retryOutcomes = retries.map(r => r.retry);
    const retryGranted = retryOutcomes.includes('retry_granted');
    // Actual enforcement: the final enforcement record's outcome, NOT lifted by
    // a later grant. A warned-only event never stopped anything.
    const finalEnfOutcome = lastEnf ? str(lastEnf.row.outcome) : (retries.length ? 'retry-only' : 'none');
    const actuallyStopped = !!lastEnf && STOPPED_OUTCOMES.has(finalEnfOutcome) && !retryGrantedAfter(ev.records);

    events.push({
      key: ev.key, keyKind: ev.keyKind,
      recordCount: ev.records.length,
      kinds: [...new Set(ev.records.map(r => r.kind))],
      hasEnforcement: enforcement.length > 0,
      finalEnfOutcome,
      enfOutcomes,
      conflictingOutcome: enfOutcomes.length > 1,
      retryOutcomes,
      retryGranted,
      actuallyStopped,
      signals: union,
      signalDrift: !sameSet(firstSigs, lastSigs),
      redacted: union.includes(REDACTED_MARKER),
      severity: str((lastEnf ?? lastRec).row.severity) || 'unknown',
      tool: str((lastEnf ?? lastRec).row.tool) || 'tool',
      event: str((lastEnf ?? lastRec).row.event) || 'unknown',
      // Delivery is tracked across ALL records, never just the final one.
      anyValidatedDelivery: ev.records.some(r => { const n = notifyOf(r.row); return DELIVERED_STATUSES.has(n.status) && !!n.deliveredVia; }),
      finalNotify: notifyOf(lastRec.row),
      firstNotify: notifyOf(firstRec.row),
      coalescedEver: ev.records.some(r => notifyOf(r.row).status === 'coalesced'),
      suppressedEver: ev.records.some(r => notifyOf(r.row).status === 'suppressed'),
      detectedAt: str(lastRec.row.detectedAt),
    });
  }
  return events;
}

/** True if a retry_granted appears after the last denial/warning record. */
function retryGrantedAfter(records) {
  let lastEnfIdx = -1;
  records.forEach((r, i) => { if (r.kind === 'denial' || r.kind === 'warning') lastEnfIdx = i; });
  return records.some((r, i) => i > lastEnfIdx && r.retry === 'retry_granted');
}

// ── 3. Analyse ────────────────────────────────────────────────────────────────

const counter = () => new Map();
const bump = (m, k, n = 1) => m.set(k, (m.get(k) ?? 0) + n);
const sortedObj = (m) => Object.fromEntries([...m.entries()].sort((a, b) => b[1] - a[1] || String(a[0]).localeCompare(String(b[0]))));

/**
 * @param {ReturnType<typeof groupEvents>} events
 * @param {{ malformed: Array<{lineNo:number,reason:string}>, rowCount: number, blankLines: number }} parse
 */
export function analyse(events, parse) {
  // "known" needs reconstructable signals; a signal-less retry-only event is not
  // malformed (finding 5) but has no signal footprint for a policy to key on.
  const known = events.filter(e => !e.redacted && e.signals.length > 0);
  const unknown = events.filter(e => e.redacted || e.signals.length === 0);
  const signalless = events.filter(e => e.signals.length === 0);

  const unknownReasons = counter();
  for (const e of unknown) bump(unknownReasons, e.signals.length === 0 ? (e.hasEnforcement ? 'empty-signals' : 'retry-or-other-only') : e.signals.length === 1 ? 'redacted-only' : 'redacted-plus-partial');

  const keyKinds = counter(), recordsPerEvent = counter(), outcomeTransitions = counter();
  let multiRecord = 0, conflicting = 0, drift = 0;
  for (const e of events) {
    bump(keyKinds, e.keyKind);
    bump(recordsPerEvent, String(e.recordCount));
    if (e.recordCount > 1) multiRecord++;
    if (e.conflictingOutcome) { conflicting++; bump(outcomeTransitions, e.enfOutcomes.join(' -> ')); }
    if (e.signalDrift) drift++;
  }

  // ACTUAL outcome accounting (finding 4) — what the guard truly did.
  const actual = { actuallyStopped: 0, warnedOnly: 0, retryGranted: 0, retryDeniedOrFailed: 0, other: 0 };
  const finalEnfDist = counter();
  for (const e of events) {
    bump(finalEnfDist, e.finalEnfOutcome);
    if (e.actuallyStopped) actual.actuallyStopped++;
    else if (e.retryGranted) actual.retryGranted++;
    else if (e.retryOutcomes.some(o => o === 'retry_denied' || o === 'retry_grant_failed')) actual.retryDeniedOrFailed++;
    else if (e.finalEnfOutcome === 'warned') actual.warnedOnly++;
    else actual.other++;
  }

  const severityAll = counter(), toolAll = counter(), eventKindAll = counter(), recordKindAll = counter();
  for (const e of events) { bump(severityAll, e.severity); bump(toolAll, e.tool); bump(eventKindAll, e.event); for (const k of e.kinds) bump(recordKindAll, k); }

  // Delivery across ALL records (finding 7) — never "person reached".
  const delivery = { anyValidatedDelivery: 0, coalescedEver: 0, suppressedEver: 0, finalStatus: counter(), unknownFinal: 0 };
  for (const e of events) {
    if (e.anyValidatedDelivery) delivery.anyValidatedDelivery++;
    if (e.coalescedEver) delivery.coalescedEver++;
    if (e.suppressedEver) delivery.suppressedEver++;
    const fs = `${e.finalNotify.status} via=${e.finalNotify.deliveredVia ?? 'none'}`;
    bump(delivery.finalStatus, fs);
    if (e.finalNotify.status === 'none' || e.finalNotify.status === 'pending') delivery.unknownFinal++;
  }

  const isInjection = (e) => e.signals.some(s => INJECTION_SET.has(s));
  const injection = known.filter(isInjection);
  const rest = known.filter(e => !isInjection(e));

  // Policy comparison: HYPOTHETICAL signal-set match, alongside how many of
  // those events ACTUALLY stopped. No enforcement-rate claim, no 100% baseline.
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

  const perSignal = new Map();
  for (const e of known) {
    for (const s of e.signals) {
      const known_s = KNOWN_SIGNAL_SET.has(s);
      if (!perSignal.has(s)) {
        perSignal.set(s, {
          signal: s, safe: safeSignalName(s),
          family: SIGNAL_FAMILY[s] ?? 'unclassified',
          known: known_s, events: 0,
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
  const unclassified = perSignalRows.filter(r => r.family === 'unclassified').map(r => r.safe);
  const schemaOnlyKnown = known.filter(e => e.signals.every(s => SCHEMA_SET.has(s))).length;
  const dates = events.map(e => e.detectedAt.slice(0, 10)).filter(d => /^\d{4}-\d{2}-\d{2}$/.test(d)).sort();

  return {
    banner: BANNER,
    scope: 'logged-signal comparison; actual outcome and hypothetical match reported separately; unknown rows excluded from every percentage',
    dateRange: dates.length ? { from: dates[0], to: dates[dates.length - 1] } : null,
    rows: { total: parse.rowCount, parsed: parse.rowCount - parse.malformed.length, malformed: parse.malformed.length, blankLines: parse.blankLines },
    malformed: parse.malformed.slice(0, 50),
    events: {
      total: events.length, keyedBy: sortedObj(keyKinds), recordsPerEvent: sortedObj(recordsPerEvent),
      recordKinds: sortedObj(recordKindAll), multiRecord, conflictingOutcome: conflicting,
      outcomeTransitions: sortedObj(outcomeTransitions), signalDriftBetweenFirstAndLast: drift,
    },
    actual: { ...actual, finalEnforcementOutcome: sortedObj(finalEnfDist) },
    unknown: {
      total: unknown.length, signalless: signalless.length, reasons: sortedObj(unknownReasons),
      neverLoggedSignals: [...NEVER_LOGGED_SIGNALS],
      note: 'Signals outside the notify allowlist are written as redacted-signal; security-config-write signals are among them, so they are structurally invisible here.',
    },
    known: { total: known.total ?? known.length, schemaRejectOnly: schemaOnlyKnown },
    severity: sortedObj(severityAll), tools: sortedObj(toolAll), eventKinds: sortedObj(eventKindAll),
    delivery: {
      anyValidatedDelivery: delivery.anyValidatedDelivery, coalescedEver: delivery.coalescedEver,
      suppressedEver: delivery.suppressedEver, unknownFinal: delivery.unknownFinal,
      finalStatus: sortedObj(delivery.finalStatus), total: events.length,
    },
    injection: { set: [...INJECTION_FLAVOURED], withSignal: injection.length, without: rest.length },
    policies,
    sensitivity: { broadFloorPlusExternalEgress: { matched: broadPlusEgressMatched, delta: broadPlusEgressMatched - broadMatched } },
    perSignal: perSignalRows,
    unclassifiedSignals: unclassified,
  };
}

// ── 4. Render ─────────────────────────────────────────────────────────────────

const pct = (n, d) => (d > 0 ? `${((100 * n) / d).toFixed(1)}%` : 'n/a');
const kv = (obj) => Object.entries(obj).map(([k, v]) => `${k}=${v}`).join(', ') || '(none)';

export function renderMarkdown(s) {
  const K = s.known.total;
  const out = [];
  out.push('```', s.banner, '```', '');
  out.push(`**Window:** ${s.dateRange ? `${s.dateRange.from} to ${s.dateRange.to}` : 'n/a'} (dates from the log's own timestamps; no host named)`, '');
  out.push('### Input accounting', '');
  out.push('| rows | parsed | malformed | blank | events | multi-record | conflicting | signal drift |');
  out.push('|---|---|---|---|---|---|---|---|');
  out.push(`| ${s.rows.total} | ${s.rows.parsed} | **${s.rows.malformed}** | ${s.rows.blankLines} | ${s.events.total} | ${s.events.multiRecord} | ${s.events.conflictingOutcome} | ${s.events.signalDriftBetweenFirstAndLast} |`, '');
  out.push(`- events keyed by: ${kv(s.events.keyedBy)}`);
  out.push(`- records per event: ${kv(s.events.recordsPerEvent)}`);
  out.push(`- record kinds present: ${kv(s.events.recordKinds)}`);
  if (s.events.conflictingOutcome) out.push(`- enforcement outcome transitions: ${kv(s.events.outcomeTransitions)}`);
  if (s.rows.malformed) out.push(`- malformed lines (first 50): ${s.malformed.map(m => `${m.lineNo}:${m.reason}`).join(', ')}`);
  out.push('');

  out.push('### ACTUAL outcome (what the guard did — separate from any policy hypothesis)', '');
  out.push('| category | events | note |');
  out.push('|---|---|---|');
  out.push(`| actually stopped | ${s.actual.actuallyStopped} | final outcome auto_denied / denied_no_prompt_surface, not lifted by a grant |`);
  out.push(`| warned only | ${s.actual.warnedOnly} | advisory; NO permission decision emitted — did not stop the call |`);
  out.push(`| retry granted | ${s.actual.retryGranted} | a scoped one-shot re-offer; NOT proof of execution |`);
  out.push(`| retry denied / grant failed | ${s.actual.retryDeniedOrFailed} | |`);
  out.push(`| other | ${s.actual.other} | |`);
  out.push('');
  out.push(`- final enforcement outcome distribution: ${kv(s.actual.finalEnforcementOutcome)}`, '');

  out.push('### Unknown bucket (excluded from every percentage)', '');
  out.push(`- unknown events: **${s.unknown.total}** of ${s.events.total} (${kv(s.unknown.reasons)}); signal-less events (incl. retry-only): ${s.unknown.signalless}`);
  out.push(`- known (reconstructable-signal) events: **${K}** (schema-reject only: ${s.known.schemaRejectOnly})`);
  out.push(`- structurally never logged (redacted at write): ${s.unknown.neverLoggedSignals.join(', ')} — ${s.unknown.note}`, '');

  out.push('### Notify delivery — across ALL records (never "person reached")', '');
  out.push('| measure | events |');
  out.push('|---|---|');
  out.push(`| any validated delivery (status delivered/sent + channel) | **${s.delivery.anyValidatedDelivery}** of ${s.delivery.total} |`);
  out.push(`| coalesced at some point | ${s.delivery.coalescedEver} |`);
  out.push(`| suppressed at some point | ${s.delivery.suppressedEver} |`);
  out.push(`| final status none/pending (unknown) | ${s.delivery.unknownFinal} |`);
  out.push('');
  out.push(`- final status distribution: ${kv(s.delivery.finalStatus)}`, '');

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
    const cells = ids.map(id => { const c = r.policies[id]; return `${c.matched} / ${c.noMatch}${c.gatesByItself ? '' : ' ⁽ᶜ⁾'}`; });
    out.push(`| ${r.safe}${r.injectionFlavoured ? ' ⚑' : ''}${r.known ? '' : ' ⚠unknown-id'} | ${r.family} | ${r.events} | ${cells.join(' | ')} |`);
  }
  out.push('');
  out.push('⁽ᶜ⁾ signal not in that policy\'s gate set; any match there comes from a co-occurring signal. ⚑ injection-flavoured. ⚠ a signal name absent from the guard\'s known vocabulary.');
  out.push(`- unclassified signals (present in log, absent from the policy map — fix the map): ${s.unclassifiedSignals.length ? s.unclassifiedSignals.join(', ') : 'none'}`);
  return out.join('\n');
}

// ── 5. Main ────────────────────────────────────────────────────────────────

export function run(text) {
  const parsed = parseDenials(text);
  const events = groupEvents(parsed.records);
  const summary = analyse(events, { malformed: parsed.malformed, rowCount: parsed.records.length + parsed.malformed.length, blankLines: parsed.blankLines });
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
