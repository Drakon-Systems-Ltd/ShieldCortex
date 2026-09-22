#!/usr/bin/env node
/**
 * ADR-002 measurement harness, Half A — logged-signal policy comparison
 * (#555, #556).
 *
 *   node scripts/guard-policy-replay.mjs <denials.jsonl> [--json out.json] [--md out.md] [--quiet]
 *
 * Reads an Action Guard denials log and answers ONE question per policy:
 * "of the events the guard stopped, which would still be gated if enforcement
 * keyed on this policy's signal set, and which would become audit-only?"
 *
 * What this is NOT — printed as a banner on every run, because the number is
 * easy to misread:
 *   - not a classifier replay: no command is re-run through the guard. The
 *     log does not hold the command (the surface is redacted), so it cannot be.
 *   - not an effect-achieved measurement: nothing here observes whether an
 *     action would have done damage. Half B (`scripts/guard-effect-fixtures/`)
 *     is the harness for that, on synthetic fixtures.
 *   - the current-tiers column is a baseline by construction: every row in a
 *     denials log is an event the current tiers stopped.
 *
 * Lineage: this replaces the ad-hoc aggregation script behind #555's numbers.
 * Its useful parts are kept (two rows per event is normal; count events, not
 * rows; the notify-delivery question). Its four defects are fixed:
 *   1. hand-picked signal set → every observed signal is classified via
 *      `scripts/lib/guard-policy-sets.mjs`, and any signal outside that map is
 *      listed as `unclassified`, never dropped.
 *   2. `pipe-download-to-shell` missing from the injection set → present.
 *   3. malformed rows silently skipped → counted, with line numbers.
 *   4. last-record-wins per actionId → all records kept; first/last reported;
 *      an actionId whose records disagree on outcome is counted as a conflict.
 *
 * Privacy: this prints counts, signal names, outcome enums, tool names and
 * notify statuses only. It never prints `reason`, `surface`, session or
 * correlation ids, or any command text — none of which it needs. Output is
 * safe to paste into a public issue.
 *
 * Node core only. Exports its functions for the harness test; runs `main`
 * only when invoked directly.
 */
import { readFileSync, writeFileSync, realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  POLICIES, gates, gatingSignals, SIGNAL_FAMILY, INJECTION_FLAVOURED,
  NEVER_LOGGED_SIGNALS, REDACTED_MARKER, SCHEMA_OR_SCAN_GAP,
} from './lib/guard-policy-sets.mjs';

export const BANNER = [
  '=== LOGGED-SIGNAL POLICY COMPARISON ===',
  'This is NOT a classifier replay and NOT an effect-achieved measurement.',
  'Input: the signal NAMES the guard wrote to denials.jsonl. Each policy is evaluated on those',
  'names only; no command is re-run through the classifier and no effect is observed.',
  'Rows whose signals cannot be reconstructed (redacted-signal, empty) are bucketed "unknown"',
  'and are EXCLUDED FROM EVERY PERCENTAGE below. The current-tiers column is a baseline by',
  'construction: a denials log only contains events the current tiers stopped.',
].join('\n');

const INJECTION_SET = new Set(INJECTION_FLAVOURED);
const SCHEMA_SET = new Set(SCHEMA_OR_SCAN_GAP);
const OUTCOME_SPLIT = ['warned', 'auto_denied', 'denied_no_prompt_surface'];

// ── 1. Parse: every line is accounted for ───────────────────────────────────

/**
 * @param {string} text
 * @returns {{ rows: Array<{lineNo:number,row:object}>, malformed: Array<{lineNo:number,reason:string}>, blankLines: number }}
 */
export function parseDenials(text) {
  const rows = [];
  const malformed = [];
  let blankLines = 0;
  const lines = text.split(/\r?\n/);
  lines.forEach((line, i) => {
    const lineNo = i + 1;
    if (line.trim() === '') { blankLines++; return; }
    let row;
    try { row = JSON.parse(line); } catch { malformed.push({ lineNo, reason: 'not-json' }); return; }
    if (row === null || typeof row !== 'object' || Array.isArray(row)) { malformed.push({ lineNo, reason: 'not-object' }); return; }
    if (!Array.isArray(row.signals)) { malformed.push({ lineNo, reason: 'signals-not-array' }); return; }
    if (typeof row.outcome !== 'string' || row.outcome === '') { malformed.push({ lineNo, reason: 'missing-outcome' }); return; }
    rows.push({ lineNo, row });
  });
  // A trailing newline yields one empty final "line"; that is not a blank row.
  if (lines.length && lines[lines.length - 1] === '') blankLines--;
  return { rows, malformed, blankLines };
}

// ── 2. Group: all records per event, nothing wins by position ───────────────

const str = (v) => (typeof v === 'string' ? v : '');
const notifyOf = (row) => {
  const n = row.notify && typeof row.notify === 'object' ? row.notify : null;
  return { status: n ? str(n.status) || 'none' : 'none', deliveredVia: n ? str(n.deliveredVia) || null : null };
};

/**
 * @param {Array<{lineNo:number,row:object}>} rows
 */
export function groupEvents(rows) {
  const byKey = new Map();
  for (const r of rows) {
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
    const first = ev.records[0].row;
    const last = ev.records[ev.records.length - 1].row;
    const outcomes = [...new Set(ev.records.map(x => x.row.outcome))];
    const sigs = (row) => row.signals.map(s => String(s ?? '').trim()).filter(Boolean);
    const union = [...new Set(ev.records.flatMap(x => sigs(x.row)))];
    const firstSigs = sigs(first), lastSigs = sigs(last);
    const sameSet = (a, b) => a.length === b.length && a.every(s => b.includes(s));
    events.push({
      key: ev.key,
      keyKind: ev.keyKind,
      recordCount: ev.records.length,
      firstOutcome: first.outcome,
      lastOutcome: last.outcome,
      outcomes,
      conflictingOutcome: outcomes.length > 1,
      signals: union,
      signalDrift: !sameSet(firstSigs, lastSigs),
      redacted: union.includes(REDACTED_MARKER),
      severity: str(last.severity) || 'unknown',
      tool: str(last.tool) || 'tool',
      event: str(last.event) || 'unknown',
      notifyFirst: notifyOf(first),
      notifyLast: notifyOf(last),
      detectedAt: str(last.detectedAt),
    });
  }
  return events;
}

// ── 3. Analyse: unknown bucket first, then policies on the known ────────────

const counter = () => new Map();
const bump = (m, k, n = 1) => m.set(k, (m.get(k) ?? 0) + n);
const sortedObj = (m) => Object.fromEntries([...m.entries()].sort((a, b) => b[1] - a[1] || String(a[0]).localeCompare(String(b[0]))));

/**
 * @param {ReturnType<typeof groupEvents>} events
 * @param {{ malformed: Array<{lineNo:number,reason:string}>, rowCount: number, blankLines: number }} parse
 */
export function analyse(events, parse) {
  const known = events.filter(e => !e.redacted && e.signals.length > 0);
  const unknown = events.filter(e => e.redacted || e.signals.length === 0);

  const unknownReasons = counter();
  for (const e of unknown) bump(unknownReasons, e.signals.length === 0 ? 'empty-signals' : e.signals.length === 1 ? 'redacted-only' : 'redacted-plus-partial');

  const keyKinds = counter();
  const recordsPerEvent = counter();
  const outcomeTransitions = counter();
  let multiRecord = 0, conflicting = 0, drift = 0;
  for (const e of events) {
    bump(keyKinds, e.keyKind);
    bump(recordsPerEvent, String(e.recordCount));
    if (e.recordCount > 1) multiRecord++;
    if (e.conflictingOutcome) { conflicting++; bump(outcomeTransitions, e.outcomes.join(' -> ')); }
    if (e.signalDrift) drift++;
  }

  const outcomeAll = counter(), severityAll = counter(), toolAll = counter(), eventKindAll = counter();
  const notifyLast = counter(), notifyFirstToLast = counter();
  let deliveredToSomeone = 0;
  for (const e of events) {
    bump(outcomeAll, OUTCOME_SPLIT.includes(e.lastOutcome) ? e.lastOutcome : `other:${e.lastOutcome}`);
    bump(severityAll, e.severity);
    bump(toolAll, e.tool);
    bump(eventKindAll, e.event);
    bump(notifyLast, `${e.notifyLast.status} via=${e.notifyLast.deliveredVia ?? 'none'}`);
    bump(notifyFirstToLast, `${e.notifyFirst.status} -> ${e.notifyLast.status}`);
    if (e.notifyLast.deliveredVia) deliveredToSomeone++;
  }

  const outcomeKnown = counter();
  for (const e of known) bump(outcomeKnown, OUTCOME_SPLIT.includes(e.lastOutcome) ? e.lastOutcome : `other:${e.lastOutcome}`);

  const isInjection = (e) => e.signals.some(s => INJECTION_SET.has(s));
  const injection = known.filter(isInjection);
  const rest = known.filter(e => !isInjection(e));

  const policies = POLICIES.map(p => {
    const gated = known.filter(e => gates(p, e.signals));
    const gatedInj = injection.filter(e => gates(p, e.signals)).length;
    const gatedRest = rest.filter(e => gates(p, e.signals)).length;
    const gatedBy = counter();
    for (const e of gated) for (const s of gatingSignals(p, e.signals)) bump(gatedBy, s);
    // Among UNKNOWN events, how many already gate on the partial signals that
    // survived redaction. A lower bound, reported apart, never in a percentage.
    const unknownLowerBound = unknown.filter(e => gates(p, e.signals.filter(s => s !== REDACTED_MARKER))).length;
    return {
      id: p.id,
      label: p.label,
      gateSet: [...p.gateSet].sort(),
      gated: gated.length,
      auditOnly: known.length - gated.length,
      injectionGated: gatedInj,
      injectionAuditOnly: injection.length - gatedInj,
      restGated: gatedRest,
      restAuditOnly: rest.length - gatedRest,
      gatedBySignal: sortedObj(gatedBy),
      unknownLowerBoundGated: unknownLowerBound,
    };
  });

  // Sensitivity: the one contested membership between the two floors.
  const broad = POLICIES.find(p => p.id === 'broad-floor');
  const broadPlusEgress = { gateSet: new Set([...broad.gateSet, 'external-egress', 'network-egress']) };
  const broadGated = known.filter(e => gates(broad, e.signals)).length;
  const broadPlusEgressGated = known.filter(e => gates(broadPlusEgress, e.signals)).length;

  // Per-signal table over KNOWN events only.
  const perSignal = new Map();
  for (const e of known) {
    for (const s of e.signals) {
      if (!perSignal.has(s)) {
        perSignal.set(s, {
          signal: s,
          family: SIGNAL_FAMILY[s] ?? 'unclassified',
          events: 0,
          injectionFlavoured: INJECTION_SET.has(s),
          policies: Object.fromEntries(POLICIES.map(p => [p.id, { gated: 0, auditOnly: 0, gatesByItself: p.gateSet.has(s) }])),
        });
      }
      const slot = perSignal.get(s);
      slot.events++;
      for (const p of POLICIES) {
        if (gates(p, e.signals)) slot.policies[p.id].gated++; else slot.policies[p.id].auditOnly++;
      }
    }
  }
  const perSignalRows = [...perSignal.values()].sort((a, b) => b.events - a.events || a.signal.localeCompare(b.signal));
  const unclassified = perSignalRows.filter(r => r.family === 'unclassified').map(r => r.signal);
  const schemaOnlyKnown = known.filter(e => e.signals.every(s => SCHEMA_SET.has(s))).length;

  const dates = events.map(e => e.detectedAt.slice(0, 10)).filter(d => /^\d{4}-\d{2}-\d{2}$/.test(d)).sort();

  return {
    banner: BANNER,
    scope: 'logged-signal comparison; unknown rows excluded from every percentage',
    dateRange: dates.length ? { from: dates[0], to: dates[dates.length - 1] } : null,
    rows: { total: parse.rowCount, parsed: parse.rowCount - parse.malformed.length, malformed: parse.malformed.length, blankLines: parse.blankLines },
    malformed: parse.malformed.slice(0, 50),
    events: {
      total: events.length,
      keyedBy: sortedObj(keyKinds),
      recordsPerEvent: sortedObj(recordsPerEvent),
      multiRecord,
      conflictingOutcome: conflicting,
      outcomeTransitions: sortedObj(outcomeTransitions),
      signalDriftBetweenFirstAndLast: drift,
    },
    unknown: {
      total: unknown.length,
      reasons: sortedObj(unknownReasons),
      neverLoggedSignals: [...NEVER_LOGGED_SIGNALS],
      note: 'Signals outside the notify allowlist are written as redacted-signal; security-config-write signals are among them, so they are structurally invisible here.',
    },
    known: { total: known.length, schemaRejectOnly: schemaOnlyKnown },
    outcomes: { allEvents: sortedObj(outcomeAll), knownEvents: sortedObj(outcomeKnown) },
    severity: sortedObj(severityAll),
    tools: sortedObj(toolAll),
    eventKinds: sortedObj(eventKindAll),
    notify: {
      lastStatus: sortedObj(notifyLast),
      firstToLast: sortedObj(notifyFirstToLast),
      deliveredToSomeone,
      total: events.length,
    },
    injection: { set: [...INJECTION_FLAVOURED], withSignal: injection.length, without: rest.length },
    policies,
    sensitivity: {
      broadFloorPlusExternalEgress: { gated: broadPlusEgressGated, delta: broadPlusEgressGated - broadGated },
    },
    perSignal: perSignalRows,
    unclassifiedSignals: unclassified,
  };
}

// ── 4. Render ───────────────────────────────────────────────────────────────

const pct = (n, d) => (d > 0 ? `${((100 * n) / d).toFixed(1)}%` : 'n/a');
const kv = (obj) => Object.entries(obj).map(([k, v]) => `${k}=${v}`).join(', ') || '(none)';

export function renderMarkdown(s) {
  const K = s.known.total;
  const out = [];
  out.push('```', s.banner, '```', '');
  out.push(`**Window:** ${s.dateRange ? `${s.dateRange.from} to ${s.dateRange.to}` : 'n/a'} (dates from the log's own timestamps; no host named)`, '');
  out.push('### Input accounting', '');
  out.push('| rows | parsed | malformed | blank lines | events | multi-record events | conflicting outcome | signal drift first→last |');
  out.push('|---|---|---|---|---|---|---|---|');
  out.push(`| ${s.rows.total} | ${s.rows.parsed} | **${s.rows.malformed}** | ${s.rows.blankLines} | ${s.events.total} | ${s.events.multiRecord} | ${s.events.conflictingOutcome} | ${s.events.signalDriftBetweenFirstAndLast} |`, '');
  out.push(`- events keyed by: ${kv(s.events.keyedBy)}`);
  out.push(`- records per event: ${kv(s.events.recordsPerEvent)}`);
  if (s.events.conflictingOutcome) out.push(`- outcome transitions on conflicting events: ${kv(s.events.outcomeTransitions)}`);
  if (s.rows.malformed) out.push(`- malformed lines (first 50): ${s.malformed.map(m => `${m.lineNo}:${m.reason}`).join(', ')}`);
  out.push('');
  out.push('### Unknown bucket (excluded from every percentage)', '');
  out.push(`- unknown events: **${s.unknown.total}** of ${s.events.total} (${kv(s.unknown.reasons)})`);
  out.push(`- known events: **${K}** (of which schema-reject only: ${s.known.schemaRejectOnly})`);
  out.push(`- structurally never logged (redacted at write): ${s.unknown.neverLoggedSignals.join(', ')} — ${s.unknown.note}`, '');
  out.push('### Outcome split (final record per event)', '');
  out.push('| outcome | all events | known events | % of known |');
  out.push('|---|---|---|---|');
  const outcomeKeys = [...new Set([...Object.keys(s.outcomes.allEvents), ...Object.keys(s.outcomes.knownEvents)])];
  for (const k of outcomeKeys) out.push(`| ${k} | ${s.outcomes.allEvents[k] ?? 0} | ${s.outcomes.knownEvents[k] ?? 0} | ${pct(s.outcomes.knownEvents[k] ?? 0, K)} |`);
  out.push('');
  out.push(`- severity (all events): ${kv(s.severity)}`);
  out.push(`- tools (all events): ${kv(s.tools)}`);
  out.push(`- event kinds: ${kv(s.eventKinds)}`, '');
  out.push('### Notify delivery (final record per event)', '');
  out.push('| final notify status | events |');
  out.push('|---|---|');
  for (const [k, v] of Object.entries(s.notify.lastStatus)) out.push(`| ${k} | ${v} |`);
  out.push('');
  out.push(`- **delivered to a person (deliveredVia set): ${s.notify.deliveredToSomeone} of ${s.notify.total}**`);
  out.push(`- first→last status transitions: ${kv(s.notify.firstToLast)}`, '');
  out.push('### Policy comparison (known events only)', '');
  out.push(`- injection-flavoured set: ${s.injection.set.join(', ')}`);
  out.push(`- known events carrying an injection-flavoured signal: **${s.injection.withSignal}** (${pct(s.injection.withSignal, K)}); without: **${s.injection.without}**`, '');
  out.push('| policy | gated | audit-only | % gated | injection: gated / audit-only | rest: gated / audit-only | unknown lower bound (not in %) |');
  out.push('|---|---|---|---|---|---|---|');
  for (const p of s.policies) {
    out.push(`| ${p.id} | ${p.gated} | ${p.auditOnly} | ${pct(p.gated, K)} | ${p.injectionGated} / ${p.injectionAuditOnly} | ${p.restGated} / ${p.restAuditOnly} | ${p.unknownLowerBoundGated} |`);
  }
  out.push('');
  out.push(`- sensitivity: adding plain \`external-egress\` to the broad floor would gate ${s.sensitivity.broadFloorPlusExternalEgress.gated} (+${s.sensitivity.broadFloorPlusExternalEgress.delta}).`);
  for (const p of s.policies) out.push(`- ${p.id} gated by signal: ${kv(p.gatedBySignal)}`);
  out.push('');
  out.push('### Per signal (known events carrying the signal; gated / audit-only under each policy)', '');
  const ids = s.policies.map(p => p.id);
  out.push(`| signal | family | events | ${ids.join(' | ')} |`);
  out.push(`|---|---|---|${ids.map(() => '---').join('|')}|`);
  for (const r of s.perSignal) {
    const cells = ids.map(id => {
      const c = r.policies[id];
      return `${c.gated} / ${c.auditOnly}${c.gatesByItself ? '' : ' ⁽ᶜ⁾'}`;
    });
    out.push(`| ${r.signal}${r.injectionFlavoured ? ' ⚑' : ''} | ${r.family} | ${r.events} | ${cells.join(' | ')} |`);
  }
  out.push('');
  out.push('⁽ᶜ⁾ the signal is not in that policy\'s gate set; any gated count there comes from a co-occurring signal. ⚑ injection-flavoured.');
  out.push(`- unclassified signals (present in log, absent from the policy map — fix the map, do not ignore): ${s.unclassifiedSignals.length ? s.unclassifiedSignals.join(', ') : 'none'}`);
  return out.join('\n');
}

// ── 5. Main ─────────────────────────────────────────────────────────────────

export function run(text) {
  const parsed = parseDenials(text);
  const events = groupEvents(parsed.rows);
  const summary = analyse(events, { malformed: parsed.malformed, rowCount: parsed.rows.length + parsed.malformed.length, blankLines: parsed.blankLines });
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
