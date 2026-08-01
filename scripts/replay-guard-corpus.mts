/**
 * Replay a corpus of real Action Guard stop events through `evaluateToolCall`
 * and report how many still stop.
 *
 * Usage:  npx tsx scripts/replay-guard-corpus.mts <corpus.json> [--by-threat] [--show <threat>]
 *
 * The corpus is a JSON array of audit records of the shape
 *   { ts, action, threats[], severity, preview }
 * where `preview` is the audit log's `"<Tool> :: command=… description=…"` line.
 *
 * CAVEAT, stated up front because it bounds every number this prints: the audit
 * log stores a TRUNCATED preview (~100 chars of the command), not the full tool
 * call. A replay therefore measures the guard against the head of each command,
 * which is where the great majority of these rules match — but a verdict that
 * depended on a later segment cannot be reproduced. Read the output as "how the
 * guard now treats this command shape", not as a bit-exact re-run.
 */

import { readFileSync } from 'node:fs';
import { evaluateToolCall } from '../src/defence/iron-dome/tool-action-guard.js';

interface CorpusEvent {
  ts: string;
  action: string;
  threats: string[];
  severity: string;
  preview: string;
}

/** Pull `command=` / `path=` / `url=` back out of an audit preview line. */
function parsePreview(preview: string): { tool: string; args: Record<string, unknown> } | null {
  const head = preview.match(/^([\w.:-]+)\s*::\s*/);
  if (!head) return null;
  const tool = head[1];
  const rest = preview.slice(head[0].length);
  const args: Record<string, unknown> = {};
  // Fields are `key=value` runs separated by ` key=` at the top level. The last
  // field runs to end-of-string (and may itself be truncated mid-token).
  const FIELD = /(?:^|\s)(command|path|file_path|url|description|timeout|run_in_background)=/g;
  const marks: Array<{ key: string; start: number }> = [];
  let m: RegExpExecArray | null;
  while ((m = FIELD.exec(rest)) !== null) marks.push({ key: m[1], start: m.index + m[0].length });
  for (let i = 0; i < marks.length; i++) {
    const end = i + 1 < marks.length ? rest.lastIndexOf(` ${marks[i + 1].key}=`, marks[i + 1].start) : rest.length;
    args[marks[i].key] = rest.slice(marks[i].start, end < 0 ? rest.length : end);
  }
  if (!marks.length) args.command = rest;
  // `description` is host metadata, not part of the execution surface — the
  // guard never scanned it, so replaying it would invent signals.
  delete args.description;
  delete args.timeout;
  delete args.run_in_background;
  return { tool, args };
}

const [, , corpusPath, ...flags] = process.argv;
if (!corpusPath) {
  console.error('usage: replay-guard-corpus.mts <corpus.json> [--by-threat] [--show <threat>]');
  process.exit(2);
}
const showThreat = flags.includes('--show') ? flags[flags.indexOf('--show') + 1] : null;
const corpus: CorpusEvent[] = JSON.parse(readFileSync(corpusPath, 'utf8'));

let stops = 0;
let passes = 0;
let unparsed = 0;
const perThreat = new Map<string, { total: number; nowPasses: number }>();
const escalations: Array<{ was: string; now: string; preview: string }> = [];
const relaxed: string[] = [];
const stillStopping: string[] = [];

for (const ev of corpus) {
  const parsed = parsePreview(ev.preview);
  if (!parsed) { unparsed++; continue; }
  const v = evaluateToolCall(parsed.tool, parsed.args);
  const nowStops = v.decision !== 'allow';
  if (nowStops) stops++; else passes++;
  for (const t of ev.threats) {
    const e = perThreat.get(t) ?? { total: 0, nowPasses: 0 };
    e.total++;
    if (!nowStops) e.nowPasses++;
    perThreat.set(t, e);
  }
  // An event that was require_approval and is now `block` is a TIGHTENING —
  // surfaced explicitly so a precision pass can never smuggle one in unseen.
  if (ev.action === 'require_approval' && v.decision === 'block') {
    escalations.push({ was: ev.action, now: v.decision, preview: ev.preview.slice(0, 120) });
  }
  if (!nowStops && (showThreat ? ev.threats.includes(showThreat) : false)) {
    relaxed.push(`[${ev.threats.join(',')}] ${ev.preview.replace(/\n/g, '\\n').slice(0, 150)}`);
  }
  if (nowStops && flags.includes('--dump-stops')) {
    stillStopping.push(
      `${v.decision === 'block' ? 'BLOCK' : 'GATE '} [${v.signals.join(',')}] ` +
      `${String(parsed.args.command ?? parsed.args.url ?? '').replace(/\n/g, '\\n').slice(0, 115)}`,
    );
  }
}

const replayed = stops + passes;
console.log(`corpus: ${corpus.length} events (${unparsed} unparseable, ${replayed} replayed)`);
console.log(`still stops:  ${stops}  (${((stops / replayed) * 100).toFixed(1)}%)`);
console.log(`now passes:   ${passes}  (${((passes / replayed) * 100).toFixed(1)}%)`);

if (flags.includes('--by-threat')) {
  console.log('\nper original threat  (now-passes / events carrying that threat)');
  [...perThreat.entries()]
    .sort((a, b) => b[1].total - a[1].total)
    .forEach(([t, e]) => console.log(`  ${String(e.nowPasses).padStart(4)} / ${String(e.total).padEnd(4)}  ${t}`));
}
if (escalations.length) {
  console.log(`\nTIGHTENED (was require_approval, now block): ${escalations.length}`);
  escalations.slice(0, 20).forEach(e => console.log(`  ${e.preview}`));
}
if (stillStopping.length) {
  console.log(`\nstill stopping (${stillStopping.length}):`);
  [...new Set(stillStopping)].sort().forEach(s => console.log(`  ${s}`));
}
if (showThreat) {
  console.log(`\nnow-passing events carrying "${showThreat}": ${relaxed.length}`);
  relaxed.slice(0, 40).forEach(r => console.log(`  ${r}`));
}
