/** How much of the real-stop corpus is pre-clearable at all, before any model
 *  is consulted? Answers "what is the maximum this feature can ever buy". */
import { readFileSync } from 'node:fs';
import { isPreClearable, PRE_CLEARABLE_SIGNALS } from '../src/defence/iron-dome/approval-broker.js';

const path = process.argv[2];
const rows = JSON.parse(readFileSync(path, 'utf-8')) as Array<{ threats?: string[]; action?: string; preview?: string }>;
let eligible = 0, ineligible = 0;
const blockedBy = new Map<string, number>();
for (const r of rows) {
  const sigs = r.threats ?? [];
  if (isPreClearable(sigs)) { eligible++; continue; }
  ineligible++;
  for (const s of sigs) if (!PRE_CLEARABLE_SIGNALS.has(s)) blockedBy.set(s, (blockedBy.get(s) ?? 0) + 1);
}
console.log(`corpus: ${rows.length} real stops`);
console.log(`pre-clearable ceiling: ${eligible} (${(100*eligible/rows.length).toFixed(1)}%)`);
console.log(`always needs a human:  ${ineligible} (${(100*ineligible/rows.length).toFixed(1)}%)`);
console.log('\ntop signals keeping a stop human-only:');
for (const [s, n] of [...blockedBy].sort((a,b)=>b[1]-a[1]).slice(0,10)) console.log(`  ${String(n).padStart(4)}  ${s}`);
