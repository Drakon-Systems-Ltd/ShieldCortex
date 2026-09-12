/**
 * Held-out evaluation of the L2 leaf — LAB ONLY, never shipped.
 *
 * Runs `detectNonAuthoritativeInstruction` from the BUILT output against the
 * draw from pi-holdout-gen.mjs, under `web` and `tool_result`, and prints
 * counts. It never prints a generated string, a matched span, or anything else
 * from which one could be reconstructed — which is the point. A held-out set
 * you can read is a held-out set you will tune against, and then it is just
 * another ratchet.
 *
 * Counting rules, stated so the numbers mean one thing:
 *
 *   false positive — a benign string detected under ANY label. The pessimistic
 *                    reading, because one label firing is one operator seeing a
 *                    quarantine they did not deserve.
 *   recall hit     — an attack string detected under EVERY label. The
 *                    pessimistic reading in the other direction.
 *
 * Gates: false positives at or below 2%, recall at or above 90%. Non-English is
 * measured and reported separately and is NOT part of either gate; the layer is
 * an English regex tier and the honest number is the one it actually scores.
 *
 * Usage:
 *   npm run build:ts
 *   node scripts/lab/pi-holdout-eval.mjs [--variation N]
 */

import { generate, digest } from './pi-holdout-gen.mjs';
import { detectNonAuthoritativeInstruction } from '../../dist/defence/firewall/provenance-policy.js';

const LABELS = ['web', 'tool_result'];
const FP_GATE = 0.02;
const RECALL_GATE = 0.9;

function pct(hit, total) {
  return total === 0 ? '0.0%' : `${((hit / total) * 100).toFixed(1)}%`;
}

function tally(map, key, hit) {
  const row = map.get(key) ?? { hit: 0, total: 0 };
  row.total += 1;
  if (hit) row.hit += 1;
  map.set(key, row);
}

function lines(map, render) {
  return [...map.entries()]
    .sort((a, b) => a[0].localeCompare(b[0]))
    .map(([key, row]) => `    ${key.padEnd(24)} ${render(row)}`);
}

function main() {
  const argv = process.argv.slice(2);
  const at = argv.indexOf('--variation');
  const variation = at === -1 ? 0 : Number.parseInt(argv[at + 1] ?? '0', 10);
  if (!Number.isInteger(variation) || variation < 0) throw new Error('--variation wants a non-negative integer');

  const set = generate(variation);
  const out = [];

  // ── benign ──
  let falsePositives = 0;
  const perGenre = new Map();
  const perLabelFp = new Map(LABELS.map((label) => [label, 0]));
  for (const { genre, text } of set.benign) {
    let anyLabel = false;
    for (const label of LABELS) {
      if (detectNonAuthoritativeInstruction(text, label).detected) {
        anyLabel = true;
        perLabelFp.set(label, (perLabelFp.get(label) ?? 0) + 1);
      }
    }
    if (anyLabel) falsePositives += 1;
    tally(perGenre, genre, anyLabel);
  }

  // ── attack ──
  let detected = 0;
  const perShape = new Map();
  const perVariant = new Map();
  for (const { shape, variant, text } of set.attack) {
    const everyLabel = LABELS.every((label) => detectNonAuthoritativeInstruction(text, label).detected);
    if (everyLabel) detected += 1;
    tally(perShape, shape, everyLabel);
    tally(perVariant, variant, everyLabel);
  }

  // ── non-English, measured and excluded from the gates ──
  let nonEnglishHits = 0;
  for (const { text } of set.nonEnglish) {
    if (LABELS.every((label) => detectNonAuthoritativeInstruction(text, label).detected)) nonEnglishHits += 1;
  }

  const fpRate = set.benign.length === 0 ? 0 : falsePositives / set.benign.length;
  const recall = set.attack.length === 0 ? 0 : detected / set.attack.length;
  const pass = fpRate <= FP_GATE && recall >= RECALL_GATE;

  out.push('held-out evaluation (counts only; no generated string is ever printed)');
  out.push(`  variation            ${set.variation}`);
  out.push(`  digest               ${digest(set)}`);
  out.push(`  labels               ${LABELS.join(', ')}`);
  out.push('');
  out.push(`benign   ${set.benign.length} strings across ${perGenre.size} genres`);
  out.push(`  false positives      ${falsePositives}  (${pct(falsePositives, set.benign.length)})   gate <= 2.0%`);
  for (const label of LABELS) {
    out.push(`  under ${label.padEnd(15)}${perLabelFp.get(label)}`);
  }
  out.push('  per genre (hits / total):');
  out.push(...lines(perGenre, (row) => `${String(row.hit).padStart(3)} / ${row.total}`));
  out.push('');
  out.push(`attack   ${set.attack.length} strings across ${perShape.size} shapes`);
  out.push(`  detected             ${detected}  (${pct(detected, set.attack.length)})   gate >= 90.0%`);
  out.push('  per shape (hits / total):');
  out.push(...lines(perShape, (row) => `${String(row.hit).padStart(3)} / ${row.total}   ${pct(row.hit, row.total)}`));
  out.push('  per variant (hits / total):');
  out.push(...lines(perVariant, (row) => `${String(row.hit).padStart(3)} / ${row.total}   ${pct(row.hit, row.total)}`));
  out.push('');
  out.push(`non-english   ${set.nonEnglish.length} strings — out of scope, measured not asserted`);
  out.push(`  detected             ${nonEnglishHits}  (${pct(nonEnglishHits, set.nonEnglish.length)})`);
  out.push('');
  out.push(`VERDICT  ${pass ? 'PASS' : 'FAIL'}   fp ${pct(falsePositives, set.benign.length)} <= 2.0%   recall ${pct(detected, set.attack.length)} >= 90.0%`);
  out.push('');

  process.stdout.write(out.join('\n'));
  process.exitCode = pass ? 0 : 1;
}

main();
