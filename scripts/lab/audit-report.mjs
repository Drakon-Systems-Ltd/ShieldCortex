/**
 * Production-audit release gate — LAB ONLY, never shipped (#466).
 *
 * `npm audit` on its own is a bad gate: it exits non-zero for advisories we
 * have consciously accepted, so teams learn to ignore it, and then a real one
 * goes by unread. This wraps it so the gate means exactly one thing:
 *
 *     exit 0  <=>  every production advisory is either fixed or waived in
 *                  docs/security/audit-waivers.md, and no waiver has expired.
 *
 * Waivers are applied by EXACT advisory ID. Nothing is waived by package name,
 * severity or wildcard — a new advisory on an already-waived package fails the
 * gate, which is the whole point.
 *
 * `npm audit --json` also emits a node per *dependent* of a vulnerable package
 * (`@huggingface/transformers` has `via: ["sharp"]` and no advisory ID of its
 * own). Those are resolved transitively: a node carrying no advisory IDs is
 * waived only when every package it derives from is itself fully waived.
 *
 * Usage:
 *   npm run audit:release                 # the gate
 *   node scripts/lab/audit-report.mjs --json
 *   node scripts/lab/audit-report.mjs --omit=optional   # extra npm audit flags
 *
 * Exit codes: 0 pass, 1 unwaived advisory or expired/invalid waiver,
 *             2 could not run or parse `npm audit` at all.
 *
 * `spawnSync` is called with a fixed argv array and no shell, so nothing here
 * is interpolated into a command line.
 */

import { spawnSync } from 'child_process';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join, resolve } from 'path';

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
export const WAIVER_FILE = join(REPO_ROOT, 'docs', 'security', 'audit-waivers.md');

/** The fenced block in the waiver markdown that carries the machine-readable records. */
const WAIVER_BLOCK = /```json audit-waivers\r?\n([\s\S]*?)```/;

/**
 * Pull the waiver records out of the markdown.
 *
 * Deliberately strict: a waiver file that exists but cannot be parsed is a
 * failure, not an empty waiver set. Waiving nothing would still be a red gate,
 * but silently *reading* nothing after someone mangles the JSON is how a stale
 * waiver survives a refactor.
 */
export function parseWaivers(markdown) {
  const block = WAIVER_BLOCK.exec(markdown);
  if (!block) {
    throw new Error('no ```json audit-waivers block found in the waiver file');
  }
  const parsed = JSON.parse(block[1]);
  if (!Array.isArray(parsed.waivers)) {
    throw new Error('waiver file parsed, but `.waivers` is not an array');
  }
  for (const w of parsed.waivers) {
    if (!w.id) throw new Error('a waiver has no `id`');
    if (!Array.isArray(w.advisories) || w.advisories.length === 0) {
      throw new Error(`waiver ${w.id} has no \`advisories\` list`);
    }
    for (const a of w.advisories) {
      if (typeof a !== 'number') {
        throw new Error(`waiver ${w.id} lists a non-numeric advisory id: ${JSON.stringify(a)}`);
      }
    }
    if (!/^\d{4}-\d{2}-\d{2}$/.test(w.expires ?? '')) {
      throw new Error(`waiver ${w.id} has no ISO \`expires\` date`);
    }
    if (!w.owner) throw new Error(`waiver ${w.id} has no \`owner\``);
    if (!w.reason) throw new Error(`waiver ${w.id} has no \`reason\``);
  }
  return parsed.waivers;
}

/** Advisory ids a waiver record covers, as a flat Set. */
export function waivedAdvisoryIds(waivers) {
  return new Set(waivers.flatMap((w) => w.advisories));
}

/**
 * Classify every node in an `npm audit --json` report as waived or not.
 *
 * Returns `{ unwaived, waived, waivedIds, seenIds }` where `unwaived` and
 * `waived` are arrays of `{ name, severity, ids, viaPackages }`.
 *
 * Package-only nodes (no advisory ids of their own) are resolved against the
 * classification of the packages they derive from, iterating to a fixed point
 * so a chain of any depth settles. Anything still undecided fails closed.
 */
export function classify(report, waivedIds) {
  const nodes = Object.entries(report.vulnerabilities ?? {}).map(([name, v]) => ({
    name,
    severity: v.severity,
    ids: (v.via ?? []).filter((x) => typeof x === 'object' && x !== null).map((x) => x.source),
    viaPackages: (v.via ?? []).filter((x) => typeof x === 'string' && x !== name),
  }));

  const verdict = new Map();
  // Seed: nodes with their own advisory ids decide themselves.
  for (const n of nodes) {
    if (n.ids.length > 0) verdict.set(n.name, n.ids.every((id) => waivedIds.has(id)));
  }
  // Fixed point: a package-only node inherits from everything it derives from.
  for (let pass = 0; pass < nodes.length + 1; pass++) {
    let changed = false;
    for (const n of nodes) {
      if (verdict.has(n.name)) continue;
      const parents = n.viaPackages;
      // No ids and no parents: nothing to justify it, so it is not waived.
      if (parents.length === 0) {
        verdict.set(n.name, false);
        changed = true;
        continue;
      }
      if (parents.every((p) => verdict.get(p) === true)) {
        verdict.set(n.name, true);
        changed = true;
      } else if (parents.some((p) => verdict.get(p) === false)) {
        verdict.set(n.name, false);
        changed = true;
      }
    }
    if (!changed) break;
  }
  for (const n of nodes) if (!verdict.has(n.name)) verdict.set(n.name, false);

  const seenIds = new Set(nodes.flatMap((n) => n.ids));
  return {
    unwaived: nodes.filter((n) => verdict.get(n.name) === false),
    waived: nodes.filter((n) => verdict.get(n.name) === true),
    waivedIds: [...seenIds].filter((id) => waivedIds.has(id)),
    seenIds,
  };
}

/** Waivers whose `expires` is in the past, relative to `now`. */
export function expiredWaivers(waivers, now = new Date()) {
  const today = now.toISOString().slice(0, 10);
  return waivers.filter((w) => w.expires < today);
}

/**
 * Run `npm audit --omit=dev --json` and return the parsed report.
 *
 * npm exits non-zero whenever advisories exist, so the exit code carries no
 * information here — only unparseable output does.
 */
export function runNpmAudit(extraArgs = [], cwd = REPO_ROOT) {
  const args = ['audit', '--omit=dev', '--json', ...extraArgs];
  const res = spawnSync('npm', args, { cwd, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  if (res.error) {
    throw new Error(`could not run \`npm ${args.join(' ')}\`: ${res.error.message}`);
  }
  let report;
  try {
    report = JSON.parse(res.stdout);
  } catch {
    throw new Error(
      `\`npm ${args.join(' ')}\` produced no JSON (exit ${res.status}).\n` +
        `stderr: ${(res.stderr || '').trim().slice(0, 800)}`,
    );
  }
  if (report.error) {
    throw new Error(`npm audit reported an error: ${JSON.stringify(report.error).slice(0, 800)}`);
  }
  return report;
}

function main() {
  const argv = process.argv.slice(2);
  const wantJson = argv.includes('--json');
  const extra = argv.filter((a) => a !== '--json');

  let waivers;
  try {
    waivers = parseWaivers(readFileSync(WAIVER_FILE, 'utf8'));
  } catch (err) {
    console.error(`[audit:release] waiver file unusable — ${err.message}`);
    console.error(`[audit:release] file: ${WAIVER_FILE}`);
    process.exit(1);
  }

  let report;
  try {
    report = runNpmAudit(extra);
  } catch (err) {
    console.error(`[audit:release] ${err.message}`);
    process.exit(2);
  }

  const waivedIds = waivedAdvisoryIds(waivers);
  const { unwaived, waived, waivedIds: hitIds, seenIds } = classify(report, waivedIds);
  const expired = expiredWaivers(waivers);
  const unusedWaivers = waivers.filter((w) => !w.advisories.some((id) => seenIds.has(id)));
  const totals = report.metadata?.vulnerabilities ?? {};

  if (wantJson) {
    console.log(
      JSON.stringify(
        {
          audited: ['--omit=dev', ...extra],
          npmTotals: totals,
          unwaived: unwaived.map((n) => ({ name: n.name, severity: n.severity, advisories: n.ids })),
          waived: waived.map((n) => ({ name: n.name, severity: n.severity, advisories: n.ids })),
          waivedAdvisoryIdsHit: hitIds,
          expiredWaivers: expired.map((w) => ({ id: w.id, expires: w.expires })),
          unusedWaivers: unusedWaivers.map((w) => w.id),
          pass: unwaived.length === 0 && expired.length === 0,
        },
        null,
        2,
      ),
    );
  } else {
    console.log(`[audit:release] npm audit --omit=dev${extra.length ? ' ' + extra.join(' ') : ''}`);
    console.log(
      `[audit:release] npm totals: ${JSON.stringify(totals)} across ${Object.keys(report.vulnerabilities ?? {}).length} node(s)`,
    );
    for (const n of waived) {
      console.log(
        `[audit:release]   WAIVED   ${n.name} (${n.severity})` +
          (n.ids.length ? ` advisories ${n.ids.join(', ')}` : ' — derives from a waived package'),
      );
    }
    for (const n of unwaived) {
      console.log(
        `[audit:release]   UNWAIVED ${n.name} (${n.severity})` +
          (n.ids.length ? ` advisories ${n.ids.join(', ')}` : ` via ${n.viaPackages.join(', ')}`),
      );
    }
    for (const w of expired) {
      console.log(`[audit:release]   EXPIRED  waiver ${w.id} lapsed on ${w.expires}`);
    }
    for (const w of unusedWaivers) {
      console.log(
        `[audit:release]   note: waiver ${w.id} matched no advisory in this tree` +
          ' (expected when auditing without optional dependencies; delete it once the advisory is gone for good)',
      );
    }
  }

  if (expired.length > 0) {
    console.error(
      `[audit:release] FAIL — ${expired.length} waiver(s) past their review date.` +
        ` Re-do the reachability review in ${WAIVER_FILE} or remove the entry.`,
    );
    process.exit(1);
  }
  if (unwaived.length > 0) {
    console.error(
      `[audit:release] FAIL — ${unwaived.length} unwaived production advisory node(s).` +
        ` Fix them, or add an entry to ${WAIVER_FILE} naming the exact advisory ids.`,
    );
    process.exit(1);
  }
  console.error(
    `[audit:release] PASS — 0 unwaived production advisories` +
      ` (${hitIds.length} waived: ${hitIds.join(', ') || 'none in this tree'}).`,
  );
}

// Only run the gate when invoked directly; the tests import the helpers above.
if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  main();
}
