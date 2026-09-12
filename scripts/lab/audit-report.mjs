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
 * own). Those are resolved transitively, and the rule is per ENTRY rather than
 * per node: a node is waived only when every advisory in its `via` is waived
 * AND every package in its `via` resolves to a node that is itself waived.
 * Review found the weaker version — seed the node from its own advisory ids,
 * then never look at the rest of `via` — passing a report whose waived node also
 * derived from a package that did not exist.
 *
 * Usage:
 *   npm run audit:release                 # the gate
 *   node scripts/lab/audit-report.mjs --json
 *   node scripts/lab/audit-report.mjs --omit=optional   # extra npm audit flags
 *
 * Environment:
 *   SC_AUDIT_TIMEOUT_MS   wall-clock deadline for the `npm audit` subprocess
 *                         (default 120000; it is SIGKILLed on expiry, exit 2)
 *
 * Exit codes: 0 pass, 1 unwaived advisory or expired/invalid waiver,
 *             2 could not run `npm audit`, or its output is not a usable
 *               report. Undecidable is NOT zero findings: exit 2 is the gate
 *               refusing to answer, and CI must treat it as a failure.
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
 * Is this string a real calendar date in `YYYY-MM-DD` form?
 *
 * The spelling check alone accepted `2099-99-99`, and expiry then compares
 * strings — so a typo (or a deliberately absurd date) bought an entry that no
 * `expiredWaivers` run could ever retire. Round-trip through `Date.UTC` so the
 * month and day have to survive being turned into a real instant: 2099-99-99
 * rolls over into 2107 and fails, as does 2026-02-30.
 */
export function isCalendarDate(value) {
  const m = String(value ?? '').match(/^(\d{4})-(\d{2})-(\d{2})$/);
  if (!m) return false;
  const [year, month, day] = [Number(m[1]), Number(m[2]), Number(m[3])];
  const at = new Date(Date.UTC(year, month - 1, day));
  return at.getUTCFullYear() === year && at.getUTCMonth() === month - 1 && at.getUTCDate() === day;
}

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
    if (!isCalendarDate(w.expires)) {
      throw new Error(
        `waiver ${w.id} has no real ISO \`expires\` date (got ${JSON.stringify(w.expires)})`,
      );
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
 * A node is waived only when EVERY entry in its `via` is: each advisory id it
 * carries is listed in a waiver, and each package it derives from resolves to a
 * node that is itself waived. Package references are resolved by iterating to a
 * fixed point, so a chain of any depth settles; anything still undecided —
 * including a reference into a cycle, or one the report never defined — fails
 * closed.
 *
 * This is classification, not validation: `report` must already have been
 * through `auditReportProblems()` (`runNpmAudit` does it), because an empty or
 * missing map classifies as "nothing to report" here and that is only a true
 * statement about a report we have established we can read.
 */
export function classify(report, waivedIds) {
  const nodes = Object.entries(report.vulnerabilities ?? {}).map(([name, v]) => ({
    name,
    severity: v.severity,
    ids: (v.via ?? []).filter((x) => typeof x === 'object' && x !== null).map((x) => x.source),
    viaPackages: (v.via ?? []).filter((x) => typeof x === 'string' && x !== name),
  }));

  const verdict = new Map();
  // An unwaived advisory of a node's own decides it immediately and finally:
  // nothing further down its `via` can rescue it.
  for (const n of nodes) {
    if (n.ids.some((id) => !waivedIds.has(id))) verdict.set(n.name, false);
  }
  // Fixed point. A node still undecided carries only waived advisories, if any,
  // so what is left to establish is its packages — EVERY one of them, whether or
  // not the node also had advisories of its own. Review found the older version,
  // which seeded a node `true` from its own waived ids and never looked at its
  // `via` packages again, passing a report whose waived node also derived from
  // `missing-package`.
  for (let pass = 0; pass < nodes.length + 1; pass++) {
    let changed = false;
    for (const n of nodes) {
      if (verdict.has(n.name)) continue;
      const parents = n.viaPackages;
      // No ids and no parents: nothing to justify it, so it is not waived.
      if (n.ids.length === 0 && parents.length === 0) {
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

/** A plain `{}` object — not null, not an array, not a string. */
function isPlainObject(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Everything wrong with an `npm audit --json` payload, as a list of reasons.
 *
 * Syntactically valid JSON is not a usable audit report. `{}` parses; so does
 * `{"metadata":{"vulnerabilities":{"high":1,"total":1}}}`, which says "one high
 * advisory" while carrying no node to name it. Read either one the tolerant way
 * — `report.vulnerabilities ?? {}` — and the gate prints PASS, 0 unwaived, over
 * a report it could not read. That is the worst possible failure mode for a
 * security gate: silence that looks like a clean bill of health.
 *
 * So the shape is checked before anything is classified, and the strongest
 * check is the cross-one: `metadata.vulnerabilities.total` must equal the
 * number of nodes in `vulnerabilities`. npm derives that histogram from that
 * map, so the two agree in every real report (measured across seven of them,
 * from 0 to 7 advisories). When they disagree, the payload is not an npm audit
 * report and must not be classified as an empty one.
 *
 * Returns [] for a usable report.
 */
export function auditReportProblems(report) {
  if (!isPlainObject(report)) {
    return [`expected a JSON object, got ${Array.isArray(report) ? 'an array' : typeof report}`];
  }
  const problems = [];
  const nodes = report.vulnerabilities;
  if (!isPlainObject(nodes)) {
    problems.push(
      `\`vulnerabilities\` is ${nodes === undefined ? 'missing' : JSON.stringify(nodes)}` +
        ' — a report with no vulnerability map is undecidable, not clean',
    );
  }
  const totals = report.metadata?.vulnerabilities;
  if (!isPlainObject(totals)) {
    problems.push(
      `\`metadata.vulnerabilities\` is ${totals === undefined ? 'missing' : JSON.stringify(totals)}`,
    );
    return problems;
  }
  for (const [key, value] of Object.entries(totals)) {
    if (!Number.isSafeInteger(value) || value < 0) {
      problems.push(`\`metadata.vulnerabilities.${key}\` is not a count: ${JSON.stringify(value)}`);
    }
  }
  if (!Number.isSafeInteger(totals.total)) {
    problems.push('`metadata.vulnerabilities.total` is missing');
    return problems;
  }
  if (problems.length > 0) return problems;

  const nodeCount = Object.keys(nodes).length;
  if (totals.total !== nodeCount) {
    problems.push(
      `audit output inconsistent: metadata.vulnerabilities.total is ${totals.total}` +
        ` but \`vulnerabilities\` carries ${nodeCount} node(s)`,
    );
  }
  const bucketSum = Object.entries(totals)
    .filter(([key]) => key !== 'total')
    .reduce((sum, [, value]) => sum + value, 0);
  if (bucketSum !== totals.total) {
    problems.push(
      `audit output inconsistent: severity counts sum to ${bucketSum},` +
        ` metadata.vulnerabilities.total says ${totals.total}`,
    );
  }
  problems.push(...viaProblems(nodes));
  return problems;
}

/**
 * Everything unreadable in the `via` lists of a vulnerability map.
 *
 * `via` is how npm says WHY a node is vulnerable, and it holds exactly two
 * kinds of thing: advisory objects carrying an integer `source`, and the names
 * of other nodes in the same report that this one derives from. Classification
 * filtered for those two kinds and DISCARDED everything else, which meant an
 * entry it could not read simply stopped existing. Review measured the
 * consequence on v2-shaped reports with consistent totals:
 *
 *   via: [{ source: 1124066 }, 999999 ]              PASS, "1 waived"
 *   via: [{ source: 1124066 }, null ]                PASS, "1 waived"
 *   via: [{ source: 1124066 }, "missing-package" ]   PASS, "1 waived"
 *
 * The third has no `missing-package` node anywhere in the report, so the gate
 * announced a clean bill of health over a dependency chain it could not follow.
 * None of the three is a shape npm 7+ emits — this is incomplete validation, not
 * a demonstrated bypass with real npm output — but a security gate that silently
 * discards what it cannot read is the failure mode this whole file exists to
 * close. Unreadable is exit 2, the same as any other undecidable report.
 */
export function viaProblems(nodes) {
  const problems = [];
  const describe = (value) => JSON.stringify(value) ?? String(value);
  for (const [name, node] of Object.entries(nodes)) {
    if (!isPlainObject(node)) {
      problems.push(`\`vulnerabilities.${name}\` is ${describe(node)}, not a vulnerability node`);
      continue;
    }
    if (!Array.isArray(node.via)) {
      problems.push(
        `unreadable via entry on ${name}: \`via\` is ${node.via === undefined ? 'missing' : describe(node.via)}` +
          ' — a node that does not say why it is vulnerable is undecidable, not clean',
      );
      continue;
    }
    node.via.forEach((entry, index) => {
      if (isPlainObject(entry)) {
        if (!Number.isSafeInteger(entry.source)) {
          problems.push(
            `unreadable via entry on ${name}: via[${index}] is an advisory whose` +
              ` \`source\` is ${describe(entry.source)}, not an integer advisory id`,
          );
        }
        return;
      }
      if (typeof entry === 'string') {
        // A node may name itself; npm does that for a package with a direct
        // advisory. Naming anything else means the report claims a chain it did
        // not include, and the missing link is exactly what would decide it.
        if (entry !== name && !Object.prototype.hasOwnProperty.call(nodes, entry)) {
          problems.push(
            `unreadable via entry on ${name}: via[${index}] names ${describe(entry)},` +
              ' which is not a node in this report',
          );
        }
        return;
      }
      problems.push(
        `unreadable via entry on ${name}: via[${index}] is ${describe(entry)} — expected an` +
          ' advisory object with an integer `source`, or the name of another node in this report',
      );
    });
  }
  return problems;
}

/** How long `npm audit` gets before the gate gives up on it. */
export const DEFAULT_AUDIT_TIMEOUT_MS = 120_000;

/**
 * The deadline for this run: `SC_AUDIT_TIMEOUT_MS` if it is a positive number,
 * otherwise the default. Read per call so a spawned CLI can be given a short
 * deadline by its environment without the module having to be reloaded.
 */
function auditTimeoutMs(override) {
  if (typeof override === 'number' && Number.isFinite(override) && override > 0) return override;
  const fromEnv = Number(process.env.SC_AUDIT_TIMEOUT_MS);
  if (Number.isFinite(fromEnv) && fromEnv > 0) return fromEnv;
  return DEFAULT_AUDIT_TIMEOUT_MS;
}

/**
 * Run `npm audit --omit=dev --json` and return the parsed report.
 *
 * npm exits non-zero whenever advisories exist, so the exit code carries no
 * information here — only output we cannot read as a report does. Every throw
 * from this function means "could not measure" and is exit 2 at the CLI.
 *
 * The subprocess has a real wall-clock deadline, because a declared timeout on
 * the *caller* is not one: `spawnSync` blocks the event loop, so the 120 s Jest
 * timeout on the live test could never fire. Review proved it — a fixture npm
 * that answered after 1,500 ms passed a test declared with a 20 ms timeout.
 * The deadline has to be on the child, and it is enforced with SIGKILL rather
 * than SIGTERM: a signal the child may trap is not a deadline either.
 */
export function runNpmAudit(extraArgs = [], cwd = REPO_ROOT, { timeoutMs } = {}) {
  const args = ['audit', '--omit=dev', '--json', ...extraArgs];
  const deadline = auditTimeoutMs(timeoutMs);
  const res = spawnSync('npm', args, {
    cwd,
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
    timeout: deadline,
    killSignal: 'SIGKILL',
  });
  if (res.error) {
    if (res.error.code === 'ETIMEDOUT') {
      throw new Error(
        `\`npm ${args.join(' ')}\` did not answer within ${deadline} ms and was killed.` +
          ' Set SC_AUDIT_TIMEOUT_MS to raise the deadline, or SC_SKIP_LIVE_AUDIT=1 to' +
          ' turn the live drift check off knowingly.',
      );
    }
    throw new Error(`could not run \`npm ${args.join(' ')}\`: ${res.error.message}`);
  }
  if (res.signal) {
    throw new Error(`\`npm ${args.join(' ')}\` was killed by ${res.signal} before it finished`);
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
  if (report && report.error) {
    throw new Error(`npm audit reported an error: ${JSON.stringify(report.error).slice(0, 800)}`);
  }
  const problems = auditReportProblems(report);
  if (problems.length > 0) {
    throw new Error(
      `\`npm ${args.join(' ')}\` did not produce a usable report (exit ${res.status}):\n` +
        problems.map((p) => `  - ${p}`).join('\n'),
    );
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
