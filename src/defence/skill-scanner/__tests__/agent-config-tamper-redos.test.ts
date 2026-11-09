/**
 * ReDoS gate for the agent_config_tamper rows (PR #949 review, blocker 1).
 *
 * Two shapes were measured by the reviewer on the first revision:
 *   ">".repeat(100000)            : >20 s (main: 0.16 s)  - redirect row
 *   "Edit:\n" + " ".repeat(100000): 45 s   (main: 0.20 s) - Markdown verb-colon row
 * Each input is checked per regex and through the full scan. The budgets are
 * wall-clock; a fixed regex finishes in milliseconds, a polynomial one never
 * finishes, so the margin is wide on purpose.
 *
 * Where the time is measured (changed 9 Nov 2026, PR #949 CI disposition):
 *
 * The 500 ms budget is asserted on numbers taken in a FRESH Node process that
 * loads the built scanner (dist/) and times the same 22 inputs at the same
 * three levels, one sample each. It used to be asserted on numbers taken
 * inside the Jest worker. On Node 22.14.0 that worker is a long-lived process
 * that has already run several hundred suites, and late in its life the same
 * regexes on the same inputs ran 19-66x slower (full scan 558-901 ms against
 * 49-76 ms for identical bytes one commit earlier; Node 24 was unaffected).
 * The gate was measuring the age of the worker, not the regexes. The cause of
 * the slow mode is not known; it is tracked separately.
 *
 * Three things keep the gate honest:
 *   1. Budget, inputs and skip set are unchanged; only the process changed.
 *   2. A negative control plants one deliberately quadratic row in the same
 *      child harness and must MISS the budget (see CONTROL_ROW below).
 *   3. The in-worker run is kept for all 22 inputs. Its numbers are printed
 *      and asserted against a 5,000 ms catastrophic ceiling, which a
 *      polynomial regex still breaks in any engine mode (20 s and 45 s above).
 *
 * The child needs dist/, which `npm test` builds before Jest starts
 * (scripts/run-jest.mjs). A bare `jest` run without a build fails here with
 * the child's import error rather than passing.
 */

import { describe, it, expect, beforeAll, afterAll } from '@jest/globals';
import { spawnSync } from 'node:child_process';
import { scanSkillContent } from '../scan-skill.js';
import type { SkillScanResult } from '../scan-skill.js';
import { detectSkillThreats, skillPatternGroupRows } from '../patterns.js';
import type { SkillThreatResult } from '../patterns.js';

const N = 100_000;
const BUDGET_MS = 500;

const ADVERSARIAL: Array<[string, string]> = [
  ['100k ">"', '>'.repeat(N)],
  ['Edit:\\n + 100k spaces', 'Edit:\n' + ' '.repeat(N)],
  ['Edit:\\n + 100k tabs', 'Edit:\n' + '\t'.repeat(N)],
  ['repeated "Edit:\\n  " blocks', 'Edit:\n  '.repeat(N / 16)],
  ['"Edit:\\n" + blank lines', 'Edit:\n' + '\n'.repeat(N)],
  ['Edit: + spaced blank lines', 'Edit:\n' + ' \n'.repeat(N / 2)],
  ['list markers', 'Add:\n' + '- '.repeat(N / 2)],
  ['"> " repeated', '> '.repeat(N / 2)],
  ['">x" repeated', '>x'.repeat(N / 2)],
  ['">" + long path run', '>' + 'a'.repeat(N)],
  ['">" + dotted path run', '>' + '.claude/'.repeat(N / 8)],
  ['tee -a run', 'tee -a '.repeat(N / 7)],
  ['tee + non-space run', 'tee ' + 'x'.repeat(N)],
  ['Add word runs', 'Add '.repeat(N / 8)],
  ['Add + long line', 'Add ' + 'x '.repeat(N / 2)],
  ['install + mcp words', 'install '.repeat(N / 8) + 'mcp server'],
  ['config-file mentions', 'Edit .claude/settings.json '.repeat(N / 26)],
  ['negation runs', "not never n't ".repeat(N / 14)],
  ['underscore var name', 'A_'.repeat(N / 2) + 'BASE_URL'],
  ['long A run', 'A'.repeat(N)],
  ['quote and ws run', 'sandbox' + ' '.repeat(N) + ':'],
  ['CR runs', 'Edit:\r\n'.repeat(N / 7)],
];

// A 100 KB run of one non-space word takes ~18 s through scanSkillContent on
// main as well (a pre-existing stage outside agent_config_tamper; detectSkillThreats
// and every agent_config_tamper row are fast on it). These inputs stay in the
// per-row and detectSkillThreats gates but are excluded from the full-scan gate
// so this suite measures only what PR #949 changed.
const FULL_SCAN_SLOW_ON_MAIN = new Set(['">" + long path run', 'tee + non-space run', 'underscore var name', 'long A run']);

function ms(fn: () => void): number {
  const t = process.hrtime.bigint();
  fn();
  return Number(process.hrtime.bigint() - t) / 1e6;
}

function timed<T>(fn: () => T): { elapsed: number; value: T } {
  const t = process.hrtime.bigint();
  const value = fn();
  return { elapsed: Number(process.hrtime.bigint() - t) / 1e6, value };
}

// ── Fresh-process harness ───────────────────────────────────────────────────

/** In-worker numbers are reported, and asserted only against this ceiling. */
const IN_WORKER_CEILING_MS = 5_000;
/** Time allowed for the 22-input child; a child that overruns it fails the gate. */
const GATE_CHILD_TIMEOUT_MS = 120_000;
/** Time the negative control gets on top of the measured cost of starting a child. */
const CONTROL_CAP_MS = 3_000;

/**
 * Negative control: the trailing-whitespace trim regex, the textbook quadratic
 * shape (for each of n start positions `\s+` runs to the end of the whitespace
 * run, `$` fails, and the engine backs off one character at a time). It is
 * planted as one extra row beside the real agent_config_tamper rows and timed
 * by the same child harness on one of the 22 gate inputs: 'sandbox', 100,000
 * spaces, ':'. The real rows must be under budget on that input (asserted by
 * the fresh-process gate); with the planted row the same measurement must miss it.
 * This is the defect class the reviewer reported (20 s and 45 s at 100 KB).
 */
const CONTROL_ROW = { source: '\\s+$', flags: '' };
const CONTROL_INPUT_LABEL = 'quote and ws run';

interface ChildInput { label: string; text: string; fullScan: boolean }
interface ChildRequest {
  patternsModule: string;
  scanModule: string;
  plantedRows: Array<{ source: string; flags: string }>;
  inputs: ChildInput[];
}
interface Measured {
  label: string;
  /** Slowest single row on this input. */
  rowMaxMs: number;
  rowMaxSource: string;
  /** True when the slowest row is a planted control row, not a real row. */
  rowMaxPlanted: boolean;
  detectMs: number;
  detectSig: string;
  fullMs: number | null;
  fullSig: string | null;
}
interface ChildReport { node: string; rows: string[]; results: Measured[] }
interface ChildRun {
  wallMs: number;
  timedOut: boolean;
  status: number | null;
  signal: string | null;
  stderr: string;
  report: ChildReport | null;
}

function detectSignature(r: SkillThreatResult): string {
  return r.threats.join(',');
}

/** Outcome of a full scan, including whether it fell into the catch-all failure path. */
function fullSignature(r: SkillScanResult): string {
  return [r.riskLevel, r.findings.length, r.summary.includes('scan failed') ? 'scan-failed' : 'scanned'].join('|');
}

// Runs in the child via `node --input-type=module -e`. Plain JavaScript with
// no backslashes, backticks or template placeholders, so it can sit in a
// template literal unescaped. It mirrors the in-worker measurement below: the
// same three levels in the same order, one sample each, same clock.
const CHILD_HARNESS = `
let raw = '';
process.stdin.setEncoding('utf8');
for await (const chunk of process.stdin) raw += chunk;
const req = JSON.parse(raw);
const { detectSkillThreats, skillPatternGroupRows } = await import(req.patternsModule);
const { scanSkillContent } = await import(req.scanModule);

function timed(fn) {
  const t = process.hrtime.bigint();
  const value = fn();
  return { elapsed: Number(process.hrtime.bigint() - t) / 1e6, value };
}

const realRows = [...skillPatternGroupRows('agent_config_tamper')];
const plantedRows = req.plantedRows.map((r) => new RegExp(r.source, r.flags));
const timedRows = [...realRows, ...plantedRows];
const results = [];
for (const input of req.inputs) {
  let rowMaxMs = -1;
  let rowMaxIndex = -1;
  for (let i = 0; i < timedRows.length; i++) {
    const { elapsed } = timed(() => timedRows[i].test(input.text));
    if (elapsed > rowMaxMs) { rowMaxMs = elapsed; rowMaxIndex = i; }
  }
  const detect = timed(() => detectSkillThreats(input.text));
  let fullMs = null;
  let fullSig = null;
  if (input.fullScan) {
    const full = timed(() => scanSkillContent(input.text, undefined, 'claude-md', 'CLAUDE.md'));
    fullMs = full.elapsed;
    fullSig = [
      full.value.riskLevel,
      full.value.findings.length,
      full.value.summary.includes('scan failed') ? 'scan-failed' : 'scanned',
    ].join('|');
  }
  results.push({
    label: input.label,
    rowMaxMs,
    rowMaxSource: rowMaxIndex >= 0 ? timedRows[rowMaxIndex].source.slice(0, 60) : '',
    rowMaxPlanted: rowMaxIndex >= realRows.length,
    detectMs: detect.elapsed,
    detectSig: detect.value.threats.join(','),
    fullMs,
    fullSig,
  });
}
process.stdout.write(JSON.stringify({
  node: process.version,
  rows: realRows.map((r) => r.source + '/' + r.flags),
  results,
}));
`;

const DIST_SCANNER = new URL('../../../../dist/defence/skill-scanner/', import.meta.url);

function runChild(
  inputs: ChildInput[],
  plantedRows: Array<{ source: string; flags: string }>,
  timeoutMs: number,
): ChildRun {
  const request: ChildRequest = {
    patternsModule: new URL('patterns.js', DIST_SCANNER).href,
    scanModule: new URL('scan-skill.js', DIST_SCANNER).href,
    plantedRows,
    inputs,
  };
  const { elapsed, value: child } = timed(() => spawnSync(
    process.execPath,
    ['--input-type=module', '-e', CHILD_HARNESS],
    {
      input: JSON.stringify(request),
      encoding: 'utf8',
      timeout: timeoutMs,
      killSignal: 'SIGKILL',
      env: { ...process.env },
    },
  ));
  const timedOut = (child.error as NodeJS.ErrnoException | undefined)?.code === 'ETIMEDOUT';
  let report: ChildReport | null = null;
  if (!timedOut && child.status === 0) {
    try {
      report = JSON.parse(child.stdout) as ChildReport;
    } catch {
      report = null;
    }
  }
  return {
    wallMs: elapsed,
    timedOut,
    status: child.status,
    signal: child.signal,
    stderr: (child.stderr ?? '').slice(-2_000),
    report,
  };
}

function describeRun(run: ChildRun): string {
  return `timedOut=${run.timedOut} status=${run.status} signal=${run.signal} wall=${run.wallMs.toFixed(0)} ms stderr=${run.stderr}`;
}

function fmt(n: number | null | undefined): string {
  return n === null || n === undefined ? 'skipped' : `${n.toFixed(1)} ms`;
}

function table(title: string, rowsOut: Array<Partial<Measured> & { label: string }>): string {
  return [
    `[redos-gate] ${title}`,
    ...rowsOut.map((r) => `[redos-gate]   ${r.label} | every row max=${fmt(r.rowMaxMs)} | detectSkillThreats=${fmt(r.detectMs)} | full scan=${fmt(r.fullMs)}`),
  ].join('\n');
}

describe('agent_config_tamper ReDoS gate', () => {
  const rows = skillPatternGroupRows('agent_config_tamper');

  // One child for the whole suite: the fresh-process measurement of all 22
  // inputs. Started before any test in this file so it is as early in the
  // suite as the old in-worker measurement was.
  let gate: ChildRun | undefined;

  beforeAll(() => {
    gate = runChild(
      ADVERSARIAL.map(([label, text]) => ({ label, text, fullScan: !FULL_SCAN_SLOW_ON_MAIN.has(label) })),
      [],
      GATE_CHILD_TIMEOUT_MS,
    );
    if (gate.report) {
      console.log(table(`fresh process, node ${gate.report.node}, budget ${BUDGET_MS} ms, child wall ${gate.wallMs.toFixed(0)} ms`, gate.report.results));
    }
  }, GATE_CHILD_TIMEOUT_MS + 30_000);

  function freshReport(): ChildReport {
    if (!gate || !gate.report) {
      throw new Error(`fresh-process child produced no report (${gate ? describeRun(gate) : 'not started'})`);
    }
    return gate.report;
  }

  function fresh(label: string): Measured {
    const found = freshReport().results.find((r) => r.label === label);
    if (!found) throw new Error(`fresh-process child returned no numbers for input: ${label}`);
    return found;
  }

  it('has rows to test', () => {
    expect(rows.length).toBeGreaterThan(10);
  });

  // ── 1. The asserted gate: a fresh process, unchanged 500 ms budget ────────
  describe('fresh process (asserted)', () => {
    it('child finished and timed the built copy of the same rows on the same inputs', () => {
      const report = freshReport();
      expect(report.rows).toEqual(rows.map((re) => `${re.source}/${re.flags}`));
      expect(report.results.map((r) => r.label)).toEqual(ADVERSARIAL.map(([label]) => label));
    });

    for (const [label] of ADVERSARIAL) {
      it(`every row finishes under ${BUDGET_MS} ms: ${label}`, () => {
        const r = fresh(label);
        expect(r.rowMaxPlanted).toBe(false);
        expect({ re: r.rowMaxSource, ok: r.rowMaxMs < BUDGET_MS, ms: r.rowMaxMs }).toEqual({ re: r.rowMaxSource, ok: true, ms: r.rowMaxMs });
      });

      it(`detectSkillThreats finishes under ${BUDGET_MS} ms: ${label}`, () => {
        expect(fresh(label).detectMs).toBeLessThan(BUDGET_MS);
      });

      const fullScanIt = FULL_SCAN_SLOW_ON_MAIN.has(label) ? it.skip : it;
      fullScanIt(`full scan finishes under ${BUDGET_MS} ms: ${label}`, () => {
        const r = fresh(label);
        expect(r.fullMs).not.toBeNull();
        expect(r.fullMs as number).toBeLessThan(BUDGET_MS);
      });
    }
  });

  // ── 2. Negative control: the same harness must catch a quadratic row ──────
  describe('negative control', () => {
    it(`a planted quadratic row misses the ${BUDGET_MS} ms budget in the same child harness`, () => {
      const controlInput = ADVERSARIAL.find(([label]) => label === CONTROL_INPUT_LABEL);
      if (!controlInput) throw new Error(`control input missing from the gate inputs: ${CONTROL_INPUT_LABEL}`);
      expect(FULL_SCAN_SLOW_ON_MAIN.has(CONTROL_INPUT_LABEL)).toBe(false);

      // Calibration: the same planted row on the same shape at 1/100 of the
      // size. It must come back with a number, under budget, with the planted
      // row timed. That shows a control child starts, loads the scanner and
      // reports, so a miss below is the regex and not a broken harness. Its
      // wall time is the cost of starting a child, used for the cap below.
      const calibration = runChild(
        [{ label: 'control calibration', text: 'sandbox' + ' '.repeat(N / 100) + ':', fullScan: false }],
        [CONTROL_ROW],
        GATE_CHILD_TIMEOUT_MS,
      );
      if (!calibration.report) throw new Error(`control calibration child produced no report (${describeRun(calibration)})`);
      expect(calibration.report.results).toHaveLength(1);
      expect(calibration.report.rows).toEqual(rows.map((re) => `${re.source}/${re.flags}`));
      expect(calibration.report.results[0].rowMaxMs).toBeLessThan(BUDGET_MS);

      // The control: 100 KB. The child is killed CONTROL_CAP_MS after the
      // measured start-up cost; a kill counts as a miss. A child that exits
      // any other way without a report is a broken control and fails here.
      const capMs = Math.ceil(calibration.wallMs) + CONTROL_CAP_MS;
      const control = runChild(
        [{ label: 'control', text: controlInput[1], fullScan: false }],
        [CONTROL_ROW],
        capMs,
      );
      const measured = control.report ? control.report.results[0] : undefined;
      console.log([
        `[redos-gate] negative control, planted row /${CONTROL_ROW.source}/ on "${CONTROL_INPUT_LABEL}"`,
        `[redos-gate]   calibration (1 KB): every row max=${fmt(calibration.report.results[0].rowMaxMs)} | child wall ${calibration.wallMs.toFixed(0)} ms`,
        `[redos-gate]   control (100 KB): ${control.timedOut ? `killed at the ${capMs} ms cap (miss)` : `every row max=${fmt(measured?.rowMaxMs)} planted=${measured?.rowMaxPlanted}`} | child wall ${control.wallMs.toFixed(0)} ms`,
      ].join('\n'));

      if (!control.timedOut && !measured) throw new Error(`control child neither reported nor hit the cap (${describeRun(control)})`);
      const missed = control.timedOut
        || (measured !== undefined && measured.rowMaxPlanted && measured.rowMaxMs >= BUDGET_MS);
      expect(missed).toBe(true);
    }, GATE_CHILD_TIMEOUT_MS + 60_000);
  });

  // ── 3. In this Jest worker: reported, catastrophic ceiling only ───────────
  describe('in this Jest worker (reported)', () => {
    const inWorker = new Map<string, Partial<Measured> & { label: string }>();
    const record = (label: string): Partial<Measured> & { label: string } => {
      let entry = inWorker.get(label);
      if (!entry) {
        entry = { label };
        inWorker.set(label, entry);
      }
      return entry;
    };

    afterAll(() => {
      console.log(table(`in this Jest worker, node ${process.version}, reported, ceiling ${IN_WORKER_CEILING_MS} ms`, [...inWorker.values()]));
    });

    for (const [label, text] of ADVERSARIAL) {
      it(`every row stays under the ${IN_WORKER_CEILING_MS} ms ceiling: ${label}`, () => {
        let rowMaxMs = -1;
        for (const re of rows) {
          const elapsed = ms(() => { re.test(text); });
          if (elapsed > rowMaxMs) rowMaxMs = elapsed;
          expect({ re: re.source.slice(0, 60), ok: elapsed < IN_WORKER_CEILING_MS }).toEqual({ re: re.source.slice(0, 60), ok: true });
        }
        record(label).rowMaxMs = rowMaxMs;
      });

      it(`detectSkillThreats stays under the ${IN_WORKER_CEILING_MS} ms ceiling: ${label}`, () => {
        const { elapsed, value } = timed(() => detectSkillThreats(text));
        record(label).detectMs = elapsed;
        record(label).detectSig = detectSignature(value);
        expect(elapsed).toBeLessThan(IN_WORKER_CEILING_MS);
      });

      const fullScanIt = FULL_SCAN_SLOW_ON_MAIN.has(label) ? it.skip : it;
      fullScanIt(`full scan stays under the ${IN_WORKER_CEILING_MS} ms ceiling: ${label}`, () => {
        const { elapsed, value } = timed(() => scanSkillContent(text, undefined, 'claude-md', 'CLAUDE.md'));
        record(label).fullMs = elapsed;
        record(label).fullSig = fullSignature(value);
        expect(elapsed).toBeLessThan(IN_WORKER_CEILING_MS);
      });
    }

    // The child times dist/, this worker runs the TypeScript sources. Same
    // scan outcome on every input shows the fresh process did the same work
    // (and did not, for example, return early through the scan's catch-all).
    it('the fresh process reached the same scan outcome as this worker on every input', () => {
      const fromChild = freshReport().results.map((r) => ({ label: r.label, detect: r.detectSig, full: r.fullSig }));
      const fromWorker = ADVERSARIAL.map(([label]) => ({
        label,
        detect: inWorker.get(label)?.detectSig,
        full: inWorker.get(label)?.fullSig ?? null,
      }));
      expect(fromChild).toEqual(fromWorker);
    });
  });
});
