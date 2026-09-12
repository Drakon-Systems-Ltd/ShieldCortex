/**
 * #466 — the published security claim must match the measured audit.
 *
 * `skills/shieldcortex/SKILL.md` used to carry `npm_audit: clean` and
 * `snyk: no-known-vulnerabilities`. Both were false: `npm audit --omit=dev`
 * reported 7 advisories, and no workflow in `.github/` has ever run snyk. A
 * claim nobody re-checks is a claim that rots, so this suite re-checks it.
 *
 * Two legs, on purpose:
 *
 *   Hermetic (always runs, no network) — the claim must be structurally
 *   honest and must agree with docs/security/audit-waivers.md, and a tooling
 *   claim may only appear if that tool actually runs in CI. These are the
 *   checks that would have caught #466.
 *
 *   Live (runs `npm audit --omit=dev`) — the numbers in the claim must equal
 *   the numbers npm reports right now. This suite is the one place that
 *   deliberately departs from the repo's "no network in tests" convention:
 *   a security claim that silently passes when it cannot be verified is worse
 *   than no test. If you are genuinely offline, set SC_SKIP_LIVE_AUDIT=1 and
 *   understand you have turned off the drift detector, not satisfied it.
 *
 * Three outcomes for the live leg, never two — DRIFT, MEASURED and
 * UNAVAILABLE are different facts:
 *
 *   measured    -> the assertions run, and a mismatch is a red suite. That is
 *                  claim drift, and it should stop a release.
 *   unavailable -> `npm audit` could not produce a report (no network, a
 *                  registry blip, the deadline expired). The leg is SKIPPED,
 *                  with the reason in the skipped test's name, and the
 *                  hermetic leg still has to pass. Before this, an ECONNRESET
 *                  from the registry turned the ordinary unit suite red with
 *                  no code regression behind it — which teaches a team to
 *                  re-run until green, the exact habit that lets real drift
 *                  through.
 *   opted out   -> SC_SKIP_LIVE_AUDIT=1, also a visible skip.
 *
 * "Unavailable" must never be silently green either, which is why it is an
 * explicit skip naming the reason rather than a passing test.
 */

import { afterEach, describe, expect, it } from '@jest/globals';
import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { invokesScanner, workflowExecutableSteps } from './support/workflow-executable-surface.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(HERE, '..', '..');
const SKILL_MD = join(REPO_ROOT, 'skills', 'shieldcortex', 'SKILL.md');
const WAIVERS_MD = join(REPO_ROOT, 'docs', 'security', 'audit-waivers.md');
const WORKFLOWS = join(REPO_ROOT, '.github', 'workflows');
const AUDIT_SCRIPT = join(REPO_ROOT, 'scripts', 'lab', 'audit-report.mjs');

/** ESM specifiers must be file: URLs under this jest setup. */
const auditModule = await import(pathToFileURL(AUDIT_SCRIPT).href);
const {
  parseWaivers,
  waivedAdvisoryIds,
  classify,
  expiredWaivers,
  runNpmAudit,
  isCalendarDate,
  auditReportProblems,
  auditTimeoutMs,
  DEFAULT_AUDIT_TIMEOUT_MS,
} = auditModule as {
  parseWaivers: (md: string) => Array<Record<string, unknown> & { id: string; advisories: number[]; expires: string }>;
  waivedAdvisoryIds: (w: Array<{ advisories: number[] }>) => Set<number>;
  classify: (
    report: unknown,
    waived: Set<number>,
  ) => { unwaived: Array<{ name: string }>; waived: Array<{ name: string }>; waivedIds: number[] };
  expiredWaivers: (w: Array<{ expires: string }>, now?: Date) => unknown[];
  runNpmAudit: (
    extra?: string[],
    cwd?: string,
    opts?: { timeoutMs?: number },
  ) => { vulnerabilities: Record<string, unknown> };
  isCalendarDate: (value: unknown) => boolean;
  auditReportProblems: (report: unknown) => string[];
  auditTimeoutMs: (override?: number) => number;
  DEFAULT_AUDIT_TIMEOUT_MS: number;
};

/** Read one `key: value` out of the SKILL.md frontmatter metadata block. */
function skillMetadata(): Map<string, string> {
  const text = readFileSync(SKILL_MD, 'utf8');
  const front = /^---\r?\n([\s\S]*?)\r?\n---/.exec(text);
  if (!front) throw new Error('SKILL.md has no YAML frontmatter');
  const out = new Map<string, string>();
  let inMetadata = false;
  for (const line of front[1].split(/\r?\n/)) {
    if (/^metadata:\s*$/.test(line)) {
      inMetadata = true;
      continue;
    }
    if (inMetadata && /^\S/.test(line)) break; // dedented — metadata block ended
    if (!inMetadata) continue;
    const kv = /^\s{2}([A-Za-z0-9_-]+):\s*(.*)$/.exec(line);
    if (kv) out.set(kv[1], kv[2].replace(/^"(.*)"$/, '$1').trim());
  }
  return out;
}

/**
 * The claim's shape, so both legs read the same two numbers.
 * e.g. "0 unwaived production advisories; 2 waived (...)"
 */
const CLAIM_SHAPE = /^(\d+) unwaived production advisor(?:y|ies); (\d+) waived\b/;

function parseClaim(): { unwaived: number; waived: number; raw: string } {
  const raw = skillMetadata().get('npm_audit');
  if (!raw) throw new Error('SKILL.md metadata has no npm_audit key');
  const m = CLAIM_SHAPE.exec(raw);
  if (!m) {
    throw new Error(
      `SKILL.md npm_audit claim is not in the checkable form ` +
        `"<n> unwaived production advisories; <n> waived ...". Got: ${raw}`,
    );
  }
  return { unwaived: Number(m[1]), waived: Number(m[2]), raw };
}

const waiverMarkdown = readFileSync(WAIVERS_MD, 'utf8');

/** Scanners whose result SKILL.md may only advertise if CI actually runs them. */
const SCANNERS = ['snyk', 'trivy', 'grype', 'dependabot'] as const;

/**
 * Scanner results claimed in SKILL.md metadata that no workflow backs.
 *
 * `workflowSources` is the RAW text of each `.github/workflows` file. The rule
 * takes sources rather than a haystack on purpose: it used to be handed the
 * concatenated, lowercased text and ask `.includes(scanner)`, and review broke
 * that three times over —
 *
 *     # snyk is not installed or run      (a comment is not a step)
 *     env:
 *       run: snyk                          (a value under a key spelled `run`)
 *     run: echo "snyk is not installed"    (a step that names it and runs echo)
 *
 * — each time permitting `snyk: no-known-vulnerabilities` back into SKILL.md.
 * Mentioning a scanner is not running one, and neither is parking its name
 * somewhere a walker will trip over.
 *
 * So the rule asks two separate questions, both structural: WHERE the value came
 * from (only `jobs.<id>.steps[].run`/`.uses` and `jobs.<id>.uses`, and only from
 * jobs and steps not switched off with `if: false`) and WHETHER it invokes the
 * scanner (the command a statement starts, or the owner/repo of an action). See
 * support/workflow-executable-surface.ts.
 *
 * Pure so the rule can be exercised in both directions — the failure that
 * matters is "claimed but never run", and the case that must stay GREEN is
 * "claimed and genuinely wired up", which a one-sided test would not catch.
 */
export function scannerClaimViolations(metadataKeys: string[], workflowSources: string[]): string[] {
  const claimed = new Set(metadataKeys);
  const steps = workflowSources.flatMap(workflowExecutableSteps);
  return SCANNERS.filter((s) => claimed.has(s) && !invokesScanner(steps, s));
}


describe('#466 hermetic — the SKILL.md security claim is structurally honest', () => {
  it('states counts in a form a machine can re-check', () => {
    const claim = parseClaim();
    expect(Number.isInteger(claim.unwaived)).toBe(true);
    expect(Number.isInteger(claim.waived)).toBe(true);
  });

  it('does not make an unqualified "clean" / "no known vulnerabilities" claim', () => {
    const raw = parseClaim().raw.toLowerCase();
    for (const forbidden of ['clean', 'no known vulnerabilities', 'no-known-vulnerabilities', 'none']) {
      expect(raw.includes(forbidden)).toBe(false);
    }
  });

  it('points at the waiver file whenever it claims anything is waived', () => {
    const claim = parseClaim();
    if (claim.waived > 0) {
      expect(claim.raw).toContain('docs/security/audit-waivers.md');
    }
  });

  it('claims exactly as many waived advisories as the waiver file records', () => {
    const waivers = parseWaivers(waiverMarkdown);
    const ids = waivedAdvisoryIds(waivers);
    expect(parseClaim().waived).toBe(ids.size);
  });

  it('names, in the claim, every GHSA id the waiver file lists', () => {
    const waivers = parseWaivers(waiverMarkdown);
    const claim = parseClaim().raw;
    for (const w of waivers) {
      for (const ghsa of ((w as { ghsa?: string[] }).ghsa ?? [])) {
        expect(claim).toContain(ghsa);
      }
    }
  });

  it('carries no waiver that has already lapsed', () => {
    expect(expiredWaivers(parseWaivers(waiverMarkdown))).toEqual([]);
  });

  it('only claims a scanner that some workflow actually runs', () => {
    const workflows = readdirSync(WORKFLOWS).map((f) => readFileSync(join(WORKFLOWS, f), 'utf8'));
    expect(scannerClaimViolations([...skillMetadata().keys()], workflows)).toEqual([]);
  });
});

describe('#466 hermetic — the scanner rule permits a claim exactly when CI earns it', () => {
  /** A one-job workflow whose steps are the lines given. */
  const oneJob = (...lines: string[]): string =>
    ['jobs:', '  sec:', '    steps:', ...lines.map((line) => `      ${line}`)].join('\n');

  it('flags a claim no workflow backs', () => {
    expect(scannerClaimViolations(['npm_audit', 'snyk'], [oneJob('- run: npm test')])).toEqual(['snyk']);
  });

  it('permits the claim once a workflow actually runs the scanner', () => {
    expect(
      scannerClaimViolations(['npm_audit', 'snyk'], [oneJob('- run: snyk test --all-projects')]),
    ).toEqual([]);
  });

  it('permits a claim backed by an action rather than a shell command', () => {
    expect(
      scannerClaimViolations(['trivy'], [oneJob('- uses: aquasecurity/trivy-action@0.24.0')]),
    ).toEqual([]);
  });

  it('does not care about a scanner that runs in CI but is not claimed', () => {
    expect(scannerClaimViolations(['npm_audit'], [oneJob('- run: snyk test')])).toEqual([]);
  });

  it('reports every unbacked claim, not just the first', () => {
    expect(scannerClaimViolations(['snyk', 'trivy', 'grype'], [oneJob('- run: npm test')])).toEqual([
      'snyk',
      'trivy',
      'grype',
    ]);
  });

  // ── The mutations review used to get past this rule ──────────────────────
  //
  // Each of these files mentions snyk. None of them runs it. The old rule —
  // `concatenatedWorkflowText.includes('snyk')` — permitted the claim for all
  // three, and the first one is a single comment line.

  it('refuses a claim backed only by a comment', () => {
    expect(scannerClaimViolations(['snyk'], ['# snyk is not installed or run\n'])).toEqual(['snyk']);
  });

  it('refuses a claim backed only by a comment inside a real job', () => {
    const workflow = [
      'name: CI',
      'jobs:',
      '  test:',
      '    steps:',
      '      # TODO: wire up snyk once we have a token',
      '      - run: npm test',
    ].join('\n');
    expect(scannerClaimViolations(['snyk'], [workflow])).toEqual(['snyk']);
  });

  it('refuses a claim backed only by a step that is switched off', () => {
    const workflow = [
      'jobs:',
      '  sec:',
      '    steps:',
      '      - name: Scan',
      '        if: false',
      '        run: snyk test --all-projects',
      '      - run: npm test',
    ].join('\n');
    expect(scannerClaimViolations(['snyk'], [workflow])).toEqual(['snyk']);
  });

  it('refuses a claim backed only by a job that is switched off', () => {
    const workflow = [
      'jobs:',
      '  sec:',
      '    if: false',
      '    steps:',
      '      - run: snyk test',
    ].join('\n');
    expect(scannerClaimViolations(['snyk'], [workflow])).toEqual(['snyk']);
  });

  it('refuses a claim backed only by a step NAME', () => {
    const workflow = [
      'jobs:',
      '  sec:',
      '    steps:',
      '      - name: snyk (disabled, see #123)',
      '        run: echo skipping',
    ].join('\n');
    expect(scannerClaimViolations(['snyk'], [workflow])).toEqual(['snyk']);
  });

  it('still permits a step carrying a real condition — conditional is not disabled', () => {
    const workflow = [
      'jobs:',
      '  sec:',
      '    steps:',
      "      - if: github.ref == 'refs/heads/main'",
      '        run: snyk test',
    ].join('\n');
    expect(scannerClaimViolations(['snyk'], [workflow])).toEqual([]);
  });

  it('reads a multi-line run block, where the scanner is not on the first line', () => {
    const workflow = [
      'jobs:',
      '  sec:',
      '    steps:',
      '      - run: |',
      '          npm ci',
      '          npx snyk test --all-projects',
    ].join('\n');
    expect(scannerClaimViolations(['snyk'], [workflow])).toEqual([]);
  });

  it('is not fooled by a scanner name in an unrelated key', () => {
    const workflow = ['jobs:', '  sec:', '    env:', '      SCANNER: snyk', '    steps:', '      - run: npm test'].join(
      '\n',
    );
    expect(scannerClaimViolations(['snyk'], [workflow])).toEqual(['snyk']);
  });

  it('refuses when a workflow file is unparseable rather than permitting it', () => {
    expect(scannerClaimViolations(['snyk'], ['\t\t}}}} snyk {{{{\n'])).toEqual(['snyk']);
  });

  // ── The second round of mutations review got past this rule ──────────────
  //
  // The first three fixtures below all permitted the claim at ef06f9d3. The
  // `env:` one is the decisive case: the ONLY shell step in it prints
  // "skipped", so nothing whatsoever runs snyk, and the walker collected the
  // name out of a job's environment because the key happened to be spelled
  // `run`. The others are a `with:` input and a step switched off by an
  // expression that is constantly false but is not the bare word `false`.

  it('refuses a claim backed by a key merely SPELLED run, in a job environment', () => {
    const workflow = [
      'jobs:',
      '  sec:',
      '    env:',
      '      run: snyk',
      '    steps:',
      '      - run: printf "snyk scan skipped\\n"',
    ].join('\n');
    expect(scannerClaimViolations(['snyk'], [workflow])).toEqual(['snyk']);
  });

  it('refuses a claim backed by a step input rather than the step', () => {
    expect(
      scannerClaimViolations(['snyk'], [oneJob('- uses: acme/runner@v1', '  with:', '    run: snyk test')]),
    ).toEqual(['snyk']);
  });

  it('refuses a claim backed by a step behind a constantly-false expression', () => {
    expect(
      scannerClaimViolations(['snyk'], [oneJob('- if: ${{ false && github.event_name == \'push\' }}', '  run: snyk test')]),
    ).toEqual(['snyk']);
  });

  it.each([
    'echo "snyk is not installed"',
    'echo snyk is disabled',
    'printf \'snyk: skipped\\n\'',
    'grep -r snyk . || true',
  ])('refuses a claim backed by a step that only NAMES the scanner: %s', (command) => {
    expect(scannerClaimViolations(['snyk'], [oneJob(`- run: ${command}`)])).toEqual(['snyk']);
  });

  it.each([
    '- run: snyk test',
    '- run: npx snyk test',
    '- run: npx --yes snyk test --all-projects',
    '- run: pnpm dlx snyk test',
    '- run: bunx snyk test',
    '- run: SNYK_TOKEN=${{ secrets.SNYK_TOKEN }} snyk test',
    '- run: npm ci && snyk test',
    '- run: ./node_modules/.bin/snyk test',
    '- uses: snyk/actions/node@v1',
    '- uses: snyk/actions/node@master',
  ])('permits a claim backed by a step that genuinely invokes it: %s', (step) => {
    expect(scannerClaimViolations(['snyk'], [oneJob(step)])).toEqual([]);
  });

  it('does not mistake an action whose name merely starts with the scanner’s letters', () => {
    expect(scannerClaimViolations(['snyk'], [oneJob('- uses: acme/snykish-linter@v1')])).toEqual(['snyk']);
  });

  it('permits a job that delegates to a reusable scanner workflow', () => {
    const workflow = ['jobs:', '  sec:', '    uses: snyk/.github/.workflows/scan.yml@v1'].join('\n');
    expect(scannerClaimViolations(['snyk'], [workflow])).toEqual([]);
  });
});

describe('#466 hermetic — the waiver gate is not vacuous', () => {
  const waivers = parseWaivers(waiverMarkdown);
  const ids = waivedAdvisoryIds(waivers);

  it('waives a node whose advisory ids are all listed', () => {
    const report = { vulnerabilities: { sharp: { severity: 'high', via: [...ids].map((id) => ({ source: id })) } } };
    const r = classify(report, ids);
    expect(r.unwaived).toEqual([]);
    expect(r.waived.map((n) => n.name)).toEqual(['sharp']);
  });

  it('does NOT waive a new advisory on an already-waived package', () => {
    const report = {
      vulnerabilities: { sharp: { severity: 'high', via: [{ source: [...ids][0] }, { source: 999999 }] } },
    };
    expect(classify(report, ids).unwaived.map((n) => n.name)).toEqual(['sharp']);
  });

  it('waives a derived node only while its source package stays waived', () => {
    const waivedSource = {
      vulnerabilities: {
        sharp: { severity: 'high', via: [...ids].map((id) => ({ source: id })) },
        '@huggingface/transformers': { severity: 'high', via: ['sharp'] },
      },
    };
    expect(classify(waivedSource, ids).unwaived).toEqual([]);

    const unwaivedSource = {
      vulnerabilities: {
        sharp: { severity: 'high', via: [{ source: 999999 }] },
        '@huggingface/transformers': { severity: 'high', via: ['sharp'] },
      },
    };
    expect(classify(unwaivedSource, ids).unwaived.map((n) => n.name).sort()).toEqual([
      '@huggingface/transformers',
      'sharp',
    ]);
  });

  it('fails closed on a node with neither advisory ids nor a source package', () => {
    const report = { vulnerabilities: { mystery: { severity: 'high', via: [] } } };
    expect(classify(report, ids).unwaived.map((n) => n.name)).toEqual(['mystery']);
  });

  /**
   * The older rule seeded a node from its own advisory ids and then never looked
   * at the rest of its `via`. So a node carrying one waived advisory was decided
   * `true` before anyone asked where else it derived from — and review found
   * that passing a report whose waived node also derived from a package that
   * was never defined. Waiving is per ENTRY: all the advisories AND all the
   * packages.
   */
  it('does NOT waive a node whose own advisories are waived but whose source package is not', () => {
    const report = {
      vulnerabilities: {
        lodash: { severity: 'high', via: [{ source: 999999 }] },
        sharp: { severity: 'high', via: [...[...ids].map((id) => ({ source: id })), 'lodash'] },
      },
    };
    expect(classify(report, ids).unwaived.map((n) => n.name).sort()).toEqual(['lodash', 'sharp']);
    expect(classify(report, ids).waived).toEqual([]);
  });

  it('fails closed on a waived node whose source package the report never defined', () => {
    const report = {
      vulnerabilities: {
        sharp: { severity: 'high', via: [...[...ids].map((id) => ({ source: id })), 'missing-package'] },
      },
    };
    expect(classify(report, ids).unwaived.map((n) => n.name)).toEqual(['sharp']);
  });

  it('fails closed on a cycle rather than waiving both ends of it', () => {
    const report = {
      vulnerabilities: {
        a: { severity: 'high', via: ['b'] },
        b: { severity: 'high', via: ['a'] },
      },
    };
    expect(classify(report, ids).unwaived.map((n) => n.name).sort()).toEqual(['a', 'b']);
  });

  it('rejects a waiver file with no expiry, owner, reason or advisory ids', () => {
    const bad = (body: string) => '```json audit-waivers\n' + body + '\n```';
    expect(() => parseWaivers(bad('{"waivers":[{"id":"x","advisories":[1]}]}'))).toThrow(/expires/);
    expect(() => parseWaivers(bad('{"waivers":[{"id":"x","advisories":[]}]}'))).toThrow(/advisories/);
    expect(() =>
      parseWaivers(bad('{"waivers":[{"id":"x","advisories":[1],"expires":"2099-01-01"}]}')),
    ).toThrow(/owner/);
    expect(() => parseWaivers('no fenced block here')).toThrow(/audit-waivers block/);
  });

  it('treats a lapsed expiry date as expired', () => {
    const lapsed = [{ expires: '2000-01-01' }];
    expect(expiredWaivers(lapsed, new Date('2026-09-12T00:00:00Z'))).toHaveLength(1);
    expect(expiredWaivers([{ expires: '2099-01-01' }], new Date('2026-09-12T00:00:00Z'))).toHaveLength(0);
  });

  it('rejects an expiry that is spelled like a date but is not one', () => {
    const bad = (expires: string) =>
      '```json audit-waivers\n' +
      JSON.stringify({
        waivers: [{ id: 'x', advisories: [1], expires, owner: 'o', reason: 'r' }],
      }) +
      '\n```';
    // A waiver dated 2099-99-99 can never expire: `expires < today` compares
    // strings, and no real date sorts above it.
    for (const impossible of ['2099-99-99', '2026-13-01', '2026-02-30', '2026-00-10', '2026-01-32']) {
      expect(() => parseWaivers(bad(impossible))).toThrow(/expires/);
    }
    expect(parseWaivers(bad('2026-02-28'))[0].expires).toBe('2026-02-28');
    expect(parseWaivers(bad('2028-02-29'))[0].expires).toBe('2028-02-29'); // leap year
  });

  it('accepts only real calendar dates', () => {
    for (const good of ['2026-01-01', '2026-12-31', '2028-02-29', '1970-01-01']) {
      expect(isCalendarDate(good)).toBe(true);
    }
    for (const bad of ['2099-99-99', '2027-02-29', '2026-1-1', '26-01-01', '2026-01-01T00:00:00Z', '', null, 20260101]) {
      expect(isCalendarDate(bad)).toBe(false);
    }
  });
});

describe('#466 hermetic — an unreadable audit report is undecidable, not clean', () => {
  const clean = {
    auditReportVersion: 2,
    vulnerabilities: {},
    metadata: { vulnerabilities: { info: 0, low: 0, moderate: 0, high: 0, critical: 0, total: 0 } },
  };

  it('accepts the shape npm really emits', () => {
    expect(auditReportProblems(clean)).toEqual([]);
    expect(
      auditReportProblems({
        ...clean,
        vulnerabilities: { sharp: { severity: 'high', via: [{ source: 1124066 }] } },
        metadata: { vulnerabilities: { info: 0, low: 0, moderate: 0, high: 1, critical: 0, total: 1 } },
      }),
    ).toEqual([]);
  });

  it('rejects the payloads that used to classify as zero findings', () => {
    expect(auditReportProblems({ metadata: { vulnerabilities: { high: 1, total: 1 } } })).not.toEqual([]);
    expect(auditReportProblems({})).not.toEqual([]);
    expect(auditReportProblems({ ...clean, vulnerabilities: null })).not.toEqual([]);
  });

  it('rejects a total the vulnerability map cannot account for', () => {
    const problems = auditReportProblems({
      ...clean,
      metadata: { vulnerabilities: { info: 0, low: 0, moderate: 0, high: 2, critical: 0, total: 2 } },
    });
    expect(problems.join('\n')).toMatch(/audit output inconsistent/);
  });

  it('rejects anything that is not a JSON object', () => {
    for (const notAReport of [null, [], 'ok', 42, undefined]) {
      expect(auditReportProblems(notAReport)).not.toEqual([]);
    }
  });

  /**
   * Classification filtered `via` for the two kinds of entry it understands and
   * discarded the rest, so an entry it could not read simply stopped existing.
   * All three shapes below are v2-shaped with consistent totals, and all three
   * exited 0 "1 waived" at ef06f9d3.
   */
  const oneNode = (via: unknown[]) => ({
    ...clean,
    vulnerabilities: { sharp: { severity: 'high', via } },
    metadata: { vulnerabilities: { info: 0, low: 0, moderate: 0, high: 1, critical: 0, total: 1 } },
  });

  it.each([
    ['a bare number', [{ source: 1124066 }, 999999]],
    ['a null', [{ source: 1124066 }, null]],
    ['a nested array', [{ source: 1124066 }, ['sharp']]],
    ['a boolean', [{ source: 1124066 }, true]],
    ['an advisory with a string source', [{ source: '1124066' }]],
    ['an advisory with no source at all', [{ title: 'something' }]],
    ['an advisory with a fractional source', [{ source: 1.5 }]],
  ])('refuses a via entry that is %s', (_label, via) => {
    expect(auditReportProblems(oneNode(via)).join('\n')).toMatch(/unreadable via entry on sharp/);
  });

  it('refuses a via that names a package the report never defined', () => {
    expect(auditReportProblems(oneNode([{ source: 1124066 }, 'missing-package'])).join('\n')).toMatch(
      /names "missing-package", which is not a node in this report/,
    );
  });

  it('refuses a node with no via list, and one that is not a node at all', () => {
    expect(auditReportProblems(oneNode(undefined as unknown as unknown[])).join('\n')).toMatch(
      /`via` is missing/,
    );
    expect(
      auditReportProblems({
        ...clean,
        vulnerabilities: { sharp: 'high' },
        metadata: { vulnerabilities: { info: 0, low: 0, moderate: 0, high: 1, critical: 0, total: 1 } },
      }).join('\n'),
    ).toMatch(/not a vulnerability node/);
  });

  it('accepts the two via shapes npm really emits, including a self-reference', () => {
    expect(auditReportProblems(oneNode([{ source: 1124066 }, 'sharp']))).toEqual([]);
    expect(
      auditReportProblems({
        ...clean,
        vulnerabilities: {
          sharp: { severity: 'high', via: [{ source: 1124066 }] },
          '@huggingface/transformers': { severity: 'high', via: ['sharp'] },
        },
        metadata: { vulnerabilities: { info: 0, low: 0, moderate: 0, high: 2, critical: 0, total: 2 } },
      }),
    ).toEqual([]);
  });
});

/**
 * The deadline rule, which has to match what the gate ADVISES.
 *
 * `runNpmAudit`'s timeout message says to set `SC_AUDIT_TIMEOUT_MS` to raise the
 * deadline, and the live leg below passes `timeoutMs: 60_000` explicitly. Under
 * the old caller-wins precedence that advice was inert for exactly the caller
 * that prints it — review measured a 500 ms fixture passing with the variable
 * set to 50 ms. The environment is the operator's override now, in both
 * directions, and these cases pin the rule the prose promises.
 */
describe('#466 hermetic — the audit deadline is what the gate says it is', () => {
  const saved = process.env.SC_AUDIT_TIMEOUT_MS;

  afterEach(() => {
    if (saved === undefined) delete process.env.SC_AUDIT_TIMEOUT_MS;
    else process.env.SC_AUDIT_TIMEOUT_MS = saved;
  });

  it('uses the default when neither the caller nor the environment says', () => {
    delete process.env.SC_AUDIT_TIMEOUT_MS;
    expect(auditTimeoutMs()).toBe(DEFAULT_AUDIT_TIMEOUT_MS);
  });

  it('honours a caller that names its own deadline', () => {
    delete process.env.SC_AUDIT_TIMEOUT_MS;
    expect(auditTimeoutMs(5_000)).toBe(5_000);
  });

  it('lets the environment SHORTEN a deadline the caller set — the measured defect', () => {
    process.env.SC_AUDIT_TIMEOUT_MS = '200';
    expect(auditTimeoutMs(60_000)).toBe(200);
  });

  it('lets the environment RAISE it too, which is what the timeout message advises', () => {
    process.env.SC_AUDIT_TIMEOUT_MS = '300000';
    expect(auditTimeoutMs(60_000)).toBe(300_000);
  });

  it.each(['', 'abc', '0', '-1', 'Infinity', 'NaN'])(
    'ignores an environment value that is not a positive number: %s',
    (value) => {
      process.env.SC_AUDIT_TIMEOUT_MS = value;
      expect(auditTimeoutMs(60_000)).toBe(60_000);
      expect(auditTimeoutMs()).toBe(DEFAULT_AUDIT_TIMEOUT_MS);
    },
  );
});

/** What the live leg found out before any test ran. */
export type LiveAuditOutcome =
  | { kind: 'measured'; report: { vulnerabilities: Record<string, unknown> } }
  | { kind: 'unavailable'; reason: string }
  | { kind: 'opted-out' };

/**
 * Decide which of the three outcomes applies. Pure apart from the injected
 * runner, so both branches can be exercised without a registry.
 */
export function liveAuditOutcome(
  run: () => { vulnerabilities: Record<string, unknown> },
  optedOut: boolean,
): LiveAuditOutcome {
  if (optedOut) return { kind: 'opted-out' };
  try {
    return { kind: 'measured', report: run() };
  } catch (err) {
    return { kind: 'unavailable', reason: (err as Error).message };
  }
}

/**
 * The name Jest prints for the live leg. An unavailable audit has to say so on
 * the terminal, with the reason attached — "skipped" that does not say why is
 * how a permanently broken check survives.
 */
export function liveAuditTitle(outcome: LiveAuditOutcome): string {
  switch (outcome.kind) {
    case 'measured':
      return '#466 live — the claim equals what npm audit reports now';
    case 'opted-out':
      return '#466 live — skipped: SC_SKIP_LIVE_AUDIT=1, the drift detector is off';
    default:
      return `#466 live — skipped: live audit unavailable — ${outcome.reason.split('\n')[0]}`;
  }
}

/**
 * Run it ONCE, here, before any test is defined.
 *
 * Jest has no runtime skip: a test body cannot decide to become pending, it can
 * only pass or fail. The availability of `npm audit` therefore has to be known
 * at collection time for "unavailable" to be expressible as a skip at all.
 * `runNpmAudit` is synchronous, so this blocks the worker for the duration —
 * bounded by the deadline below, which is deliberately well inside the batch
 * budget the full suite runs under.
 */
const liveAudit = liveAuditOutcome(
  () => runNpmAudit([], REPO_ROOT, { timeoutMs: 60_000 }),
  process.env.SC_SKIP_LIVE_AUDIT === '1',
);
if (liveAudit.kind === 'unavailable') {
  console.warn(`[#466] live audit unavailable — ${liveAudit.reason}`);
}

(liveAudit.kind === 'measured' ? describe : describe.skip)(liveAuditTitle(liveAudit), () => {
  it('reports 0 unwaived production advisories and exactly the waived set the claim names', () => {
    if (liveAudit.kind !== 'measured') throw new Error('unreachable: leg is skipped');
    const waivers = parseWaivers(waiverMarkdown);
    const ids = waivedAdvisoryIds(waivers);
    const result = classify(liveAudit.report, ids);
    const claim = parseClaim();

    expect(result.unwaived.map((n) => n.name)).toEqual([]);
    expect(claim.unwaived).toBe(result.unwaived.length);
    expect(claim.waived).toBe(result.waivedIds.length);
  });
});

describe('#466 hermetic — the live leg tells drift apart from unavailability', () => {
  const report = { vulnerabilities: {} };

  it('measures when npm answers', () => {
    expect(liveAuditOutcome(() => report, false)).toEqual({ kind: 'measured', report });
  });

  it('is unavailable — not clean, and not a failure — when npm cannot answer', () => {
    const outcome = liveAuditOutcome(() => {
      throw new Error('npm audit reported an error: {"code":"ECONNRESET"}');
    }, false);
    expect(outcome.kind).toBe('unavailable');
    expect(liveAuditTitle(outcome)).toContain('skipped: live audit unavailable — ');
    expect(liveAuditTitle(outcome)).toContain('ECONNRESET');
  });

  it('names the deadline when the audit is killed for taking too long', () => {
    const outcome = liveAuditOutcome(() => {
      throw new Error('`npm audit --omit=dev --json` did not answer within 300 ms and was killed.');
    }, false);
    expect(liveAuditTitle(outcome)).toContain('did not answer within 300 ms');
  });

  it('reports the opt-out as its own outcome, not as unavailability', () => {
    const outcome = liveAuditOutcome(() => report, true);
    expect(outcome).toEqual({ kind: 'opted-out' });
    expect(liveAuditTitle(outcome)).toContain('SC_SKIP_LIVE_AUDIT=1');
  });

  it('keeps the reason to one line so the test name stays readable', () => {
    const outcome = liveAuditOutcome(() => {
      throw new Error('first line\nsecond line\nthird line');
    }, false);
    expect(liveAuditTitle(outcome)).toContain('first line');
    expect(liveAuditTitle(outcome)).not.toContain('second line');
  });
});
