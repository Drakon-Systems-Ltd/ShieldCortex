/**
 * #466 — the release gate must never print PASS over a report it cannot read.
 *
 * `scripts/lab/audit-report.mjs` validated JSON *syntax* and `report.error`,
 * then classified `report.vulnerabilities ?? {}`. Review reproduced the
 * consequence by putting a fixture `npm` on PATH and running the real CLI:
 *
 *   npm prints {"metadata":{"vulnerabilities":{"high":1,"total":1}}}, exit 1
 *   gate prints "PASS — 0 unwaived production advisories", exit 0
 *
 *   npm prints {}, exit 1
 *   gate prints PASS, exit 0
 *
 * One high advisory announced in the metadata, no node to name it, and a green
 * release gate. Undecidable is not zero findings — it has to be exit 2.
 *
 * These tests spawn the ACTUAL script rather than importing its helpers,
 * because the defect lived in the seam between parse and classify: a unit test
 * on either side of that seam passes while the CLI still exits 0. The exit code
 * is the product here.
 */

import { afterAll, beforeAll, describe, expect, it } from '@jest/globals';
import { spawnSync } from 'node:child_process';
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(HERE, '..', '..');
const AUDIT_SCRIPT = join(REPO_ROOT, 'scripts', 'lab', 'audit-report.mjs');
const CLAIMS_SUITE = join('src', '__tests__', 'release-audit-claims.test.ts');

/** The two advisory ids docs/security/audit-waivers.md waives. */
const WAIVED = [1124066, 1193725];

let fakeBin: string;
let home: string;

beforeAll(() => {
  fakeBin = mkdtempSync(join(tmpdir(), 'sc466-fakebin-'));
  home = mkdtempSync(join(tmpdir(), 'sc466-fakehome-'));
});

afterAll(() => {
  rmSync(fakeBin, { recursive: true, force: true });
  rmSync(home, { recursive: true, force: true });
});

/**
 * Put a fake `npm` on the fixture PATH: it prints `stdout` verbatim, after
 * `delayMs`, and exits with `code`.
 *
 * The shebang is this process's own node binary, so the fixture does not
 * depend on a `node` being resolvable from the stripped PATH.
 */
function installFakeNpm(stdout: string, { code = 1, stderr = '', delayMs = 0 } = {}): void {
  const body =
    `#!${process.execPath}\n` +
    `const emit = () => {\n` +
    `  process.stderr.write(${JSON.stringify(stderr)});\n` +
    `  process.stdout.write(${JSON.stringify(stdout)});\n` +
    `  process.exit(${code});\n` +
    `};\n` +
    (delayMs > 0 ? `setTimeout(emit, ${delayMs});\n` : `emit();\n`);
  const npmPath = join(fakeBin, 'npm');
  writeFileSync(npmPath, body);
  chmodSync(npmPath, 0o755);
}

function runGate(
  stdout: string,
  {
    code = 1,
    stderr = '',
    delayMs = 0,
    extraArgs = [] as string[],
    timeoutMs = 0,
  } = {},
): { status: number | null; stdout: string; stderr: string } {
  installFakeNpm(stdout, { code, stderr, delayMs });

  const res = spawnSync(process.execPath, [AUDIT_SCRIPT, ...extraArgs], {
    cwd: REPO_ROOT,
    encoding: 'utf8',
    env: {
      PATH: `${fakeBin}:/usr/bin:/bin`,
      HOME: home,
      npm_config_cache: join(home, 'npm-cache'),
      ...(timeoutMs > 0 ? { SC_AUDIT_TIMEOUT_MS: String(timeoutMs) } : {}),
    },
    timeout: 60_000,
  });
  return { status: res.status, stdout: res.stdout ?? '', stderr: res.stderr ?? '' };
}

/** A report npm would really emit: n nodes, metadata agreeing with the map. */
function realisticReport(nodes: Record<string, { severity: string; via?: unknown[] }>) {
  const counts: Record<string, number> = { info: 0, low: 0, moderate: 0, high: 0, critical: 0 };
  for (const node of Object.values(nodes)) counts[node.severity] = (counts[node.severity] ?? 0) + 1;
  return JSON.stringify({
    auditReportVersion: 2,
    vulnerabilities: nodes,
    metadata: {
      vulnerabilities: { ...counts, total: Object.keys(nodes).length },
      dependencies: { prod: 1, dev: 0, optional: 0, peer: 0, peerOptional: 0, total: 1 },
    },
  });
}

describe('#466 CLI — a report the gate cannot read is exit 2, never PASS', () => {
  it('refuses metadata-only output that announces advisories with no nodes', () => {
    const res = runGate(JSON.stringify({ metadata: { vulnerabilities: { high: 1, total: 1 } } }));
    expect(res.status).toBe(2);
    expect(res.stderr).toMatch(/vulnerabilities` is missing/);
    expect(res.stderr).not.toMatch(/PASS/);
  });

  it('refuses `{}`', () => {
    const res = runGate('{}');
    expect(res.status).toBe(2);
    expect(res.stderr).not.toMatch(/PASS/);
  });

  it('refuses a null vulnerability map', () => {
    const res = runGate(
      JSON.stringify({
        vulnerabilities: null,
        metadata: { vulnerabilities: { info: 0, low: 0, moderate: 0, high: 0, critical: 0, total: 0 } },
      }),
    );
    expect(res.status).toBe(2);
    expect(res.stderr).toMatch(/undecidable, not clean/);
  });

  it('refuses a total that does not match the node count', () => {
    const res = runGate(
      JSON.stringify({
        auditReportVersion: 2,
        vulnerabilities: { sharp: { severity: 'high', via: [{ source: WAIVED[0] }] } },
        metadata: { vulnerabilities: { info: 0, low: 0, moderate: 0, high: 3, critical: 0, total: 3 } },
      }),
    );
    expect(res.status).toBe(2);
    expect(res.stderr).toMatch(/audit output inconsistent/);
    expect(res.stderr).toMatch(/total is 3 but `vulnerabilities` carries 1 node/);
  });

  it('refuses severity counts that do not add up to the total', () => {
    const res = runGate(
      JSON.stringify({
        auditReportVersion: 2,
        vulnerabilities: { sharp: { severity: 'high', via: [{ source: WAIVED[0] }] } },
        metadata: { vulnerabilities: { info: 0, low: 0, moderate: 0, high: 0, critical: 0, total: 1 } },
      }),
    );
    expect(res.status).toBe(2);
    expect(res.stderr).toMatch(/severity counts sum to 0/);
  });

  it('refuses a non-integer count', () => {
    const res = runGate(
      JSON.stringify({
        vulnerabilities: {},
        metadata: { vulnerabilities: { high: 'many', total: 0 } },
      }),
    );
    expect(res.status).toBe(2);
    expect(res.stderr).toMatch(/is not a count/);
  });

  it('refuses output that is not JSON at all', () => {
    const res = runGate('npm ERR! code ENOTFOUND\n', { code: 1 });
    expect(res.status).toBe(2);
    expect(res.stderr).toMatch(/produced no JSON/);
  });

  it('refuses a non-zero exit with no output', () => {
    const res = runGate('', { code: 7, stderr: 'npm ERR! network request failed\n' });
    expect(res.status).toBe(2);
    expect(res.stderr).toMatch(/produced no JSON \(exit 7\)/);
    expect(res.stderr).toMatch(/network request failed/);
  });

  it('refuses npm’s own error envelope', () => {
    const res = runGate(
      JSON.stringify({ error: { code: 'ECONNRESET', summary: 'request to registry failed' } }),
    );
    expect(res.status).toBe(2);
    expect(res.stderr).toMatch(/npm audit reported an error/);
  });

  /**
   * npm's envelope can say nothing at all. Review's fixture is npm's real
   * shape for a network failure — `{"summary":"","detail":""}` on stdout, the
   * cause on stderr — and at ef06f9d3 the whole diagnostic was:
   *
   *     [audit:release] npm audit reported an error: {"summary":"","detail":""}
   *
   * Two empty strings. The exit status and the stderr were both discarded.
   */
  it('names the subprocess status and stderr when the error envelope says nothing', () => {
    const res = runGate(JSON.stringify({ error: { summary: '', detail: '' } }), {
      code: 1,
      stderr: 'npm error code ECONNRESET\nnpm error network request to https://registry.npmjs.org/ failed\n',
    });
    expect(res.status).toBe(2);
    expect(res.stderr).toMatch(/npm audit reported an error \(exit 1\)/);
    expect(res.stderr).toMatch(/ECONNRESET/);
    expect(res.stderr).toMatch(/registry\.npmjs\.org/);
    expect(res.stderr).not.toMatch(/PASS/);
  });

  it('bounds the stderr it quotes, so a chatty npm cannot bury the reason', () => {
    const res = runGate(JSON.stringify({ error: { summary: '', detail: '' } }), {
      code: 1,
      stderr: `npm error code ECONNRESET\n${'x'.repeat(20_000)}`,
    });
    expect(res.status).toBe(2);
    expect(res.stderr).toMatch(/ECONNRESET/);
    // 2 KB of it, not 20 KB.
    expect((res.stderr.match(/x/g) ?? []).length).toBeLessThan(2_100);
  });

  it('refuses a report that is valid JSON but not an object', () => {
    const res = runGate('[]');
    expect(res.status).toBe(2);
    expect(res.stderr).toMatch(/expected a JSON object, got an array/);
  });

  /**
   * A `via` entry the gate cannot read used to be an entry it dropped.
   * Classification filtered for the two kinds it understands — advisory objects
   * and package names — and discarded the rest, so all three payloads below are
   * v2-shaped with totals that agree and all three exited 0 at ef06f9d3:
   *
   *   via: [{source: 1124066}, 999999]            PASS — 0 unwaived (1 waived)
   *   via: [{source: 1124066}, null]              PASS — 0 unwaived (1 waived)
   *   via: [{source: 1124066}, "missing-package"] PASS — 0 unwaived (1 waived)
   *
   * The last names a node the report does not contain, so the gate announced a
   * clean bill of health over a chain it could not follow. None of the three is
   * a shape npm 7+ emits — incomplete validation rather than a demonstrated
   * bypass with real output — but silently discarding the unreadable is the one
   * failure mode this gate exists to prevent.
   */
  it.each([
    ['a bare number', [{ source: WAIVED[0] }, 999999]],
    ['a null', [{ source: WAIVED[0] }, null]],
    ['a nested array', [{ source: WAIVED[0] }, ['sharp']]],
    ['an advisory whose source is a string', [{ source: String(WAIVED[0]) }]],
  ])('refuses a via entry that is %s', (_label, via) => {
    const res = runGate(realisticReport({ sharp: { severity: 'high', via } }));
    expect(res.status).toBe(2);
    expect(res.stderr).toMatch(/unreadable via entry on sharp/);
    expect(res.stderr).not.toMatch(/PASS/);
  });

  it('refuses a via that names a package with no node in the report', () => {
    const res = runGate(
      realisticReport({ sharp: { severity: 'high', via: [{ source: WAIVED[0] }, 'missing-package'] } }),
    );
    expect(res.status).toBe(2);
    expect(res.stderr).toMatch(/names "missing-package", which is not a node in this report/);
    expect(res.stderr).not.toMatch(/PASS/);
  });

  it('refuses a node carrying no via list at all', () => {
    const res = runGate(
      JSON.stringify({
        auditReportVersion: 2,
        vulnerabilities: { sharp: { severity: 'high' } },
        metadata: {
          vulnerabilities: { info: 0, low: 0, moderate: 0, high: 1, critical: 0, total: 1 },
          dependencies: { prod: 1, dev: 0, optional: 0, peer: 0, peerOptional: 0, total: 1 },
        },
      }),
    );
    expect(res.status).toBe(2);
    expect(res.stderr).toMatch(/unreadable via entry on sharp: `via` is missing/);
  });

  it('refuses to run at all when there is no npm on PATH', () => {
    const res = spawnSync(process.execPath, [AUDIT_SCRIPT], {
      cwd: REPO_ROOT,
      encoding: 'utf8',
      env: { PATH: join(home, 'empty'), HOME: home },
      timeout: 60_000,
    });
    expect(res.status).toBe(2);
    expect(res.stderr).toMatch(/could not run `npm audit/);
  });
});

describe('#466 CLI — a report the gate CAN read still decides on the merits', () => {
  it('passes a clean tree', () => {
    const res = runGate(realisticReport({}));
    expect(res.stderr).toMatch(/PASS — 0 unwaived production advisories/);
    expect(res.status).toBe(0);
  });

  it('passes the waived sharp chain exactly as the live tree reports it', () => {
    const res = runGate(
      realisticReport({
        '@huggingface/transformers': { severity: 'high', via: ['sharp'] },
        sharp: { severity: 'high', via: WAIVED.map((source) => ({ source })) },
      }),
    );
    expect(res.stderr).toMatch(/PASS — 0 unwaived production advisories/);
    expect(res.status).toBe(0);
  });

  it('fails with exit 1 — not 2 — on a real unwaived advisory', () => {
    const res = runGate(
      realisticReport({ lodash: { severity: 'high', via: [{ source: 999999 }] } }),
    );
    expect(res.status).toBe(1);
    expect(res.stderr).toMatch(/FAIL — 1 unwaived production advisory node/);
  });

  /**
   * Exit 1, not 2 and not 0. The report is perfectly readable; the verdict is
   * that `sharp`'s own advisories being waived does not waive the unwaived
   * `lodash` it derives from. At ef06f9d3 `sharp` was seeded `true` from its own
   * ids and its `via` packages were never consulted again, so the gate named one
   * unwaived node where there are two.
   */
  it('does not waive a node whose advisories are waived but whose source package is not', () => {
    const res = runGate(
      realisticReport({
        lodash: { severity: 'high', via: [{ source: 999999 }] },
        sharp: { severity: 'high', via: [...WAIVED.map((source) => ({ source })), 'lodash'] },
      }),
    );
    expect(res.status).toBe(1);
    expect(res.stderr).toMatch(/FAIL — 2 unwaived production advisory node/);
    // The per-node verdicts are the report, on stdout; the summary is on stderr.
    expect(res.stdout).toMatch(/UNWAIVED sharp/);
    expect(res.stdout).toMatch(/UNWAIVED lodash/);
    expect(res.stdout).not.toMatch(/WAIVED {3}sharp/);
  });

  it('reports the measured totals in --json mode', () => {
    const res = runGate(
      realisticReport({ sharp: { severity: 'high', via: WAIVED.map((source) => ({ source })) } }),
      { extraArgs: ['--json'] },
    );
    expect(res.status).toBe(0);
    const parsed = JSON.parse(res.stdout);
    expect(parsed.pass).toBe(true);
    expect(parsed.npmTotals.total).toBe(1);
    expect(parsed.waivedAdvisoryIdsHit.sort()).toEqual([...WAIVED].sort());
  });
});

/**
 * The deadline has to live on the subprocess. Review proved a caller-side one
 * is inert: `spawnSync` blocks the event loop, so the live test's declared
 * 120 s Jest timeout could never fire — a fixture npm that answered after
 * 1,500 ms passed a test declared with a 20 ms timeout, and an npm that never
 * answered would hang the suite indefinitely.
 */
describe('#466 CLI — the audit subprocess has a deadline that actually fires', () => {
  it('kills a slow npm and exits 2 rather than waiting for it', () => {
    const started = Date.now();
    const res = runGate(realisticReport({}), { delayMs: 10_000, timeoutMs: 400 });
    const elapsed = Date.now() - started;
    expect(res.status).toBe(2);
    expect(res.stderr).toMatch(/did not answer within 400 ms and was killed/);
    expect(res.stderr).toMatch(/SC_SKIP_LIVE_AUDIT=1/);
    // The fixture would have answered — with a PASSING report — at 10 s. Coming
    // back in well under that is what proves the deadline fired and not merely
    // that the gate disliked the output.
    expect(elapsed).toBeLessThan(8_000);
  }, 30_000);

  it('leaves an audit that answers inside the deadline alone', () => {
    const res = runGate(realisticReport({}), { delayMs: 150, timeoutMs: 10_000 });
    expect(res.stderr).toMatch(/PASS — 0 unwaived production advisories/);
    expect(res.status).toBe(0);
  }, 30_000);
});

/**
 * The live leg's three outcomes, driven through a real Jest run.
 *
 * The unit tests in release-audit-claims.test.ts pin the classification; these
 * pin the CONSEQUENCE, which is the thing that was wrong: a registry blip used
 * to turn the ordinary unit suite red with no code regression behind it, and
 * "re-run until green" is a habit that lets real drift through. Unavailable has
 * to be a visible skip, and drift has to be a failure, in the same suite.
 *
 * A nested Jest run is the only way to observe a skip: Jest has no runtime
 * skip, so whether a leg is pending is decided at collection time in the child.
 */
describe('#466 — an unavailable audit skips the live leg; drift still fails it', () => {
  function runClaimsSuite(label: string, extraEnv: Record<string, string> = {}): {
    status: number | null;
    failed: number;
    pending: number;
    pendingNames: string[];
    failureMessages: string;
  } {
    const outFile = join(home, `nested-${label}.json`);
    const res = spawnSync(
      process.execPath,
      [
        join('scripts', 'run-jest.mjs'),
        '--runInBand',
        '--no-cache',
        `--cacheDirectory=${join(home, 'jest-cache')}`,
        '--runTestsByPath',
        CLAIMS_SUITE,
        '--json',
        `--outputFile=${outFile}`,
      ],
      {
        cwd: REPO_ROOT,
        encoding: 'utf8',
        env: {
          PATH: `${fakeBin}:/usr/bin:/bin`,
          HOME: home,
          SHIELDCORTEX_CONFIG_DIR: join(home, 'config'),
          SHIELDCORTEX_AUDIT_DIR: join(home, 'audit'),
          npm_config_cache: join(home, 'npm-cache'),
          ...extraEnv,
        },
        timeout: 240_000,
      },
    );
    const report = JSON.parse(readFileSync(outFile, 'utf8'));
    const assertions = report.testResults.flatMap(
      (suite: { assertionResults: Array<{ status: string; fullName: string; failureMessages: string[] }> }) =>
        suite.assertionResults,
    );
    return {
      status: res.status,
      failed: report.numFailedTests,
      pending: report.numPendingTests,
      pendingNames: assertions.filter((a: { status: string }) => a.status === 'pending').map((a: { fullName: string }) => a.fullName),
      failureMessages: assertions.flatMap((a: { failureMessages: string[] }) => a.failureMessages).join('\n'),
    };
  }

  it('skips, naming the reason, when the registry blips', () => {
    installFakeNpm(
      JSON.stringify({ error: { code: 'ECONNRESET', summary: 'request to registry failed' } }),
    );
    const run = runClaimsSuite('blip');
    expect(run.failed).toBe(0);
    expect(run.status).toBe(0);
    expect(run.pending).toBeGreaterThanOrEqual(1);
    expect(run.pendingNames.join('\n')).toContain('skipped: live audit unavailable');
    expect(run.pendingNames.join('\n')).toContain('ECONNRESET');
  }, 300_000);

  it('still fails when npm answers and the answer contradicts the claim', () => {
    installFakeNpm(
      realisticReport({ lodash: { severity: 'high', via: [{ source: 999999 }] } }),
    );
    const run = runClaimsSuite('drift');
    expect(run.failed).toBeGreaterThanOrEqual(1);
    expect(run.status).not.toBe(0);
    expect(run.failureMessages).toContain('lodash');
    expect(run.pendingNames.join('\n')).not.toContain('live audit unavailable');
  }, 300_000);

  /**
   * The live leg passes `timeoutMs: 60_000` explicitly, and the message a
   * timeout prints tells the operator to set `SC_AUDIT_TIMEOUT_MS`. Under
   * caller-wins precedence that advice did nothing for the one caller that ever
   * reads it: review measured a 500 ms fixture passing with the variable set to
   * 50 ms. So the environment now overrides the caller, and this is the
   * consequence — a fixture that would answer (with a report that CONTRADICTS
   * the claim, so a measured leg would be red) is cut off by the variable
   * instead, and the leg is a skip naming the deadline.
   */
  it('lets the environment shorten a deadline the caller set for itself', () => {
    installFakeNpm(realisticReport({}), { delayMs: 8_000 });
    const run = runClaimsSuite('env-deadline', { SC_AUDIT_TIMEOUT_MS: '400' });
    expect(run.failed).toBe(0);
    expect(run.status).toBe(0);
    expect(run.pendingNames.join('\n')).toContain('skipped: live audit unavailable');
    expect(run.pendingNames.join('\n')).toContain('did not answer within 400 ms');
  }, 300_000);

  it('skips on the documented opt-out, without calling npm at all', () => {
    installFakeNpm('this fixture must never be parsed', { code: 0 });
    const outFile = join(home, 'nested-optout.json');
    const res = spawnSync(
      process.execPath,
      [
        join('scripts', 'run-jest.mjs'),
        '--runInBand',
        '--no-cache',
        `--cacheDirectory=${join(home, 'jest-cache')}`,
        '--runTestsByPath',
        CLAIMS_SUITE,
        '--json',
        `--outputFile=${outFile}`,
      ],
      {
        cwd: REPO_ROOT,
        encoding: 'utf8',
        env: {
          PATH: `${fakeBin}:/usr/bin:/bin`,
          HOME: home,
          SHIELDCORTEX_CONFIG_DIR: join(home, 'config'),
          SC_SKIP_LIVE_AUDIT: '1',
        },
        timeout: 240_000,
      },
    );
    const report = JSON.parse(readFileSync(outFile, 'utf8'));
    const pending = report.testResults
      .flatMap((suite: { assertionResults: Array<{ status: string; fullName: string }> }) => suite.assertionResults)
      .filter((a: { status: string }) => a.status === 'pending')
      .map((a: { fullName: string }) => a.fullName)
      .join('\n');
    expect(report.numFailedTests).toBe(0);
    expect(res.status).toBe(0);
    expect(pending).toContain('SC_SKIP_LIVE_AUDIT=1');
  }, 300_000);
});
