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
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(HERE, '..', '..');
const AUDIT_SCRIPT = join(REPO_ROOT, 'scripts', 'lab', 'audit-report.mjs');

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
 * Install a fake `npm` that prints `stdout` verbatim and exits with `code`,
 * then run the real gate against it.
 *
 * The shebang is this process's own node binary, so the fixture does not
 * depend on a `node` being resolvable from the stripped PATH.
 */
function runGate(
  stdout: string,
  { code = 1, stderr = '', delayMs = 0, extraArgs = [] as string[] } = {},
): { status: number | null; stdout: string; stderr: string } {
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

  const res = spawnSync(process.execPath, [AUDIT_SCRIPT, ...extraArgs], {
    cwd: REPO_ROOT,
    encoding: 'utf8',
    env: {
      PATH: `${fakeBin}:/usr/bin:/bin`,
      HOME: home,
      npm_config_cache: join(home, 'npm-cache'),
    },
    timeout: 60_000,
  });
  return { status: res.status, stdout: res.stdout ?? '', stderr: res.stderr ?? '' };
}

/** A report npm would really emit: n nodes, metadata agreeing with the map. */
function realisticReport(nodes: Record<string, { severity: string; via: unknown[] }>) {
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

  it('refuses a report that is valid JSON but not an object', () => {
    const res = runGate('[]');
    expect(res.status).toBe(2);
    expect(res.stderr).toMatch(/expected a JSON object, got an array/);
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
