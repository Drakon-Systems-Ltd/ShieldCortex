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
 */

import { describe, expect, it } from '@jest/globals';
import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(HERE, '..', '..');
const SKILL_MD = join(REPO_ROOT, 'skills', 'shieldcortex', 'SKILL.md');
const WAIVERS_MD = join(REPO_ROOT, 'docs', 'security', 'audit-waivers.md');
const WORKFLOWS = join(REPO_ROOT, '.github', 'workflows');
const AUDIT_SCRIPT = join(REPO_ROOT, 'scripts', 'lab', 'audit-report.mjs');

/** ESM specifiers must be file: URLs under this jest setup. */
const auditModule = await import(pathToFileURL(AUDIT_SCRIPT).href);
const { parseWaivers, waivedAdvisoryIds, classify, expiredWaivers, runNpmAudit } = auditModule as {
  parseWaivers: (md: string) => Array<Record<string, unknown> & { id: string; advisories: number[]; expires: string }>;
  waivedAdvisoryIds: (w: Array<{ advisories: number[] }>) => Set<number>;
  classify: (
    report: unknown,
    waived: Set<number>,
  ) => { unwaived: Array<{ name: string }>; waived: Array<{ name: string }>; waivedIds: number[] };
  expiredWaivers: (w: Array<{ expires: string }>, now?: Date) => unknown[];
  runNpmAudit: (extra?: string[], cwd?: string) => { vulnerabilities: Record<string, unknown> };
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
 * Pure so the rule can be exercised in both directions — the failure that
 * matters is "claimed but never run", and the case that must stay GREEN is
 * "claimed and genuinely wired up", which a one-sided test would not catch.
 * `workflowsText` is the concatenated, lowercased contents of
 * `.github/workflows`.
 */
export function scannerClaimViolations(metadataKeys: string[], workflowsText: string): string[] {
  const claimed = new Set(metadataKeys);
  return SCANNERS.filter((s) => claimed.has(s) && !workflowsText.includes(s));
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
    const workflows = readdirSync(WORKFLOWS)
      .map((f) => readFileSync(join(WORKFLOWS, f), 'utf8').toLowerCase())
      .join('\n');
    expect(scannerClaimViolations([...skillMetadata().keys()], workflows)).toEqual([]);
  });
});

describe('#466 hermetic — the scanner rule permits a claim exactly when CI earns it', () => {
  it('flags a claim no workflow backs', () => {
    expect(scannerClaimViolations(['npm_audit', 'snyk'], 'jobs:\n  test:\n    run: npm test')).toEqual([
      'snyk',
    ]);
  });

  it('permits the claim once a workflow actually runs the scanner', () => {
    expect(
      scannerClaimViolations(['npm_audit', 'snyk'], 'jobs:\n  sec:\n    run: snyk test --all-projects'),
    ).toEqual([]);
  });

  it('does not care about a scanner that runs in CI but is not claimed', () => {
    expect(scannerClaimViolations(['npm_audit'], 'run: snyk test')).toEqual([]);
  });

  it('reports every unbacked claim, not just the first', () => {
    expect(scannerClaimViolations(['snyk', 'trivy', 'grype'], 'run: npm test')).toEqual([
      'snyk',
      'trivy',
      'grype',
    ]);
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
});

const skipLive = process.env.SC_SKIP_LIVE_AUDIT === '1';

(skipLive ? describe.skip : describe)('#466 live — the claim equals what npm audit reports now', () => {
  it(
    'reports 0 unwaived production advisories and exactly the waived set the claim names',
    () => {
      const waivers = parseWaivers(waiverMarkdown);
      const ids = waivedAdvisoryIds(waivers);
      const report = runNpmAudit([], REPO_ROOT);
      const result = classify(report, ids);
      const claim = parseClaim();

      expect(result.unwaived.map((n) => n.name)).toEqual([]);
      expect(claim.unwaived).toBe(result.unwaived.length);
      expect(claim.waived).toBe(result.waivedIds.length);
    },
    120_000,
  );
});
