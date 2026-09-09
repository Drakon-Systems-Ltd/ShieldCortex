import { describe, it, expect } from '@jest/globals';
import fs from 'fs';
import path from 'path';
import { createRequire } from 'module';
import { fileURLToPath } from 'url';

import { nodeSupportVerdict } from '../doctor.js';

const require = createRequire(import.meta.url);
const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const doctorSrc = fs.readFileSync(path.join(repoRoot, 'src', 'setup', 'doctor.ts'), 'utf-8');
const enginesRange: string = JSON.parse(
  fs.readFileSync(path.join(repoRoot, 'package.json'), 'utf-8'),
).engines.node;

/**
 * `doctor` used to WARN on an unsupported Node. npm `engines` is advisory
 * unless engine-strict is set, so a Node 20 user installs successfully with
 * only an EBADENGINE warning and then hard-fails at runtime — better-sqlite3
 * 13's binding.gyp defines NAPI_VERSION=10 and Node 20 caps at Node-API 9.
 * `handleDoctorCommand` exits 0 on warnings, so the preflight reported a
 * healthy box on a runtime where nothing could open the database.
 */
describe('setup doctor: unsupported Node is FAIL, not WARN', () => {
  const UNSUPPORTED = ['v20.19.0', 'v22.0.0', 'v22.13.1', 'v23.5.0', 'v18.20.4'];
  const SUPPORTED = ['v22.14.0', 'v22.23.2', 'v24.0.0', 'v24.20.0', 'v26.1.0'];

  for (const version of UNSUPPORTED) {
    it(`${version} is FAIL`, () => {
      const verdict = nodeSupportVerdict(version);
      expect(verdict.status).toBe('FAIL');
      expect(verdict.status).not.toBe('WARN');
      expect(verdict.message).toContain(version);
      expect(verdict.message).toContain('^22.14.0 || >=24.0.0');
    });
  }

  for (const version of SUPPORTED) {
    it(`${version} is PASS`, () => {
      expect(nodeSupportVerdict(version).status).toBe('PASS');
    });
  }

  it('the FAIL message names the cause and the fix, not just the range', () => {
    const { message } = nodeSupportVerdict('v20.19.0');
    expect(message).toContain('Node-API 10');
    expect(message).toContain('will not load');
    expect(message).toMatch(/reinstall ShieldCortex/i);
  });

  it('accepts a bare version string as well as a `v`-prefixed one', () => {
    expect(nodeSupportVerdict('22.13.1').status).toBe('FAIL');
    expect(nodeSupportVerdict('22.14.0').status).toBe('PASS');
    expect(nodeSupportVerdict('22.14.0').message).toContain('v22.14.0');
  });

  it('never disagrees with the declared engines range', () => {
    // The real invariant: doctor is a preflight for `engines.node`, so its
    // verdict must be exactly `semver.satisfies` against the declared range.
    // Anything else is drift between the gate and the thing it gates.
    const semver = require('semver') as typeof import('semver');
    for (const version of [...UNSUPPORTED, ...SUPPORTED]) {
      const bare = version.replace(/^v/, '');
      const expected = semver.satisfies(bare, enginesRange) ? 'PASS' : 'FAIL';
      expect({ version, status: nodeSupportVerdict(version).status }).toEqual({ version, status: expected });
    }
  });

  it('checkNode routes through the shared verdict, and any FAIL exits non-zero', () => {
    // Wiring: the verdict is covered above; what rots is whether the caller
    // still uses it, and whether a FAIL actually changes doctor's exit code.
    expect(doctorSrc).toMatch(/function checkNode\(\): void \{\s*const verdict = nodeSupportVerdict\(process\.version\);\s*add\(verdict\.status, verdict\.message\);/);
    expect(doctorSrc).toContain('process.exit(fails > 0 ? 1 : 0)');
  });
});
