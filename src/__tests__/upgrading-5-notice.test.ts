/**
 * 5.0.0 is a breaking release. Michael's gate (2026-09-12): be very clear on
 * the README, the website and npm *before* people update. This suite is the
 * README + npm half of that gate. The website lives in a different repo and
 * is checked there.
 *
 * A major that people walk into from `npm install -g shieldcortex` without
 * seeing Node 20 is gone is a broken major. These strings are the contract.
 */
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

function read(rel: string): string {
  return fs.readFileSync(path.join(ROOT, rel), 'utf8');
}

describe('5.0.0 breaking notice — visible before anyone updates', () => {
  it('ships docs/UPGRADING-5.md in the npm tarball', () => {
    const pkg = JSON.parse(read('package.json')) as { files: string[] };
    expect(pkg.files).toContain('docs/UPGRADING-5.md');
    expect(pkg.files).toContain('docs/security/audit-waivers.md');
    expect(fs.existsSync(path.join(ROOT, 'docs/UPGRADING-5.md'))).toBe(true);
  });

  it('engines refuse Node 20', () => {
    const pkg = JSON.parse(read('package.json')) as { engines: { node: string } };
    expect(pkg.engines.node).toBe('^22.14.0 || >=24.0.0');
  });

  it('README warns above the install command and links the upgrade page', () => {
    const readme = read('README.md');
    expect(readme).toMatch(/ShieldCortex 5\.0 requires Node 22\.14\+ or Node 24/);
    expect(readme).toMatch(/Node 20 is no longer supported/);
    expect(readme).toMatch(/docs\/UPGRADING-5\.md/);
    expect(readme).toMatch(/Action Guard stays off by default/);
    // The warning must appear before the Quick Start install block, not buried.
    expect(readme.indexOf('ShieldCortex 5.0 requires Node')).toBeLessThan(
      readme.indexOf('## 🚀 Quick Start'),
    );
  });

  it('Quick Start states the Node floor before the install command', () => {
    const readme = read('README.md');
    const qs = readme.indexOf('## 🚀 Quick Start');
    const req = readme.indexOf('### Requirements', qs);
    const install = readme.indexOf('npm install -g shieldcortex', qs + 1);
    expect(req).toBeGreaterThan(qs);
    expect(install).toBeGreaterThan(req);
    expect(readme.slice(req, install)).toMatch(/Node 22\.14\+/);
    expect(readme.slice(req, install)).toMatch(/Node 20 is not supported/);
  });

  it('CHANGELOG opens Unreleased with a Breaking (5.0.0) block', () => {
    const log = read('CHANGELOG.md');
    const unreleased = log.indexOf('## [Unreleased]');
    const breaking = log.indexOf('### ⚠️ Breaking (5.0.0)', unreleased);
    const added = log.indexOf('### Added', unreleased);
    expect(breaking).toBeGreaterThan(unreleased);
    expect(added).toBeGreaterThan(breaking);
    expect(log.slice(breaking, added)).toMatch(/Node 20 is no longer supported/);
    expect(log.slice(breaking, added)).toMatch(/docs\/UPGRADING-5\.md/);
  });

  it('postinstall banner names 5.0, the Node floor, Guard-off, and the upgrade URL', () => {
    const src = read('scripts/postinstall.mjs');
    expect(src).toMatch(/5\.0 requires Node 22\.14\+ or Node 24 \(Node 20 is gone\)/);
    expect(src).toMatch(/Action Guard is off by default/);
    expect(src).toMatch(/Drakon-Systems-Ltd\/ShieldCortex\/blob\/main\/docs\/UPGRADING-5\.md/);
    expect(src).toMatch(/ShieldCortex 5 dropped Node 20/);
  });

  it('upgrade page names the Node floor, the stay-on-4 path, and the backup', () => {
    const page = read('docs/UPGRADING-5.md');
    expect(page).toMatch(/^# Upgrading to ShieldCortex 5\.0/m);
    expect(page).toMatch(/Node 20 is gone|Node 20 is no longer supported|Install refuses/);
    expect(page).toMatch(/npm install -g shieldcortex@5/);
    expect(page).toMatch(/npm install -g shieldcortex@4/);
    expect(page).toMatch(/~\/\.shieldcortex/);
    expect(page).toMatch(/Action Guard stays off by default/);
    expect(page).toMatch(/#474/);
  });
});
