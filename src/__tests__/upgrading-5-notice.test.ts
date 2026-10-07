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

  it('README states the Node floor in Install, before the install command, and links the upgrade page', () => {
    const readme = read('README.md');
    expect(readme).toMatch(/ShieldCortex 5\.x requires Node 22\.14\+ or Node 24/);
    expect(readme).toMatch(/Node 20 is no longer supported/);
    expect(readme).toMatch(/docs\/UPGRADING-5\.md/);
    expect(readme).toMatch(/Action Guard stays off by default/);
    // The floor sits in the Install section, immediately before the command,
    // so a global install still sees it. It is not a warning box above the title.
    const section = readme.indexOf('## Install');
    const floor = readme.indexOf('ShieldCortex 5.x requires Node');
    const npm = readme.indexOf('npm install -g shieldcortex', section);
    expect(section).toBeGreaterThan(0);
    expect(floor).toBeGreaterThan(section);
    expect(npm).toBeGreaterThan(floor);
    const block = readme.slice(section, npm);
    expect(block).toMatch(/Node 22\.14\+/);
    expect(block).toMatch(/Node 20 is no longer supported/);
    expect(block).toMatch(/Node 23/);
    // engines is advisory unless engine-strict is set (src/cli/doctor.ts); the
    // README must say both halves, not "warns but does not refuse".
    expect(block).toMatch(/engine-strict/);
    expect(block).toMatch(/installs anyway/);
    expect(readme).not.toMatch(/does not refuse|only warns|or any 24/);
    // postinstall, the wiring offer and the macOS dashboard kick can all
    // restart something, so `update` may not claim to leave restarts to you.
    expect(readme).not.toMatch(/leaves restarts to you/);
  });

  it('CHANGELOG 5.0.0 section opens with Breaking, below the Unreleased section', () => {
    const log = read('CHANGELOG.md');
    const five = log.indexOf('## [5.0.0]');
    const four = log.indexOf('## [4.54.15]');
    const breaking = log.indexOf('### ⚠️ Breaking (5.0.0)', five);
    const added = log.indexOf('### Added', five);
    expect(five).toBeGreaterThan(log.indexOf('## [Unreleased]'));
    expect(breaking).toBeGreaterThan(five);
    expect(breaking).toBeLessThan(four);
    expect(added).toBeGreaterThan(breaking);
    expect(log.slice(breaking, added)).toMatch(/Node 20 is no longer supported/);
    expect(log.slice(breaking, added)).toMatch(/docs\/UPGRADING-5\.md/);
    // Unreleased sits above 5.0.0 (asserted above). Its contents are whatever
    // has landed since the release — "(none yet)" at release time, real
    // entries afterwards — so only its shape is asserted, not emptiness
    // (the emptiness check failed the moment the first post-5.0.0 entry landed).
    const unreleased = log.slice(log.indexOf('## [Unreleased]'), five);
    expect(unreleased).toMatch(/\(none yet\)|^- /m);
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
