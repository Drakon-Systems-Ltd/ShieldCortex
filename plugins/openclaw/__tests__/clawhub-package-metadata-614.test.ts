import fs from 'node:fs';
import path from 'node:path';
import url from 'node:url';
import { describe, expect, it } from '@jest/globals';

/**
 * #614 — ClawHub refuses an external code plugin whose package.json lacks
 * `openclaw.compat.pluginApi` or `openclaw.build.openclawVersion`. Without them
 * the plugin cannot be listed, so `openclaw plugins search shieldcortex` finds
 * nothing and `openclaw plugins install clawhub:...` cannot work.
 *
 * These tests read the REAL package.json that ships in the tarball. They pin
 * that the fields exist, and that the compat floor says the same thing as
 * `engines.openclaw`, so the listing never advertises a host floor the package
 * itself does not declare.
 */

const here = path.dirname(url.fileURLToPath(import.meta.url));
const pkg = JSON.parse(fs.readFileSync(path.join(here, '..', 'package.json'), 'utf-8'));

const VERSION = /^\d{4}\.\d{1,2}\.\d{1,2}(-[0-9A-Za-z.]+)?$/;

describe('#614 ClawHub package metadata', () => {
  it('declares openclaw.compat.pluginApi as a lower-bound range', () => {
    expect(typeof pkg.openclaw?.compat?.pluginApi).toBe('string');
    expect(pkg.openclaw.compat.pluginApi).toMatch(/^>=\d{4}\.\d{1,2}\.\d{1,2}/);
  });

  it('declares openclaw.build.openclawVersion as a concrete version', () => {
    expect(pkg.openclaw?.build?.openclawVersion).toMatch(VERSION);
  });

  it('declares minGatewayVersion and pluginSdkVersion as concrete versions', () => {
    expect(pkg.openclaw.compat.minGatewayVersion).toMatch(VERSION);
    expect(pkg.openclaw.build.pluginSdkVersion).toMatch(VERSION);
  });

  it('compat floor agrees with engines.openclaw', () => {
    expect(pkg.openclaw.compat.pluginApi).toBe(pkg.engines.openclaw);
    expect(`>=${pkg.openclaw.compat.minGatewayVersion}`).toBe(pkg.engines.openclaw);
  });

  it('ships package.json fields the listing depends on', () => {
    expect(pkg.openclaw.extensions).toEqual(['./dist/index.js']);
    expect(pkg.files).toContain('openclaw.plugin.json');
  });
});
