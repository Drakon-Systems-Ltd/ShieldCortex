import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { describe, expect, it } from '@jest/globals';

/**
 * OpenClaw 2026.4.24+ plugin-install security audit textually flags any
 * plugin source file that contains both an fs-read API name AND a network
 * send call as [potential-exfiltration]. The scan includes comment text
 * (v4.12.9 confirmed: a doc comment naming the API tripped it). This test
 * mirrors that exact behaviour — no comment stripping — so the local guard
 * fires before publish, not after the fleet hits a fresh install.
 */
describe('plugin source files — no fs-read + fetch pairing (OpenClaw 2026.4.24+ audit)', () => {
  const thisFile = fileURLToPath(import.meta.url);
  const repoRoot = path.resolve(path.dirname(thisFile), '..', '..');
  const pluginDir = path.join(repoRoot, 'plugins', 'openclaw');

  // OpenClaw scans every .ts file at the plugin package root; it does not
  // descend into dist/.
  const sources = fs
    .readdirSync(pluginDir)
    .filter(f => f.endsWith('.ts'))
    .map(f => path.join(pluginDir, f));

  it.each(sources)('%s does not pair fs-read with network send (raw text scan)', filePath => {
    const src = fs.readFileSync(filePath, 'utf-8');
    // Mirror OpenClaw's textual scan — comments are NOT stripped. A
    // doc-comment that names both APIs will trip the audit just as code
    // would, so the test must trip too.
    const hasFsRead = /\b(?:readFileSync|readFile)\b/.test(src);
    const hasFetch = /\bfetch\s*\(/.test(src);
    if (hasFsRead && hasFetch) {
      throw new Error(
        `${path.basename(filePath)} contains both fs-read and network-send tokens — ` +
          `OpenClaw 2026.4.24+ will flag this as potential-exfiltration on every install. ` +
          `Move one operation to a separate module (see cloud-sync.ts) AND keep the API ` +
          `names out of any comment that lives alongside the other operation.`,
      );
    }
    expect(hasFsRead && hasFetch).toBe(false);
  });

  it('scans at least the four files OpenClaw audits (index, interceptor, intercept-ingest, cloud-sync)', () => {
    const names = sources.map(s => path.basename(s));
    expect(names).toEqual(
      expect.arrayContaining(['index.ts', 'interceptor.ts', 'intercept-ingest.ts', 'cloud-sync.ts']),
    );
  });
});
