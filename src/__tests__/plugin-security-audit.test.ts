import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { describe, expect, it } from '@jest/globals';

/**
 * OpenClaw 2026.4.24 added a plugin-install security audit. It flags any
 * plugin source file that contains BOTH a `readFileSync`/`readFile` import
 * and a `fetch(` call as `[potential-exfiltration] File read combined with
 * network send`. The heuristic is textual — it does not analyse data flow.
 *
 * The fix (v4.12.8) extracted `cloudSync` to its own module so no plugin
 * file pairs the two APIs. This test guards that separation: if anyone
 * later adds a `fetch(` call to a file that already reads files (or vice
 * versa), the audit warning will return on the next OpenClaw install.
 */
describe('plugin source files — no fs-read + fetch pairing (OpenClaw 2026.4.24+ audit)', () => {
  const thisFile = fileURLToPath(import.meta.url);
  const repoRoot = path.resolve(path.dirname(thisFile), '..', '..');
  const pluginDir = path.join(repoRoot, 'plugins', 'openclaw');

  // The same set OpenClaw's audit scans: TypeScript sources at the root of
  // the plugin package (it does not descend into dist/).
  const sources = fs
    .readdirSync(pluginDir)
    .filter(f => f.endsWith('.ts'))
    .map(f => path.join(pluginDir, f));

  it.each(sources)('%s does not contain both readFileSync/readFile AND fetch(', filePath => {
    const raw = fs.readFileSync(filePath, 'utf-8');
    // Match what OpenClaw's audit actually scans: imports and call
    // expressions, not comment prose. Strip block + line comments first
    // so explanatory comments naming the APIs don't false-positive.
    const src = raw.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/[^\n]*/g, '');
    const hasFsRead = /\b(?:readFileSync|readFile)\b/.test(src);
    const hasFetch = /\bfetch\s*\(/.test(src);
    if (hasFsRead && hasFetch) {
      throw new Error(
        `${path.basename(filePath)} contains both fs-read and fetch() — ` +
          `OpenClaw 2026.4.24+ plugin audit will flag this as potential-exfiltration. ` +
          `Move one of the two operations to a separate module (see cloud-sync.ts for the pattern).`,
      );
    }
    expect(hasFsRead && hasFetch).toBe(false);
  });

  it('scans at least the three files OpenClaw audits (index, interceptor, intercept-ingest)', () => {
    const names = sources.map(s => path.basename(s));
    expect(names).toEqual(expect.arrayContaining(['index.ts', 'interceptor.ts', 'intercept-ingest.ts']));
  });
});
