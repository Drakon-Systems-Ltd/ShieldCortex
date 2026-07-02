import fs from 'fs';
import path from 'path';
import { describe, expect, it } from '@jest/globals';

/**
 * Source hygiene: no raw control bytes in TypeScript sources.
 *
 * A literal NUL byte (the actual 0x00 byte, not the `\u0000` escape) shipped
 * inside a template literal in src/cli/migrate-legacy.ts and made grep/
 * ugrep/git-diff classify the file as binary — silently hiding its contents
 * from every text tool that swept the repo. Runtime-identical, tooling-
 * hostile. Control characters belong in escape sequences, never raw.
 */
describe('source hygiene', () => {
  const roots = ['src', 'plugins'].map((r) => path.join(process.cwd(), r));
  const skip = new Set(['node_modules', 'dist', '__fixtures__']);

  function collectTsFiles(dir: string, out: string[] = []): string[] {
    let entries: fs.Dirent[] = [];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return out;
    }
    for (const entry of entries) {
      if (skip.has(entry.name)) continue;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) collectTsFiles(full, out);
      else if (entry.isFile() && entry.name.endsWith('.ts')) out.push(full);
    }
    return out;
  }

  it('no .ts source file contains a raw NUL byte', () => {
    const offenders: string[] = [];
    for (const root of roots) {
      for (const file of collectTsFiles(root)) {
        if (fs.readFileSync(file).includes(0)) {
          offenders.push(path.relative(process.cwd(), file));
        }
      }
    }
    expect(offenders).toEqual([]);
  });
});
