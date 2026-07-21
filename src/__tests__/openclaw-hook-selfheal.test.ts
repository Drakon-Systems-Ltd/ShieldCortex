import fs from 'fs';
import path from 'path';
import { fileURLToPath, pathToFileURL } from 'url';
import { describe, expect, it } from '@jest/globals';

/**
 * Guards for the cortex-memory hook's bootstrap self-heal.
 *
 * #109 — the self-copy used to migrate only `HOOK.md` + `handler.ts`, omitting
 * the `runtime.mjs` that handler.ts imports at module load. The migrated hook
 * therefore threw on the next gateway start. The expected file set here is
 * DERIVED from the hook directory's actual contents, not restated: drop a new
 * file into hooks/openclaw/cortex-memory/ and every consumer that doesn't copy
 * it fails this suite, so the manifest can't silently rot.
 *
 * #108 — the mutating branches (legacy-dir deletion, self-copy) are gated on an
 * opt-out. The gate itself is a pure predicate in runtime.mjs, exercised for
 * real below; the placement of the gate relative to the mutations is checked by
 * source analysis, which is how the other hook invariants are tested (the hook
 * can't be imported here — jiti loads it with a live OpenClaw event shape).
 */

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '..', '..');

const HOOK_DIR = path.join(repoRoot, 'hooks', 'openclaw', 'cortex-memory');
const BUNDLED_HOOK_DIR = path.join(
  repoRoot, 'skills', 'shieldcortex', 'bundled', 'cortex-memory-hook',
);
const INSTALLER = path.join(repoRoot, 'src', 'setup', 'openclaw.ts');

/** The real manifest: every file the hook directory actually ships. */
function manifestOf(dir: string): string[] {
  return fs
    .readdirSync(dir)
    .filter((f) => fs.statSync(path.join(dir, f)).isFile())
    .sort();
}

/** Pull a `const NAME = [...]` string-array literal out of a source file. */
function parseStringArrayConst(source: string, name: string): string[] {
  const match = source.match(new RegExp(`const\\s+${name}\\s*=\\s*\\[([^\\]]*)\\]`));
  expect(match).not.toBeNull();
  return Array.from(match![1].matchAll(/["']([^"']+)["']/g)).map((m) => m[1]).sort();
}

function selfHealSource(dir: string): string {
  const source = fs.readFileSync(path.join(dir, 'handler.ts'), 'utf-8');
  const start = source.indexOf('async function selfCheckAndHeal');
  const end = source.indexOf('// ==================== MAIN HANDLER');
  expect(start).toBeGreaterThan(-1);
  expect(end).toBeGreaterThan(start);
  return source.slice(start, end);
}

describe('cortex-memory self-heal — copied file set is complete (#109)', () => {
  const manifest = manifestOf(HOOK_DIR);

  it('the hook directory manifest is non-trivial and includes runtime.mjs', () => {
    // Sanity: if this ever became [] or lost runtime.mjs, the derived
    // comparisons below would pass vacuously.
    expect(manifest.length).toBeGreaterThanOrEqual(3);
    expect(manifest).toContain('runtime.mjs');
    expect(manifest).toContain('handler.ts');
  });

  it("handler.ts HOOK_FILES matches the hook directory's actual contents", () => {
    const source = fs.readFileSync(path.join(HOOK_DIR, 'handler.ts'), 'utf-8');
    expect(parseStringArrayConst(source, 'HOOK_FILES')).toEqual(manifest);
  });

  it('the bundled skill copy carries the same complete manifest', () => {
    const source = fs.readFileSync(path.join(BUNDLED_HOOK_DIR, 'handler.ts'), 'utf-8');
    expect(parseStringArrayConst(source, 'HOOK_FILES')).toEqual(manifestOf(BUNDLED_HOOK_DIR));
    // The bundled copy is the one that most often runs from an unexpected path
    // (skills-only installs), i.e. the copy that actually performs a migration.
    expect(manifestOf(BUNDLED_HOOK_DIR)).toEqual(manifest);
  });

  it('the installer copies the same set the hook expects', () => {
    const source = fs.readFileSync(INSTALLER, 'utf-8');
    expect(parseStringArrayConst(source, 'HOOK_FILES')).toEqual(manifest);
  });

  for (const [label, dir] of [['hook', HOOK_DIR], ['bundled', BUNDLED_HOOK_DIR]] as const) {
    it(`${label}: the self-copy iterates HOOK_FILES, never a literal subset`, () => {
      const body = selfHealSource(dir);
      expect(body).toMatch(/for\s*\(const file of HOOK_FILES\)/);
      // The exact regression from #109: a hardcoded pair that drops runtime.mjs.
      expect(body).not.toMatch(/filesToCopy\s*=\s*\[/);
    });

    it(`${label}: a partial copy is reported as broken, not as success`, () => {
      const body = selfHealSource(dir);
      // Failed copies are tracked and must suppress the "migrated, no action
      // needed" bootstrap notice — a half-copied hook cannot load.
      expect(body).toMatch(/failed\.push\(file\)/);
      expect(body).toMatch(/INCOMPLETE migration/);
      expect(body.indexOf('INCOMPLETE migration'))
        .toBeLessThan(body.indexOf('SHIELDCORTEX_HOOK_MIGRATED.md'));
    });
  }
});

describe('cortex-memory self-heal — opt-out gate (#108)', () => {
  const runtimeUrl = pathToFileURL(path.join(HOOK_DIR, 'runtime.mjs')).href;

  it('defaults to enabled, preserving pre-4.47.12 behaviour', async () => {
    const { isSelfHealEnabled } = await import(runtimeUrl);
    // Absent, empty, unreadable-and-defaulted-to-{}, and unrelated configs all
    // leave the self-heal on.
    expect(isSelfHealEnabled(undefined, {})).toBe(true);
    expect(isSelfHealEnabled(null, {})).toBe(true);
    expect(isSelfHealEnabled({}, {})).toBe(true);
    expect(isSelfHealEnabled({ openclawAutoMemory: true }, {})).toBe(true);
  });

  it('is disabled by SHIELDCORTEX_SKIP_SELF_HEAL=1', async () => {
    const { isSelfHealEnabled, SELF_HEAL_SKIP_ENV } = await import(runtimeUrl);
    expect(SELF_HEAL_SKIP_ENV).toBe('SHIELDCORTEX_SKIP_SELF_HEAL');
    expect(isSelfHealEnabled({}, { [SELF_HEAL_SKIP_ENV]: '1' })).toBe(false);
    // Only an explicit "1" opts out — a stray empty/other value must not
    // silently disable memory self-repair.
    expect(isSelfHealEnabled({}, { [SELF_HEAL_SKIP_ENV]: '' })).toBe(true);
    expect(isSelfHealEnabled({}, { [SELF_HEAL_SKIP_ENV]: '0' })).toBe(true);
  });

  it('is disabled by "selfHeal": false in config.json', async () => {
    const { isSelfHealEnabled } = await import(runtimeUrl);
    expect(isSelfHealEnabled({ selfHeal: false }, {})).toBe(false);
    expect(isSelfHealEnabled({ selfHeal: true }, {})).toBe(true);
    // Strictly `false` — a truthy-but-odd value stays on rather than
    // half-disabling by accident.
    expect(isSelfHealEnabled({ selfHeal: 'no' }, {})).toBe(true);
  });

  it('the env flag wins over an enabling config', async () => {
    const { isSelfHealEnabled, SELF_HEAL_SKIP_ENV } = await import(runtimeUrl);
    expect(isSelfHealEnabled({ selfHeal: true }, { [SELF_HEAL_SKIP_ENV]: '1' })).toBe(false);
  });

  for (const [label, dir] of [['hook', HOOK_DIR], ['bundled', BUNDLED_HOOK_DIR]] as const) {
    it(`${label}: the gate is resolved before anything is written`, () => {
      const body = selfHealSource(dir);
      const gate = body.indexOf('await isSelfHealEnabled()');
      expect(gate).toBeGreaterThan(-1);
      for (const mutation of ['fs.rm(', 'fs.mkdir(', 'fs.copyFile(']) {
        expect(body.indexOf(mutation)).toBeGreaterThan(gate);
      }
    });

    it(`${label}: the deletion is announced BEFORE it happens`, () => {
      const body = selfHealSource(dir);
      // No backup is taken, so the log line is the only record of what went —
      // it has to be emitted before the rm, not after it.
      expect(body.indexOf('Self-heal: removing stale legacy hook'))
        .toBeLessThan(body.indexOf('fs.rm('));
    });

    it(`${label}: disabled mode warns about both mutations and writes nothing`, () => {
      const body = selfHealSource(dir);
      // Two guarded branches: the legacy-dir delete and the self-copy.
      const warnOnly = body.match(/Self-heal disabled/g) ?? [];
      expect(warnOnly.length).toBe(2);
      expect(body).toMatch(/would have recursively removed/i);
      expect(body).toMatch(/Would have created that/i);
      expect(body).toMatch(/Nothing was deleted/i);
      expect(body).toMatch(/Nothing was written/i);
    });
  }
});
