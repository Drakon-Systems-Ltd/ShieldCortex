import { describe, it, expect } from '@jest/globals';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

import { engineOutcomeFromEnsure, renderEngineFailure } from '../update.js';
import { ensureNativeBinding } from '../../setup/native-binding.js';

/**
 * `shieldcortex update`'s closing output contradicted the recovery it had just
 * selected.
 *
 * For the packaged-prebuild / Node-API class, `ensureNativeBinding` runs NO
 * rebuild on purpose — a source build cannot override a packaged better-sqlite3
 * 13 prebuild, because the package resolver picks the shipped file first — and
 * the remediation says exactly that. But the final block still announced
 * "Database engine could not be rebuilt automatically" and the closing panel
 * still said "engine: database binding needs manual rebuild", recommending the
 * futile remedy the class-aware remediation exists to retire.
 *
 * These tests drive the REAL `ensureNativeBinding` (only its verify/rebuild
 * seams are injected, never its classification) and assert over the COMPLETE
 * engine-failure output `update` emits — headline, remediation body, and the
 * closing-panel detail row.
 */

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const updateSrc = fs.readFileSync(path.join(repoRoot, 'src', 'cli', 'update.ts'), 'utf-8');

const INSTALL_DIR = '/opt/shieldcortex';

/** The exact wording a Node build too old for better-sqlite3 13 produces. */
const NODE_API_ERROR =
  "The module 'better-sqlite3' requires Node-API version 10, but this version of Node.js only supports version 9 add-ons.";

/** An unloadable packaged prebuild — same class, different signature. */
const PREBUILD_ERROR =
  '/opt/shieldcortex/node_modules/better-sqlite3/prebuilds/linux-arm64.node: invalid ELF header';

/** A missing/source-only binding — the class a rebuild CAN still heal. */
const SOURCE_ONLY_ERROR = 'Could not locate the bindings file. Tried: …';

/** Everything `update` prints (and panels) about a failed engine verification. */
function completeEngineOutput(rendered: { headline: string; body: string[]; detail: string }): string {
  return [rendered.headline, ...rendered.body, rendered.detail].join('\n');
}

async function outputForFailure(error: string) {
  const rebuildCalls: Array<{ fromSource: boolean }> = [];
  const result = await ensureNativeBinding({
    verify: () => ({ ok: false, error }),
    rebuild: async (_dir, opts) => {
      rebuildCalls.push({ fromSource: opts?.fromSource ?? false });
      return { ok: false, output: 'rebuilt dependencies successfully' };
    },
    installDir: () => INSTALL_DIR,
  });
  const rendered = renderEngineFailure(engineOutcomeFromEnsure(result));
  return { rebuildCalls, result, rendered };
}

describe('update engine failure output is class-aware (packaged prebuild / Node-API)', () => {
  for (const [label, error] of [
    ['Node-API version too old', NODE_API_ERROR],
    ['unloadable packaged prebuild', PREBUILD_ERROR],
  ] as const) {
    it(`never recommends or claims a rebuild for: ${label}`, async () => {
      const { rebuildCalls, rendered } = await outputForFailure(error);

      // Premise: this class deliberately attempts no rebuild at all.
      expect(rebuildCalls).toEqual([]);
      expect(rendered).not.toBeNull();
      const output = completeEngineOutput(rendered!);

      // The contradiction, in every form it appeared in.
      expect(output).not.toMatch(/could not be rebuilt/i);
      expect(output).not.toMatch(/needs manual rebuild/i);
      expect(output).not.toMatch(/manual rebuild/i);
      expect(output).not.toContain('npm run build-release');
      expect(output).not.toContain('shieldcortex repair');

      // What it says instead: the selected, class-aware remediation.
      expect(output).toContain('binding remains unavailable');
      expect(output).toContain('reinstall ShieldCortex');
      expect(output).toContain('cannot safely override the packaged prebuild');
      expect(rendered!.detail).toBe('engine: binding remains unavailable; follow remediation above');
    });
  }

  it('keeps the rebuild framing for a missing/source-only binding, which a rebuild CAN heal', async () => {
    const { rebuildCalls, rendered } = await outputForFailure(SOURCE_ONLY_ERROR);

    // Premise: this class really does get both rebuild attempts.
    expect(rebuildCalls).toEqual([{ fromSource: false }, { fromSource: true }]);
    expect(rendered).not.toBeNull();
    const output = completeEngineOutput(rendered!);

    expect(output).toContain('Database engine could not be rebuilt automatically.');
    expect(output).toContain('npm run build-release');
    expect(rendered!.detail).toBe('engine: database binding needs manual rebuild');
  });

  it('reports nothing when the binding is healthy or was healed', () => {
    expect(renderEngineFailure(engineOutcomeFromEnsure({ status: 'ok' }))).toBeNull();
    expect(
      renderEngineFailure(engineOutcomeFromEnsure({ status: 'healed', rebuildOutput: 'built' })),
    ).toBeNull();
  });

  it('a failed result with no remediation prints nothing rather than a bare contradiction', () => {
    expect(renderEngineFailure(engineOutcomeFromEnsure({ status: 'failed', error: NODE_API_ERROR }))).toBeNull();
  });
});

describe('runUpdate renders the engine block only through renderEngineFailure', () => {
  // Wiring test in the #171 tradition: the renderer is covered above; what
  // rots is whether THIS caller still routes through it. A stray literal in
  // runUpdate would reintroduce the contradiction while the unit tests stayed
  // green.
  function bodyOf(fnName: string): string {
    const at = updateSrc.indexOf(`async function ${fnName}`);
    expect({ fn: fnName, found: at >= 0 }).toEqual({ fn: fnName, found: true });
    return updateSrc.slice(at, updateSrc.indexOf('\n}', at));
  }

  const body = bodyOf('runUpdate');

  it('calls the renderer and uses its headline and detail', () => {
    expect(body).toMatch(/renderEngineFailure\(engineResult\)/);
    expect(body).toMatch(/engineFailure\.headline/);
    expect(body).toMatch(/engineFailure\.body/);
    expect(body).toMatch(/details\.push\(engineFailure\.detail\)/);
  });

  it('hard-codes neither of the old contradictory strings', () => {
    expect(body).not.toContain('Database engine could not be rebuilt automatically.');
    expect(body).not.toContain('engine: database binding needs manual rebuild');
  });

  it('the class-aware strings live in exactly one place each', () => {
    const count = (needle: string) => updateSrc.split(needle).length - 1;
    expect(count('Database engine could not be rebuilt automatically.')).toBe(1);
    expect(count('engine: database binding needs manual rebuild')).toBe(1);
    expect(count('Database engine binding remains unavailable; follow the remediation below.')).toBe(1);
    expect(count('engine: binding remains unavailable; follow remediation above')).toBe(1);
  });
});
