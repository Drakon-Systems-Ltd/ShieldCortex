/**
 * The memory caps a capture hook judges fullness against (#1124).
 *
 * pre-compact, session-end and stop choose how selective extraction is from
 * (stored STM + LTM) / (STM cap + LTM cap). Those caps used to be hardcoded
 * 100 / 1000 copies of DEFAULT_CONFIG, so after a signed `config --memory-cap`
 * raise the hooks still divided by 1100: a raised store looked fuller than the
 * cap doctor and consolidation enforce, and extraction tightened too early.
 *
 * The answer comes from the compiled resolver — `resolveMemoryConfig()` in
 * dist/memory/config.js, the one cleanup, consolidation and doctor use — and
 * never from a parse of config.json here. That resolver owns the integrity
 * rules (#1125, #1132): a cap is honoured as written only under a verifying
 * embedded signature, and an unverified cap is clamped to
 * max(default, min(stored, setter maximum)). A second reader in this file would
 * drift from those rules, which is the defect being fixed.
 *
 * Resolved by package layout — `dist/` two directories up — like the defence
 * and embedder loaders in save-memory.mjs. Tests substitute it the same way, by
 * building a package around a copy of this file; nothing here reads an
 * environment switch.
 *
 * Fails toward the built-in defaults, never toward skipping capture: a missing
 * build, a throwing read or an unusable answer yields 100 / 1000, which is
 * exactly the selectivity these hooks had before #1124. The caps only pick a
 * salience band; nothing here evicts, deletes or refuses a save.
 */

import { dirname, resolve } from 'path';
import { fileURLToPath, pathToFileURL } from 'url';

/** src/memory/types.ts DEFAULT_CONFIG — what the hooks hardcoded before #1124. */
const DEFAULT_CAPS = Object.freeze({ maxShortTermMemories: 100, maxLongTermMemories: 1000 });

/**
 * The resolver already refuses anything below its minimum; this only keeps an
 * older or broken build from handing the fullness ratio a zero or a NaN.
 *
 * It must stay no narrower than the resolver's own domain (validateCap: a
 * finite whole number). Under a verifying signature the resolver honours a
 * cap with no setter ceiling, so a valid answer can exceed
 * Number.MAX_SAFE_INTEGER; an isSafeInteger test here would refuse it and, since
 * a refused answer falls back whole, drop the valid companion cap with it.
 */
function usableCap(value) {
  return Number.isInteger(value) && value > 0;
}

/**
 * @returns {Promise<{ maxShortTermMemories: number, maxLongTermMemories: number }>}
 */
export async function resolveCaptureMemoryCaps() {
  try {
    const here = dirname(fileURLToPath(import.meta.url));
    const distRoot = resolve(here, '..', '..', 'dist');
    const mod = await import(pathToFileURL(resolve(distRoot, 'memory', 'config.js')).href);
    const config = mod.resolveMemoryConfig();
    const stm = config?.maxShortTermMemories;
    const ltm = config?.maxLongTermMemories;
    if (usableCap(stm) && usableCap(ltm)) {
      return { maxShortTermMemories: stm, maxLongTermMemories: ltm };
    }
  } catch {
    // No build, or the read failed: keep the pre-#1124 denominator below.
  }
  return { ...DEFAULT_CAPS };
}
