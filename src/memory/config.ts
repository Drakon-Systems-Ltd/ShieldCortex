/**
 * Operator-configurable memory caps (#236 follow-up).
 *
 * `MemoryConfig` had no user-config path at all: `maxShortTermMemories` and
 * `maxLongTermMemories` were hardcoded in `DEFAULT_CONFIG` and every call site
 * defaulted straight to it, so raising the ceiling meant editing `dist/`. On a
 * store that has reached the cap, every surviving write permanently evicts an
 * older memory — so the cap is not a soft preference, it is the point at which
 * the product starts forgetting on the operator's behalf. That number should
 * be theirs.
 *
 * Config lives in `~/.shieldcortex/config.json` under a `memory` block,
 * matching the existing namespaced-block convention (`actionGuard`,
 * `interceptor`):
 *
 *   { "memory": { "maxLongTermMemories": 5000, "maxShortTermMemories": 250 } }
 *
 * Validation fails toward the DEFAULT, never toward destruction. A cap of 0 or
 * a negative would make `enforceMemoryLimits` evict the entire store on the
 * next pass, so anything below MIN_MEMORY_CAP is refused rather than honoured —
 * an operator fat-fingering a zero must not lose their memory.
 *
 * Invalid values are refused LOUDLY (once per process). A config key that is
 * silently ignored is the same class of defect as #225: the operator believes
 * they have configured something, and nothing tells them otherwise.
 */

import { readRawConfig } from '../cloud/config.js';
import { DEFAULT_CONFIG, type MemoryConfig } from './types.js';

/**
 * Lowest cap an operator may set. Below this, `enforceMemoryLimits` would be a
 * store-wipe rather than a bound.
 */
export const MIN_MEMORY_CAP = 10;

/** Keys accepted inside the `memory` block. */
const CAP_KEYS = ['maxShortTermMemories', 'maxLongTermMemories'] as const;
type CapKey = (typeof CAP_KEYS)[number];

/** Warn at most once per key per process — this is read on every write path. */
const warned = new Set<string>();

function warnOnce(key: string, message: string): void {
  if (warned.has(key)) return;
  warned.add(key);
  console.warn(`[shieldcortex] ${message}`);
}

/** Reset the once-per-process warning state. Tests only. */
export function __resetCapWarningsForTest(): void {
  warned.clear();
}

/** The `memory` block from raw config, or an empty object. Mirrors actionGuardBlock. */
function memoryBlock(raw: Record<string, unknown>): Record<string, unknown> {
  return raw.memory && typeof raw.memory === 'object' && !Array.isArray(raw.memory)
    ? (raw.memory as Record<string, unknown>)
    : {};
}

/**
 * Validate one cap override. Returns undefined (keep the default) for anything
 * that is not a finite, whole number at or above MIN_MEMORY_CAP.
 *
 * Deliberately strict about type: a JSON string `"5000"` is refused rather than
 * coerced, matching the `=== true` discipline used for the config booleans. A
 * config value the loader silently reinterprets is a config value the operator
 * cannot reason about.
 */
export function validateCap(value: unknown, key: string = 'cap'): number | undefined {
  if (value === undefined) return undefined;

  if (typeof value !== 'number' || !Number.isFinite(value)) {
    warnOnce(key, `memory.${key} must be a number — ignoring ${JSON.stringify(value)} and using the default.`);
    return undefined;
  }
  if (!Number.isInteger(value)) {
    warnOnce(key, `memory.${key} must be a whole number — ignoring ${value} and using the default.`);
    return undefined;
  }
  if (value < MIN_MEMORY_CAP) {
    warnOnce(
      key,
      `memory.${key}=${value} is below the minimum of ${MIN_MEMORY_CAP} and would evict the whole store — ignoring it and using the default.`,
    );
    return undefined;
  }
  return value;
}

/**
 * `DEFAULT_CONFIG` with any valid operator overrides from the `memory` block
 * applied. Never throws: an unreadable or malformed config yields the defaults,
 * because failing to parse config must not stop memories being stored.
 *
 * `readRawConfig()` is mtime-cached, so this is cheap enough to sit on the
 * write path as a default parameter.
 */
export function resolveMemoryConfig(base: MemoryConfig = DEFAULT_CONFIG): MemoryConfig {
  let block: Record<string, unknown>;
  try {
    block = memoryBlock(readRawConfig());
  } catch {
    return base;
  }

  const resolved: MemoryConfig = { ...base };
  for (const key of CAP_KEYS) {
    const override = validateCap(block[key], key);
    if (override !== undefined) resolved[key satisfies CapKey] = override;
  }
  return resolved;
}
