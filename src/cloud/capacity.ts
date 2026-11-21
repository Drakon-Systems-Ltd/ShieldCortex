/**
 * Capacity values for `shieldcortex config --memory-cap` / `--disk-budget`
 * (#1043). Pure parsing and bounds only: no I/O, no config reads.
 *
 * The stored keys are memory.maxLongTermMemories, memory.maxShortTermMemories
 * and storage.diskBudgetBytes. Defaults are unchanged (LTM 1000, STM 100,
 * directory budget 100 MiB): an absent or invalid stored value means the
 * default, never a smaller number.
 */

export const LTM_CAP_MIN = 100;
export const LTM_CAP_MAX = 100_000;
export const STM_CAP_MIN = 10;
export const STM_CAP_MAX = 10_000;

const MiB = 1024 * 1024;
const GiB = 1024 * MiB;
export const DISK_BUDGET_MIN_BYTES = 50 * MiB;
export const DISK_BUDGET_MAX_BYTES = 50 * GiB;

export interface MemoryCapSpec {
  maxLongTermMemories?: number;
  maxShortTermMemories?: number;
}

export type Parsed<T> = { ok: true; value: T } | { ok: false; error: string };

const MEMORY_CAP_USAGE = 'Use ltm=N, stm=N or ltm=N,stm=M '
  + `(LTM ${LTM_CAP_MIN}-${LTM_CAP_MAX}, STM ${STM_CAP_MIN}-${STM_CAP_MAX}, whole numbers).`;

/** `ltm=2000`, `stm=200` or `ltm=2000,stm=200` (either order, each key once). */
export function parseMemoryCapSpec(spec: string): Parsed<MemoryCapSpec> {
  const out: MemoryCapSpec = {};
  const parts = spec.split(',');
  if (parts.length > 2) return { ok: false, error: `Invalid --memory-cap value. ${MEMORY_CAP_USAGE}` };
  for (const part of parts) {
    const m = part.trim().match(/^(ltm|stm)=([0-9]{1,7})$/);
    if (!m) return { ok: false, error: `Invalid --memory-cap value. ${MEMORY_CAP_USAGE}` };
    const [, tier, digits] = m;
    const n = Number(digits);
    if (tier === 'ltm') {
      if (out.maxLongTermMemories !== undefined) return { ok: false, error: `--memory-cap names ltm twice. ${MEMORY_CAP_USAGE}` };
      if (n < LTM_CAP_MIN || n > LTM_CAP_MAX) {
        return { ok: false, error: `--memory-cap ltm must be between ${LTM_CAP_MIN} and ${LTM_CAP_MAX}.` };
      }
      out.maxLongTermMemories = n;
    } else {
      if (out.maxShortTermMemories !== undefined) return { ok: false, error: `--memory-cap names stm twice. ${MEMORY_CAP_USAGE}` };
      if (n < STM_CAP_MIN || n > STM_CAP_MAX) {
        return { ok: false, error: `--memory-cap stm must be between ${STM_CAP_MIN} and ${STM_CAP_MAX}.` };
      }
      out.maxShortTermMemories = n;
    }
  }
  return { ok: true, value: out };
}

const UNIT_BYTES: Record<string, bigint> = {
  '': 1n,
  b: 1n,
  kb: 1000n,
  mb: 1000n ** 2n,
  gb: 1000n ** 3n,
  kib: 1024n,
  mib: 1024n ** 2n,
  gib: 1024n ** 3n,
};

/**
 * A budget for display. Whole MiB/GiB print as such (`100 MB` keeps doctor's
 * long-standing label for the 100 MiB default); anything else prints with two
 * decimals so a decimal budget is never rounded to a wrong whole number.
 */
export function formatBudget(bytes: number): string {
  if (bytes >= GiB && bytes % GiB === 0) return `${bytes / GiB} GB`;
  if (bytes % MiB === 0) return `${bytes / MiB} MB`;
  if (bytes >= GiB) return `${(bytes / GiB).toFixed(2)} GB`;
  return `${(bytes / MiB).toFixed(2)} MB`;
}

const DISK_BUDGET_USAGE = 'Use a whole number with an optional unit, e.g. 250MB, 1GB, 500MiB or a byte count '
  + `(${formatBudget(DISK_BUDGET_MIN_BYTES)} to ${formatBudget(DISK_BUDGET_MAX_BYTES)}).`;

/**
 * `250MB`, `1GB`, `500MiB`, `1gib` or a bare byte count. KB/MB/GB are decimal,
 * KiB/MiB/GiB binary. No signs, fractions, exponents or spaces. The product is
 * computed exactly (BigInt) before the bounds check.
 */
export function parseDiskBudget(input: string): Parsed<number> {
  const m = input.trim().match(/^([0-9]{1,15})(b|kb|mb|gb|kib|mib|gib)?$/i);
  if (!m) return { ok: false, error: `Invalid --disk-budget value. ${DISK_BUDGET_USAGE}` };
  const bytes = BigInt(m[1]) * UNIT_BYTES[(m[2] ?? '').toLowerCase()];
  if (bytes < BigInt(DISK_BUDGET_MIN_BYTES) || bytes > BigInt(DISK_BUDGET_MAX_BYTES)) {
    return { ok: false, error: `--disk-budget is out of range. ${DISK_BUDGET_USAGE}` };
  }
  return { ok: true, value: Number(bytes) };
}

/** A stored storage.diskBudgetBytes the loader may honour. */
export function isValidDiskBudgetBytes(value: unknown): value is number {
  return typeof value === 'number'
    && Number.isSafeInteger(value)
    && value >= DISK_BUDGET_MIN_BYTES
    && value <= DISK_BUDGET_MAX_BYTES;
}
