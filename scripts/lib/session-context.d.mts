import type { SalienceMemory, SalienceOptions } from './salience.mjs';
export function orderByEffectiveSalience<T extends SalienceMemory>(memories: T[], opts?: SalienceOptions): T[];
