import type { SalienceMemory } from './salience.mjs';
export function compareRecallResults(a: SalienceMemory & { rank?: number }, b: SalienceMemory & { rank?: number }): number;
