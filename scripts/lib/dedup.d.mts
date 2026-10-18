export function tokenize(text: string): Set<string>;
export function jaccardSimilarity(textA: string, textB: string): number;
export function isNearDuplicate(candidate: { title: string; content: string }, existing: { title: string; content: string }, thresholds: { titleJaccard: number; combinedThreshold: number }): { duplicate: boolean; combined: number; titleSim: number };
