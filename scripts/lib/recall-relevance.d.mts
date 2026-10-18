export interface RecallRelevanceRow { title?: string; content?: string; rank?: number; [key: string]: unknown }
export interface RecallRelevanceOptions { queryTerms?: string[]; relFactor?: number; minTermMatches?: number; maxBm25?: number | null }
export function filterByRelevance<T extends RecallRelevanceRow>(rows: T[], opts?: RecallRelevanceOptions): { kept: T[]; dropped: Array<{ row: T; reason: string }> };
export function extractQueryTerms(query: string): string[];
