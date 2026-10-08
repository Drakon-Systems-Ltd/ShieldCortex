export type ContentClass = 'transactional' | 'consequence' | 'neutral';
export function classifyContentClass(text: unknown): ContentClass;
export function contentClassFactor(text: unknown, opts?: { boost?: number; penalty?: number }): number;
