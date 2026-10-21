export type ClawhubState = 'synced' | 'pending' | 'submitted' | 'unknown' | 'absent';
export function readLatestVersion(inspectJson: unknown): string;
export function readVersionList(inspectJson: unknown): string[];
export function reportsPendingSubmission(publishOutput: unknown, target: string): boolean;
export function diagnose(input: { latest: string; versions?: string[]; target: string; readFailed?: boolean; submitted?: boolean }): ClawhubState;
export function describeState(input: { state: ClawhubState; latest: string; target: string; waitedMs?: number; submitted?: boolean }): string;
export function exitCodeFor(state: string): number;
