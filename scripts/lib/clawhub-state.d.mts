export function readLatestVersion(inspectJson: unknown): string;
export function readVersionList(inspectJson: unknown): string[];
export function diagnose(input: { latest: string; versions?: string[]; target: string }): 'synced' | 'pending' | 'absent';
export function describeState(input: { state: 'synced' | 'pending' | 'absent'; latest: string; target: string; waitedMs?: number }): string;
export function exitCodeFor(state: string): number;
