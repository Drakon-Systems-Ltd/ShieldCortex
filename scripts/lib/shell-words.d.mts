export type ShellToken =
  | { type: 'word'; value: string; bare: string }
  | { type: 'op'; value: string };
export function shellTokens(text: string): { tokens: ShellToken[]; complete: boolean };
export function shellWords(text: string, depth?: number): string[];
export function lexicalPathNormalise(p: string): string;
export const EXPANSION_MARK: string;
export function expansionWords(text: string, depth?: number): Array<{ value: string; expands: boolean }>;
export function claudeWordExpands(text: string): boolean;
export const CLAUDE_TRANSCRIPT_NAMED_RE: RegExp;
export function claudeJoinedWordMayBeTranscript(text: string): boolean;
