export type ShellToken =
  | { type: 'word'; value: string; bare: string }
  | { type: 'op'; value: string };
export function shellTokens(text: string): { tokens: ShellToken[]; complete: boolean };
export function shellWords(text: string, depth?: number): string[];
export function lexicalPathNormalise(p: string): string;
