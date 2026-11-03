export type ConfigSignatureVerdict = 'valid' | 'self-heal' | 'tampered' | 'unsigned';

export function configSignatureVerdict(input: {
  parsed: Record<string, unknown>;
  raw: string;
  key: string | null;
  legacySig: string | null | undefined;
}): ConfigSignatureVerdict;

export function verdictAuthenticates(verdict: ConfigSignatureVerdict): boolean;

export function configSignatureVerdictAt(
  configPath: string,
  parsed: Record<string, unknown>,
  raw: string,
): ConfigSignatureVerdict;

export function configIsLinkedUnauthenticated(configPath: string, parsed: unknown, raw: string): boolean;
