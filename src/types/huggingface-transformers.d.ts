/**
 * Ambient module for the optional @huggingface/transformers dependency.
 *
 * The package is intentionally optional (scan-only / edge installs must not
 * require the ~349MB ML stack). TypeScript still typechecks dynamic imports
 * of it in worker entrypoints, so CI `npm ci` environments that skip or fail
 * the optional install must not fail `tsc` with TS2307.
 *
 * Runtime behaviour is unchanged: missing package still throws at import time
 * and is handled by the workers' existing load-error paths.
 */
declare module '@huggingface/transformers' {
  // Minimal surface used by ShieldCortex workers. Keep this loose on purpose —
  // we do not vendor the full upstream type graph.
  export const env: {
    allowRemoteModels: boolean;
    allowLocalModels: boolean;
    cacheDir: string;
    [key: string]: unknown;
  };

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  export function pipeline(...args: any[]): Promise<any>;

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const transformers: any;
  export default transformers;
}
