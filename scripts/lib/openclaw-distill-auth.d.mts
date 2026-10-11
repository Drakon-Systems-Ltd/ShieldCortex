import type { DistillProvider } from './capture-distill.mjs';
export function resolveOpenClawDistillProvider(opts?: { env?: NodeJS.ProcessEnv; openclawHome?: string; config?: Record<string, unknown> }): DistillProvider;
export function preferredProviders(oc?: Record<string, unknown>, env?: NodeJS.ProcessEnv): string[];
