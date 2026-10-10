export const SELF_HEAL_SKIP_ENV: 'SHIELDCORTEX_SKIP_SELF_HEAL';
export function isSelfHealEnabled(config: { selfHeal?: boolean } | null | undefined, env?: NodeJS.ProcessEnv): boolean;
export function createOpenClawRuntime(opts?: { logPrefix?: string; configPath?: string }): {
  callCortex: (tool: string, args?: Record<string, unknown>, options?: { retries?: number; timeout?: number }) => Promise<string | null>;
  isOpenClawAutoMemoryEnabled: (config: { openclawAutoMemory?: boolean } | null | undefined) => boolean;
  isSelfHealEnabled: typeof isSelfHealEnabled;
  loadShieldConfig: () => Promise<Record<string, unknown>>;
  resolveServerCmd: () => Promise<string>;
  resolvePackageRoot: () => Promise<string | null>;
  loadOpenClawExtract: () => Promise<{
    extractSessionMemories: typeof import('../../../scripts/lib/openclaw-extract.mjs').extractSessionMemories;
    extractKeywordMemory: typeof import('../../../scripts/lib/openclaw-extract.mjs').extractKeywordMemory;
    extractSessionMemoriesWithDistill: typeof import('../../../scripts/lib/openclaw-extract.mjs').extractSessionMemoriesWithDistill | null;
    loadMemoryCandidateScreen: typeof import('../../../scripts/lib/openclaw-extract.mjs').loadMemoryCandidateScreen | null;
  } | null>;
};
