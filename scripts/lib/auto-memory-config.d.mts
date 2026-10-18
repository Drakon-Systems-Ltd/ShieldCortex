export interface AutoMemoryConfig {
  maxTranscriptBytes: number; maxTranscriptLines: number; keepSlashCommandProse: boolean;
  stopHookSamplingTurns: number; stopHookSalienceBypass: boolean; stopHookWindowBytes: number;
  enableSessionEnd: boolean; enableStop: boolean; captureMode: string | undefined;
  rawConfig: Record<string, unknown>;
}
export function getAutoMemoryConfig(): AutoMemoryConfig;
