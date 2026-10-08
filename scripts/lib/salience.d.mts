export interface SalienceMemory {
  salience?: number;
  content?: string;
  last_accessed?: string | null;
  access_count?: number | null;
  pinned?: number | boolean | null;
  downvote_count?: number | null;
}
export interface SalienceOptions {
  halfLifeDays?: number;
  accessNorm?: number;
  accessFloor?: number;
  pinBoost?: number;
  downvoteDecay?: number;
  fragmentFactor?: number;
  classBoost?: number;
  classPenalty?: number;
  now?: number;
}
export function computeEffectiveSalience(memory: SalienceMemory, opts?: SalienceOptions): number;
