import type Database from 'better-sqlite3';
export interface AutoMemoryCandidate {
  title: string; content: string; category: string; salience: number;
  tags: string[]; memoryPurpose?: string;
}
export function saveAutoExtractedMemory(db: Database.Database, memory: AutoMemoryCandidate, project?: string | null, opts?: { source?: string }): Promise<void>;
export interface AutoCaptureScreenDefence {
  detectNonAuthoritativeInstruction?: ((content: string, sourceType: string) => { detected: boolean; patterns: string[] }) | null;
  detectMemoryDirective?: ((text: string) => { detected: boolean; patterns: string[] }) | null;
}
export function screenAutoCaptureCandidate(
  defence: AutoCaptureScreenDefence,
  content: unknown,
  title?: unknown,
): { indicator: 'memory_directive' | 'non_authoritative_instruction'; patterns: string[] } | null;
