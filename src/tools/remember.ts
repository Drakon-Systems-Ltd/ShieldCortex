/**
 * Remember Tool
 *
 * Store memories with automatic salience detection and categorization.
 */

import { z } from 'zod';
import { addMemory, searchMemories } from '../memory/store.js';
import { calculateSalience, analyzeSalienceFactors, explainSalience } from '../memory/salience.js';
import { MemoryCategory, MemoryType } from '../memory/types.js';

// Input schema for the remember tool
export const rememberSchema = z.object({
  title: z.string().describe('Short title for the memory (what to remember)'),
  content: z.string().describe('Detailed content of the memory'),
  category: z.enum([
    'architecture', 'pattern', 'preference', 'error',
    'context', 'learning', 'todo', 'note', 'relationship', 'custom'
  ]).optional().describe('Category of memory (auto-detected if not provided)'),
  type: z.enum(['short_term', 'long_term', 'episodic']).optional()
    .describe('Memory type (auto-determined based on salience if not provided)'),
  project: z.string().optional().describe('Project this memory belongs to'),
  tags: z.array(z.string()).optional().describe('Tags for categorization'),
  importance: z.enum(['low', 'normal', 'high', 'critical']).optional()
    .describe('Override automatic salience detection'),
});

export type RememberInput = z.infer<typeof rememberSchema>;

/**
 * Execute the remember tool
 */
export function executeRemember(input: RememberInput): {
  success: boolean;
  memory?: {
    id: number;
    title: string;
    salience: number;
    type: MemoryType;
    category: MemoryCategory;
    reason: string;
  };
  error?: string;
} {
  try {
    // Map importance to salience override
    let salienceOverride: number | undefined;
    if (input.importance) {
      const importanceMap: Record<string, number> = {
        low: 0.3,
        normal: 0.5,
        high: 0.8,
        critical: 1.0,
      };
      salienceOverride = importanceMap[input.importance];
    }

    // Check for duplicates
    const existing = searchMemories({
      query: input.title,
      project: input.project,
      limit: 3,
    });

    // If very similar memory exists, update instead
    if (existing.length > 0 && existing[0].relevanceScore > 0.9) {
      const existingMemory = existing[0].memory;
      return {
        success: true,
        memory: {
          id: existingMemory.id,
          title: existingMemory.title,
          salience: existingMemory.salience,
          type: existingMemory.type,
          category: existingMemory.category,
          reason: 'Updated existing similar memory',
        },
      };
    }

    // Create the memory
    const memory = addMemory({
      title: input.title,
      content: input.content,
      category: input.category,
      type: input.type,
      project: input.project,
      tags: input.tags,
      salience: salienceOverride,
    });

    // Explain why this was remembered
    const factors = analyzeSalienceFactors({ title: input.title, content: input.content });
    const reason = explainSalience(factors);

    return {
      success: true,
      memory: {
        id: memory.id,
        title: memory.title,
        salience: memory.salience,
        type: memory.type,
        category: memory.category,
        reason,
      },
    };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}

/**
 * Format the remember result for MCP response
 */
export function formatRememberResult(result: ReturnType<typeof executeRemember>): string {
  if (!result.success) {
    return `Failed to remember: ${result.error}`;
  }

  const m = result.memory!;
  return [
    `✓ Remembered: "${m.title}"`,
    `  ID: ${m.id}`,
    `  Type: ${m.type}`,
    `  Category: ${m.category}`,
    `  Salience: ${(m.salience * 100).toFixed(0)}%`,
    `  Reason: ${m.reason}`,
  ].join('\n');
}
