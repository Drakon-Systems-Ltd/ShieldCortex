/**
 * Recall Tool
 *
 * Search and retrieve memories using semantic search and filters.
 */

import { z } from 'zod';
import { searchMemories, recallWithEmbeddings, accessMemory, getRecentMemories, getHighPriorityMemories } from '../memory/store.js';
import { formatTimeSinceAccess } from '../memory/decay.js';
import { Memory, SearchResult } from '../memory/types.js';
import { MemoryNotFoundError, formatErrorForMcp } from '../errors.js';
import { resolveProject } from '../context/project-context.js';
import type { DefenceSource } from '../defence/types.js';

const sourceSchema = z.object({
  type: z.enum(['user', 'cli', 'hook', 'email', 'web', 'agent', 'file', 'api', 'tool_response']),
  identifier: z.string(),
}).optional().describe('Caller identity for access control');

// Input schema for the recall tool
export const recallSchema = z.object({
  query: z.string().optional().describe('Search query (semantic search)'),
  category: z.enum([
    'architecture', 'pattern', 'preference', 'error',
    'context', 'learning', 'todo', 'note', 'relationship', 'custom'
  ]).optional().describe('Filter by category'),
  type: z.enum(['short_term', 'long_term', 'episodic']).optional()
    .describe('Filter by memory type'),
  project: z.string().optional().describe('Filter by project'),
  tags: z.array(z.string()).optional().describe('Filter by tags'),
  limit: z.number().min(1).max(50).optional().default(10)
    .describe('Maximum number of results'),
  includeDecayed: z.boolean().optional().default(false)
    .describe('Include memories that have decayed below threshold'),
  includeGlobal: z.boolean().optional().default(true)
    .describe('Include global memories in search results (default: true)'),
  mode: z.enum(['search', 'recent', 'important']).optional().default('search')
    .describe('Recall mode: search (query-based), recent (by time), important (by salience)'),
  source: sourceSchema,
});

export type RecallInput = z.infer<typeof recallSchema>;

/**
 * Execute the recall tool
 */
export async function executeRecall(input: RecallInput): Promise<{
  success: boolean;
  memories?: Memory[];
  contradictions?: Map<number, { memoryId: number; title: string; score: number }[]>;
  count?: number;
  error?: string;
}> {
  try {
    // Resolve project (auto-detect if not provided)
    const resolvedProject = resolveProject(input.project);
    const projectFilter = resolvedProject ?? undefined;

    const source = input.source as DefenceSource | undefined;
    let memories: Memory[] = [];
    let contradictions: Map<number, { memoryId: number; title: string; score: number }[]> | undefined;

    switch (input.mode) {
      case 'recent':
        memories = getRecentMemories(input.limit, projectFilter, source);
        break;

      case 'important':
        memories = getHighPriorityMemories(input.limit, projectFilter, source);
        break;

      case 'search':
      default:
        // Use embedding-enhanced recall: FTS5 first, vector fallback if < 3 results
        const results = await searchMemories({
          query: input.query || '',
          category: input.category,
          type: input.type,
          project: projectFilter,
          tags: input.tags,
          limit: input.limit,
          includeDecayed: input.includeDecayed,
          includeGlobal: input.includeGlobal,
        }, undefined, source);
        memories = results.map(r => r.memory);

        // If FTS5 returned few results, try embedding fallback for additional matches
        if (memories.length < 3 && input.query && input.query.trim()) {
          try {
            const embeddingMemories = await recallWithEmbeddings(input.query, {
              limit: input.limit,
              project: projectFilter,
              threshold: 0.3,
            });
            // Merge: keep FTS results, add new embedding results
            const existingIds = new Set(memories.map(m => m.id));
            for (const em of embeddingMemories) {
              if (!existingIds.has(em.id)) {
                memories.push(em);
                existingIds.add(em.id);
              }
            }
            // Cap at limit
            memories = memories.slice(0, input.limit);
          } catch {
            // Embedding fallback failed silently — FTS results are still valid
          }
        }

        // Extract contradictions from search results
        const contradictionEntries = results
          .filter(r => r.contradictions && r.contradictions.length > 0)
          .map(r => [r.memory.id, r.contradictions!] as const);
        if (contradictionEntries.length > 0) {
          contradictions = new Map(contradictionEntries);
        }
        break;
    }

    // Access each memory to reinforce it
    memories = memories.map(m => accessMemory(m.id, undefined, source) || m);

    return {
      success: true,
      memories,
      contradictions,
      count: memories.length,
    };
  } catch (error) {
    return {
      success: false,
      error: formatErrorForMcp(error),
    };
  }
}

/**
 * Format a single memory for display
 */
export function formatMemory(memory: Memory, verbose: boolean = false): string {
  const lines = [
    `[${memory.id}] **${memory.title}**`,
    verbose
      ? `    ${memory.content}`
      : `    ${memory.content.slice(0, 200)}${memory.content.length > 200 ? '...' : ''}`,
  ];

  if (verbose) {
    lines.push(`    Type: ${memory.type} | Category: ${memory.category}`);
    lines.push(`    Salience: ${(memory.salience * 100).toFixed(0)}% | Accessed: ${memory.accessCount}x`);
    lines.push(`    Last access: ${formatTimeSinceAccess(memory)}`);
    if (memory.tags.length > 0) {
      lines.push(`    Tags: ${memory.tags.join(', ')}`);
    }
    if (memory.project) {
      lines.push(`    Project: ${memory.project}`);
    }
  } else {
    lines.push(`    (${memory.type}, ${memory.category}, ${formatTimeSinceAccess(memory)})`);
  }

  return lines.join('\n');
}

/**
 * Format the recall result for MCP response
 */
export function formatRecallResult(
  result: Awaited<ReturnType<typeof executeRecall>>,
  verbose: boolean = false
): string {
  if (!result.success) {
    return `Failed to recall: ${result.error}`;
  }

  if (!result.memories || result.memories.length === 0) {
    return 'No memories found matching your query.';
  }

  const header = `Found ${result.count} ${result.count === 1 ? 'memory' : 'memories'}:\n`;
  const formattedMemories = result.memories.map(m => {
    let output = formatMemory(m, verbose);
    const contradictions = result.contradictions?.get(m.id);
    if (contradictions && contradictions.length > 0) {
      output += `\n  ⚠️ CONTRADICTS: ${contradictions.map(c => `"${c.title}" (ID ${c.memoryId})`).join(', ')}`;
    }
    return output;
  }).join('\n\n');

  return header + formattedMemories;
}

/**
 * Get a single memory by ID
 */
export const getMemorySchema = z.object({
  id: z.number().describe('Memory ID to retrieve'),
  source: sourceSchema,
});

export function executeGetMemory(input: { id: number; source?: DefenceSource }): {
  success: boolean;
  memory?: Memory;
  error?: string;
} {
  try {
    const memory = accessMemory(input.id, undefined, input.source);
    if (!memory) {
      const error = new MemoryNotFoundError(input.id);
      return {
        success: false,
        error: error.toUserMessage(),
      };
    }
    return { success: true, memory };
  } catch (error) {
    return {
      success: false,
      error: formatErrorForMcp(error),
    };
  }
}
