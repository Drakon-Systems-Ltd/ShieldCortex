/**
 * Context Tool
 *
 * Manages context injection and session handling.
 * This is the key tool for solving the compaction problem.
 */

import { z } from 'zod';
import { strictObject } from '../lib/zod-strict.js';
import {
  generateContextSummary,
  formatContextSummary,
  startSession,
  endSession,
  getSuggestedContext,
  consolidate,
  previewConsolidation,
  exportMemories,
  importMemories,
} from '../memory/consolidate.js';
import { getMemoryStats, getProjectMemories, logAllowedRead } from '../memory/store.js';
import { getSalienceDistribution, type SalienceDistribution } from '../memory/metrics.js';
import { getDatabase } from '../database/init.js';
import { Memory, ContextSummary, ConsolidationResult } from '../memory/types.js';
import { resolveProject } from '../context/project-context.js';
import { guardReadBySensitivity, guardContextSummary } from '../defence/trust/read-guard.js';
import type { DefenceSource } from '../defence/types.js';

// Input schema for getting context
export const getContextSchema = strictObject({
  project: z.string().optional().describe('Project to get context for'),
  query: z.string().optional().describe('Current query/task to find relevant context for'),
  format: z.enum(['summary', 'detailed', 'raw']).optional().default('summary')
    .describe('Output format'),
  source: strictObject({
    type: z.enum(['user', 'cli', 'hook', 'email', 'web', 'agent', 'file', 'api', 'tool_response']),
    identifier: z.string(),
  }).optional().describe('Caller identity for access control'),
});

export type GetContextInput = z.infer<typeof getContextSchema>;

/**
 * Execute the get_context tool
 */
export async function executeGetContext(input: GetContextInput & { sourceAttested?: boolean }): Promise<{
  success: boolean;
  context?: string;
  summary?: ContextSummary;
  relevantMemories?: Memory[];
  error?: string;
}> {
  try {
    // Resolve project (auto-detect if not provided)
    const resolvedProject = resolveProject(input.project);
    const projectFilter = resolvedProject ?? undefined;

    // Read guard: get_context is a SHARED-CONTEXT bootstrap surface that feeds
    // the prompt, so strip RESTRICTED + quarantined for everyone (matching the
    // .mjs prompt hooks) but keep INTERNAL project context available — a
    // sensitivity guard, not the per-caller own-only ACL, so a low-trust
    // subagent isn't blacked out from the context it needs. Owner-specific
    // RESTRICTED retrieval is the explicit get_memory tool's job.

    // Generate context summary
    const summary = guardContextSummary(await generateContextSummary(projectFilter));

    // If there's a query, also get specifically relevant memories
    let relevantMemories: Memory[] = [];
    if (input.query) {
      relevantMemories = guardReadBySensitivity(await getSuggestedContext(input.query, projectFilter, 5));
    }

    // Format based on requested format
    let context: string;
    switch (input.format) {
      case 'raw':
        context = JSON.stringify({ summary, relevantMemories }, null, 2);
        break;
      case 'detailed':
        context = formatDetailedContext(summary, relevantMemories);
        break;
      case 'summary':
      default:
        context = formatContextSummary(summary);
        if (relevantMemories.length > 0) {
          context += '\n\n### Relevant to Current Query\n';
          context += relevantMemories.map(m =>
            `- **${m.title}**: ${m.content.slice(0, 100)}...`
          ).join('\n');
        }
        break;
    }

    // Provenance ledger: one allowed-read row per get_context call, covering
    // every memory surfaced into the context.
    const source = input.source as DefenceSource | undefined;
    if (source) {
      const surfacedIds = [
        ...summary.recentMemories, ...summary.keyDecisions,
        ...summary.activePatterns, ...summary.pendingItems, ...relevantMemories,
      ].map(m => m.id);
      logAllowedRead(source, 'get_context', [...new Set(surfacedIds)], projectFilter, input.sourceAttested);
    }

    return {
      success: true,
      context,
      summary,
      relevantMemories,
    };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}

/**
 * Format detailed context output
 */
function formatDetailedContext(summary: ContextSummary, relevant: Memory[]): string {
  const lines: string[] = [];

  if (summary.project) {
    lines.push(`# Project Context: ${summary.project}\n`);
  } else {
    lines.push('# Memory Context\n');
  }

  // Key decisions
  if (summary.keyDecisions.length > 0) {
    lines.push('## Architecture & Decisions\n');
    for (const m of summary.keyDecisions) {
      lines.push(`### ${m.title}`);
      lines.push(m.content);
      lines.push(`*Salience: ${(m.salience * 100).toFixed(0)}% | Category: ${m.category}*\n`);
    }
  }

  // Patterns
  if (summary.activePatterns.length > 0) {
    lines.push('## Active Patterns\n');
    for (const m of summary.activePatterns) {
      lines.push(`### ${m.title}`);
      lines.push(m.content);
      lines.push('');
    }
  }

  // Pending
  if (summary.pendingItems.length > 0) {
    lines.push('## Pending Items\n');
    for (const m of summary.pendingItems) {
      lines.push(`- [ ] **${m.title}**: ${m.content.slice(0, 100)}`);
    }
    lines.push('');
  }

  // Relevant to query
  if (relevant.length > 0) {
    lines.push('## Relevant to Current Context\n');
    for (const m of relevant) {
      lines.push(`### ${m.title}`);
      lines.push(m.content);
      lines.push(`*Type: ${m.type} | Tags: ${m.tags.join(', ') || 'none'}*\n`);
    }
  }

  // Recent activity
  if (summary.recentMemories.length > 0) {
    lines.push('## Recent Activity\n');
    for (const m of summary.recentMemories.slice(0, 5)) {
      lines.push(`- **${m.title}** (${m.category})`);
    }
  }

  return lines.join('\n');
}

// Session management
export const startSessionSchema = strictObject({
  project: z.string().optional().describe('Project for this session'),
});

export async function executeStartSession(input: { project?: string }): Promise<{
  success: boolean;
  sessionId?: number;
  context?: string;
  error?: string;
}> {
  try {
    // Resolve project (auto-detect if not provided)
    const resolvedProject = resolveProject(input.project);
    const projectFilter = resolvedProject ?? undefined;

    const { sessionId, context } = await startSession(projectFilter);
    // Read guard: start_session is a shared-context bootstrap surface (sibling of
    // get_context) — strip RESTRICTED + quarantined before formatting so the
    // session preamble never leaks credential-class memories.
    const formattedContext = formatContextSummary(guardContextSummary(context));

    return {
      success: true,
      sessionId,
      context: formattedContext,
    };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}

export const endSessionSchema = strictObject({
  sessionId: z.number().describe('Session ID to end'),
  summary: z.string().optional().describe('Summary of what was accomplished'),
});

export function executeEndSession(input: { sessionId: number; summary?: string }): {
  success: boolean;
  consolidationResult?: ConsolidationResult;
  error?: string;
} {
  try {
    endSession(input.sessionId, input.summary);

    // Run consolidation
    const consolidationResult = consolidate();

    return {
      success: true,
      consolidationResult,
    };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}

// Consolidation
export const consolidateSchema = strictObject({
  force: z.boolean().optional().default(false)
    .describe('Force consolidation even if not due'),
  dryRun: z.boolean().optional().default(false)
    .describe('Preview what would happen without actually doing it'),
});

export function executeConsolidate(input: { force?: boolean; dryRun?: boolean }): {
  success: boolean;
  result?: ConsolidationResult;
  preview?: {
    toPromote: number;
    toDelete: number;
    promoteList: string[];
    deleteList: string[];
  };
  error?: string;
} {
  try {
    if (input.dryRun) {
      // Preview mode - don't actually do anything
      const preview = previewConsolidation();
      return {
        success: true,
        preview: {
          toPromote: preview.toPromote.length,
          toDelete: preview.toDelete.length,
          promoteList: preview.toPromote.slice(0, 10).map(m => m.title),
          deleteList: preview.toDelete.slice(0, 10).map(m => `${m.title} (${m.category})`),
        },
      };
    }

    const result = consolidate();
    return { success: true, result };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}

// Stats
export const statsSchema = strictObject({
  project: z.string().optional().describe('Get stats for specific project'),
});

export function executeStats(input: { project?: string }): {
  success: boolean;
  stats?: ReturnType<typeof getMemoryStats>;
  salience?: SalienceDistribution;
  error?: string;
} {
  try {
    // Resolve project (auto-detect if not provided)
    const resolvedProject = resolveProject(input.project);
    const projectFilter = resolvedProject ?? undefined;

    const stats = getMemoryStats(projectFilter);
    // Phase 0: include the salience-wall instrument so memory_stats surfaces it.
    const salience = getSalienceDistribution(getDatabase(), projectFilter);
    return { success: true, stats, salience };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}

export function formatStats(stats: ReturnType<typeof getMemoryStats>, salience?: SalienceDistribution): string {
  const lines = [
    '## Memory Statistics',
    '',
    `Total memories: ${stats.total}`,
    `  - Short-term: ${stats.shortTerm}`,
    `  - Long-term: ${stats.longTerm}`,
    `  - Episodic: ${stats.episodic}`,
    '',
    `Average salience: ${(stats.averageSalience * 100).toFixed(1)}%`,
    '',
    '### By Category',
  ];

  for (const [category, count] of Object.entries(stats.byCategory)) {
    lines.push(`  - ${category}: ${count}`);
  }

  // Phase 0: the salience-wall instrument. Raw salience saturates for surviving
  // memories, so a high wall % means the score has stopped discriminating.
  if (salience) {
    lines.push(
      '',
      '### Memory Quality',
      `  - At salience wall (≥0.95): ${salience.wall.ltmAtOrAbove095}/${salience.wall.ltmTotal} long-term (${salience.wall.ltmPct}%)`,
      `  - Fragments in wall: ${salience.fragments.atOrAbove095} (${salience.fragments.pctOfWall}%)`,
    );
    for (const w of salience.warnings) lines.push(`  ⚠ ${w}`);
  }

  return lines.join('\n');
}

// Export/Import
export const exportSchema = strictObject({
  project: z.string().optional().describe('Export only memories for this project'),
});

export function executeExport(input: { project?: string; source?: DefenceSource; sourceAttested?: boolean }): {
  success: boolean;
  data?: string;
  count?: number;
  error?: string;
} {
  try {
    // Memory export is free — audit_export will gate the audit trail
    // export when that feature is built (defence/audit/export.ts)

    // Resolve project (auto-detect if not provided)
    const resolvedProject = resolveProject(input.project);
    const projectFilter = resolvedProject ?? undefined;

    // Read ACL: filter the bulk dump to rows this caller may read.
    const data = exportMemories(projectFilter, input.source);
    const memories = JSON.parse(data) as Array<{ id: number }>;
    // Provenance ledger: a bulk export is the highest-value read to audit.
    if (input.source) {
      logAllowedRead(input.source, 'export_memories', memories.map(m => m.id), projectFilter, input.sourceAttested);
    }
    return {
      success: true,
      data,
      count: memories.length,
    };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}

export const importSchema = strictObject({
  data: z.string().describe('JSON data to import'),
});

export function executeImport(input: { data: string }): {
  success: boolean;
  imported?: number;
  error?: string;
} {
  try {
    const imported = importMemories(input.data);
    return { success: true, imported };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}
