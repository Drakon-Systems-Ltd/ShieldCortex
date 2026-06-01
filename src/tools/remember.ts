/**
 * Remember Tool
 *
 * Store memories with automatic salience detection and categorization.
 */

import { z } from 'zod';
import { addMemory, searchMemories, detectRelationships, createMemoryLink, getLastTruncationInfo } from '../memory/store.js';
import { calculateSalience, analyzeSalienceFactors, explainSalience } from '../memory/salience.js';
import { MemoryCategory, MemoryType, MemoryPurpose, MemoryScope } from '../memory/types.js';
import { formatErrorForMcp } from '../errors.js';
import { resolveProject } from '../context/project-context.js';
import { shouldFilterMemory } from '../memory/save-filter.js';

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
  scope: z.enum(['project', 'global']).optional()
    .describe('Memory scope: project (default) or global (cross-project)'),
  transferable: z.boolean().optional()
    .describe('Whether this memory can be transferred to other projects'),
  memoryPurpose: z.enum(['user', 'feedback', 'project', 'reference']).optional()
    .describe('Purpose of memory: user (preferences), feedback (corrections/confirmations), project (work context), reference (docs/specs)'),
  memoryScope: z.enum(['private', 'team']).optional()
    .describe('Scope: private (agent-specific) or team (shared across agents)'),
  source: z.object({
    type: z.enum(['user', 'cli', 'hook', 'email', 'web', 'agent', 'file', 'api', 'tool_response']),
    identifier: z.string(),
  }).optional().describe('Source of this memory for trust scoring (agents should pass this)'),
  sourceType: z.enum(['user', 'cli', 'hook', 'email', 'web', 'agent', 'file', 'api', 'tool_response']).optional()
    .describe('Flat source type for integrations that cannot pass nested objects'),
  sourceIdentifier: z.string().optional()
    .describe('Flat source identifier for integrations that cannot pass nested objects'),
  sessionId: z.string().optional().describe('Optional integration session identifier'),
  agentId: z.string().optional().describe('Optional integration agent identifier'),
  workspaceDir: z.string().optional().describe('Optional workspace/source path'),
});

export type RememberInput = z.infer<typeof rememberSchema>;

/**
 * Execute the remember tool
 */
export async function executeRemember(input: RememberInput): Promise<{
  success: boolean;
  memory?: {
    id: number;
    title: string;
    salience: number;
    type: MemoryType;
    category: MemoryCategory;
    reason: string;
    linksCreated?: number;
    truncated?: {
      wasTruncated: boolean;
      originalLength: number;
      truncatedLength: number;
    };
  };
  error?: string;
}> {
  try {
    // Validate non-empty title and content
    const title = input.title?.trim();
    const content = input.content?.trim();

    if (!title || title.length === 0) {
      return {
        success: false,
        error: 'Title cannot be empty. Provide a meaningful short title for the memory.',
      };
    }

    if (!content || content.length === 0) {
      return {
        success: false,
        error: 'Content cannot be empty. Provide detailed content for the memory.',
      };
    }

    // Resolve project (auto-detect if not provided)
    const resolvedProject = resolveProject(input.project);
    const derivedSource = input.source ?? (
      input.sourceType && input.sourceIdentifier
        ? { type: input.sourceType, identifier: input.sourceIdentifier }
        : undefined
    );
    const metadata = {
      ...(input.sessionId ? { sessionId: input.sessionId } : {}),
      ...(input.agentId ? { agentId: input.agentId } : {}),
      ...(input.workspaceDir ? { workspaceDir: input.workspaceDir } : {}),
      ...(derivedSource?.type ? { sourceType: derivedSource.type } : {}),
      ...(derivedSource?.identifier ? { sourceIdentifier: derivedSource.identifier } : {}),
    };

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

    // Check for duplicates (use trimmed title)
    const existing = await searchMemories({
      query: title,
      project: resolvedProject ?? undefined,
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

    // Create the memory (use trimmed title and content)
    // v4.0.0: Save filter — prevent storing derivable info
    const filterResult = shouldFilterMemory(title, content);
    if (!filterResult.allowed) {
      return {
        success: false,
        error: `Memory filtered: ${filterResult.reason}${filterResult.warning ? ' — ' + filterResult.warning : ''}`,
      };
    }

    const memoryInput = {
      title,
      content,
      category: input.category,
      type: input.type,
      project: resolvedProject ?? undefined,
      tags: input.tags,
      salience: salienceOverride,
      scope: input.scope,
      transferable: input.transferable,
      metadata: Object.keys(metadata).length > 0 ? metadata : undefined,
      memoryPurpose: input.memoryPurpose,
      memoryScope: input.memoryScope,
    };

    // Defence-in-depth against the "salience wall": automated/hook callers
    // (e.g. the OpenClaw hook, which shells out `remember` with importance:"high"
    // /"critical" and sourceType:"hook") must not mint 0.8/1.0-salience memories
    // the way a human deliberately saving something can. Cap the FINAL resolved
    // salience — covering BOTH the importance-derived override and the
    // calculateSalience fall-through — at the same 0.6 the dedicated auto-extract
    // writer enforces, so even a stale/un-refactored hook can't exceed it by ANY
    // path. Interactive remembers (no source, or a user/cli/agent source) stay
    // uncapped — deliberate intent is honoured. Resolve salience exactly as
    // addMemory does, from the SAME memoryInput object, so there is no input-shape
    // drift, then clamp and pass it verbatim.
    //
    // Canonical constant: scripts/lib/extract-memorable-segments.mjs:24
    // (AUTO_EXTRACT_SALIENCE_CAP = 0.6). It lives in a build-script .mjs outside
    // the compiled src/ surface, so the value is mirrored here.
    if (derivedSource?.type === 'hook') {
      const AUTO_EXTRACT_SALIENCE_CAP = 0.6;
      const effective = memoryInput.salience ?? calculateSalience(memoryInput);
      memoryInput.salience = Math.min(effective, AUTO_EXTRACT_SALIENCE_CAP);
    }

    const memory = addMemory(memoryInput, undefined, derivedSource ?? { type: 'cli', identifier: 'mcp' });

    // Auto-detect and create relationships with existing memories
    let linksCreated = 0;
    try {
      const potentialLinks = detectRelationships(memory, 3);
      for (const link of potentialLinks) {
        const created = createMemoryLink(memory.id, link.targetId, link.relationship, link.strength);
        if (created) linksCreated++;
      }
    } catch {
      // Silently ignore relationship detection errors
    }

    // Explain why this was remembered (use trimmed values)
    const factors = analyzeSalienceFactors({ title, content });
    const reason = explainSalience(factors);

    // Check if content was truncated
    const truncationInfo = getLastTruncationInfo();

    return {
      success: true,
      memory: {
        id: memory.id,
        title: memory.title,
        salience: memory.salience,
        type: memory.type,
        category: memory.category,
        reason,
        linksCreated,
        truncated: truncationInfo?.wasTruncated ? truncationInfo : undefined,
      },
    };
  } catch (error) {
    return {
      success: false,
      error: formatErrorForMcp(error),
    };
  }
}

/**
 * Format the remember result for MCP response
 */
export function formatRememberResult(result: Awaited<ReturnType<typeof executeRemember>>): string {
  if (!result.success) {
    return `Failed to remember: ${result.error}`;
  }

  const m = result.memory!;
  const lines = [
    `✓ Remembered: "${m.title}"`,
    `  ID: ${m.id}`,
    `  Type: ${m.type}`,
    `  Category: ${m.category}`,
    `  Salience: ${(m.salience * 100).toFixed(0)}%`,
    `  Reason: ${m.reason}`,
  ];
  if (m.linksCreated && m.linksCreated > 0) {
    lines.push(`  Links: ${m.linksCreated} related memories connected`);
  }
  if (m.truncated && m.truncated.wasTruncated) {
    const originalKB = (m.truncated.originalLength / 1024).toFixed(1);
    const truncatedKB = (m.truncated.truncatedLength / 1024).toFixed(1);
    lines.push(`  ⚠️  WARNING: Content truncated from ${originalKB}KB to ${truncatedKB}KB (10KB limit)`);
    lines.push(`  Consider splitting large memories into smaller, focused pieces.`);
  }
  return lines.join('\n');
}
