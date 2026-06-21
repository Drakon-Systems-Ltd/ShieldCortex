/**
 * Forget Tool
 *
 * Delete memories - either individually or in bulk.
 */

import { z } from 'zod';
import { deleteMemory, searchMemories, getMemoryById } from '../memory/store.js';
import { getDatabase, withTransaction } from '../database/init.js';
import {
  MemoryNotFoundError,
  BulkDeleteSafetyError,
  formatErrorForMcp,
} from '../errors.js';
import { resolveProject } from '../context/project-context.js';
import { isRevokeBySourceEnabled } from '../cloud/config.js';
import type { DefenceSource } from '../defence/types.js';

/**
 * Upper bound on rows a single revoke-by-source call may delete. Caps the blast
 * radius of the mass-delete primitive — a larger match must be narrowed (by
 * project/category/etc.) or paged.
 */
const MAX_REVOKE_ROWS = 500;

// Input schema for the forget tool
export const forgetSchema = z.object({
  id: z.number().optional().describe('Specific memory ID to delete'),
  query: z.string().optional().describe('Delete memories matching this query'),
  category: z.enum([
    'architecture', 'pattern', 'preference', 'error',
    'context', 'learning', 'todo', 'note', 'relationship', 'custom'
  ]).optional().describe('Delete all memories in this category'),
  project: z.string().optional().describe('Delete all memories for this project'),
  olderThan: z.number().optional().describe('Delete memories older than N days'),
  belowSalience: z.number().min(0).max(1).optional()
    .describe('Delete memories with salience below this threshold'),
  dryRun: z.boolean().optional().default(false)
    .describe('Preview what would be deleted without actually deleting'),
  confirm: z.boolean().optional().default(false)
    .describe('Confirm bulk deletion (required for operations affecting multiple memories)'),
  source: z.object({
    type: z.enum(['user', 'cli', 'hook', 'email', 'web', 'agent', 'file', 'api', 'tool_response']),
    identifier: z.string(),
  }).optional().describe('Caller identity for access control'),
  fromSource: z.string().optional()
    .describe('Revoke-by-source: delete all memories written by this source. Exact "type:identifier", or a "type:*" / "type:" prefix to revoke a whole source type. Authorised by the trust-hierarchy revoke ACL (you must own the source or outrank it). Distinct from `source` (the caller).'),
});

export type ForgetInput = z.infer<typeof forgetSchema>;

/**
 * Execute the forget tool
 */
export async function executeForget(input: ForgetInput): Promise<{
  success: boolean;
  deleted?: number;
  denied?: number;
  wouldDelete?: number;
  memories?: { id: number; title: string }[];
  error?: string;
}> {
  try {
    const db = getDatabase();

    // Revoke-by-source gate: a destructive mass-delete primitive that a hijacked
    // agent must not be able to invoke. OFF by default; only an out-of-band human
    // action (`shieldcortex config --allow-revoke-by-source`) enables it.
    if (input.fromSource !== undefined && !isRevokeBySourceEnabled()) {
      return {
        success: false,
        error: 'revoke-by-source is disabled. Enable it deliberately with `shieldcortex config --allow-revoke-by-source` (an out-of-band action), then re-run.',
      };
    }

    // Resolve project (auto-detect if not provided)
    const resolvedProject = resolveProject(input.project);

    const source = input.source as DefenceSource | undefined;

    // Single ID deletion
    if (input.id !== undefined) {
      const memory = getMemoryById(input.id);
      if (!memory) {
        const error = new MemoryNotFoundError(input.id);
        return {
          success: false,
          error: error.toUserMessage(),
        };
      }

      if (input.dryRun) {
        return {
          success: true,
          wouldDelete: 1,
          memories: [{ id: memory.id, title: memory.title }],
        };
      }

      const deleted = deleteMemory(input.id, source);
      if (!deleted && source) {
        return {
          success: false,
          error: `Access denied: insufficient permissions to delete memory ${input.id}`,
        };
      }
      return {
        success: true,
        deleted: 1,
        memories: [{ id: memory.id, title: memory.title }],
      };
    }

    // Build bulk delete query
    const conditions: string[] = [];
    const params: unknown[] = [];

    if (input.query) {
      // Get IDs from FTS search
      const results = await searchMemories({
        query: input.query,
        limit: 100,
        includeDecayed: true,
      });
      if (results.length === 0) {
        return { success: true, deleted: 0, memories: [] };
      }
      const ids = results.map(r => r.memory.id);
      conditions.push(`id IN (${ids.map(() => '?').join(',')})`);
      params.push(...ids);
    }

    if (input.category) {
      conditions.push('category = ?');
      params.push(input.category);
    }

    if (resolvedProject) {
      conditions.push('project = ?');
      params.push(resolvedProject);
    }

    if (input.olderThan !== undefined) {
      conditions.push("created_at < datetime('now', ? || ' days')");
      params.push(-input.olderThan);
    }

    if (input.belowSalience !== undefined) {
      conditions.push('salience < ?');
      params.push(input.belowSalience);
    }

    // Revoke-by-source: target every memory written by a given source. Exact
    // "type:identifier", or a "type:*" / "type:" prefix for a whole source type.
    // Per-row authorisation is the trust-hierarchy revoke ACL (in deleteMemory
    // via mode:'revoke') — this clause only SELECTS the candidates. Project scope
    // still applies; pass project:"*" to revoke a source across all projects.
    if (input.fromSource !== undefined) {
      const fs = input.fromSource.trim();
      if (!fs || fs === '*' || fs === ':' || fs === ':*') {
        return {
          success: false,
          error: 'fromSource must name a source (e.g. "agent:agent-spawned" or "agent:*"), not a blanket wildcard.',
        };
      }
      if (fs.endsWith(':*') || fs.endsWith(':')) {
        conditions.push('source LIKE ?');
        params.push(`${fs.replace(/:\*?$/, '')}:%`);
      } else {
        conditions.push('source = ?');
        params.push(fs);
      }
    }

    if (conditions.length === 0) {
      return {
        success: false,
        error: 'No deletion criteria specified. Provide id, query, category, project, olderThan, or belowSalience.',
      };
    }

    const whereClause = conditions.join(' AND ');

    // Get affected memories
    const affected = db.prepare(
      `SELECT id, title FROM memories WHERE ${whereClause}`
    ).all(...params) as { id: number; title: string }[];

    if (affected.length === 0) {
      return { success: true, deleted: 0, memories: [] };
    }

    // Blast-radius cap on revoke-by-source: refuse a single call that would
    // delete more than MAX_REVOKE_ROWS — narrow it (by project/category/etc.).
    if (input.fromSource !== undefined && affected.length > MAX_REVOKE_ROWS) {
      return {
        success: false,
        wouldDelete: affected.length,
        error: `revoke-by-source matched ${affected.length} memories (cap ${MAX_REVOKE_ROWS}). Narrow the scope (project/category/query) and re-run.`,
      };
    }

    // Dry run - just show what would be deleted
    if (input.dryRun) {
      return {
        success: true,
        wouldDelete: affected.length,
        memories: affected.slice(0, 20), // Limit preview
      };
    }

    // Require confirmation for bulk deletes
    if (affected.length > 1 && !input.confirm) {
      const error = new BulkDeleteSafetyError(affected.length);
      return {
        success: false,
        wouldDelete: affected.length,
        memories: affected.slice(0, 10),
        error: error.toUserMessage(),
      };
    }

    // Execute deletion within a transaction for atomicity. Route every
    // affected id through deleteMemory(id, source) — NOT a raw bulk DELETE —
    // so each row gets the same enforcement as the single-ID path: delete-ACL
    // check (+ access-denial audit on refusal), graph cleanup, cloud-sync
    // delete, and the dashboard `memory_deleted` event. A low-trust / non-owner
    // caller therefore can't mass-delete protected memories. better-sqlite3 is
    // synchronous, so the per-row loop stays inside one transaction atomically.
    // revoke-by-source uses the trust-hierarchy revoke ACL (own OR outrank);
    // every other bulk forget stays own-only.
    const deleteMode = input.fromSource !== undefined ? 'revoke' : 'delete';
    const deletedMemories: { id: number; title: string }[] = [];
    withTransaction(() => {
      for (const memory of affected) {
        if (deleteMemory(memory.id, source, { mode: deleteMode })) {
          deletedMemories.push(memory);
        }
      }
    });

    const denied = affected.length - deletedMemories.length;

    return {
      success: true,
      deleted: deletedMemories.length,
      ...(denied > 0 ? { denied } : {}),
      memories: deletedMemories,
    };
  } catch (error) {
    return {
      success: false,
      error: formatErrorForMcp(error),
    };
  }
}

/**
 * Format the forget result for MCP response
 */
export function formatForgetResult(result: Awaited<ReturnType<typeof executeForget>>): string {
  if (!result.success) {
    if (result.wouldDelete !== undefined) {
      const preview = result.memories?.map(m => `  - [${m.id}] ${m.title}`).join('\n') || '';
      return [
        `⚠️  ${result.error}`,
        '',
        'Preview of memories to delete:',
        preview,
        result.memories && result.memories.length < (result.wouldDelete || 0)
          ? `  ... and ${(result.wouldDelete || 0) - result.memories.length} more`
          : '',
      ].join('\n');
    }
    return `Failed to forget: ${result.error}`;
  }

  if (result.wouldDelete !== undefined) {
    // Dry run result
    const preview = result.memories?.map(m => `  - [${m.id}] ${m.title}`).join('\n') || '';
    return [
      `🔍 Dry run: Would delete ${result.wouldDelete} ${result.wouldDelete === 1 ? 'memory' : 'memories'}:`,
      preview,
      result.memories && result.memories.length < result.wouldDelete
        ? `  ... and ${result.wouldDelete - result.memories.length} more`
        : '',
    ].join('\n');
  }

  if (result.deleted === 0) {
    return 'No memories matched the deletion criteria.';
  }

  const deleted = result.memories?.map(m => `  - [${m.id}] ${m.title}`).join('\n') || '';
  return [
    `✓ Deleted ${result.deleted} ${result.deleted === 1 ? 'memory' : 'memories'}:`,
    deleted,
  ].join('\n');
}
