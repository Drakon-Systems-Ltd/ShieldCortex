/**
 * ShieldCortex MCP Server
 *
 * Brain-like memory system for Claude Code.
 * Solves context compaction and memory persistence issues.
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { initDatabase } from './database/init.js';
import { resolveMemoryConfig } from './memory/config.js';
import { getCurrentVersion } from './api/version.js';
import {
  initProjectContext,
  getActiveProject,
  setActiveProject,
  getProjectContextInfo,
  GLOBAL_PROJECT_SENTINEL,
} from './context/project-context.js';

// Import tools
import { rememberSchema, executeRemember, formatRememberResult } from './tools/remember.js';
import { recallSchema, executeRecall, formatRecallResult, getMemorySchema, executeGetMemory, executeGetRelated, formatMemory } from './tools/recall.js';
import { forgetSchema, executeForget, formatForgetResult } from './tools/forget.js';
import {
  getContextSchema, executeGetContext,
  startSessionSchema, executeStartSession,
  endSessionSchema, executeEndSession,
  consolidateSchema, executeConsolidate,
  statsSchema, executeStats, formatStats,
  exportSchema, executeExport,
  importSchema, executeImport,
} from './tools/context.js';
import { generateContextSummary, formatContextSummary, consolidate, fullCleanup } from './memory/consolidate.js';
import { getHighPriorityMemories, getRecentMemories, getRelatedMemories, createMemoryLink, RelationshipType, enrichMemory } from './memory/store.js';
import { detectContradictions, getContradictionsFor } from './memory/contradiction.js';
import { handleGraphQuery, handleGraphEntities, handleGraphExplain } from './tools/graph.js';
import { handleThreatGraphQuery } from './tools/threat-graph.js';
import { checkDatabaseSize } from './database/init.js';
import { queryAuditLogs, getAuditStats, getLifetimeStats } from './defence/audit/index.js';
import { scanExistingMemories } from './defence/scanner/index.js';
import type { FirewallResult as FwResult, DefenceSource } from './defence/types.js';
import { resolveToolSource as resolveToolSourceImpl } from './defence/trust/resolve-tool-source.js';
import { inferSourceFromEnvironment } from './defence/trust/env-detector.js';
import { scanToolResponse, shouldScanToolResponse } from './defence/tool-response-scanner.js';
import { UNTRUSTED_TOOL_TAG } from './defence/tool-response-enforce.js';
import { guardReadBySensitivity, guardContextSummary } from './defence/trust/read-guard.js';
import { getToolResponseScanConfig } from './cloud/config.js';
import { checkKillPhrase } from './defence/iron-dome/index.js';

import {
  isKillSwitchActive,
  getKillSwitchMeta,
  assertOperationAllowed,
  activateKillSwitch,
  deactivateKillSwitch,
  KillSwitchError,
} from './api/control.js';
import type { OperationKind } from './api/control.js';

// Shared source schema for access control on MCP tools.
// NOTE: 'user' is intentionally NOT accepted from MCP callers. MCP tools are
// always invoked by an agent, hook, CLI or API — never by a literal human
// typing — so accepting type:'user' would let a prompt-injected agent
// self-attest as the human operator and earn trust=1.0, bypassing the
// quarantine band and RESTRICTED read gating. The 'user' type still exists
// internally for things like dashboard-originated writes, but it must never
// be honoured when it arrives over the MCP transport.
const sourceParam = z.object({
  type: z.enum(['cli', 'hook', 'email', 'web', 'agent', 'file', 'api', 'tool_response']),
  identifier: z.string(),
}).optional().describe('Caller identity for access control (agents should pass this). type:"user" is rejected — MCP is never a human channel.');

/**
 * Wrap an MCP tool handler to scan its response for threats.
 * Advisory mode: appends a warning but never blocks.
 * Enforce mode: can redact credential leaks.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function withResponseScan(toolName: string, handler: (...args: any[]) => any): (...args: any[]) => any {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return async (...handlerArgs: any[]) => {
    const result = await handler(...handlerArgs);
    const config = getToolResponseScanConfig();
    if (!config.scanToolResponses || !shouldScanToolResponse(toolName)) return result;

    const textContent = result.content
      .filter((c: { type: string }) => c.type === 'text')
      .map((c: { text: string }) => c.text)
      .join('\n');

    if (textContent.length < 20) return result;

    const scan = scanToolResponse(toolName, textContent, config.toolResponseMode);
    if (scan.clean) return result;

    // Enforce mode: swap the threatening text for the sanitised payload the
    // scanner produced (injection withheld, secrets redacted, exfil stripped).
    // Non-text blocks (e.g. images) are preserved. Advisory mode keeps the
    // observe-only behaviour: leave the response intact, append a warning.
    if (scan.mode === 'enforce' && scan.sanitisedContent !== null) {
      const nonText = result.content.filter((c: { type: string }) => c.type !== 'text');
      if (scan.blocked) {
        // Whole payload withheld → surface as a tool error so the agent can tell
        // "withheld by firewall" apart from "no results / empty".
        return {
          ...result,
          content: [...nonText, { type: 'text' as const, text: scan.sanitisedContent }],
          isError: true,
        };
      }
      // Redacted-and-delivered → cleaned payload + the untrusted-origin tag in a
      // SEPARATE block, so redacted structured output (JSON/CSV) stays parseable.
      return {
        ...result,
        content: [
          ...nonText,
          { type: 'text' as const, text: scan.sanitisedContent },
          { type: 'text' as const, text: UNTRUSTED_TOOL_TAG },
        ],
      };
    }

    // Advisory: append warning to the response.
    return {
      ...result,
      content: [
        ...result.content,
        {
          type: 'text' as const,
          text: `\n---\n**[ShieldCortex]** ${scan.summary}\nAudit ID: ${scan.auditId}`,
        },
      ],
    };
  };
}

/**
 * Resolve source for an MCP tool call — always returns full ResolvedToolSource
 * (source + attested + clamped). #283: callers must thread `attested` into
 * checkAccess / guardRead*; discarding it reopens ownership spoof.
 */
function resolveToolSourceFull(declaredSource: DefenceSource | undefined, toolName: string) {
  return resolveToolSourceImpl(declaredSource, {
    toolName,
    project: getActiveProject(),
  });
}

/** Source-only helper for paths that truly need only the identity string. */
function resolveToolSource(declaredSource: DefenceSource | undefined, toolName: string): DefenceSource {
  return resolveToolSourceFull(declaredSource, toolName).source;
}

/**
 * Wrap an MCP tool handler to enforce kill switch lockdown.
 * If the kill switch is active and the operation kind is blocked,
 * returns a lockdown error instead of executing the handler.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function withKillSwitchGuard(kind: OperationKind, handler: (...args: any[]) => any): (...args: any[]) => any {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return async (...handlerArgs: any[]) => {
    try {
      assertOperationAllowed(kind);
    } catch (e) {
      if (e instanceof KillSwitchError) {
        const meta = e.meta;
        return {
          content: [{
            type: 'text' as const,
            text: `## KILL SWITCH ACTIVE\n\nAll operations are locked down.\n\n` +
              `**Triggered:** ${meta?.triggeredAt ?? 'unknown'}\n` +
              `**Source:** ${meta?.source ?? 'unknown'}\n` +
              (meta?.phrase ? `**Phrase:** "${meta.phrase}"\n` : '') +
              `\nUse \`iron_dome_resume\` to resume after investigation.`,
          }],
          isError: true,
        };
      }
      throw e;
    }
    return handler(...handlerArgs);
  };
}

/**
 * Check text for kill phrase and trigger kill switch if detected.
 * Returns true if kill switch was activated.
 */
export function checkAndTriggerKillSwitch(text: string, source: string): boolean {
  if (isKillSwitchActive()) return false; // already active
  try {
    // Statically imported (see top of file) — no circular dep:
    // iron-dome/index does not import server.ts. try/catch is purely
    // defensive against a kill-phrase check failing at runtime.
    const result = checkKillPhrase(text);
    return result.triggered;
  } catch {
    return false;
  }
}

/**
 * Create and configure the MCP server
 */
export function createServer(dbPath?: string): McpServer {
  // Initialize database. Caps come from the operator's `memory` block when set
  // (see memory/config.ts) — the ceiling at which the product starts forgetting
  // on their behalf should be theirs to choose.
  const config = resolveMemoryConfig();
  if (dbPath) {
    config.dbPath = dbPath;
  }
  initDatabase(config.dbPath);

  // Initialize project context (auto-detect from working directory)
  initProjectContext();
  const projectInfo = getProjectContextInfo();
  if (projectInfo.project) {
    console.error(`[shieldcortex] Project: "${projectInfo.project}" (from ${projectInfo.source})`);
  } else {
    console.error('[shieldcortex] Project: global scope');
  }

  // Create MCP server
  const server = new McpServer({
    name: 'shieldcortex',
    version: getCurrentVersion(),
  });

  // ============================================
  // TOOLS
  // ============================================

  // Remember - Store a memory
  server.tool(
    'remember',
    `Store information in memory for later recall. Use this to remember:
- Architecture decisions ("We're using PostgreSQL for the database")
- Code patterns ("The auth flow uses JWT tokens")
- User preferences ("Always use TypeScript strict mode")
- Error resolutions ("Fixed by updating the dependency")
- Project context ("This is a React + Node.js project")
- Important notes ("Remember to test the edge cases")

The system automatically detects importance, categorizes, and manages storage.
Content is scanned through the defence pipeline before storage. Suspicious content may be quarantined.`,
    {
      title: z.string().describe('Short title for the memory'),
      content: z.string().describe('Detailed content'),
      category: z.enum([
        'architecture', 'pattern', 'preference', 'error',
        'context', 'learning', 'todo', 'note', 'relationship', 'custom'
      ]).optional().describe('Category (auto-detected if not provided)'),
      type: z.enum(['short_term', 'long_term', 'episodic']).optional()
        .describe('Memory type (auto-determined if not provided)'),
      project: z.string().optional().describe('Project scope. Auto-detected from working directory if not provided. Use "*" for global.'),
      tags: z.array(z.string()).optional().describe('Tags for categorization'),
      importance: z.enum(['low', 'normal', 'high', 'critical']).optional()
        .describe('Override automatic salience'),
      scope: z.enum(['project', 'global']).optional()
        .describe('Memory scope: project (default) or global (cross-project)'),
      transferable: z.boolean().optional()
        .describe('Whether this memory can be transferred to other projects'),
      source: sourceParam,
    },
    { title: 'Store Memory', readOnlyHint: false, destructiveHint: false, idempotentHint: false },
    withKillSwitchGuard('memory_write', async (args) => {
      // Check for kill phrase in content before storing
      const textToCheck = `${args.title ?? ''} ${args.content ?? ''}`;
      if (checkAndTriggerKillSwitch(textToCheck, 'remember')) {
        const meta = getKillSwitchMeta();
        return {
          content: [{ type: 'text' as const, text: `## KILL SWITCH ACTIVATED\n\nKill phrase detected in memory content. All operations locked down.\n\nTriggered: ${meta?.triggeredAt}\nUse \`iron_dome_resume\` to resume after investigation.` }],
          isError: true,
        };
      }
      const resolved = resolveToolSourceFull(args.source as DefenceSource | undefined, 'remember');
      const result = await executeRemember({ ...args, source: resolved.source, sourceAttested: resolved.attested });
      return {
        content: [{ type: 'text', text: formatRememberResult(result) }],
      };
    })
  );

  // Recall - Search and retrieve memories
  server.tool(
    'recall',
    `Search and retrieve memories. Use this to:
- Find relevant context ("What do I know about auth?")
- Get recent activity ("What did we work on?")
- Find decisions ("What architecture decisions were made?")

Modes: search (query-based), recent (by time), important (by salience)`,
    {
      query: z.string().optional().describe('Search query'),
      category: z.enum([
        'architecture', 'pattern', 'preference', 'error',
        'context', 'learning', 'todo', 'note', 'relationship', 'custom'
      ]).optional().describe('Filter by category'),
      type: z.enum(['short_term', 'long_term', 'episodic']).optional()
        .describe('Filter by type'),
      project: z.string().optional().describe('Project scope. Auto-detected if not provided. Use "*" for all projects.'),
      tags: z.array(z.string()).optional().describe('Filter by tags'),
      limit: z.number().min(1).max(50).optional().default(10)
        .describe('Max results'),
      includeDecayed: z.boolean().optional().default(false)
        .describe('Include decayed memories'),
      includeGlobal: z.boolean().optional().default(true)
        .describe('Include global memories in search results (default: true)'),
      mode: z.enum(['search', 'recent', 'important']).optional().default('search')
        .describe('Recall mode'),
      source: sourceParam,
    },
    { title: 'Search Memories', readOnlyHint: true, destructiveHint: false, idempotentHint: true },
    withKillSwitchGuard('memory_read', withResponseScan('recall', async (args) => {
      const resolved = resolveToolSourceFull(args.source as DefenceSource | undefined, 'recall');
      const result = await executeRecall({ ...args, source: resolved.source, sourceAttested: resolved.attested });
      return {
        content: [{ type: 'text', text: formatRecallResult(result, true) }],
      };
    }))
  );

  // Forget - Delete memories
  server.tool(
    'forget',
    `Delete memories. Use dryRun: true to preview, confirm: true for bulk.`,
    {
      id: z.number().optional().describe('Memory ID to delete'),
      query: z.string().optional().describe('Delete matching query'),
      category: z.enum([
        'architecture', 'pattern', 'preference', 'error',
        'context', 'learning', 'todo', 'note', 'relationship', 'custom'
      ]).optional().describe('Delete category'),
      project: z.string().optional().describe('Project scope for deletion. Auto-detected if not provided. Use "*" for all projects.'),
      olderThan: z.number().optional().describe('Delete older than N days'),
      belowSalience: z.number().min(0).max(1).optional()
        .describe('Delete below salience'),
      dryRun: z.boolean().optional().default(false)
        .describe('Preview only'),
      confirm: z.boolean().optional().default(false)
        .describe('Confirm bulk delete'),
      source: sourceParam,
      fromSource: z.string().optional()
        .describe('Revoke-by-source: delete all memories written by this source ("type:identifier", or "type:*" for a whole type). Authorised by the trust-hierarchy revoke ACL (own the source or outrank it). Use project:"*" to revoke across all projects.'),
    },
    { title: 'Delete Memories', readOnlyHint: false, destructiveHint: true, idempotentHint: false },
    withKillSwitchGuard('memory_write', async (args) => {
      // Delete is destructive, and revoke-by-source grants cross-identity power,
      // so the caller identity MUST be the unspoofable runtime identity — derive
      // it from the environment, NOT the MCP-declared `source` param. Honouring a
      // declared identity would let a caller claim ownership of any peer source's
      // memories (the clamp only caps trust SCORE, not identity).
      const source = inferSourceFromEnvironment().source;
      const result = await executeForget({ ...args, source });
      return {
        content: [{ type: 'text', text: formatForgetResult(result) }],
      };
    })
  );

  // Get Context - THE KEY TOOL
  server.tool(
    'get_context',
    `Get relevant context from memory. THE KEY TOOL for maintaining context.

Use at session start, after compaction, when switching tasks, or to recall project info.
Returns: architecture decisions, patterns, pending items, recent activity.`,
    {
      project: z.string().optional().describe('Project scope. Auto-detected if not provided. Use "*" for all projects.'),
      query: z.string().optional().describe('Current task for relevant context'),
      format: z.enum(['summary', 'detailed', 'raw']).optional().default('summary')
        .describe('Output format'),
      source: sourceParam,
    },
    { title: 'Get Project Context', readOnlyHint: true, destructiveHint: false, idempotentHint: true },
    withKillSwitchGuard('memory_read', withResponseScan('get_context', async (args) => {
      const resolved = resolveToolSourceFull(args.source as DefenceSource | undefined, 'get_context');
      const result = await executeGetContext({ ...args, source: resolved.source, sourceAttested: resolved.attested });
      return {
        content: [{
          type: 'text',
          text: result.success ? result.context! : `Error: ${result.error}`
        }],
      };
    }))
  );

  // Start Session
  server.tool(
    'start_session',
    'Start a new coding session. Returns relevant context.',
    {
      project: z.string().optional().describe('Project scope. Auto-detected if not provided. Use "*" for global.'),
    },
    { title: 'Start Session', readOnlyHint: false, destructiveHint: false, idempotentHint: false },
    withKillSwitchGuard('memory_write', async (args) => {
      const result = await executeStartSession(args);
      return {
        content: [{
          type: 'text',
          text: result.success
            ? `Session ${result.sessionId} started.\n\n${result.context}`
            : `Error: ${result.error}`
        }],
      };
    })
  );

  // End Session
  server.tool(
    'end_session',
    'End session and trigger consolidation.',
    {
      sessionId: z.number().describe('Session ID'),
      summary: z.string().optional().describe('Session summary'),
    },
    { title: 'End Session', readOnlyHint: false, destructiveHint: false, idempotentHint: true },
    withKillSwitchGuard('memory_write', async (args) => {
      const result = executeEndSession(args);
      if (!result.success) {
        return { content: [{ type: 'text', text: `Error: ${result.error}` }] };
      }
      const r = result.consolidationResult!;
      return {
        content: [{
          type: 'text',
          text: `Session ended. Consolidation: ${r.consolidated} promoted, ${r.decayed} decayed, ${r.deleted} deleted.`
        }],
      };
    })
  );

  // Consolidate
  server.tool(
    'consolidate',
    'Run memory consolidation (like brain sleep). Promotes STM to LTM, decays old memories. Use dryRun to preview.',
    {
      force: z.boolean().optional().default(false).describe('Force consolidation'),
      dryRun: z.boolean().optional().default(false).describe('Preview what would happen without doing it'),
    },
    { title: 'Run Memory Consolidation', readOnlyHint: false, destructiveHint: false, idempotentHint: false },
    withKillSwitchGuard('consolidation', async (args) => {
      const result = executeConsolidate(args);
      if (!result.success) {
        return { content: [{ type: 'text', text: `Error: ${result.error}` }] };
      }

      // Dry run returns preview
      if (result.preview) {
        const p = result.preview;
        const lines = [
          '## Consolidation Preview (Dry Run)',
          '',
          `Would promote: ${p.toPromote} memories`,
          `Would delete: ${p.toDelete} memories`,
        ];
        if (p.promoteList.length > 0) {
          lines.push('', '**To promote:**');
          lines.push(...p.promoteList.map(t => `  - ${t}`));
        }
        if (p.deleteList.length > 0) {
          lines.push('', '**At risk of deletion:**');
          lines.push(...p.deleteList.map(t => `  - ${t}`));
        }
        return { content: [{ type: 'text', text: lines.join('\n') }] };
      }

      // Actual consolidation result
      const r = result.result!;
      return {
        content: [{
          type: 'text',
          text: `Consolidation: ${r.consolidated} promoted, ${r.decayed} updated, ${r.deleted} deleted.`
        }],
      };
    })
  );

  // Stats
  server.tool(
    'memory_stats',
    'Get memory statistics.',
    {
      project: z.string().optional().describe('Project scope. Auto-detected if not provided. Use "*" for all projects.'),
    },
    { title: 'Memory Statistics', readOnlyHint: true, destructiveHint: false, idempotentHint: true },
    withKillSwitchGuard('status', async (args) => {
      const result = executeStats(args);
      return {
        content: [{
          type: 'text',
          text: result.success ? formatStats(result.stats!, result.salience) : `Error: ${result.error}`
        }],
      };
    })
  );

  // Get Memory by ID
  server.tool(
    'get_memory',
    'Get a specific memory by ID.',
    {
      id: z.number().describe('Memory ID'),
      source: sourceParam,
    },
    { title: 'Get Memory by ID', readOnlyHint: true, destructiveHint: false, idempotentHint: true },
    withKillSwitchGuard('memory_read', withResponseScan('get_memory', async (args) => {
      const resolved = resolveToolSourceFull(args.source as DefenceSource | undefined, 'get_memory');
      const result = executeGetMemory({ ...args, source: resolved.source, sourceAttested: resolved.attested });
      return {
        content: [{
          type: 'text',
          text: result.success ? formatMemory(result.memory!, true) : `Error: ${result.error}`
        }],
      };
    }))
  );

  // Export memories
  server.tool(
    'export_memories',
    'Export memories as JSON for backup.',
    {
      project: z.string().optional().describe('Project scope. Auto-detected if not provided. Use "*" for all projects.'),
      source: sourceParam,
    },
    { title: 'Export Memories', readOnlyHint: true, destructiveHint: false, idempotentHint: true },
    withKillSwitchGuard('memory_read', withResponseScan('export_memories', async (args) => {
      const resolved = resolveToolSourceFull(args.source as DefenceSource | undefined, 'export_memories');
      const result = executeExport({ ...args, source: resolved.source, sourceAttested: resolved.attested });
      return {
        content: [{
          type: 'text',
          text: result.success
            ? `Exported ${result.count} memories:\n\n${result.data}`
            : `Error: ${result.error}`
        }],
      };
    }))
  );

  // Import memories
  server.tool(
    'import_memories',
    'Import memories from JSON.',
    {
      data: z.string().describe('JSON data'),
    },
    { title: 'Import Memories', readOnlyHint: false, destructiveHint: false, idempotentHint: false },
    withKillSwitchGuard('memory_write', async (args) => {
      // Check imported content for kill phrase
      try {
        const parsed = JSON.parse(args.data);
        const entries = Array.isArray(parsed) ? parsed : (parsed.memories ?? []);
        for (const entry of entries) {
          const text = `${entry.title ?? ''} ${entry.content ?? ''}`;
          if (checkAndTriggerKillSwitch(text, 'import_memories')) {
            const meta = getKillSwitchMeta();
            return {
              content: [{ type: 'text' as const, text: `## KILL SWITCH ACTIVATED\n\nKill phrase detected in imported content. All operations locked down.\n\nTriggered: ${meta?.triggeredAt}\nUse \`iron_dome_resume\` to resume after investigation.` }],
              isError: true,
            };
          }
        }
      } catch {
        // JSON parse failures will be caught by executeImport
      }
      const result = executeImport(args);
      return {
        content: [{
          type: 'text',
          text: result.success
            ? `Imported ${result.imported} memories.`
            : `Error: ${result.error}`
        }],
      };
    })
  );

  // Get Related Memories
  server.tool(
    'get_related',
    'Get memories related to a specific memory. Shows connections and relationships.',
    {
      id: z.number().describe('Memory ID to find relationships for'),
      source: sourceParam,
    },
    { title: 'Get Related Memories', readOnlyHint: true, destructiveHint: false, idempotentHint: true },
    withKillSwitchGuard('memory_read', withResponseScan('get_related', async (args) => {
      const resolved = resolveToolSourceFull(args.source as DefenceSource | undefined, 'get_related');
      const result = executeGetRelated({ id: args.id, source: resolved.source, sourceAttested: resolved.attested });
      if (!result.success) {
        return { content: [{ type: 'text', text: `Error: ${result.error}` }], isError: true };
      }
      const related = result.related!;
      if (related.length === 0) {
        return { content: [{ type: 'text', text: 'No related memories found.' }] };
      }
      const lines = [`## Related Memories for ID ${args.id}\n`];
      for (const r of related) {
        const arrow = r.direction === 'outgoing' ? '→' : '←';
        lines.push(`${arrow} **${r.memory.title}** (${r.relationship}, ${(r.strength * 100).toFixed(0)}% strength)`);
        lines.push(`  ID: ${r.memory.id} | ${r.memory.category} | ${(r.memory.salience * 100).toFixed(0)}% salience`);
      }
      return { content: [{ type: 'text', text: lines.join('\n') }] };
    }))
  );

  // Link Memories
  server.tool(
    'link_memories',
    'Create a relationship link between two memories.',
    {
      sourceId: z.number().describe('Source memory ID'),
      targetId: z.number().describe('Target memory ID'),
      relationship: z.enum(['references', 'extends', 'contradicts', 'related'])
        .describe('Type of relationship'),
      strength: z.number().min(0).max(1).optional().default(0.5)
        .describe('Relationship strength (0-1)'),
    },
    { title: 'Link Memories', readOnlyHint: false, destructiveHint: false, idempotentHint: true },
    withKillSwitchGuard('memory_write', async (args) => {
      const link = createMemoryLink(
        args.sourceId,
        args.targetId,
        args.relationship as RelationshipType,
        args.strength
      );
      if (!link) {
        return { content: [{ type: 'text', text: 'Failed to create link. Memories may not exist or link already exists.' }] };
      }
      return { content: [{ type: 'text', text: `✓ Linked memory ${args.sourceId} → ${args.targetId} (${args.relationship})` }] };
    })
  );

  // Set Project - Switch active project context
  server.tool(
    'set_project',
    `Switch active project context. Use "${GLOBAL_PROJECT_SENTINEL}" for global/all projects.`,
    {
      project: z.string().describe(`Project name, or "${GLOBAL_PROJECT_SENTINEL}" for global scope`),
    },
    { title: 'Switch Project', readOnlyHint: false, destructiveHint: false, idempotentHint: true },
    withKillSwitchGuard('config', async (args) => {
      const oldProject = getActiveProject();
      setActiveProject(args.project === GLOBAL_PROJECT_SENTINEL ? null : args.project);
      const newProject = getActiveProject();
      return {
        content: [{
          type: 'text',
          text: `Project context changed: ${oldProject || 'global'} → ${newProject || 'global'}`
        }]
      };
    })
  );

  // Get Project - Show current project scope (status — allowed during lockdown)
  server.tool(
    'get_project',
    'Show current project scope and detection info.',
    {},
    { title: 'Show Current Project', readOnlyHint: true, destructiveHint: false, idempotentHint: true },
    async () => {
      const info = getProjectContextInfo();
      const lines = [
        `**Current Project:** ${info.project || 'global (all projects)'}`,
        `**Detection Source:** ${info.source}`,
        `**Scope:** ${info.isGlobal ? 'Global - queries return all projects' : `Scoped - queries filtered to "${info.project}"`}`,
      ];
      return { content: [{ type: 'text', text: lines.join('\n') }] };
    }
  );

  // ============================================
  // ORGANIC BRAIN TOOLS (Phase 3)
  // ============================================

  // Detect Contradictions - Find conflicting memories
  server.tool(
    'detect_contradictions',
    `Scan memories for potential contradictions. Finds memories that may contain
conflicting information about the same topic, such as:
- Different solutions to the same problem
- Conflicting recommendations (use X vs don't use X)
- Opposite decisions or preferences

Contradictions are automatically detected during consolidation and linked,
but you can use this tool to check for new contradictions at any time.`,
    {
      project: z.string().optional().describe('Filter by project (omit for current project)'),
      category: z.enum([
        'architecture', 'pattern', 'preference', 'error',
        'context', 'learning', 'todo', 'note', 'relationship', 'custom'
      ]).optional().describe('Filter by category'),
      minScore: z.number().min(0).max(1).optional().default(0.4)
        .describe('Minimum contradiction score (0-1, default 0.4)'),
      limit: z.number().min(1).max(50).optional().default(10)
        .describe('Maximum results to return'),
    },
    { title: 'Detect Contradictions', readOnlyHint: true, destructiveHint: false, idempotentHint: true },
    withKillSwitchGuard('consolidation', withResponseScan('detect_contradictions', async (args) => {
      const project = args.project ?? getActiveProject() ?? undefined;
      const contradictions = detectContradictions({
        project,
        category: args.category,
        minScore: args.minScore,
        limit: args.limit,
      }).filter(
        // Drop a pair if either side is RESTRICTED/quarantined (don't leak a
        // credential-class memory's title via a contradiction listing).
        (c) => guardReadBySensitivity([c.memoryA, c.memoryB]).length === 2,
      );

      if (contradictions.length === 0) {
        return { content: [{ type: 'text', text: 'No contradictions detected.' }] };
      }

      const lines = ['## Potential Contradictions\n'];
      for (const c of contradictions) {
        lines.push(`### ${c.reason} (${(c.score * 100).toFixed(0)}% confidence)`);
        lines.push(`**Memory A:** [#${c.memoryA.id}] ${c.memoryA.title}`);
        lines.push(`**Memory B:** [#${c.memoryB.id}] ${c.memoryB.title}`);
        if (c.sharedTopics.length > 0) {
          lines.push(`**Shared Topics:** ${c.sharedTopics.join(', ')}`);
        }
        lines.push('');
      }

      lines.push(`\n*Found ${contradictions.length} potential contradiction(s). Use \`get_related\` to see linked contradictions.*`);

      return { content: [{ type: 'text', text: lines.join('\n') }] };
    }))
  );

  // ============================================
  // KNOWLEDGE GRAPH TOOLS
  // ============================================

  // Graph Query - Traverse from an entity
  server.tool(
    'graph_query',
    'Traverse the knowledge graph from an entity. Returns each reachable entity once, at its shallowest depth, with the edge that first reached it (BFS spanning tree — parallel edges between the same pair are not enumerated).',
    {
      entity: z.string().describe('Entity name to start from'),
      depth: z.number().optional().describe('Max traversal depth (default 2)'),
      predicates: z.array(z.string()).optional().describe('Filter by predicate types'),
    },
    { title: 'Knowledge Graph Query', readOnlyHint: true, destructiveHint: false, idempotentHint: true },
    withKillSwitchGuard('graph', withResponseScan('graph_query', async (args) => handleGraphQuery(args)))
  );

  // Threat Graph - query the security event graph (Phase A)
  server.tool(
    'threat_graph',
    'Query the threat graph — the security event graph projected from the defence audit ledgers. Views: sources (per-source counters), source (one source with its triggered patterns + recent events), events (recent notable events), campaigns (coordinated-attack clusters), allowances (operator auto-release grants), conflicts (relation-channel disputes awaiting review). Responses are row- and byte-capped with an explicit truncated flag.',
    {
      view: z.enum(['sources', 'source', 'events', 'campaigns', 'allowances', 'conflicts']).describe('What to list'),
      key: z.string().optional().describe("Source key for view 'source', e.g. 'agent:build-bot'"),
      project: z.string().optional().describe('Filter events by originating project'),
      since: z.string().optional().describe('ISO timestamp — only rows seen at/after this'),
      limit: z.number().optional().describe('Max rows (default 50, hard cap 200)'),
    },
    { title: 'Threat Graph Query', readOnlyHint: true, destructiveHint: false, idempotentHint: true },
    withKillSwitchGuard('graph', withResponseScan('threat_graph', async (args) => handleThreatGraphQuery(args)))
  );

  // Graph Entities - List known entities
  server.tool(
    'graph_entities',
    'List known entities in the knowledge graph, optionally filtered by type.',
    {
      type: z.string().optional().describe('Filter by entity type (person, tool, concept, file, language, service, pattern)'),
      minMentions: z.number().optional().describe('Minimum memory references (default 1)'),
      limit: z.number().optional().describe('Max results (default 50)'),
    },
    { title: 'List Graph Entities', readOnlyHint: true, destructiveHint: false, idempotentHint: true },
    withKillSwitchGuard('graph', withResponseScan('graph_entities', async (args) => handleGraphEntities(args)))
  );

  // Graph Explain - Find paths between entities
  server.tool(
    'graph_explain',
    'Explain the relationship between two entities by finding paths connecting them in the knowledge graph.',
    {
      from: z.string().describe('Source entity name'),
      to: z.string().describe('Target entity name'),
      maxDepth: z.number().optional().describe('Max path length (default 4)'),
    },
    { title: 'Explain Entity Relationship', readOnlyHint: true, destructiveHint: false, idempotentHint: true },
    withKillSwitchGuard('graph', withResponseScan('graph_explain', async (args) => handleGraphExplain(args)))
  );

  // ============================================
  // DEFENCE TOOLS
  // ============================================

  // Audit Query
  server.tool('audit_query', 'Query defence audit logs for forensic analysis', {
    startTime: z.string().optional().describe('ISO timestamp start'),
    endTime: z.string().optional().describe('ISO timestamp end'),
    operation: z.enum(['write', 'read', 'delete', 'update']).optional(),
    source: z.string().optional().describe('Filter by source'),
    firewallResult: z.enum(['ALLOW', 'BLOCK', 'QUARANTINE']).optional(),
    limit: z.number().default(50),
  },
  { title: 'Query Audit Logs', readOnlyHint: true, destructiveHint: false, idempotentHint: true },
  async (args) => {
    const logs = queryAuditLogs(args);
    const text = logs.length === 0 ? 'No audit logs found.' : logs.map(l => `[${l.timestamp}] ${l.firewall_result} | source:${l.source_type}:${l.source_identifier} | trust:${l.trust_score}`).join('\n');
    return { content: [{ type: 'text', text }] };
  });

  // Quarantine Review
  server.tool('quarantine_review', 'Review and manage quarantined memories', {
    action: z.enum(['list', 'approve', 'reject', 'approve_by_source']),
    quarantineId: z.number().optional().describe('ID for approve/reject'),
    sourceIdentifier: z.string().optional().describe('Source identifier for batch approve (e.g. "user-spawned>task-1")'),
    notes: z.string().optional(),
  },
  { title: 'Review Quarantined Memories', readOnlyHint: false, destructiveHint: false, idempotentHint: false },
  withKillSwitchGuard('memory_write', async (args) => {
    const db = (await import('./database/init.js')).getDatabase();
    if (args.action === 'list') {
      const items = db.prepare('SELECT * FROM quarantine WHERE status = ? ORDER BY created_at DESC LIMIT 50').all('pending');
      const text = items.length === 0 ? 'No items in quarantine.' : (items as any[]).map((q: any) => `[${q.id}] ${q.original_title || 'Untitled'} | source: ${q.source_type}:${q.source_identifier} | reason: ${q.reason}`).join('\n');
      return { content: [{ type: 'text', text }] };
    } else if (args.action === 'approve' && args.quarantineId) {
      const { approveQuarantineItem } = await import('./defence/quarantine/review.js');
      const result = approveQuarantineItem(args.quarantineId, args.notes || 'mcp');
      if (!result) {
        return { content: [{ type: 'text', text: `Quarantine item ${args.quarantineId} was not pending or no longer exists.` }] };
      }
      return { content: [{ type: 'text', text: `Quarantine item ${args.quarantineId} approved${result.memoryId ? ` and promoted to memory ${result.memoryId}` : ''}.` }] };
    } else if (args.action === 'reject' && args.quarantineId) {
      const { rejectQuarantineItem } = await import('./defence/quarantine/review.js');
      const result = rejectQuarantineItem(args.quarantineId, args.notes || 'mcp');
      if (!result) {
        return { content: [{ type: 'text', text: `Quarantine item ${args.quarantineId} was not pending or no longer exists.` }] };
      }
      return { content: [{ type: 'text', text: `Quarantine item ${args.quarantineId} rejected.` }] };
    } else if (args.action === 'approve_by_source' && args.sourceIdentifier) {
      const { approveQuarantineItemsBySource } = await import('./defence/quarantine/review.js');
      const result = approveQuarantineItemsBySource(args.sourceIdentifier, args.notes || 'batch-approve');
      if (result.total === 0) {
        return { content: [{ type: 'text', text: `No pending quarantine items from source "${args.sourceIdentifier}".` }] };
      }
      return { content: [{ type: 'text', text: `Batch approved ${result.updated} of ${result.total} items from "${args.sourceIdentifier}" (${result.promoted} promoted to memory).` }] };
    }
    return { content: [{ type: 'text', text: 'Invalid action or missing required parameters.' }] };
  }));

  // Defence Stats (allowed during lockdown)
  server.tool('defence_stats', 'Get defence system statistics', {
    timeRange: z.enum(['24h', '7d', '30d']).default('24h'),
  },
  { title: 'Defence Statistics', readOnlyHint: true, destructiveHint: false, idempotentHint: true },
  async (args) => {
    const stats = getAuditStats(args.timeRange);
    const fmt = new Intl.NumberFormat('en-US');
    const n = (v: number) => fmt.format(v);

    const lines = [
      `🛡️  ShieldCortex Defence Stats (${args.timeRange})`,
      `${'─'.repeat(36)}`,
      `  Total operations:  ${n(stats.totalOperations)}`,
      `  Allowed:           ${n(stats.allowedCount)}`,
      `  Blocked:           ${n(stats.blockedCount)}`,
      `  Quarantined:       ${n(stats.quarantinedCount)}`,
      `  Top sources:       ${stats.topSources.map(s => `${s.source}(${n(s.count)})`).join(', ') || 'none'}`,
    ];
    if (Object.keys(stats.threatBreakdown).length > 0) {
      lines.push(`  Threat types:      ${Object.entries(stats.threatBreakdown).map(([k,v]) => `${k}:${n(v)}`).join(', ')}`);
    }

    // Append lifetime totals
    try {
      const lifetime = getLifetimeStats();
      lines.push('');
      lines.push(`All-Time Totals`);
      lines.push(`${'─'.repeat(36)}`);
      lines.push(`  Total scans:        ${n(lifetime.totalScans)}`);
      lines.push(`  Threats blocked:    ${n(lifetime.threatsBlocked)}`);
      lines.push(`  Quarantined:        ${n(lifetime.quarantined)}`);
      lines.push(`  Credential leaks:   ${n(lifetime.credentialLeaks)}`);
      lines.push(`  Memories protected: ${n(lifetime.memoriesProtected)}`);
    } catch {
      // Lifetime stats unavailable — not a problem
    }

    return { content: [{ type: 'text', text: lines.join('\n') }] };
  });

  // Scan Tool Response — manual scanning for external MCP server outputs
  server.tool(
    'scan_tool_response',
    `Scan a tool response for injection attacks and credential leaks.
Use this to verify responses from external MCP servers before trusting their content.
Runs injection detection (40+ patterns) and credential leak scanning (25+ providers).`,
    {
      toolName: z.string().describe('Name of the tool that produced the response'),
      content: z.string().describe('The tool response content to scan'),
      mode: z.enum(['advisory', 'enforce']).optional()
        .describe('Scan mode: advisory (log only) or enforce (can redact). Default: advisory'),
    },
    { title: 'Scan Tool Response', readOnlyHint: true, destructiveHint: false, idempotentHint: true },
    async (args) => {
      // Check for kill phrase in scanned content
      if (checkAndTriggerKillSwitch(args.content, 'scan_tool_response')) {
        const meta = getKillSwitchMeta();
        return {
          content: [{ type: 'text' as const, text: `## KILL SWITCH ACTIVATED\n\nKill phrase detected in tool response. All operations locked down.\n\nTriggered: ${meta?.triggeredAt}\nUse \`iron_dome_resume\` to resume after investigation.` }],
          isError: true,
        };
      }
      const scan = scanToolResponse(args.toolName, args.content, args.mode as 'advisory' | 'enforce' | undefined);

      const lines = [
        `## Tool Response Scan: ${args.toolName}`,
        '',
        `**Clean:** ${scan.clean ? 'Yes' : 'No'}`,
        `**Mode:** ${scan.mode}`,
        `**Duration:** ${scan.durationMs}ms`,
        '',
      ];

      if (!scan.injection.clean) {
        lines.push('### Injection Detection');
        lines.push(`**Risk Level:** ${scan.injection.riskLevel}`);
        lines.push(`**Detections:** ${scan.injection.detections.length}`);
        for (const d of scan.injection.detections) {
          lines.push(`- **[${d.severity}]** \`${d.category}\` — ${d.description}`);
          if (d.match) {
            lines.push(`  - Match: \`${d.match.substring(0, 100)}\``);
          }
        }
        lines.push('');
      }

      if (scan.credentials.leaked) {
        lines.push('### Credential Leaks');
        for (const f of scan.credentials.findings) {
          lines.push(`- **${f.provider}** ${f.type} detected (${f.severity})`);
        }
        lines.push('');
      }

      if (scan.threatIndicators.length > 0) {
        lines.push(`**Threat Indicators:** ${scan.threatIndicators.join(', ')}`);
      }

      if (scan.auditId > 0) {
        lines.push(`**Audit ID:** ${scan.auditId}`);
      }

      // Enforce mode produced an actioned payload — surface it so callers using
      // this tool as a programmatic firewall receive the safe content, not just
      // a verdict. Advisory scans leave sanitisedContent null (verdict only).
      if (scan.sanitisedContent !== null) {
        lines.push('');
        lines.push(`### Enforcement (${scan.blocked ? 'BLOCKED' : 'REDACTED'})`);
        for (const action of scan.enforceActions) {
          lines.push(`- ${action}`);
        }
        if (!scan.blocked) {
          lines.push(`- origin: ${UNTRUSTED_TOOL_TAG}`);
        }
        lines.push('');
        lines.push('**Sanitised content (deliver this instead):**');
        // Dynamic fence longer than any backtick run in the content, so content
        // containing ``` cannot break out of the code block.
        const longestRun = Math.max(0, ...(scan.sanitisedContent.match(/`+/g) || []).map((s) => s.length));
        const fence = '`'.repeat(Math.max(3, longestRun + 1));
        lines.push(fence);
        lines.push(scan.sanitisedContent);
        lines.push(fence);
      }

      lines.push('');
      lines.push(scan.summary);

      return { content: [{ type: 'text', text: lines.join('\n') }] };
    }
  );

  // Scan Memories
  server.tool('scan_memories', 'Scan existing memories for signs of poisoning', {
    project: z.string().optional().describe('Scan specific project'),
    limit: z.number().default(1000).describe('Max memories to scan'),
  },
  { title: 'Scan Memories for Poisoning', readOnlyHint: true, destructiveHint: false, idempotentHint: true },
  async (args) => {
    const report = scanExistingMemories({ project: args.project, limit: args.limit });
    let text = report.summary + '\n';
    if (report.threatsFound.length > 0) {
      text += '\nThreats:\n';
      for (const t of report.threatsFound) {
        text += `  [${t.severity}] Memory #${t.memoryId}: "${t.title}" — ${t.details}\n`;
      }
    }
    return { content: [{ type: 'text', text }] };
  });

  // Scan Skill - Scan agent instruction files for threats
  server.tool('scan_skill', 'Scan an agent instruction file (skill, hook, rules) for threats. Supports Claude Code (SKILL.md), OpenClaw (HOOK.md, handler.js), Cursor (.cursorrules), Windsurf (.windsurfrules), Cline (.clinerules), GitHub Copilot, Aider, Continue.', {
    content: z.string().describe('The skill/instruction file content to scan'),
    name: z.string().optional().describe('Skill name for the report'),
    format: z.enum([
      'skill-md', 'hook-md', 'hook-js', 'rules', 'claude-md',
      'copilot-md', 'aider-yml', 'continue-json',
    ]).optional().describe('File format (auto-detected if omitted)'),
    mode: z.enum(['strict', 'balanced', 'permissive']).optional()
      .describe('Defence mode (default: balanced)'),
  },
  { title: 'Scan Instruction File for Threats', readOnlyHint: true, destructiveHint: false, idempotentHint: true },
  async (args) => {
    const { scanSkillContent } = await import('./defence/skill-scanner/index.js');
    const result = scanSkillContent(
      args.content,
      { mode: args.mode },
      args.format,
      args.name,
    );

    const lines = [
      `## Skill Scan: ${result.skillName}`,
      '',
      `**Format:** ${result.format}`,
      `**Risk Level:** ${result.riskLevel.toUpperCase()}`,
      `**Safe:** ${result.safe ? 'Yes' : 'No'}`,
      `**Scan Time:** ${result.scanDurationMs}ms`,
      '',
    ];

    if (result.findings.length > 0) {
      lines.push('### Findings\n');
      for (const f of result.findings) {
        lines.push(`- **[${f.severity.toUpperCase()}]** \`${f.pattern}\` — ${f.description}`);
        if (f.matchedText) {
          lines.push(`  - Match: \`${f.matchedText}\``);
        }
      }
      lines.push('');
    }

    lines.push(result.summary);

    return { content: [{ type: 'text', text: lines.join('\n') }] };
  });

  // ============================================
  // IRON DOME TOOLS
  // ============================================

  // Iron Dome Status (allowed during lockdown — forensic access)
  server.tool(
    'iron_dome_status',
    'Check if Iron Dome is active and show kill switch state. Shows config summary including profile, trusted channels, and approval rules.',
    {},
    { title: 'Iron Dome Status', readOnlyHint: true, destructiveHint: false, idempotentHint: true },
    async () => {
      const { getIronDomeStatus } = await import('./defence/iron-dome/index.js');
      const status = getIronDomeStatus();
      const killMeta = getKillSwitchMeta();

      const lines = [
        `## Iron Dome Status`,
        '',
      ];

      // Kill switch state (most important — show first)
      if (isKillSwitchActive() && killMeta) {
        lines.push(`**KILL SWITCH: ACTIVE**`);
        lines.push(`**Triggered:** ${killMeta.triggeredAt}`);
        lines.push(`**Source:** ${killMeta.source}`);
        if (killMeta.phrase) lines.push(`**Phrase:** "${killMeta.phrase}"`);
        if (killMeta.memoryCountAtTrigger != null) lines.push(`**Memories at trigger:** ${killMeta.memoryCountAtTrigger}`);
        lines.push('');
        lines.push('> All operations are locked down. Use `iron_dome_resume` to resume.');
        lines.push('');
      }

      lines.push(`**Iron Dome Active:** ${status.enabled ? 'Yes' : 'No'}`);

      if (status.enabled) {
        const c = status.config;
        lines.push(`**Profile:** ${c.profile ?? 'custom'}`);
        lines.push(`**Trusted Channels:** ${c.trustedChannels.join(', ')}`);
        lines.push(`**Kill Phrase:** "${c.killPhrase}"`);
        lines.push(`**Require Approval:** ${c.requireApproval.join(', ')}`);
        lines.push(`**Auto-Approve:** ${c.autoApprove.join(', ')}`);
        lines.push(`**PII Never Output:** ${c.piiRules.neverOutput.length > 0 ? c.piiRules.neverOutput.join(', ') : '(none)'}`);
        lines.push(`**PII Aggregates Only:** ${c.piiRules.aggregatesOnly.length > 0 ? c.piiRules.aggregatesOnly.join(', ') : '(none)'}`);
      }

      return { content: [{ type: 'text', text: lines.join('\n') }] };
    },
  );

  // Iron Dome Scan
  server.tool(
    'iron_dome_scan',
    'Scan text for prompt injection patterns. Returns detections with category, severity, and matched text.',
    {
      text: z.string().describe('The text to scan for injection patterns'),
    },
    { title: 'Iron Dome Injection Scan', readOnlyHint: true, destructiveHint: false, idempotentHint: true },
    async (args) => {
      const { scanForInjection } = await import('./defence/iron-dome/index.js');
      const result = scanForInjection(args.text);

      const lines = [
        `## Iron Dome Scan Result`,
        '',
        `**Clean:** ${result.clean ? 'Yes' : 'No'}`,
        `**Risk Level:** ${result.riskLevel}`,
        `**Text Length:** ${result.textLength} chars`,
        `**Summary:** ${result.summary}`,
      ];

      if (result.detections.length > 0) {
        lines.push('', '### Detections', '');
        for (const d of result.detections) {
          lines.push(`- **[${d.severity.toUpperCase()}]** \`${d.category}\` / \`${d.pattern}\` — ${d.description}`);
          lines.push(`  - Match: \`${d.match}\``);
        }
      }

      return { content: [{ type: 'text', text: lines.join('\n') }] };
    },
  );

  // Iron Dome Check
  server.tool(
    'iron_dome_check',
    'Check if an action is allowed (gateway + action gate). Use this before performing external actions like sending emails or deleting files.',
    {
      action: z.string().describe('The action type to check (e.g. "send_email", "delete_file", "api_call")'),
      channel: z.string().optional().describe('The instruction channel (e.g. "terminal", "telegram", "email")'),
      source: sourceParam,
    },
    { title: 'Iron Dome Action Check', readOnlyHint: true, destructiveHint: false, idempotentHint: true },
    async (args) => {
      const { getIronDomeStatus, isActionAllowed, validateGateway } = await import('./defence/iron-dome/index.js');
      const source = resolveToolSource(args.source as DefenceSource | undefined, 'iron_dome_check');
      const status = getIronDomeStatus();

      const lines = ['## Iron Dome Check', ''];

      if (!status.enabled) {
        lines.push('Iron Dome is not active. All actions are allowed.');
        return { content: [{ type: 'text', text: lines.join('\n') }] };
      }

      // Gateway check
      if (args.channel) {
        const gateway = validateGateway(args.channel, args.action, status.config, source);
        lines.push(`**Gateway:** ${gateway.trustLevel} — ${gateway.reason}`);
        if (!gateway.allowed) {
          lines.push('', '**Result:** BLOCKED by gateway. Channel is not trusted.');
          return { content: [{ type: 'text', text: lines.join('\n') }] };
        }
      }

      // Action gate check
      const gate = isActionAllowed(args.action, status.config, source);
      lines.push(`**Action Gate:** ${gate.decision} — ${gate.reason}`);

      return { content: [{ type: 'text', text: lines.join('\n') }] };
    },
  );

  // Iron Dome Activate
  server.tool(
    'iron_dome_activate',
    'Activate Iron Dome with a profile. Profiles: school (GDPR strict), enterprise (financial protection), personal (lighter touch), paranoid (everything requires approval).',
    {
      profile: z.enum(['school', 'enterprise', 'personal', 'paranoid']).optional()
        .describe('Security profile to activate'),
    },
    { title: 'Activate Iron Dome', readOnlyHint: false, destructiveHint: false, idempotentHint: true },
    withKillSwitchGuard('config', async (args) => {
      const { activateIronDome } = await import('./defence/iron-dome/index.js');
      const config = activateIronDome(args.profile);

      const lines = [
        `## Iron Dome Activated`,
        '',
        `**Profile:** ${config.profile ?? 'default'}`,
        `**Trusted Channels:** ${config.trustedChannels.join(', ')}`,
        `**Kill Phrase:** "${config.killPhrase}"`,
        `**Require Approval:** ${config.requireApproval.join(', ')}`,
        `**Auto-Approve:** ${config.autoApprove.join(', ')}`,
      ];

      return { content: [{ type: 'text', text: lines.join('\n') }] };
    }),
  );

  // ============================================
  // IRON DOME EMERGENCY TOOLS
  // ============================================

  // Emergency Stop — NOT guarded (must always work)
  server.tool(
    'iron_dome_emergency_stop',
    'Emergency kill switch — immediately locks down ALL agent operations. Use when you detect suspicious activity. Reversible via iron_dome_resume.',
    {},
    { title: 'Emergency Stop', readOnlyHint: false, destructiveHint: true, idempotentHint: true },
    async () => {
      activateKillSwitch({ source: 'mcp_tool' });
      const meta = getKillSwitchMeta();
      return {
        content: [{
          type: 'text',
          text: `## KILL SWITCH ACTIVATED\n\nAll operations locked down.\n\n` +
            `**Triggered:** ${meta?.triggeredAt}\n` +
            `**Source:** MCP tool\n\n` +
            `Memory creation, recall, graph queries, and all other operations are blocked.\n` +
            `Use \`iron_dome_resume\` with a reason to resume after investigation.`,
        }],
      };
    },
  );

  // Resume — NOT guarded (this IS the unlock)
  server.tool(
    'iron_dome_resume',
    'Resume agent operations after kill switch investigation. Only use after confirming the threat has been addressed.',
    {
      reason: z.string().describe('Why operations are being resumed (required for audit trail)'),
    },
    { title: 'Resume Operations', readOnlyHint: false, destructiveHint: false, idempotentHint: true },
    async (args) => {
      if (!isKillSwitchActive()) {
        return {
          content: [{ type: 'text', text: 'Kill switch is not active. No action needed.' }],
        };
      }
      deactivateKillSwitch(args.reason);
      return {
        content: [{
          type: 'text',
          text: `## Operations Resumed\n\nKill switch deactivated.\n**Reason:** ${args.reason}\n\nAll tools are now operational. Iron Dome continues protecting.`,
        }],
      };
    },
  );

  // ============================================
  // RESOURCES
  // ============================================

  // Project context resource (blocked during kill switch)
  server.resource(
    'memory://context',
    'memory://context',
    async () => {
      if (isKillSwitchActive()) {
        return { contents: [{ uri: 'memory://context', mimeType: 'text/plain', text: '[KILL SWITCH ACTIVE] Memory access blocked.' }] };
      }
      // Shared-context resource: strip RESTRICTED + quarantined (sensitivity guard).
      const summary = guardContextSummary(await generateContextSummary());
      return {
        contents: [{
          uri: 'memory://context',
          mimeType: 'text/markdown',
          text: formatContextSummary(summary),
        }],
      };
    }
  );

  // Important memories resource (blocked during kill switch)
  server.resource(
    'memory://important',
    'memory://important',
    async () => {
      if (isKillSwitchActive()) {
        return { contents: [{ uri: 'memory://important', mimeType: 'text/plain', text: '[KILL SWITCH ACTIVE] Memory access blocked.' }] };
      }
      // Shared-context resource: strip RESTRICTED + quarantined before exposing content.
      const memories = guardReadBySensitivity(getHighPriorityMemories(20));
      const text = memories.map(m =>
        `## ${m.title}\n${m.content}\n*${m.category} | ${(m.salience * 100).toFixed(0)}% salience*\n`
      ).join('\n');

      return {
        contents: [{
          uri: 'memory://important',
          mimeType: 'text/markdown',
          text: text || 'No high-priority memories stored yet.',
        }],
      };
    }
  );

  // Recent memories resource (blocked during kill switch)
  server.resource(
    'memory://recent',
    'memory://recent',
    async () => {
      if (isKillSwitchActive()) {
        return { contents: [{ uri: 'memory://recent', mimeType: 'text/plain', text: '[KILL SWITCH ACTIVE] Memory access blocked.' }] };
      }
      // Shared-context resource: strip RESTRICTED + quarantined before exposing content.
      const memories = guardReadBySensitivity(getRecentMemories(15));
      const text = memories.map(m =>
        `- **${m.title}** (${m.category}): ${m.content.slice(0, 100)}...`
      ).join('\n');

      return {
        contents: [{
          uri: 'memory://recent',
          mimeType: 'text/markdown',
          text: text || 'No recent memories.',
        }],
      };
    }
  );

  // ============================================
  // PROMPTS
  // ============================================

  // Context restoration prompt (blocked during kill switch)
  server.prompt(
    'restore_context',
    'Restore context after compaction or at session start',
    async () => {
      if (isKillSwitchActive()) {
        return {
          messages: [{ role: 'user' as const, content: { type: 'text' as const, text: '[KILL SWITCH ACTIVE] Context restoration blocked. Use iron_dome_resume to resume.' } }],
        };
      }
      // Shared-context prompt: strip RESTRICTED + quarantined (sensitivity guard).
      const summary = guardContextSummary(await generateContextSummary());
      const context = formatContextSummary(summary);

      return {
        messages: [{
          role: 'user',
          content: {
            type: 'text',
            text: `Please review this context from memory and use it:\n\n${context}`,
          },
        }],
      };
    }
  );

  // Memory search prompt
  server.prompt(
    'search_memory',
    'Search memories for information',
    async () => {
      return {
        messages: [{
          role: 'user',
          content: {
            type: 'text',
            text: `Search my memories for relevant information.`,
          },
        }],
      };
    }
  );

  // ============================================
  // AUTO-CONSOLIDATION (Anti-bloat)
  // ============================================

  // NOTE: Removed synchronous startup consolidation - it was blocking server init
  // on large databases. The 4-hour periodic cleanup handles consolidation instead.

  // Check database size on startup
  const sizeInfo = checkDatabaseSize();
  if (sizeInfo.warning || sizeInfo.blocked) {
    console.error(`[shieldcortex] ${sizeInfo.message}`);
  }

  // Schedule periodic consolidation every 4 hours
  const CONSOLIDATION_INTERVAL = 4 * 60 * 60 * 1000; // 4 hours
  setInterval(() => {
    try {
      const result = fullCleanup();
      console.error(`[shieldcortex] Scheduled cleanup: ${result.consolidation.consolidated} promoted, ${result.consolidation.deleted} deleted, ${result.merged} merged, vacuumed: ${result.vacuumed}`);
    } catch (e) {
      console.error('[shieldcortex] Scheduled cleanup failed:', e);
    }
  }, CONSOLIDATION_INTERVAL);

  return server;
}
