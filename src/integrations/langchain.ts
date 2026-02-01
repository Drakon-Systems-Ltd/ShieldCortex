/**
 * LangChain Integration for ShieldCortex
 *
 * Provides two exports:
 * - ShieldCortexMemory: A BaseMemory-compatible class that scans content through
 *   the defence pipeline before storing memories.
 * - ShieldCortexGuard: A standalone scanner that can be used as middleware
 *   in any LangChain chain without storing memories.
 *
 * Usage:
 *   import { ShieldCortexMemory, ShieldCortexGuard } from 'shieldcortex/integrations/langchain';
 *
 *   // As a memory backend
 *   const memory = new ShieldCortexMemory({ mode: 'balanced' });
 *   const vars = await memory.loadMemoryVariables({});
 *   await memory.saveContext({ input: 'hello' }, { output: 'hi' });
 *
 *   // As a standalone guard
 *   const guard = new ShieldCortexGuard();
 *   const result = guard.scan('some suspicious content');
 *   if (!result.allowed) { ... }
 */

import { runDefencePipeline } from '../defence/pipeline.js';
import { DEFAULT_DEFENCE_CONFIG } from '../defence/types.js';
import type {
  DefenceConfig,
  DefencePipelineResult,
  DefenceSource,
} from '../defence/types.js';
import {
  addMemory,
  searchMemories,
  getRecentMemories,
} from '../memory/store.js';
import type { MemoryInput } from '../memory/types.js';

// ── Config ──

export interface ShieldCortexMemoryConfig {
  /** Defence mode: strict, balanced, or permissive. Default: balanced */
  mode?: DefenceConfig['mode'];
  /** Source identifier for audit trail. Default: 'langchain-agent' */
  sourceIdentifier?: string;
  /** Source type. Default: 'agent' */
  sourceType?: DefenceSource['type'];
  /** Maximum memories to return from loadMemoryVariables. Default: 10 */
  maxResults?: number;
  /** Memory key used in the variables dict. Default: 'history' */
  memoryKey?: string;
  /** Project scope for memories. Default: auto-detected */
  project?: string;
}

// ── ShieldCortexMemory ──

/**
 * LangChain-compatible memory class that runs the defence pipeline
 * on all content before storage. Blocked content is quarantined.
 *
 * Implements the same interface as LangChain's BaseMemory:
 * - memoryVariables: string[]
 * - loadMemoryVariables(values): Promise<Record<string, string>>
 * - saveContext(inputValues, outputValues): Promise<void>
 * - clear(): Promise<void>
 */
export class ShieldCortexMemory {
  private config: DefenceConfig;
  private source: DefenceSource;
  private maxResults: number;
  private _memoryKey: string;
  private project?: string;

  /** Keys this memory populates (LangChain interface) */
  get memoryVariables(): string[] {
    return [this._memoryKey];
  }

  constructor(options: ShieldCortexMemoryConfig = {}) {
    this.config = {
      ...DEFAULT_DEFENCE_CONFIG,
      mode: options.mode ?? 'balanced',
    };
    this.source = {
      type: options.sourceType ?? 'agent',
      identifier: options.sourceIdentifier ?? 'langchain-agent',
    };
    this.maxResults = options.maxResults ?? 10;
    this._memoryKey = options.memoryKey ?? 'history';
    this.project = options.project;
  }

  /**
   * Load relevant memories. Searches by recent context or returns recent memories.
   */
  async loadMemoryVariables(
    values: Record<string, unknown>,
  ): Promise<Record<string, string>> {
    const query = values.input ?? values.query ?? values.question;

    let text: string;
    if (query && typeof query === 'string') {
      const results = await searchMemories({
        query,
        limit: this.maxResults,
        project: this.project,
      });
      text = results
        .map((r) => `[${r.memory.title}] ${r.memory.content}`)
        .join('\n');
    } else {
      const recent = getRecentMemories(this.maxResults);
      text = recent
        .map((m) => `[${m.title}] ${m.content}`)
        .join('\n');
    }

    return { [this._memoryKey]: text };
  }

  /**
   * Save conversation context. Runs the defence pipeline before storing.
   * Blocked content is automatically quarantined.
   */
  async saveContext(
    inputValues: Record<string, unknown>,
    outputValues: Record<string, unknown>,
  ): Promise<void> {
    const input = String(inputValues.input ?? inputValues.query ?? '');
    const output = String(outputValues.output ?? outputValues.response ?? '');
    const content = `User: ${input}\nAssistant: ${output}`;
    const title = input.slice(0, 100);

    const memoryInput: MemoryInput = {
      title,
      content,
      type: 'episodic',
      category: 'context',
      project: this.project,
    };

    // addMemory runs defence pipeline internally when source is provided
    try {
      addMemory(memoryInput, undefined, this.source);
    } catch (err: any) {
      // MemoryBlockedError means it was quarantined — that's expected
      if (err.name === 'MemoryBlockedError') {
        return;
      }
      throw err;
    }
  }

  /**
   * Clear all memories (not implemented — too destructive for a security tool).
   * Use the MCP forget tool or REST API for targeted deletion.
   */
  async clear(): Promise<void> {
    // Intentionally not implemented
  }
}

// ── ShieldCortexGuard ──

export interface ShieldCortexGuardConfig {
  mode?: DefenceConfig['mode'];
  sourceIdentifier?: string;
  sourceType?: DefenceSource['type'];
}

/**
 * Standalone content scanner. Does NOT store memories.
 * Use this as middleware to scan content before passing it to any memory backend.
 */
export class ShieldCortexGuard {
  private config: DefenceConfig;
  private source: DefenceSource;

  constructor(options: ShieldCortexGuardConfig = {}) {
    this.config = {
      ...DEFAULT_DEFENCE_CONFIG,
      mode: options.mode ?? 'balanced',
    };
    this.source = {
      type: options.sourceType ?? 'agent',
      identifier: options.sourceIdentifier ?? 'langchain-guard',
    };
  }

  /**
   * Scan content through the full defence pipeline.
   * Returns the pipeline result — check result.allowed.
   */
  scan(content: string, title?: string, source?: DefenceSource): DefencePipelineResult {
    return runDefencePipeline(
      content,
      title ?? 'Untitled',
      source ?? this.source,
      this.config,
    );
  }

  /**
   * Convenience: returns true if content is safe.
   */
  isAllowed(content: string, title?: string): boolean {
    return this.scan(content, title).allowed;
  }
}
