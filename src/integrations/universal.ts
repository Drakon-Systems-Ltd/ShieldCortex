import { runDefencePipeline } from '../defence/pipeline.js';
import { DEFAULT_DEFENCE_CONFIG } from '../defence/types.js';
import type { DefenceConfig, DefencePipelineResult, DefenceSource } from '../defence/types.js';

export interface ExternalMemoryRecord {
  id?: string;
  title?: string;
  content: string;
  tags?: string[];
  metadata?: Record<string, unknown>;
  createdAt?: string;
}

export interface ExternalMemoryBackend {
  readonly name: string;
  save(record: ExternalMemoryRecord): Promise<{ id: string }>;
  search?(query: string, options?: { limit?: number }): Promise<ExternalMemoryRecord[]>;
  delete?(id: string): Promise<boolean>;
}

export interface GuardedMemoryBridgeConfig {
  mode?: DefenceConfig['mode'];
  sourceType?: DefenceSource['type'];
  sourceIdentifier?: string;
  blockOnThreat?: boolean;
}

export interface GuardedSaveResult {
  allowed: boolean;
  externalId?: string;
  defence: DefencePipelineResult;
  reason: string;
}

export interface GuardedSearchResult {
  results: ExternalMemoryRecord[];
  blocked: Array<{ record: ExternalMemoryRecord; reason: string }>;
  advisories: Array<{ record: ExternalMemoryRecord; reason: string }>;
}

/**
 * Wraps any memory backend with ShieldCortex defence checks.
 *
 * This is the core "complement" integration: existing memory systems keep
 * their own storage, while ShieldCortex adds security/audit controls.
 */
export class ShieldCortexGuardedMemoryBridge {
  private readonly backend: ExternalMemoryBackend;
  private readonly config: DefenceConfig;
  private readonly sourceType: DefenceSource['type'];
  private readonly sourceIdentifier: string;
  private readonly blockOnThreat: boolean;

  constructor(backend: ExternalMemoryBackend, options: GuardedMemoryBridgeConfig = {}) {
    this.backend = backend;
    this.config = {
      ...DEFAULT_DEFENCE_CONFIG,
      mode: options.mode ?? DEFAULT_DEFENCE_CONFIG.mode,
    };
    this.sourceType = options.sourceType ?? 'api';
    this.sourceIdentifier = options.sourceIdentifier ?? 'external-memory-bridge';
    this.blockOnThreat = options.blockOnThreat ?? true;
  }

  async save(record: ExternalMemoryRecord): Promise<GuardedSaveResult> {
    const source: DefenceSource = {
      type: this.sourceType,
      identifier: `${this.sourceIdentifier}:${this.backend.name}:write`,
    };

    const defence = runDefencePipeline(
      record.content,
      record.title ?? `${this.backend.name} external memory write`,
      source,
      this.config,
      getProjectScope(record.metadata),
    );

    if (!defence.allowed && this.blockOnThreat) {
      return {
        allowed: false,
        defence,
        reason: defence.firewall.reason,
      };
    }

    const saved = await this.backend.save(record);

    return {
      allowed: true,
      externalId: saved.id,
      defence,
      reason: defence.firewall.reason,
    };
  }

  async search(query: string, options: { limit?: number } = {}): Promise<GuardedSearchResult> {
    if (!this.backend.search) {
      throw new Error(`Backend ${this.backend.name} does not support search()`);
    }

    const records = await this.backend.search(query, options);
    const allowed: ExternalMemoryRecord[] = [];
    const blocked: Array<{ record: ExternalMemoryRecord; reason: string }> = [];
    const advisories: Array<{ record: ExternalMemoryRecord; reason: string }> = [];

    for (const record of records) {
      const source: DefenceSource = {
        type: this.sourceType,
        identifier: `${this.sourceIdentifier}:${this.backend.name}:read`,
      };

      const defence = runDefencePipeline(
        record.content,
        record.title ?? `${this.backend.name} external memory read`,
        source,
        this.config,
        getProjectScope(record.metadata),
      );

      if (defence.allowed) {
        allowed.push(record);
      } else if (this.blockOnThreat) {
        blocked.push({ record, reason: defence.firewall.reason });
      } else {
        // Advisory mode: return the record but keep explicit risk context.
        allowed.push(record);
        advisories.push({ record, reason: defence.firewall.reason });
      }
    }

    return {
      results: allowed,
      blocked,
      advisories,
    };
  }

  async delete(id: string): Promise<boolean> {
    if (!this.backend.delete) {
      throw new Error(`Backend ${this.backend.name} does not support delete()`);
    }

    const source: DefenceSource = {
      type: this.sourceType,
      identifier: `${this.sourceIdentifier}:${this.backend.name}:delete`,
    };
    const idPreview = String(id).slice(0, 512);
    const defence = runDefencePipeline(
      `delete_request:${idPreview}`,
      `${this.backend.name} external memory delete`,
      source,
      this.config,
    );

    if (!defence.allowed && this.blockOnThreat) {
      return false;
    }

    return this.backend.delete(id);
  }
}

function getProjectScope(metadata: Record<string, unknown> | undefined): string | undefined {
  if (!metadata) return undefined;
  const project = metadata.project;
  return typeof project === 'string' ? project : undefined;
}
