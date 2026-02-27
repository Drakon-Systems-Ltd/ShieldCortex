import { createHash } from 'crypto';
import { mkdir, readdir, readFile, writeFile } from 'fs/promises';
import { existsSync } from 'fs';
import { homedir } from 'os';
import { join, relative, resolve } from 'path';
import type { ExternalMemoryBackend, ExternalMemoryRecord } from './universal.js';

interface MarkdownMemoryBackendOptions {
  name?: string;
  workspaceDir: string;
  rootFile?: string;
  memoryDir?: string;
}

/**
 * Generic markdown-file memory backend.
 *
 * Designed to complement file-based memory systems (OpenClaw, custom agents,
 * local notes-based memories) without replacing their native storage model.
 */
export class MarkdownMemoryBackend implements ExternalMemoryBackend {
  readonly name: string;
  private readonly workspaceDir: string;
  private readonly rootFile: string;
  private readonly memoryDir: string;

  constructor(options: MarkdownMemoryBackendOptions) {
    this.name = options.name ?? 'markdown-memory';
    this.workspaceDir = resolve(options.workspaceDir);
    this.rootFile = options.rootFile ?? 'MEMORY.md';
    this.memoryDir = options.memoryDir ?? 'memory';
  }

  async save(record: ExternalMemoryRecord): Promise<{ id: string }> {
    await mkdir(this.workspaceDir, { recursive: true });

    const rootPath = resolve(this.workspaceDir, this.rootFile);
    const timestamp = new Date().toISOString();
    const title = sanitizeHeading(record.title ?? 'Untitled memory');
    const id = record.id ?? buildRecordId(record, timestamp);

    const entry = [
      '',
      `## ${title}`,
      '',
      `${record.content.trim()}`,
      '',
      `<!-- shieldcortex:${id} ${timestamp} -->`,
      '',
    ].join('\n');

    if (!existsSync(rootPath)) {
      const header = '# Memory\n\n';
      await writeFile(rootPath, `${header}${entry}`, 'utf-8');
    } else {
      await appendToFile(rootPath, entry);
    }

    return { id };
  }

  async search(query: string, options: { limit?: number } = {}): Promise<ExternalMemoryRecord[]> {
    const normalized = query.trim().toLowerCase();
    if (!normalized) return [];

    const limit = options.limit ?? 10;
    const files = await this.listMemoryFiles();
    const ranked: Array<{ score: number; record: ExternalMemoryRecord }> = [];

    for (const file of files) {
      const content = await readFile(file, 'utf-8').catch(() => '');
      if (!content) continue;

      const idx = content.toLowerCase().indexOf(normalized);
      if (idx === -1) continue;

      const before = content.slice(0, idx);
      const line = before.split('\n').length;
      const snippet = extractSnippet(content, idx, 220);
      const score = scoreMatch(content, normalized);
      const rel = relative(this.workspaceDir, file);

      ranked.push({
        score,
        record: {
          id: `${rel}#L${line}`,
          title: `${rel}#L${line}`,
          content: snippet,
          metadata: {
            sourcePath: rel,
            line,
            provider: this.name,
          },
        },
      });
    }

    ranked.sort((a, b) => b.score - a.score);
    return ranked.slice(0, limit).map((r) => r.record);
  }

  async delete(id: string): Promise<boolean> {
    // Markdown backends are append-only by default to avoid unsafe mutation.
    // Callers can perform targeted edits themselves if they need hard delete.
    void id;
    return false;
  }

  private async listMemoryFiles(): Promise<string[]> {
    const files: string[] = [];
    const rootPath = resolve(this.workspaceDir, this.rootFile);
    if (existsSync(rootPath)) files.push(rootPath);

    const memoryPath = resolve(this.workspaceDir, this.memoryDir);
    if (!existsSync(memoryPath)) return files;

    const nested = await walkMarkdown(memoryPath);
    files.push(...nested);
    return files;
  }
}

/**
 * OpenClaw adapter built on top of markdown memory conventions.
 */
export class OpenClawMarkdownBackend extends MarkdownMemoryBackend {
  constructor(options: { workspaceDir?: string } = {}) {
    super({
      name: 'openclaw-markdown',
      workspaceDir: options.workspaceDir ?? join(homedir(), '.openclaw', 'workspace'),
      rootFile: 'MEMORY.md',
      memoryDir: 'memory',
    });
  }
}

async function appendToFile(filePath: string, text: string): Promise<void> {
  const current = await readFile(filePath, 'utf-8').catch(() => '');
  const suffix = current.endsWith('\n') ? '' : '\n';
  await writeFile(filePath, `${current}${suffix}${text}`, 'utf-8');
}

function sanitizeHeading(value: string): string {
  const trimmed = value.trim();
  return trimmed.replace(/[\r\n]+/g, ' ').slice(0, 140) || 'Untitled memory';
}

function buildRecordId(record: ExternalMemoryRecord, timestamp: string): string {
  const h = createHash('sha256');
  h.update(record.title ?? '');
  h.update('\n');
  h.update(record.content);
  h.update('\n');
  h.update(timestamp);
  return h.digest('hex').slice(0, 20);
}

function extractSnippet(content: string, at: number, span: number): string {
  const start = Math.max(0, at - span);
  const end = Math.min(content.length, at + span);
  const prefix = start > 0 ? '...' : '';
  const suffix = end < content.length ? '...' : '';
  return `${prefix}${content.slice(start, end).replace(/\s+/g, ' ').trim()}${suffix}`;
}

function scoreMatch(content: string, query: string): number {
  const lower = content.toLowerCase();
  let count = 0;
  let offset = 0;
  while (offset < lower.length) {
    const i = lower.indexOf(query, offset);
    if (i === -1) break;
    count++;
    offset = i + query.length;
  }
  return count;
}

async function walkMarkdown(dir: string): Promise<string[]> {
  const out: string[] = [];
  const entries = await readdir(dir, { withFileTypes: true }).catch(() => []);

  for (const entry of entries) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      const nested = await walkMarkdown(full);
      out.push(...nested);
      continue;
    }
    if (entry.isFile() && entry.name.toLowerCase().endsWith('.md')) {
      out.push(full);
    }
  }

  return out;
}
