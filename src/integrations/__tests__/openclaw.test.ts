import { afterEach, describe, expect, it } from '@jest/globals';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'fs/promises';
import { join } from 'path';
import { tmpdir } from 'os';
import { MarkdownMemoryBackend, OpenClawMarkdownBackend } from '../openclaw.js';

const tempDirs: string[] = [];

async function makeTempDir(prefix: string): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

afterEach(async () => {
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop();
    if (dir) {
      await rm(dir, { recursive: true, force: true });
    }
  }
});

describe('MarkdownMemoryBackend', () => {
  it('should create MEMORY.md and append entries', async () => {
    const workspaceDir = await makeTempDir('shieldcortex-md-');
    const backend = new MarkdownMemoryBackend({ workspaceDir });

    await backend.save({
      title: 'Deploy note',
      content: 'Deployment is handled by GitHub Actions.',
    });
    await backend.save({
      title: 'Auth note',
      content: 'Auth service uses PostgreSQL.',
    });

    const root = await readFile(join(workspaceDir, 'MEMORY.md'), 'utf-8');
    expect(root).toContain('# Memory');
    expect(root).toContain('## Deploy note');
    expect(root).toContain('## Auth note');
    expect(root).toContain('<!-- shieldcortex:');
  });

  it('should search across root and memory directory markdown files', async () => {
    const workspaceDir = await makeTempDir('shieldcortex-search-');
    const backend = new MarkdownMemoryBackend({ workspaceDir });

    await backend.save({
      title: 'Cache design',
      content: 'Redis stores response cache.',
    });

    const memoryDir = join(workspaceDir, 'memory');
    await mkdir(memoryDir, { recursive: true });
    await writeFile(
      join(memoryDir, 'architecture.md'),
      '# Architecture\n\nPostgreSQL is the source of truth for auth.\n',
      'utf-8',
    );

    const results = await backend.search('postgresql', { limit: 5 });

    expect(results.length).toBeGreaterThan(0);
    expect(results[0].metadata?.provider).toBe('markdown-memory');
  });

  it('should be append-only by default for delete()', async () => {
    const workspaceDir = await makeTempDir('shieldcortex-delete-');
    const backend = new MarkdownMemoryBackend({ workspaceDir });

    const deleted = await backend.delete('any-id');
    expect(deleted).toBe(false);
  });
});

describe('OpenClawMarkdownBackend', () => {
  it('should use openclaw-markdown provider name with override workspace', async () => {
    const workspaceDir = await makeTempDir('shieldcortex-openclaw-');
    const backend = new OpenClawMarkdownBackend({ workspaceDir });

    expect(backend.name).toBe('openclaw-markdown');

    await backend.save({
      title: 'OpenClaw memory',
      content: 'This memory complements native memory tooling.',
    });

    const root = await readFile(join(workspaceDir, 'MEMORY.md'), 'utf-8');
    expect(root).toContain('OpenClaw memory');
  });
});
