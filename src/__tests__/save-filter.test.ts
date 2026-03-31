/**
 * Tests for Memory Save Filter (v4.0.0)
 */

import { describe, it, expect } from '@jest/globals';

describe('Memory Save Filter', () => {
  it('should allow normal memory content', async () => {
    const { shouldFilterMemory } = await import('../memory/save-filter.js');
    const result = shouldFilterMemory(
      'Architecture decision',
      'We decided to use PostgreSQL because it supports JSONB and has good TypeScript support'
    );
    expect(result.allowed).toBe(true);
  });

  it('should filter file path content', async () => {
    const { shouldFilterMemory } = await import('../memory/save-filter.js');
    const result = shouldFilterMemory(
      'File location',
      'File is at /home/user/projects/app/src/index.ts'
    );
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain('file');
  });

  it('should filter git commit references', async () => {
    const { shouldFilterMemory } = await import('../memory/save-filter.js');
    const result = shouldFilterMemory(
      'Last commit',
      'commit abc1234567890 fixed the bug'
    );
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain('Git');
  });

  it('should filter import statements', async () => {
    const { shouldFilterMemory } = await import('../memory/save-filter.js');
    const result = shouldFilterMemory(
      'Import note',
      'import { useState } from "react"'
    );
    expect(result.allowed).toBe(false);
  });

  it('should filter environment variable content', async () => {
    const { shouldFilterMemory } = await import('../memory/save-filter.js');
    const result = shouldFilterMemory(
      'Env var',
      'DATABASE_URL = postgres://localhost:5432/mydb'
    );
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain('Environment');
  });

  it('should allow content when filterDerivable is disabled', async () => {
    const { shouldFilterMemory } = await import('../memory/save-filter.js');
    const result = shouldFilterMemory(
      'File location',
      'File is at /home/user/projects/app/src/index.ts',
      { filterDerivable: false }
    );
    expect(result.allowed).toBe(true);
  });

  it('should filter short content that is mostly file paths', async () => {
    const { shouldFilterMemory } = await import('../memory/save-filter.js');
    const result = shouldFilterMemory(
      'Config path',
      '~/config/app.yaml'
    );
    expect(result.allowed).toBe(false);
  });
});
