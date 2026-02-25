/**
 * formatMemory Tests
 *
 * Verifies that memory content is returned in full when verbose=true
 * and truncated to 200 chars when verbose=false.
 *
 * Regression test for GitHub issue #8:
 * https://github.com/Drakon-Systems-Ltd/ShieldCortex/issues/8
 */

import { describe, it, expect } from '@jest/globals';
import type { Memory } from '../memory/types.js';
import { formatMemory } from '../tools/recall.js';

function makeMemory(overrides: Partial<Memory> = {}): Memory {
  return {
    id: 1,
    type: 'long_term',
    category: 'architecture',
    title: 'Test Memory',
    content: 'Short content',
    project: 'test',
    tags: [],
    salience: 0.8,
    accessCount: 1,
    lastAccessed: new Date(),
    createdAt: new Date(),
    decayedScore: 0.7,
    metadata: {},
    scope: 'project',
    transferable: false,
    ...overrides,
  };
}

describe('formatMemory', () => {
  const longContent = 'A'.repeat(500);
  const shortContent = 'Short content under 200 chars';

  it('should return full content when verbose=true', () => {
    const mem = makeMemory({ content: longContent });
    const output = formatMemory(mem, true);
    expect(output).toContain(longContent);
    expect(output).not.toContain('...');
  });

  it('should truncate content to 200 chars when verbose=false', () => {
    const mem = makeMemory({ content: longContent });
    const output = formatMemory(mem, false);
    expect(output).not.toContain(longContent);
    expect(output).toContain('...');
    expect(output).toContain('A'.repeat(200));
  });

  it('should truncate by default when verbose is omitted', () => {
    const mem = makeMemory({ content: longContent });
    const output = formatMemory(mem);
    expect(output).not.toContain(longContent);
    expect(output).toContain('...');
  });

  it('should not append ellipsis to short content', () => {
    const mem = makeMemory({ content: shortContent });
    const output = formatMemory(mem, false);
    expect(output).toContain(shortContent);
    expect(output).not.toContain('...');
  });

  it('should include metadata when verbose=true', () => {
    const mem = makeMemory({ content: shortContent, tags: ['test-tag'], project: 'my-project' });
    const output = formatMemory(mem, true);
    expect(output).toContain('Type: long_term');
    expect(output).toContain('Category: architecture');
    expect(output).toContain('Tags: test-tag');
    expect(output).toContain('Project: my-project');
  });
});
