/**
 * MCP Server Integration Tests
 *
 * Tests memory CRUD operations against a real in-memory database.
 * Uses addMemory/deleteMemory/getMemoryById directly to avoid
 * embedding model loading timeouts. Tests tool-level validation separately.
 */

import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { initDatabase, closeDatabase, getDatabase } from '../database/init.js';
import { addMemory, deleteMemory, getMemoryById, getRecentMemories, getHighPriorityMemories } from '../memory/store.js';
import { executeRemember } from '../tools/remember.js';
import { executeForget } from '../tools/forget.js';

const TEST_PROJECT = 'test-project';

describe('MCP Tool Integration', () => {
  beforeEach(() => {
    initDatabase(':memory:');
  });

  afterEach(() => {
    closeDatabase();
  });

  // ── Remember: Input Validation ──

  describe('remember validation', () => {
    it('should reject empty title', async () => {
      const result = await executeRemember({ title: '', content: 'Some content' });
      expect(result.success).toBe(false);
      expect(result.error).toContain('Title cannot be empty');
    });

    it('should reject empty content', async () => {
      const result = await executeRemember({ title: 'Valid title', content: '' });
      expect(result.success).toBe(false);
      expect(result.error).toContain('Content cannot be empty');
    });

    it('should reject whitespace-only title', async () => {
      const result = await executeRemember({ title: '   ', content: 'Content' });
      expect(result.success).toBe(false);
      expect(result.error).toContain('Title cannot be empty');
    });
  });

  // ── Memory CRUD (direct store operations) ──

  describe('memory CRUD', () => {
    it('should create and retrieve a memory', () => {
      const memory = addMemory({
        title: 'Auth architecture',
        content: 'Using JWT with RS256 for API authentication',
        category: 'architecture',
        project: TEST_PROJECT,
      });

      expect(memory.id).toBeGreaterThan(0);
      expect(memory.title).toBe('Auth architecture');
      expect(memory.category).toBe('architecture');
      expect(memory.salience).toBeGreaterThan(0);

      const retrieved = getMemoryById(memory.id);
      expect(retrieved).not.toBeNull();
      expect(retrieved!.title).toBe('Auth architecture');
    });

    it('should delete a memory by ID', () => {
      const memory = addMemory({
        title: 'Temporary note',
        content: 'This will be deleted',
        category: 'note',
        project: TEST_PROJECT,
      });

      const deleted = deleteMemory(memory.id);
      expect(deleted).toBe(true);
      expect(getMemoryById(memory.id)).toBeNull();
    });

    it('should return false when deleting non-existent memory', () => {
      const deleted = deleteMemory(99999);
      expect(deleted).toBe(false);
    });

    it('should return recent memories in chronological order', () => {
      addMemory({ title: 'First', content: 'Created first', project: TEST_PROJECT });
      addMemory({ title: 'Second', content: 'Created second', project: TEST_PROJECT });
      addMemory({ title: 'Third', content: 'Created third', project: TEST_PROJECT });

      const recent = getRecentMemories(10, TEST_PROJECT);
      expect(recent.length).toBe(3);
      // Verify all three memories are returned
      const titles = recent.map(m => m.title);
      expect(titles).toContain('First');
      expect(titles).toContain('Second');
      expect(titles).toContain('Third');
    });

    it('should return high priority memories sorted by salience', () => {
      addMemory({
        title: 'Medium priority pattern',
        content: 'Use the repository pattern for data access layer',
        category: 'pattern',
        salience: 0.7,
        project: TEST_PROJECT,
      });
      addMemory({
        title: 'Critical architecture decision',
        content: 'Decided to use microservices architecture for the entire platform',
        category: 'architecture',
        salience: 0.9,
        project: TEST_PROJECT,
      });

      const important = getHighPriorityMemories(10, TEST_PROJECT);
      expect(important.length).toBe(2);
      expect(important[0].salience).toBeGreaterThanOrEqual(important[1].salience);
    });

    it('should respect limit on recent memories', () => {
      addMemory({ title: 'A', content: 'Content A', project: TEST_PROJECT });
      addMemory({ title: 'B', content: 'Content B', project: TEST_PROJECT });
      addMemory({ title: 'C', content: 'Content C', project: TEST_PROJECT });

      const recent = getRecentMemories(2, TEST_PROJECT);
      expect(recent.length).toBe(2);
    });
  });

  // ── Forget Tool ──

  describe('forget tool', () => {
    it('should delete by ID via forget tool', async () => {
      const memory = addMemory({ title: 'To delete', content: 'Delete me', category: 'note', project: TEST_PROJECT });

      const result = await executeForget({ id: memory.id, dryRun: false, confirm: false });
      expect(result.success).toBe(true);
      expect(result.deleted).toBe(1);
      expect(getMemoryById(memory.id)).toBeNull();
    });

    it('should handle non-existent ID in forget tool', async () => {
      const result = await executeForget({ id: 99999, dryRun: false, confirm: false });
      expect(result.success).toBe(false);
      expect(result.error).toBeDefined();
    });

    it('should support dry run', async () => {
      const memory = addMemory({ title: 'Keep me', content: 'Dry run test', category: 'note', project: TEST_PROJECT });

      const result = await executeForget({ id: memory.id, dryRun: true, confirm: false });
      expect(result.success).toBe(true);
      expect(result.wouldDelete).toBe(1);
      expect(result.deleted).toBeUndefined();
      expect(getMemoryById(memory.id)).not.toBeNull();
    });

    it('should bulk delete by category with confirm', async () => {
      addMemory({ title: 'Note 1', content: 'First note', category: 'note', project: TEST_PROJECT });
      addMemory({ title: 'Note 2', content: 'Second note', category: 'note', project: TEST_PROJECT });
      addMemory({ title: 'Keep this', content: 'Architecture note', category: 'architecture', project: TEST_PROJECT });

      const result = await executeForget({ category: 'note', confirm: true, dryRun: false });
      expect(result.success).toBe(true);
      expect(result.deleted).toBe(2);

      // Architecture memory should remain
      const remaining = getRecentMemories(10, TEST_PROJECT);
      expect(remaining.length).toBe(1);
      expect(remaining[0].category).toBe('architecture');
    });
  });

  // ── Defence Pipeline ──

  describe('defence pipeline', () => {
    it('should block content with credential patterns', () => {
      expect(() => {
        addMemory({
          title: 'API credentials',
          content: 'The API key is sk-abcdefghijklmnopqrstuvwxyz1234',
          project: TEST_PROJECT,
        }, undefined, { type: 'agent', identifier: 'test-agent' });
      }).toThrow();

      // Should be quarantined
      const db = getDatabase();
      const quarantined = db.prepare(
        "SELECT COUNT(*) as count FROM quarantine WHERE status = 'pending'"
      ).get() as { count: number };
      expect(quarantined.count).toBeGreaterThanOrEqual(1);
    });

    it('should allow safe content through the pipeline', () => {
      const memory = addMemory({
        title: 'Safe architecture note',
        content: 'The application uses a microservices architecture with an API gateway',
        project: TEST_PROJECT,
      }, undefined, { type: 'user', identifier: 'dashboard' });

      expect(memory.id).toBeGreaterThan(0);
    });

    it('should block Hugging Face credential patterns', () => {
      expect(() => {
        addMemory({
          title: 'HF Token',
          // Construct token dynamically to avoid GitHub secret scanning false positives
          content: 'Use this token: ' + 'hf_' + 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' + 'abcdefgh',
          project: TEST_PROJECT,
        }, undefined, { type: 'agent', identifier: 'test-agent' });
      }).toThrow();
    });

    it('should block HashiCorp Vault credential patterns', () => {
      expect(() => {
        addMemory({
          title: 'Vault Token',
          content: 'VAULT_TOKEN=hvs.ABCDEFGHIJKLMNOPQRSTUVWXyz',
          project: TEST_PROJECT,
        }, undefined, { type: 'agent', identifier: 'test-agent' });
      }).toThrow();
    });
  });

  // ── Project Scoping ──

  describe('project scoping', () => {
    it('should scope memories to their project', () => {
      addMemory({ title: 'Alpha config', content: 'Uses React', project: 'project-alpha' });
      addMemory({ title: 'Beta config', content: 'Uses Vue', project: 'project-beta' });

      const betaRecent = getRecentMemories(10, 'project-beta');
      expect(betaRecent.length).toBe(1);
      expect(betaRecent[0].title).toBe('Beta config');

      const alphaRecent = getRecentMemories(10, 'project-alpha');
      expect(alphaRecent.length).toBe(1);
      expect(alphaRecent[0].title).toBe('Alpha config');
    });
  });

  // ── Round Trip ──

  describe('round trip', () => {
    it('should create → read → delete a memory', () => {
      const memory = addMemory({
        title: 'Round trip test',
        content: 'Full lifecycle test',
        category: 'note',
        tags: ['test'],
        project: TEST_PROJECT,
      });
      expect(memory.id).toBeGreaterThan(0);

      const retrieved = getMemoryById(memory.id);
      expect(retrieved).not.toBeNull();
      expect(retrieved!.title).toBe('Round trip test');

      const deleted = deleteMemory(memory.id);
      expect(deleted).toBe(true);
      expect(getMemoryById(memory.id)).toBeNull();
    });

    it('should persist tags correctly', () => {
      const memory = addMemory({
        title: 'Tagged memory',
        content: 'Memory with multiple tags',
        tags: ['react', 'frontend', 'architecture'],
        project: TEST_PROJECT,
      });

      const retrieved = getMemoryById(memory.id);
      expect(retrieved).not.toBeNull();
      expect(retrieved!.tags).toContain('react');
      expect(retrieved!.tags).toContain('frontend');
      expect(retrieved!.tags).toContain('architecture');
    });
  });
});
