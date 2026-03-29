import { describe, it, expect } from '@jest/globals';

describe('Interceptor', () => {
  describe('extractContent', () => {
    it('should extract title and content from remember args', async () => {
      const { extractContent } = await import('../../../plugins/openclaw/interceptor.js');
      const result = extractContent('remember', {
        title: 'test title',
        content: 'test content',
        category: 'note',
        tags: ['a', 'b'],
      });
      expect(result).toEqual({ title: 'test title', content: 'test content' });
    });

    it('should return empty strings for unwatched tool', async () => {
      const { extractContent } = await import('../../../plugins/openclaw/interceptor.js');
      const result = extractContent('bash', { command: 'ls' });
      expect(result).toEqual({ title: '', content: '' });
    });

    it('should handle missing fields gracefully', async () => {
      const { extractContent } = await import('../../../plugins/openclaw/interceptor.js');
      const result = extractContent('remember', { category: 'note' });
      expect(result).toEqual({ title: '', content: '' });
    });
  });

  describe('mapSeverity', () => {
    it('should map BLOCK to critical', async () => {
      const { mapSeverity } = await import('../../../plugins/openclaw/interceptor.js');
      expect(mapSeverity({ result: 'BLOCK', anomalyScore: 0.9 })).toBe('critical');
    });

    it('should map QUARANTINE to high', async () => {
      const { mapSeverity } = await import('../../../plugins/openclaw/interceptor.js');
      expect(mapSeverity({ result: 'QUARANTINE', anomalyScore: 0.6 })).toBe('high');
    });

    it('should map ALLOW with high anomaly to medium', async () => {
      const { mapSeverity } = await import('../../../plugins/openclaw/interceptor.js');
      expect(mapSeverity({ result: 'ALLOW', anomalyScore: 0.5 })).toBe('medium');
    });

    it('should map ALLOW with low anomaly to low', async () => {
      const { mapSeverity } = await import('../../../plugins/openclaw/interceptor.js');
      expect(mapSeverity({ result: 'ALLOW', anomalyScore: 0.1 })).toBe('low');
    });

    it('should use 0.3 as the medium threshold boundary', async () => {
      const { mapSeverity } = await import('../../../plugins/openclaw/interceptor.js');
      expect(mapSeverity({ result: 'ALLOW', anomalyScore: 0.3 })).toBe('medium');
      expect(mapSeverity({ result: 'ALLOW', anomalyScore: 0.29 })).toBe('low');
    });
  });
});
