/**
 * Fragmentation Entity Extraction Tests
 *
 * Tests for extracting security-relevant entities from memory content.
 */

import { describe, it, expect } from '@jest/globals';

describe('Entity Extractor', () => {
  it('should extract URLs from content', async () => {
    const { extractEntities } = await import('../fragmentation/entity-extractor.js');
    const entities = extractEntities('Visit https://example.com/page and http://test.org');
    const urls = entities.filter((e) => e.type === 'url');
    expect(urls.length).toBe(2);
    expect(urls.map((u) => u.value)).toContain('https://example.com/page');
    expect(urls.map((u) => u.value)).toContain('http://test.org');
  });

  it('should extract IP addresses', async () => {
    const { extractEntities } = await import('../fragmentation/entity-extractor.js');
    const entities = extractEntities('Server is at 192.168.1.100 and backup at 10.0.0.5');
    const ips = entities.filter((e) => e.type === 'ip_address');
    expect(ips.length).toBe(2);
    expect(ips.map((i) => i.value)).toContain('192.168.1.100');
  });

  it('should extract file paths', async () => {
    const { extractEntities } = await import('../fragmentation/entity-extractor.js');
    const entities = extractEntities('Config is at /etc/nginx/nginx.conf');
    const paths = entities.filter((e) => e.type === 'file_path');
    expect(paths.length).toBeGreaterThan(0);
    expect(paths[0].value).toContain('/etc/nginx');
  });

  it('should extract API key patterns', async () => {
    const { extractEntities } = await import('../fragmentation/entity-extractor.js');

    const entities1 = extractEntities('OpenAI key: sk-abcdefghijklmnopqrstuvwxyz1234');
    expect(entities1.some((e) => e.type === 'api_key')).toBe(true);

    const entities2 = extractEntities('AWS key: AKIAIOSFODNN7EXAMPLE');
    expect(entities2.some((e) => e.type === 'api_key')).toBe(true);

    const entities3 = extractEntities('GitHub token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl');
    expect(entities3.some((e) => e.type === 'api_key')).toBe(true);
  });

  it('should return empty array for clean content with no entities', async () => {
    const { extractEntities } = await import('../fragmentation/entity-extractor.js');
    const entities = extractEntities('This is a simple note about project planning.');
    expect(entities).toHaveLength(0);
  });

  it('should deduplicate entities', async () => {
    const { extractEntities } = await import('../fragmentation/entity-extractor.js');
    const entities = extractEntities(
      'Visit https://example.com and again https://example.com',
    );
    const urls = entities.filter((e) => e.type === 'url');
    expect(urls.length).toBe(1);
  });
});
