import fs from 'fs';
import path from 'path';
import os from 'os';
import { createFindingsStore, FindingsStoreUnreadableError } from '../findings-store.js';
import type { XRayFinding } from '../types.js';

function makeTempDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'sc-findings-test-'));
}

function makeFinding(overrides: Partial<XRayFinding> = {}): XRayFinding {
  return {
    severity: 'high',
    category: 'eval-exec',
    title: 'Dangerous eval usage',
    description: 'Found eval() call with dynamic input',
    file: 'src/index.js',
    line: 42,
    ...overrides,
  };
}

describe('FindingsStore', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = makeTempDir();
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  describe('addFindings', () => {
    it('creates findings with UUIDs and new status', () => {
      const store = createFindingsStore(tmpDir);
      const raw = [makeFinding(), makeFinding({ title: 'Shell injection' })];

      const added = store.addFindings('scan-1', 'scan', '/project', raw);

      expect(added).toHaveLength(2);
      expect(added[0].id).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
      );
      expect(added[0].status).toBe('new');
      expect(added[0].sourceId).toBe('scan-1');
      expect(added[0].sourceKind).toBe('scan');
      expect(added[0].target).toBe('/project');
      expect(added[0].detectedAt).toBeTruthy();
      expect(added[0].updatedAt).toBeTruthy();
      expect(added[1].title).toBe('Shell injection');
    });

    it('deduplicates findings with same target+category+title+file+line', () => {
      const store = createFindingsStore(tmpDir);
      const finding = makeFinding();

      const first = store.addFindings('scan-1', 'scan', '/project', [finding]);
      expect(first).toHaveLength(1);

      const second = store.addFindings('scan-2', 'scan', '/project', [finding]);
      expect(second).toHaveLength(0);

      // All findings in store should still be just 1
      expect(store.listFindings()).toHaveLength(1);
    });

    it('deduplicates against findings the user already triaged (Phase 17 B5)', () => {
      // Re-detecting a finding the user has resolved or ignored must NOT
      // re-create it as `new` — that would undo their triage on every scan.
      for (const status of ['resolved', 'ignored', 'reviewed', 'quarantined'] as const) {
        const dir = makeTempDir();
        try {
          const store = createFindingsStore(dir);
          const finding = makeFinding();

          const first = store.addFindings('scan-1', 'scan', '/project', [finding]);
          expect(first).toHaveLength(1);
          store.updateFindingStatus(first[0].id, status);

          // Same finding re-detected on a later scan — should be deduped away.
          const second = store.addFindings('scan-2', 'scan', '/project', [finding]);
          expect(second).toHaveLength(0);

          // The triaged finding is untouched; no duplicate `new` row appeared.
          const all = store.listFindings();
          expect(all).toHaveLength(1);
          expect(all[0].status).toBe(status);
        } finally {
          fs.rmSync(dir, { recursive: true, force: true });
        }
      }
    });

    it('enforces 500 max cap', () => {
      const store = createFindingsStore(tmpDir);
      const bigBatch: XRayFinding[] = [];
      for (let i = 0; i < 510; i++) {
        bigBatch.push(makeFinding({ title: `Finding ${i}`, line: i }));
      }

      store.addFindings('scan-1', 'scan', '/project', bigBatch);
      const all = store.listFindings();
      expect(all.length).toBeLessThanOrEqual(500);
    });

    it('cleans up resolved/ignored findings older than 30 days', () => {
      const store = createFindingsStore(tmpDir);

      // Add a finding and mark it resolved
      const added = store.addFindings('scan-1', 'scan', '/project', [makeFinding()]);
      store.updateFindingStatus(added[0].id, 'resolved');

      // Manually backdate the updatedAt to 31 days ago
      const filePath = path.join(tmpDir, 'xray-findings.json');
      const data = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
      data[0].updatedAt = new Date(Date.now() - 31 * 24 * 60 * 60 * 1000).toISOString();
      fs.writeFileSync(filePath, JSON.stringify(data));

      // Adding new findings triggers cleanup
      store.addFindings('scan-2', 'scan', '/project', [makeFinding({ title: 'New one' })]);

      const all = store.listFindings();
      expect(all).toHaveLength(1);
      expect(all[0].title).toBe('New one');
    });
  });

  describe('getFinding', () => {
    it('retrieves a finding by ID', () => {
      const store = createFindingsStore(tmpDir);
      const added = store.addFindings('scan-1', 'scan', '/project', [makeFinding()]);

      const found = store.getFinding(added[0].id);
      expect(found).not.toBeNull();
      expect(found!.id).toBe(added[0].id);
      expect(found!.title).toBe('Dangerous eval usage');
    });

    it('returns null for unknown ID', () => {
      const store = createFindingsStore(tmpDir);
      expect(store.getFinding('nonexistent')).toBeNull();
    });
  });

  describe('updateFindingStatus', () => {
    it('changes status and sets updatedAt', () => {
      const store = createFindingsStore(tmpDir);
      const added = store.addFindings('scan-1', 'scan', '/project', [makeFinding()]);

      // Backdate the finding so updatedAt will definitely change
      const filePath = path.join(tmpDir, 'xray-findings.json');
      const data = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
      data[0].updatedAt = '2020-01-01T00:00:00.000Z';
      fs.writeFileSync(filePath, JSON.stringify(data));

      const updated = store.updateFindingStatus(added[0].id, 'reviewed', 'Looks fine');

      expect(updated).not.toBeNull();
      expect(updated!.status).toBe('reviewed');
      expect(updated!.resolutionNote).toBe('Looks fine');
      expect(updated!.updatedAt).not.toBe('2020-01-01T00:00:00.000Z');
    });

    it('returns null for unknown ID', () => {
      const store = createFindingsStore(tmpDir);
      expect(store.updateFindingStatus('nonexistent', 'reviewed')).toBeNull();
    });
  });

  describe('listFindings', () => {
    it('returns all findings without filters', () => {
      const store = createFindingsStore(tmpDir);
      store.addFindings('scan-1', 'scan', '/project', [
        makeFinding(),
        makeFinding({ title: 'Other', severity: 'low' }),
      ]);

      expect(store.listFindings()).toHaveLength(2);
    });

    it('filters by status', () => {
      const store = createFindingsStore(tmpDir);
      const added = store.addFindings('scan-1', 'scan', '/project', [
        makeFinding(),
        makeFinding({ title: 'Other' }),
      ]);
      store.updateFindingStatus(added[0].id, 'reviewed');

      const reviewed = store.listFindings({ status: 'reviewed' });
      expect(reviewed).toHaveLength(1);
      expect(reviewed[0].status).toBe('reviewed');
    });

    it('filters by target', () => {
      const store = createFindingsStore(tmpDir);
      store.addFindings('scan-1', 'scan', '/project-a', [makeFinding()]);
      store.addFindings('scan-2', 'scan', '/project-b', [makeFinding({ title: 'B finding' })]);

      const results = store.listFindings({ target: 'project-a' });
      expect(results).toHaveLength(1);
      expect(results[0].target).toBe('/project-a');
    });

    it('filters by severity', () => {
      const store = createFindingsStore(tmpDir);
      store.addFindings('scan-1', 'scan', '/project', [
        makeFinding({ severity: 'critical' }),
        makeFinding({ title: 'Low risk', severity: 'low' }),
      ]);

      const critical = store.listFindings({ severity: 'critical' });
      expect(critical).toHaveLength(1);
      expect(critical[0].severity).toBe('critical');
    });

    it('respects limit', () => {
      const store = createFindingsStore(tmpDir);
      store.addFindings('scan-1', 'scan', '/project', [
        makeFinding({ title: 'A', line: 1 }),
        makeFinding({ title: 'B', line: 2 }),
        makeFinding({ title: 'C', line: 3 }),
      ]);

      const limited = store.listFindings({ limit: 2 });
      expect(limited).toHaveLength(2);
    });
  });

  describe('deleteFinding', () => {
    it('removes a finding from the store', () => {
      const store = createFindingsStore(tmpDir);
      const added = store.addFindings('scan-1', 'scan', '/project', [makeFinding()]);

      expect(store.deleteFinding(added[0].id)).toBe(true);
      expect(store.getFinding(added[0].id)).toBeNull();
      expect(store.listFindings()).toHaveLength(0);
    });

    it('returns false for unknown ID', () => {
      const store = createFindingsStore(tmpDir);
      expect(store.deleteFinding('nonexistent')).toBe(false);
    });
  });

  describe('quarantineFile', () => {
    it('moves the source file to quarantine directory', () => {
      const store = createFindingsStore(tmpDir);

      // Create a temp source file
      const sourceDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-quarantine-src-'));
      const sourceFile = path.join(sourceDir, 'malicious.js');
      fs.writeFileSync(sourceFile, 'eval(dangerous_code)');

      const added = store.addFindings('scan-1', 'scan', sourceDir, [
        makeFinding({ file: sourceFile }),
      ]);

      const result = store.quarantineFile(added[0].id, 'Suspicious code');

      expect(result.moved).toBe(true);
      expect(result.quarantinePath).toBeTruthy();
      expect(fs.existsSync(sourceFile)).toBe(false);
      expect(fs.existsSync(result.quarantinePath!)).toBe(true);

      // Verify file content was preserved
      const quarantinedContent = fs.readFileSync(result.quarantinePath!, 'utf-8');
      expect(quarantinedContent).toBe('eval(dangerous_code)');

      // Verify finding status was updated
      const finding = store.getFinding(added[0].id);
      expect(finding!.status).toBe('quarantined');

      // Cleanup
      fs.rmSync(sourceDir, { recursive: true, force: true });
    });

    it('returns error for unknown finding ID', () => {
      const store = createFindingsStore(tmpDir);
      const result = store.quarantineFile('nonexistent');
      expect(result.moved).toBe(false);
      expect(result.error).toBe('Finding not found');
    });

    it('returns error for finding without file path', () => {
      const store = createFindingsStore(tmpDir);
      const added = store.addFindings('scan-1', 'scan', '/project', [
        makeFinding({ file: undefined }),
      ]);

      const result = store.quarantineFile(added[0].id);
      expect(result.moved).toBe(false);
      expect(result.error).toBe('Finding has no file path');
    });

    it('marks as quarantined even when source file does not exist', () => {
      const store = createFindingsStore(tmpDir);
      const added = store.addFindings('scan-1', 'scan', '/project', [
        makeFinding({ file: '/nonexistent/file.js' }),
      ]);

      const result = store.quarantineFile(added[0].id);
      expect(result.moved).toBe(false);
      expect(result.error).toBe('Source file does not exist');

      const finding = store.getFinding(added[0].id);
      expect(finding!.status).toBe('quarantined');
    });
  });

  describe('getStats', () => {
    it('returns counts by status', () => {
      const store = createFindingsStore(tmpDir);
      const added = store.addFindings('scan-1', 'scan', '/project', [
        makeFinding({ title: 'A', line: 1 }),
        makeFinding({ title: 'B', line: 2 }),
        makeFinding({ title: 'C', line: 3 }),
        makeFinding({ title: 'D', line: 4 }),
      ]);

      store.updateFindingStatus(added[0].id, 'reviewed');
      store.updateFindingStatus(added[1].id, 'ignored');
      store.updateFindingStatus(added[2].id, 'resolved');

      const stats = store.getStats();
      expect(stats.total).toBe(4);
      expect(stats.new).toBe(1);
      expect(stats.reviewed).toBe(1);
      expect(stats.ignored).toBe(1);
      expect(stats.resolved).toBe(1);
      expect(stats.quarantined).toBe(0);
    });

    it('returns all zeroes for empty store', () => {
      const store = createFindingsStore(tmpDir);
      const stats = store.getStats();
      expect(stats.total).toBe(0);
      expect(stats.new).toBe(0);
    });

    // #692: a never-created file is a real zero; an existing file that cannot
    // be read or parsed is unknown and must not report zero.
    it('reports a never-created findings file as absent with zero counts', () => {
      const store = createFindingsStore(path.join(tmpDir, 'never-created'));
      expect(store.getStoreState()).toBe('absent');
      expect(store.getStats()).toMatchObject({ total: 0, new: 0, store: 'absent' });
    });

    it('reports a readable findings file as ok', () => {
      const store = createFindingsStore(tmpDir);
      store.addFindings('scan-1', 'scan', '/project', [makeFinding()]);
      expect(store.getStoreState()).toBe('ok');
      expect(store.getStats()).toMatchObject({ total: 1, new: 1, store: 'ok' });
    });

    it.each([
      ['malformed JSON', '{"not": json'],
      ['a non-array JSON value', '{"findings": []}'],
    ])('refuses to count %s as zero', (_label, body) => {
      fs.writeFileSync(path.join(tmpDir, 'xray-findings.json'), body);
      const store = createFindingsStore(tmpDir);
      expect(store.getStoreState()).toBe('unreadable');
      expect(() => store.getStats()).toThrow(FindingsStoreUnreadableError);
    });

    // #692 R2: a JSON array is not enough. Every entry must be a finding the
    // store can count by lifecycle and render, or the whole file is unknown.
    const valid = (over: Record<string, unknown> = {}) => ({
      ...makeFinding(), id: 'f-1', sourceId: 'scan-1', sourceKind: 'scan', target: '/project',
      status: 'new', detectedAt: '2026-01-01T00:00:00.000Z', updatedAt: '2026-01-01T00:00:00.000Z', ...over,
    });
    const { status: _omitStatus, ...missingStatus } = valid();
    it.each([
      ['an empty object entry', [{}]],
      ['a number entry', [42]],
      ['a null entry', [null]],
      ['an unrecognised status', [valid({ status: 'unrecognised' })]],
      ['a missing status', [missingStatus]],
      ['an unknown severity', [valid({ severity: 'severe' })]],
      ['a missing id', [valid({ id: undefined })]],
      ['a valid entry mixed with an invalid one', [valid(), valid({ id: 'f-2', status: 'bogus' })]],
      ['a valid entry mixed with a non-object', [valid(), 'oops']],
    ])('refuses to count a findings array with %s', (_label, entries) => {
      fs.writeFileSync(path.join(tmpDir, 'xray-findings.json'), JSON.stringify(entries));
      const store = createFindingsStore(tmpDir);
      expect(store.getStoreState()).toBe('unreadable');
      expect(() => store.getStats()).toThrow(FindingsStoreUnreadableError);
    });

    it('accepts a findings array whose every entry is valid', () => {
      fs.writeFileSync(path.join(tmpDir, 'xray-findings.json'), JSON.stringify([valid(), valid({ id: 'f-2', status: 'resolved', file: null, line: null })]));
      const store = createFindingsStore(tmpDir);
      expect(store.getStoreState()).toBe('ok');
      expect(store.getStats()).toMatchObject({ total: 2, new: 1, resolved: 1, store: 'ok' });
    });

    it('does not drop the valid entries of a partly invalid file when a scan adds findings', () => {
      // f-2 stays `new` so the 30-day cleanup of triaged findings does not apply.
      fs.writeFileSync(path.join(tmpDir, 'xray-findings.json'), JSON.stringify([valid(), valid({ id: 'f-2', severity: 'severe' })]));
      const store = createFindingsStore(tmpDir);
      expect(store.getStoreState()).toBe('unreadable');
      store.addFindings('scan-2', 'scan', '/other', [makeFinding({ title: 'fresh' })]);
      const ids = (JSON.parse(fs.readFileSync(path.join(tmpDir, 'xray-findings.json'), 'utf-8')) as Array<{ id: string }>).map((f) => f.id);
      expect(ids).toEqual(expect.arrayContaining(['f-1', 'f-2']));
    });

    it('recovery guidance does not name a fixed home path or promise a scan repairs the file', () => {
      const msg = new FindingsStoreUnreadableError('x').message;
      expect(msg).not.toMatch(/~|\/home|\.shieldcortex\//);
      expect(msg).not.toMatch(/next scan (starts|replaces)/);
      expect(msg).toMatch(/Scanning does not repair it/);
    });

    it('refuses to count an unreadable (directory) findings path as zero', () => {
      fs.mkdirSync(path.join(tmpDir, 'xray-findings.json'));
      const store = createFindingsStore(tmpDir);
      expect(store.getStoreState()).toBe('unreadable');
      expect(() => store.getStats()).toThrow(FindingsStoreUnreadableError);
    });
  });
});
