/**
 * Phase 0 extraction fixes (2026-08-11 graph audit / threat-graph design doc).
 *
 * Pins the verified junk-entity and triple-loss bugs in extract.ts:
 *  - PascalCase code identifiers (AbortError, WorkerConfig) minted as 'tool'
 *  - documentation placeholder paths (path/to/server.js) minted as 'file'
 *  - pronouns captured as 'person' by the "Name said" pattern
 *  - ops verbs captured as 'tool' by the before-keyword pattern ("Restart server")
 *  - "chose X over Y" triples silently dropped because their subject was the
 *    literal STOPWORD 'project' (nameToId lookup never resolves at insert time)
 *
 * extractFromMemory is pure — no DB needed.
 */

import { describe, expect, it } from '@jest/globals';
import { extractFromMemory } from '../graph/extract.js';

function entityNames(title: string, content: string, type?: string): string[] {
  const { entities } = extractFromMemory(title, content, 'note');
  return entities.filter(e => (type ? e.type === type : true)).map(e => e.name);
}

describe('PascalCase junk filter', () => {
  it('does not mint error/exception/config identifiers as tools', () => {
    const tools = entityNames(
      'Worker crash',
      'The BrainWorker threw an AbortError because WorkerConfig was stale.',
      'tool',
    );
    expect(tools).not.toContain('AbortError');
    expect(tools).not.toContain('WorkerConfig');
  });

  it('also filters plural identifier forms', () => {
    const tools = entityNames('Crash log', 'We kept seeing AbortErrors and DeprecationWarnings.', 'tool');
    expect(tools).not.toContain('AbortErrors');
    expect(tools).not.toContain('DeprecationWarnings');
  });

  it('still extracts ordinary PascalCase product names', () => {
    const tools = entityNames('Setup', 'Wired ShieldCortex into the pipeline.', 'tool');
    expect(tools).toContain('ShieldCortex');
  });
});

describe('placeholder path filter', () => {
  it('does not mint documentation placeholder paths as files', () => {
    const files = entityNames(
      'MCP setup',
      'Point the command at path/to/server.js and restart.',
      'file',
    );
    expect(files).not.toContain('path/to/server.js');
  });

  it('is not bypassed by the directory-path loop for placeholders under src/', () => {
    const files = entityNames(
      'Docs',
      'Edit src/path/to/module.ts to register it, or put the handler in src/foo/bar.ts.',
      'file',
    );
    expect(files).not.toContain('src/path/to/module.ts');
    expect(files).not.toContain('src/foo/bar.ts');
  });

  it('still extracts real paths and bare filenames', () => {
    const files = entityNames(
      'API fix',
      'Patched src/api/server.ts and the root server.js entry.',
      'file',
    );
    expect(files).toContain('src/api/server.ts');
    expect(files).toContain('server.js');
  });
});

describe('"Name said" pronoun filter', () => {
  it('does not mint pronouns as people', () => {
    const people = entityNames('Meeting', 'He said the cache was stale. They mentioned a fix.', 'person');
    expect(people).not.toContain('He');
    expect(people).not.toContain('They');
  });

  it('does not mint indefinite or interrogative pronouns as people', () => {
    const people = entityNames(
      'Meeting',
      'Someone mentioned the flag. Nobody asked for it. Who suggested this?',
      'person',
    );
    expect(people).not.toContain('Someone');
    expect(people).not.toContain('Nobody');
    expect(people).not.toContain('Who');
  });

  it('still extracts real names', () => {
    const people = entityNames('Meeting', 'Alice said the cache was stale.', 'person');
    expect(people).toContain('Alice');
  });
});

describe('before-keyword verb filter', () => {
  it('does not mint ops verbs before "server"/"database" as tools', () => {
    const tools = entityNames('Ops', 'Restart server after deploy. Then restart database too.', 'tool');
    expect(tools).not.toContain('Restart');
    expect(tools).not.toContain('restart');
  });

  it('also filters gerunds and environment adjectives', () => {
    const tools = entityNames(
      'Ops',
      'Restarting server now. The dev server on 3030 and the web server are fine.',
      'tool',
    );
    expect(tools).not.toContain('Restarting');
    expect(tools).not.toContain('dev');
    expect(tools).not.toContain('web');
  });

  it('still extracts real tool names before keywords', () => {
    const tools = entityNames('Ops', 'The MongoDB database is down.', 'tool');
    expect(tools).toContain('MongoDB');
  });
});

describe('"chose X over Y" triples persist with real subjects', () => {
  it('emits a direct preferred_over triple instead of a project-subject triple', () => {
    const { triples } = extractFromMemory('Decision', 'We chose PostgreSQL over MySQL for JSON support.', 'note');
    expect(triples).toContainEqual({ subject: 'PostgreSQL', predicate: 'preferred_over', object: 'MySQL' });
  });

  it('never emits triples with the unresolvable subject "project"', () => {
    const { triples } = extractFromMemory(
      'Decision',
      'We chose PostgreSQL over MySQL. Implemented Redis for caching.',
      'note',
    );
    expect(triples.filter(t => t.subject === 'project')).toHaveLength(0);
  });
});
