/**
 * #928 round 2: entry names come from the watched file, so a name that is also
 * an Object.prototype member (__proto__, constructor, toString, ...) must be an
 * ordinary entry. Synthetic and inert: raw JSON text in an isolated temp HOME,
 * harmless placeholder values, no network, no shell.
 */
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import fs from 'fs';
import os from 'os';
import path from 'path';
import {
  WATCHED_FILES,
  diffSnapshots,
  runAgentConfigWatch,
  snapshotContent,
  type AgentConfigNotification,
  type FileSnapshot,
  type WatchedFileSpec,
} from '../audit/agent-config-watch.js';

const NAMES = ['__proto__', 'constructor', 'toString', 'hasOwnProperty', 'valueOf'];

const spec = (id: string): WatchedFileSpec => {
  const s = WATCHED_FILES.find((w) => w.id === id);
  if (!s) throw new Error(`no spec ${id}`);
  return s;
};

const q = JSON.stringify;

/** One section per case: raw JSON with an unrelated entry plus, optionally, `name` at version `v`. */
const CASES: Array<{ title: string; spec: WatchedFileSpec; keyPath: string; raw: (name: string | null, v?: string) => string }> = [
  {
    title: 'hooks',
    spec: spec('claude-settings.json'),
    keyPath: 'hooks',
    raw: (name, v = 'one') => `{"hooks":{"Other":[{"hooks":[{"type":"command","command":"echo other"}]}]${name === null ? '' : `,${q(name)}:[{"hooks":[{"type":"command","command":${q(`echo ${v}`)}}]}]`}}}`,
  },
  {
    title: 'MCP servers',
    spec: spec('claude-settings.json'),
    keyPath: 'mcpServers',
    raw: (name, v = 'one') => `{"mcpServers":{"other":{"command":"other"}${name === null ? '' : `,${q(name)}:{"command":${q(v)}}`}}}`,
  },
  {
    title: 'env',
    spec: spec('claude-settings.json'),
    keyPath: 'env',
    raw: (name, v = 'one') => `{"env":{"OTHER":"x"${name === null ? '' : `,${q(name)}:${q(v)}`}}}`,
  },
  {
    title: 'plugins',
    spec: spec('openclaw-config'),
    keyPath: 'plugins.entries',
    raw: (name, v = 'one') => `{"plugins":{"entries":{"other":{"enabled":true}${name === null ? '' : `,${q(name)}:{"enabled":true,"tag":${q(v)}}`}}}}`,
  },
  {
    title: 'task labels',
    spec: spec('vscode-tasks'),
    keyPath: 'tasks',
    raw: (name, v = 'one') => `{"tasks":[{"label":"other","command":"echo other"}${name === null ? '' : `,{"label":${q(name)},"command":${q(`echo ${v}`)}}`}]}`,
  },
];

/** A baseline as the check reads it back from disk: plain JSON-parsed objects. */
const restored = (s: FileSnapshot): FileSnapshot => JSON.parse(JSON.stringify(s));

describe.each(CASES)('prototype-named entries in $title (#928 r2)', ({ spec: sp, keyPath, raw }) => {
  it.each(NAMES)('%s: added, removed and edited are each reported', (name) => {
    const without = snapshotContent(raw(null), sp);
    const withOne = snapshotContent(raw(name, 'one'), sp);
    const withTwo = snapshotContent(raw(name, 'two'), sp);
    // The entry is kept as data in the snapshot, not lost to an inherited setter.
    expect(Object.keys(withOne[keyPath])).toHaveLength(2);
    expect(Object.keys(withOne[keyPath])).toContain(name);
    expect(Object.prototype.hasOwnProperty.call(withOne[keyPath], name)).toBe(true);

    expect(diffSnapshots(sp, without, withOne)).toEqual([{ keyPath, section: expect.any(String), kind: 'added', name }]);
    expect(diffSnapshots(sp, withOne, without)).toEqual([{ keyPath, section: expect.any(String), kind: 'removed', name }]);
    expect(diffSnapshots(sp, withOne, withTwo)).toEqual([{ keyPath, section: expect.any(String), kind: 'changed', name }]);
    expect(diffSnapshots(sp, withOne, snapshotContent(raw(name, 'one'), sp))).toEqual([]);
  });

  it.each(NAMES)('%s: a JSON-restored baseline never resolves a missing name to an inherited value', (name) => {
    const without = restored(snapshotContent(raw(null), sp));
    const withOne = snapshotContent(raw(name, 'one'), sp);
    expect(diffSnapshots(sp, without, withOne)).toEqual([{ keyPath, section: expect.any(String), kind: 'added', name }]);
    expect(diffSnapshots(sp, restored(withOne), snapshotContent(raw(null), sp))).toEqual([{ keyPath, section: expect.any(String), kind: 'removed', name }]);
    expect(diffSnapshots(sp, restored(withOne), snapshotContent(raw(name, 'two'), sp))).toEqual([{ keyPath, section: expect.any(String), kind: 'changed', name }]);
    expect(diffSnapshots(sp, restored(withOne), withOne)).toEqual([]);
  });
});

describe('task label collisions with prototype names (#928 r2)', () => {
  const sp = spec('vscode-tasks');
  const tasks = (...t: Array<[string, string]>) => `{"tasks":[${t.map(([l, c]) => `{"label":${q(l)},"command":${q(c)}}`).join(',')}]}`;

  it.each(NAMES)('two tasks labelled %s share one bucket; adding, editing or removing one is reported', (name) => {
    const one = snapshotContent(tasks([name, 'echo a']), sp);
    const two = snapshotContent(tasks([name, 'echo a'], [name, 'echo b']), sp);
    const edited = snapshotContent(tasks([name, 'echo a'], [name, 'echo c']), sp);
    expect(Object.prototype.hasOwnProperty.call(two.tasks, name)).toBe(true);
    expect(two.tasks[name]).toHaveLength(2);
    expect(diffSnapshots(sp, one, two)).toEqual([{ keyPath: 'tasks', section: 'tasks', kind: 'added', name }]);
    expect(diffSnapshots(sp, restored(two), one)).toEqual([{ keyPath: 'tasks', section: 'tasks', kind: 'removed', name }]);
    expect(diffSnapshots(sp, restored(two), edited)).toEqual([{ keyPath: 'tasks', section: 'tasks', kind: 'changed', name }]);
  });

  it('distinct prototype-named labels stay distinct entries', () => {
    const snap = snapshotContent(tasks(['__proto__', 'echo a'], ['constructor', 'echo b'], ['toString', 'echo c']), sp);
    expect(Object.keys(snap.tasks).sort()).toEqual(['__proto__', 'constructor', 'toString']);
    expect(snap.tasks.__proto__).toHaveLength(1);
  });
});

describe('end to end through the signed on-disk baseline (#928 r2)', () => {
  let home: string;
  let project: string;
  let notes: AgentConfigNotification[];
  const settings = () => path.join(home, '.claude', 'settings.json');
  const write = (raw: string) => { fs.mkdirSync(path.dirname(settings()), { recursive: true }); fs.writeFileSync(settings(), raw); };
  const run = () => runAgentConfigWatch({ home, projectRoots: [project], notify: async (n) => { notes.push(n); }, ledger: () => true });

  beforeEach(() => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-928r2-home-'));
    project = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-928r2-proj-'));
    notes = [];
  });
  afterEach(() => {
    fs.rmSync(home, { recursive: true, force: true });
    fs.rmSync(project, { recursive: true, force: true });
  });

  it('alerts on a prototype-named MCP server being added, edited and removed', async () => {
    write('{"mcpServers":{"other":{"command":"other"}}}');
    await run();
    expect(notes).toHaveLength(0);

    write('{"mcpServers":{"other":{"command":"other"},"__proto__":{"command":"one"},"constructor":{"command":"one"}}}');
    await run();
    expect(notes).toHaveLength(1);
    expect(notes[0].changes).toEqual(expect.arrayContaining([
      { label: 'MCP server added', name: '__proto__' },
      { label: 'MCP server added', name: 'constructor' },
    ]));
    expect(notes[0].changeCount).toBe(2);

    write('{"mcpServers":{"other":{"command":"other"},"__proto__":{"command":"two"},"constructor":{"command":"one"}}}');
    await run();
    expect(notes).toHaveLength(2);
    expect(notes[1].changes).toEqual([{ label: 'MCP server changed', name: '__proto__' }]);

    write('{"mcpServers":{"other":{"command":"other"}}}');
    await run();
    expect(notes).toHaveLength(3);
    expect(notes[2].changes).toEqual(expect.arrayContaining([
      { label: 'MCP server removed', name: '__proto__' },
      { label: 'MCP server removed', name: 'constructor' },
    ]));

    await run();
    expect(notes).toHaveLength(3);
  });
});
