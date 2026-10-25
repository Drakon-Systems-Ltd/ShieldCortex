import { describe, expect, it } from '@jest/globals';
// @ts-expect-error plain .mjs launcher
import { maybeSpawnAgentConfigWatch, agentConfigWatchEnabled } from '../../scripts/lib/agent-config-watch-spawn.mjs';
import fs from 'fs';
import os from 'os';
import path from 'path';

describe('agent config watch session-start launcher (#916)', () => {
  const dist = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-916-dist-'));
  fs.mkdirSync(path.join(dist, 'audit'), { recursive: true });
  fs.writeFileSync(path.join(dist, 'audit', 'agent-config-watch-runner.js'), '');
  const fakeSpawn = (calls: unknown[]) => ((cmd: string, args: string[], o: unknown) => { calls.push({ cmd, args, o }); return { on() {}, unref() {} }; }) as never;

  it('spawns detached by default and not when opted out', () => {
    const calls: any[] = [];
    expect(maybeSpawnAgentConfigWatch({}, { distRoot: dist, spawnImpl: fakeSpawn(calls) })).toBe(true);
    expect(calls[0].o).toMatchObject({ detached: true, stdio: 'ignore' });
    expect(maybeSpawnAgentConfigWatch({ sessionStart: { agentConfigWatch: false } }, { distRoot: dist, spawnImpl: fakeSpawn(calls) })).toBe(false);
    expect(calls).toHaveLength(1);
    expect(agentConfigWatchEnabled({ sessionStart: { agentConfigWatch: false } })).toBe(false);
  });

  it('fails open when the build is missing or spawn throws', () => {
    expect(maybeSpawnAgentConfigWatch({}, { distRoot: path.join(dist, 'nope') })).toBe(false);
    expect(maybeSpawnAgentConfigWatch({}, { distRoot: dist, spawnImpl: (() => { throw new Error('x'); }) as never })).toBe(false);
  });
});
