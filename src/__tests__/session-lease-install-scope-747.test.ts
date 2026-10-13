import { describe, expect, it } from '@jest/globals';
import { performance } from 'node:perf_hooks';
import { scopeForToolCall } from '../defence/iron-dome/session-lease.js';

const scope = (command: string) => scopeForToolCall('Bash', { command });

describe('session lease global install scope (#747)', () => {
  it.each([
    'npm list -g --depth=0 | grep -i shieldcortex',
    'npm list -g shieldcortex || echo "not install yet"',
    'npm outdated -g; git add .',
    'npm root -g && ls $(npm root -g)/shieldcortex/dist/install',
    'npm ls -g; npm view shieldcortex version',
    'npm list -g | grep -i x',
    'npm config get prefix -g; echo install',
    'npm ls --global && git add -A',
  ])('does not classify a read-only query as install: %s', (command) => {
    expect(scope(command)).not.toBe('install');
  });

  it.each([
    'npm install -g shieldcortex',
    'npm i -g shieldcortex@5.8.0',
    'npm --global install x',
    'npm --location=global install x',
    'npm --location global install x',
    'npm -g i x',
    'sudo npm install -g x',
    'NODE_ENV=x npm install -g x',
    'pnpm add -g x',
    'bun add -g x',
    'npm "install" -g x',
    'npm install "a|b" -g',
    'npm install x \\\n  -g',
    'npm list -g && npm install -g x',
    'cd /x; npm i -g y',
    'x=$(npm install -g foo)',
    'npm $(echo install) -g x',
    'npm $VERB -g x',
    'npm install -g "unbalanced',
    'npm ins -g x',
    'npm isntall -g x',
    '(npm install -g x)',
    '<(npm install -g x)',
    '>(npm install -g x)',
    'a; (npm i -g x)',
    'npm install x 2>&1 -g',
    'npm install x &>/dev/null -g',
    'npm install x >&2 -g',
    'npm install x 0<&3 -g',
    'npm install x >| log -g',
    'npm install --global=true x',
    'npm install -g=true x',
    'npm install --global-style x',
    'npm isntall -g x | xargs echo',
    'openclaw plugins install x',
  ])('keeps a global install scoped: %s', (command) => {
    expect(scope(command)).toBe('install');
  });

  it.each([
    ['repeated read-only pipeline', 'npm list -g | grep -i x; '.repeat(4200)],
    ['quote characters', '"'.repeat(100_001)],
  ])('classifies 100 KB of %s in under 200 ms', (_label, command) => {
    const durations = Array.from({ length: 3 }, () => {
      const start = performance.now();
      scope(command);
      return performance.now() - start;
    });
    expect(Math.min(...durations)).toBeLessThan(200);
  });
});
