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
    "npm list -g # it's fine",
    'echo "npm is great" && npm list -g',
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
    "# '\nnpm i -g evil\n# '",
    "cd /srv # it's\nnpm install -g evil\necho ok # don't",
    'echo a#b\nnpm install -g evil',
    'echo "# text"\nnpm install -g evil',
    'bash -c "cd /; npm install -g evil"',
    "sh -c 'true && npm i -g evil'",
    'ssh host "cd /; npm i -g evil"',
    'bash -c "sh -c \'npm i -g evil\'"',
    'bash -c "echo \\"hi\\"; npm i -g evil"',
    'npm run build && sh -c "npm install -g x"',
    'npm $(cat verb) -g x',
    'npm $(printf ins) -g x',
    'npm $(echo aW5zdGFsbA== | base64 -d) -g x',
    'npm "$(cat verb)" --global x',
    'npm $(cat verb) --location=global x',
    'cd /tmp && npm $(cat verb) -g x',
    'npm -g $(cat verb) x',
    'x=$(npm i -g y)',
    'npm $( $(echo install) ) -g x',
    'if ! command -v x; then npm install -g x; fi',
    '{ npm install -g x; }',
    'while true; do npm install -g x; done',
    '! npm install -g x',
    'time npm install -g x',
  ])('keeps a global install scoped: %s', (command) => {
    expect(scope(command)).toBe('install');
  });

  it.each([
    ['repeated read-only pipeline', 'npm list -g | grep -i x; '.repeat(4200)],
    ['quote characters', '"'.repeat(100_001)],
    ['nested shell quotes', 'bash -c "'.repeat(11_000) + 'unterminated tail'],
    ['many short quotes', "'a'".repeat(30_000)],
  ])('classifies 100 KB of %s in under 200 ms', (_label, command) => {
    const durations = Array.from({ length: 3 }, () => {
      const start = performance.now();
      scope(command);
      return performance.now() - start;
    });
    expect(Math.min(...durations)).toBeLessThan(200);
  });
});
