/**
 * Round-2 review regressions on #249 (PR review 4913640155).
 *
 * All three were reproduced against built code before being fixed; each test
 * below fails on the previous commit.
 */
import { summariseCommandOutput } from '../integrations/child-output.js';
import { validateOpenClawConfig } from '../integrations/openclaw-config-validate.js';

const HOME = '/home/tester';
const TOKEN = 'SEKRET-abc123456789';

describe('#249: a non-empty guarantee must not bypass redaction', () => {
  it('redacts the env token even when the ONLY surviving line carries it', () => {
    // Single line, so there is no other line the picker could prefer: if the
    // token is absent it is because redaction removed it, not because the
    // line was not chosen.
    const out = `npm warn auth token=${TOKEN} written to ${HOME}/.npmrc`;
    const r = summariseCommandOutput(out, {
      maxLines: 1, dropPluginChatter: false, mode: 'failure', neverEmpty: true,
      env: { NPM_TOKEN: TOKEN }, home: HOME,
    });
    expect(r.lines).toHaveLength(1);
    expect(r.lines[0]).not.toContain(TOKEN);
    // Either redaction layer may claim it — env-value substitution runs first,
    // the credential detector then rewrites its marker. Assert the secret is
    // gone and SOMETHING said so, not which layer got there first.
    expect(r.lines[0]).toMatch(/redacted/i);
    expect(r.lines[0]).not.toContain(HOME);
    expect(r.lines[0]).toContain('~/.npmrc');
  });

  it('caps an over-long noise line rather than emitting it whole', () => {
    const out = `npm warn ${'x'.repeat(5000)}`;
    const r = summariseCommandOutput(out, {
      maxLines: 1, neverEmpty: true, dropPluginChatter: false, home: HOME,
    });
    expect(r.lines[0].length).toBeLessThanOrEqual(200);
    expect(r.truncated).toBe(true);
  });

  it('still returns nothing when there was nothing', () => {
    expect(summariseCommandOutput('   \n  \n', { neverEmpty: true }).lines).toEqual([]);
  });

  it('does not re-admit noise unless asked', () => {
    expect(summariseCommandOutput('npm warn only noise here', { maxLines: 1 }).lines).toEqual([]);
  });
});

describe('#249: strong invalid proof beats the refusal veto', () => {
  const run = (stdout: string, stderr: string) => validateOpenClawConfig(HOME, {
    exists: () => true,
    resolveBin: () => '/usr/bin/openclaw',
    run: () => ({ status: 1, stdout, stderr } as never),
  });

  it('stays invalid when unrelated plugin chatter mentions an unknown option', () => {
    const v = run('OpenClaw config is invalid:\n  × bad key\n', '[plugins] acme: unknown option --x\n');
    expect(v.state).toBe('invalid');
  });

  it('stays invalid on the JSON verdict form', () => {
    const v = run('{"valid": false}', '[plugins] acme: unknown command foo\n');
    expect(v.state).toBe('invalid');
  });

  it('still vetoes when the only invalidity evidence is a bullet', () => {
    const v = run('Unknown command: config validate\n', '[plugins] acme: ✗ failed to load\n');
    expect(v.state).toBe('indeterminate');
  });
});

describe('#249: retained plugin chatter is a last resort, not a promotion', () => {
  it('ranks the real npm failure above another plugin\'s TypeError', () => {
    const out = [
      '[plugins] acme: TypeError: Cannot read properties of undefined',
      'npm error code EAI_AGAIN',
      'npm error request to https://registry.npmjs.org failed, reason: getaddrinfo EAI_AGAIN',
    ].join('\n');
    const r = summariseCommandOutput(out, {
      maxLines: 1, dropPluginChatter: false, mode: 'failure', home: HOME,
    });
    expect(r.lines[0]).toContain('EAI_AGAIN');
  });

  it('still surfaces plugin chatter when it is the only thing there', () => {
    const out = '[plugins] acme: manifest not found';
    const r = summariseCommandOutput(out, {
      maxLines: 1, dropPluginChatter: false, mode: 'failure', home: HOME,
    });
    expect(r.lines[0]).toContain('manifest not found');
  });

  it('prefers a non-plugin line on the no-signal tail path too', () => {
    const out = ['[plugins] acme: loaded late', 'at Object.<anonymous> (/app/x.js:1:1)'].join('\n');
    const r = summariseCommandOutput(out, {
      maxLines: 1, dropPluginChatter: false, mode: 'failure', home: HOME,
    });
    expect(r.lines[0]).toContain('x.js');
  });
});
