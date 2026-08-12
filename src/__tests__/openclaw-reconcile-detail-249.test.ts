/**
 * Review regressions on #249 (PR reviews 4913640155 and the round-3 follow-up).
 *
 * Every finding was reproduced against built code before being fixed, and each
 * test that pins a fix fails on the commit preceding it. The remainder are
 * guard cases asserting behaviour that must NOT change, and pass either side.
 *
 * The theme, twice over: a third party's chatter on our streams must carry no
 * authority. Round 2 stopped it VETOING a real verdict; round 3 stopped it
 * MANUFACTURING one. Fixing either direction alone leaves the mirror open.
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

describe('#249: only validator-owned lines may reach a verdict', () => {
  const run = (stdout: string, stderr: string) => validateOpenClawConfig(HOME, {
    exists: () => true,
    resolveBin: () => '/usr/bin/openclaw',
    run: () => ({ status: 1, stdout, stderr } as never),
  });

  it('plugin chatter cannot MANUFACTURE strong proof under an explicit refusal', () => {
    // The mirror of the round-2 finding: having stopped chatter vetoing a real
    // verdict, it must not be able to supply a fake one either.
    const v = run('[plugins] acme migration failed: cached config is invalid\nUnknown command: config validate\n', '');
    expect(v.state).toBe('indeterminate');
  });

  it('plugin chatter cannot manufacture the JSON verdict form either', () => {
    const v = run('[plugins] acme: last run reported "valid": false\nUnknown command: config validate\n', '');
    expect(v.state).toBe('indeterminate');
  });

  it('plugin chatter cannot supply a REFUSAL that vetoes a real verdict', () => {
    const v = run('OpenClaw config is invalid:\n  × bad key\n', '[plugins] acme: unknown option --x\n');
    expect(v.state).toBe('invalid');
  });

  it('detail comes from the stream carrying the verdict, not merely from stderr', () => {
    const v = run('OpenClaw config is invalid:\n  × channels.telegram: bad key\n', '[plugins] acme: noisy chatter\n');
    expect(v.state).toBe('invalid');
    expect(v.detail?.join('\n')).toContain('bad key');
    expect(v.detail?.join('\n')).not.toMatch(/exited 1/);
  });

  it('still reports invalid from stderr in the normal inverted case', () => {
    const v = run('', 'OpenClaw config is invalid:\n  × agents.main: unknown field\n');
    expect(v.state).toBe('invalid');
    expect(v.detail?.join('\n')).toContain('unknown field');
  });
});

describe('#249 round 4: chatter provenance survives wrapping and log prefixes', () => {
  const run = (stdout: string, stderr: string) => validateOpenClawConfig(HOME, {
    exists: () => true,
    resolveBin: () => '/usr/bin/openclaw',
    run: () => ({ status: 1, stdout, stderr } as never),
  });

  it('a WRAPPED continuation line under a chatter header carries no vote', () => {
    // The round-3 fix tested the tag on the line that has it. A plugin whose
    // message runs onto a second, indented line put `config is invalid` on a
    // line with no tag — and manufactured strong proof under an explicit
    // refusal, which is the same fail-open breach wearing a different shape.
    const v = run('[plugins] acme migration failed:\n  cached config is invalid\nUnknown command: config validate\n', '');
    expect(v.state).toBe('indeterminate');
  });

  it('a timestamp-prefixed chatter line carries no vote', () => {
    const v = run('2026-08-12T07:00:00.123Z [plugins] acme: cached config is invalid\nUnknown command: config validate\n', '');
    expect(v.state).toBe('indeterminate');
  });

  it('a bracketed-clock and level prefix carries no vote either', () => {
    const v = run('[07:00:00] WARN [plugins] acme: cached "valid": false\nUnknown command: config validate\n', '');
    expect(v.state).toBe('indeterminate');
  });

  it('an ANSI-coloured chatter tag carries no vote', () => {
    const v = run('[36m[plugins][0m acme: cached config is invalid\nUnknown command: config validate\n', '');
    expect(v.state).toBe('indeterminate');
  });

  it('the block ENDS at the next top-level line — OpenClaw keeps its vote', () => {
    // The guard against over-stripping: swallowing the rest of the stream
    // after any chatter line would silence the validator and re-open #221.
    const v = run('', '[plugins] acme noise:\n  more acme noise\nOpenClaw config is invalid:\n  × agents.main: unknown field\n');
    expect(v.state).toBe('invalid');
    expect(v.detail?.join('\n')).toContain('unknown field');
  });

  it('an indented bullet with no chatter above it still convicts', () => {
    // Indentation alone must never mean "someone else said it" — OpenClaw
    // indents its own issue bullets.
    const v = run('', 'OpenClaw config is invalid:\n  × agents.main: unknown field\n');
    expect(v.state).toBe('invalid');
  });
});

describe('#249 round 4: a split header/detail must not lose the cause', () => {
  const run = (stdout: string, stderr: string) => validateOpenClawConfig(HOME, {
    exists: () => true,
    resolveBin: () => '/usr/bin/openclaw',
    run: () => ({ status: 1, stdout, stderr } as never),
  });

  it('merges verdict-bearing evidence across BOTH streams', () => {
    // `.find()` stopped at the first stream that matched — the header — and
    // reported `OpenClaw config is invalid:` alone, which names no cause and
    // leaves the operator exactly where #221 left them.
    const v = run('  × channels.pager: bad key\n', 'OpenClaw config is invalid:\n');
    expect(v.state).toBe('invalid');
    const detail = v.detail?.join('\n') ?? '';
    expect(detail).toContain('channels.pager');
    expect(detail).toContain('config is invalid');
  });

  it('does not drag in a stream that carries no verdict evidence', () => {
    const v = run('Loaded 12 plugins in 340ms\n', 'OpenClaw config is invalid:\n  × agents.main: unknown field\n');
    expect(v.state).toBe('invalid');
    expect(v.detail?.join('\n')).not.toContain('340ms');
  });
});

describe('#249: chatter provenance survives wrapping and logger prefixes', () => {
  const ESC = String.fromCharCode(27);
  const run = (stdout: string, stderr: string) => validateOpenClawConfig(HOME, {
    exists: () => true,
    resolveBin: () => '/usr/bin/openclaw',
    run: () => ({ status: 1, stdout, stderr } as never),
  });
  const REFUSED = 'Unknown command: config validate\n';

  it('evidence on a plugin block\'s CONTINUATION line carries no authority', () => {
    const v = run(`[plugins] acme migration failed:\n  cached config is invalid\n${REFUSED}`, '');
    expect(v.state).toBe('indeterminate');
  });

  it('a timestamp before the tag does not launder it', () => {
    const v = run(`2026-08-12T07:00:00Z [plugins] acme: cached config is invalid\n${REFUSED}`, '');
    expect(v.state).toBe('indeterminate');
  });

  it('a log level before the tag does not launder it', () => {
    const v = run(`WARN [plugins] acme: cached config is invalid\n${REFUSED}`, '');
    expect(v.state).toBe('indeterminate');
  });

  it('ANSI colour around the tag does not launder it', () => {
    const v = run(`${ESC}[32m[plugins]${ESC}[0m acme: cached config is invalid\n${REFUSED}`, '');
    expect(v.state).toBe('indeterminate');
  });

  // The over-stripping risk. Indentation alone cannot mean "third party" —
  // OpenClaw's own issue bullets are indented, and they are the entire reason
  // an operator can act. A broad rule would pass the tests above and silently
  // destroy this one.
  it('does NOT swallow OpenClaw\'s own indented bullets', () => {
    const v = run('', 'OpenClaw config is invalid:\n  × channels.telegram: bad key\n  × agents.main: unknown field\n');
    expect(v.state).toBe('invalid');
    expect(v.detail?.join('\n')).toContain('bad key');
  });

  it('a plugin block ENDS as soon as OpenClaw speaks again', () => {
    const v = run('', '[plugins] acme: warming up\n  still warming\nOpenClaw config is invalid:\n  × channels.telegram: bad key\n');
    expect(v.state).toBe('invalid');
    expect(v.detail?.join('\n')).toContain('bad key');
    expect(v.detail?.join('\n')).not.toContain('warming');
  });

  it('merges evidence when the header and its cause land on different streams', () => {
    const v = run('  × channels.telegram: bad key\n', 'OpenClaw config is invalid:\n');
    expect(v.state).toBe('invalid');
    const detail = v.detail?.join('\n') ?? '';
    expect(detail).toContain('config is invalid');
    expect(detail).toContain('bad key');
  });
});
