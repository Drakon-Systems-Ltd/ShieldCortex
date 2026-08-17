/**
 * #339 — the temp-root exemption must be PROVEN, not spelled.
 *
 * #170 made danger a property of the delete TARGET rather than the verb, and
 * #196 stopped that exemption being laundered by an unexamined statement. Both
 * left the temp-root arm of the test purely lexical: a token that *looked* like
 * `/tmp/...` was confined, full stop. Three ways out of that, all measured on
 * 4.54.4:
 *
 *   1. `/private/tmp/x` is the SAME directory as `/tmp/x` on Darwin and was
 *      blocked, while `/tmp/x` was allowed — the guard disagreed with itself
 *      about one path, which is how an operator learns to route around it.
 *   2. `/tmp/link/subdir` is only confined if `/tmp/link` is not a symlink out
 *      of the tree. Lexically it always was.
 *   3. `cd / && rm -rf relative-target` has a relative token, and relative
 *      tokens were assumed workspace-confined with no cwd tracking at all.
 *
 * (1) is a false positive, (2) and (3) are fail-OPEN — the quiet direction.
 *
 * Both directions are pinned here. The #170 relief this file must NOT undo is
 * re-asserted alongside every tightening: a security fix that takes the honest
 * build commands back down with it has not made anyone safer.
 *
 * Fixtures are assembled at runtime (the #196 house style) so no attack-shaped
 * literal sits on disk. Nothing here deletes anything: the live-filesystem
 * cases build a sandbox under the OS temp root, ask `evaluateToolCall` what it
 * WOULD do, and unlink/rmdir what they made.
 */
import { describe, it, expect, beforeAll, afterAll } from '@jest/globals';
import { mkdtempSync, mkdirSync, symlinkSync, unlinkSync, rmdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { evaluateToolCall } from '../tool-action-guard.js';

/** Assembled at runtime so the fixtures are not attack-shaped literals on disk. */
const RMRF = ['rm', '-rf'].join(' ');
const ETC = ['/', 'etc'].join('');
const SYSTEM_TARGET = `${ETC}/foo`;

function verdict(command: string) {
  return evaluateToolCall('Bash', { command });
}

describe('#339 — Darwin alias parity', () => {
  it('/private/tmp and /tmp are the same tree, so both are confined', () => {
    expect(verdict(`${RMRF} /tmp/sc339-missing`).decision).toBe('allow');
    expect(verdict(`${RMRF} /private/tmp/sc339-missing`).decision).toBe('allow');
  });

  it('/private/var/tmp and /var/tmp are the same tree, so both are confined', () => {
    expect(verdict(`${RMRF} /var/tmp/sc339-missing`).decision).toBe('allow');
    expect(verdict(`${RMRF} /private/var/tmp/sc339-missing`).decision).toBe('allow');
  });

  it('both spellings of the per-user temp root are confined', () => {
    expect(verdict(`${RMRF} /private/var/folders/xx/yyyy/T/sc339`).decision).toBe('allow');
    expect(verdict(`${RMRF} /var/folders/xx/yyyy/T/sc339`).decision).toBe('allow');
  });

  it('the temp ROOT itself is not a confined subdirectory', () => {
    for (const root of ['/tmp', '/private/tmp', '/var/tmp', '/private/var/tmp', '/tmp/']) {
      expect(verdict(`${RMRF} ${root}`).decision).not.toBe('allow');
    }
  });

  it('a lookalike sibling of the temp root is not confined', () => {
    expect(verdict(`${RMRF} /tmpfoo/x`).decision).toBe('block');
    expect(verdict(`${RMRF} /private/tmpfoo/x`).decision).toBe('block');
  });
});

describe('#339 — confinement is resolved, not spelled (symlink escape)', () => {
  let sandbox = '';
  const escape = () => join(sandbox, 'escape-link');
  const real = () => join(sandbox, 'real-dir');

  beforeAll(() => {
    sandbox = mkdtempSync(join(tmpdir(), 'sc339-'));
    mkdirSync(real());
    symlinkSync(ETC, escape());
  });

  afterAll(() => {
    // Unlink/rmdir only — this suite never runs a recursive delete of its own.
    for (const f of [() => unlinkSync(escape()), () => rmdirSync(real()), () => rmdirSync(sandbox)]) {
      try { f(); } catch { /* best effort */ }
    }
  });

  it('a real directory under the temp root stays confined (#170 relief holds)', () => {
    expect(verdict(`${RMRF} ${real()}`).decision).toBe('allow');
  });

  it('a temp-root path that is a symlink OUT of the tree is not confined', () => {
    expect(verdict(`${RMRF} ${escape()}`).decision).toBe('block');
  });

  it('a path THROUGH a symlinked parent is not confined even when it does not exist', () => {
    expect(verdict(`${RMRF} ${escape()}/child`).decision).toBe('block');
  });

  it('a path that does not exist at all is judged lexically and stays confined', () => {
    expect(verdict(`${RMRF} ${join(sandbox, 'never-created')}`).decision).toBe('allow');
  });

  it('one escaping target costs the exemption for the whole line', () => {
    expect(verdict(`${RMRF} ${real()} ${escape()}`).decision).toBe('block');
  });
});

describe('#339 — cwd tracking for relative targets', () => {
  it('a relative target after `cd /` is a ROOT-level target', () => {
    expect(verdict(`cd / && ${RMRF} relative-target`).decision).toBe('block');
  });

  it('a relative target after `cd` into a system directory is not confined', () => {
    expect(verdict(`cd ${ETC} && ${RMRF} foo`).decision).toBe('block');
  });

  it('a relative target after `cd` into the temp root is confined', () => {
    expect(verdict(`cd /tmp && ${RMRF} sc339-missing`).decision).toBe('allow');
    expect(verdict(`cd /private/tmp && ${RMRF} sc339-missing`).decision).toBe('allow');
  });

  it('a cd the parser cannot analyse costs the exemption for later relative targets', () => {
    const dollar = '$';
    const dests = [`${dollar}HOME`, '~', '-', '', '..', `${dollar}(pwd)`, '/tmp /etc'];
    for (const dest of dests) {
      expect(verdict(`cd ${dest} && ${RMRF} foo`).decision).not.toBe('allow');
    }
    expect(verdict(`pushd /tmp && ${RMRF} foo`).decision).not.toBe('allow');
  });

  it('an uncertain branch after a cd costs the exemption for later relative targets', () => {
    expect(verdict(`cd /tmp || cd ${ETC}; ${RMRF} foo`).decision).not.toBe('allow');
  });

  it('the implicit workspace cwd keeps ordinary build deletes allowed (#170 relief holds)', () => {
    expect(verdict(`${RMRF} dist`).decision).toBe('allow');
    expect(verdict(`cd dashboard && ${RMRF} .next && npm run build`).decision).toBe('allow');
    expect(verdict(`cd dashboard && cd .. && ${RMRF} .next`).decision).not.toBe('allow');
  });
});

describe('#339 — a symlink minted on the same line is not a proof of confinement', () => {
  it('`ln -s` into the temp root taints that destination', () => {
    expect(verdict(`ln -s ${ETC} /tmp/sc339-x && ${RMRF} /tmp/sc339-x`).decision).toBe('block');
    expect(verdict(`ln -sf ${ETC} /tmp/sc339-x && ${RMRF} /tmp/sc339-x/child`).decision).toBe('block');
    expect(verdict(`ln --symbolic ${ETC} /tmp/sc339-x && ${RMRF} /tmp/sc339-x`).decision).toBe('block');
    expect(verdict(`cp -s ${ETC}/passwd /tmp/sc339-x && ${RMRF} /tmp/sc339-x`).decision).toBe('block');
  });

  it('a mint whose destination cannot be read costs the exemption', () => {
    const dollar = '$';
    expect(verdict(`ln -s ${ETC} ${dollar}TARGET && ${RMRF} /tmp/sc339-x`).decision).toBe('block');
  });

  it('a symlink minted somewhere else does not cost an unrelated delete', () => {
    expect(verdict(`ln -s ../shared/node_modules node_modules && ${RMRF} dist`).decision).toBe('allow');
  });

  it('a hard link is not a directory traversal and costs nothing', () => {
    expect(verdict(`ln a b && ${RMRF} dist`).decision).toBe('allow');
  });
});

describe('#339 — mixed and multi-target lines', () => {
  it('a confined target next to a system target still blocks', () => {
    expect(verdict(`${RMRF} /tmp/sc339-a ${SYSTEM_TARGET}`).decision).toBe('block');
  });

  it('a confined statement never launders an unconfined one', () => {
    expect(verdict(`${RMRF} /tmp/sc339-a && ${RMRF} ${SYSTEM_TARGET}`).decision).toBe('block');
  });
});

describe('#339 — #170 / #196 invariants still hold', () => {
  it('an unconfined recursive delete is still catastrophic', () => {
    expect(verdict(`${RMRF} ${SYSTEM_TARGET}`).decision).toBe('block');
  });

  it('`rm` inside a path or identifier costs the exemption nothing', () => {
    expect(verdict(`${RMRF} build/rm-cache`).decision).toBe('allow');
    expect(verdict(`${RMRF} src/rm/generated`).decision).toBe('allow');
  });

  it('a scan that truncates never exempts what it could not read', () => {
    const filler = Array.from({ length: 70 }, (_, i) => `${RMRF} build${i}`).join(' && ');
    expect(verdict(`${filler} && ${RMRF} ${SYSTEM_TARGET}`).decision).toBe('block');
  });

  it('a command substitution is command position, and is examined', () => {
    expect(verdict(`${RMRF} dist && out=$(${RMRF} ${SYSTEM_TARGET})`).decision).toBe('block');
  });

  it('an rm the splitter cannot account for keeps the gate for the whole line', () => {
    expect(verdict(`${RMRF} dist && find . -name "*.log" -exec ${RMRF} {} +`).decision)
      .not.toBe('allow');
  });

  it('a glob under the temp root is still not confined', () => {
    expect(verdict(`cd /tmp && ${RMRF} *`).decision).toBe('block');
  });
});

describe('#339 — Vision probe rows', () => {
  const rows: Array<[string, string, 'allow' | 'block']> = [
    ['tmp-name', `${RMRF} /tmp/friday-guard-probe`, 'allow'],
    ['private-tmp', `${RMRF} /private/tmp/friday-guard-probe`, 'allow'],
    ['tmp-link-subdir', `${RMRF} /tmp/sc339-no-such-link/subdir`, 'allow'],
    ['home-nontmp', `${RMRF} /home/ubuntu/friday/guard-probe-nontmp`, 'block'],
    ['cd-root-relative', `cd / && ${RMRF} relative-target`, 'block'],
    ['var-tmp', `${RMRF} /var/tmp/x`, 'allow'],
    ['private-var-folders', `${RMRF} /private/var/folders/xx/yyyy/T/z`, 'allow'],
    ['workspace-next', `cd dashboard && ${RMRF} .next && npm run build`, 'allow'],
    ['workspace-dist', `${RMRF} dist`, 'allow'],
    ['etc-foo', `${RMRF} ${SYSTEM_TARGET}`, 'block'],
    ['tmp-glob', `cd /tmp && ${RMRF} *`, 'block'],
  ];
  for (const [label, command, expected] of rows) {
    it(`${label} → ${expected}`, () => {
      expect(verdict(command).decision).toBe(expected);
    });
  }
});

describe('#339 — the write-content scanner uses the same proof', () => {
  it('a confined delete authored into a script is not a catastrophic payload', () => {
    const v = evaluateToolCall('Write', {
      file_path: 'scripts/clean.sh',
      content: `#!/bin/sh\n${RMRF} dist\n${RMRF} /tmp/sc339-missing\n`,
    });
    expect(v.signals).not.toContain('write-content-catastrophic');
  });

  it('a relative delete after `cd /` authored into a script IS a catastrophic payload', () => {
    const v = evaluateToolCall('Write', {
      file_path: 'scripts/clean.sh',
      content: `#!/bin/sh\ncd / && ${RMRF} relative-target\n`,
    });
    expect(v.decision).toBe('block');
    expect(v.signals).toContain('write-content-catastrophic');
  });
});
