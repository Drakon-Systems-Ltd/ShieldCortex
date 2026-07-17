import { describe, it, expect } from '@jest/globals';
import { evaluateToolCall } from '../tool-action-guard.js';

/**
 * Guard tune pack — issue #91 (both shapes) + the #89 use/mention remainder
 * for the standalone shred token.
 *
 * #91.1: wrapper commands (`env`, `nice`, `nohup`, `time`, `stdbuf`) before a
 *        scheduler mutation evaded modify-scheduler, which only admitted bare
 *        assignments and sudo at command position.
 * #91.2: quoting the global flag (`npm install "-g" foo`) broke the `\s-g\b`
 *        anchor and degraded a host-mutating install to the sensitive
 *        local-install tier.
 * #89:   the shred token fired as file-delete anywhere in the string, gating
 *        a grep whose *search pattern* merely mentions it. It is now anchored
 *        to command position (start / separator / sudo / env-assign prefix /
 *        xargs / find -exec). `rm`/`unlink`/`rmdir` are intentionally NOT
 *        anchored here — their mention-FP class is #84's span-classifier
 *        scope.
 *
 * Discipline (house rule): every narrowed or widened rule ships with
 * must-STILL-FIRE / must-STILL-ALLOW siblings so a precision fix can never
 * quietly become a hole, plus a timing bound on adversarial input.
 */

const verdict = (command: string) => evaluateToolCall('Bash', { command });

describe('#91.1 — modify-scheduler catches wrapper-command prefixes', () => {
  const mustFire: Array<[string, string]> = [
    ['env with assignment', 'env FOO=1 crontab -e'],
    ['bare env', 'env crontab -e'],
    ['nice with -n value', 'nice -n 10 crontab -e'],
    ['nice dash-number', 'nice -10 crontab -e'],
    ['nohup', 'nohup crontab -e'],
    ['time', 'time crontab -e'],
    ['stdbuf', 'stdbuf -oL crontab -e'],
    ['sudo then wrapper', 'sudo env crontab -e'],
    ['wrapper then sudo', 'nohup sudo crontab -e'],
    ['assignment then wrapper', 'FOO=1 nohup crontab -e'],
    ['stacked wrappers', 'nohup nice -n 5 crontab -e'],
    ['after separator', 'echo hi; env crontab -e'],
    ['wrapped at(1)', 'nohup at 02:00 -f payload.sh'],
  ];
  it.each(mustFire)('fires: %s', (_name, cmd) => {
    const v = verdict(cmd);
    expect(v.decision).toBe('require_approval');
    expect(v.signals).toContain('modify-scheduler');
  });

  const mustAllow: Array<[string, string]> = [
    ['baseline sibling: crontab -l stays exempt', 'crontab -l'],
    ['wrapped read-only listing stays exempt', 'time crontab -l'],
    ['env wrapped listing stays exempt', 'env crontab -l'],
    ['env alone piped', 'env | grep PATH'],
    ['nice on a build', 'nice -n 10 npm run build'],
    ['nohup on a server', 'nohup node server.js &'],
    ['time on tests', 'time npm test'],
    ['prose mentioning the word crontab', 'echo "edit your crontab later"'],
  ];
  it.each(mustAllow)('allows: %s', (_name, cmd) => {
    const v = verdict(cmd);
    expect(v.signals).not.toContain('modify-scheduler');
    expect(v.decision).toBe('allow');
  });

  it('stays fast on adversarial wrapper-dense input (~30k chars, no match)', () => {
    const s = 'nice -n 10 env FOO=1 nohup '.repeat(1100) + 'echo done';
    const t = process.hrtime.bigint();
    verdict(s);
    const ms = Number(process.hrtime.bigint() - t) / 1e6;
    expect(ms).toBeLessThan(300);
  });
});

describe('#91.2 — install-package-global is quote-tolerant on the -g flag', () => {
  const mustFire: Array<[string, string]> = [
    ['double-quoted -g', 'npm install "-g" foo'],
    ["single-quoted -g", "npm install '-g' foo"],
    ['abbreviation branch, quoted -g', 'npm i "-g" foo'],
    ['baseline sibling: bare -g still fires', 'npm install -g foo'],
    ['baseline sibling: --global still fires', 'npm install --global foo'],
    ['yarn global add still fires', 'yarn global add foo'],
  ];
  it.each(mustFire)('fires: %s', (_name, cmd) => {
    const v = verdict(cmd);
    expect(v.decision).toBe('require_approval');
    expect(v.signals).toContain('install-package-global');
  });

  const mustAllow: Array<[string, string]> = [
    ['workspace-local install', 'npm install foo'],
    ['dev-dep install', 'npm install -D typescript'],
    ['-g prefix of a longer flag does not count', 'npm install --global-style foo'],
    ['read-only -g query sibling (from #88)', 'npm ls -g'],
  ];
  it.each(mustAllow)('does not global-gate: %s', (_name, cmd) => {
    const v = verdict(cmd);
    expect(v.signals).not.toContain('install-package-global');
  });
});

describe('#89 remainder — shred anchored to command position', () => {
  const mustAllow: Array<[string, string]> = [
    ['quoted grep pattern (the audit-table FP)', 'grep -rn "shred" src/'],
    ['bare grep word arg', 'grep -c shred docs/notes.md'],
    ['prose mention', 'echo "we should shred the old backups"'],
  ];
  it.each(mustAllow)('does not file-delete-gate: %s', (_name, cmd) => {
    const v = verdict(cmd);
    expect(v.signals).not.toContain('file-delete');
    expect(v.decision).toBe('allow');
  });

  const mustFire: Array<[string, string]> = [
    ['command at start', 'shred -n 3 secret.txt'],
    ['after sudo', 'sudo shred secret.txt'],
    ['after separator', 'cd /tmp && shred x.key'],
    ['via xargs', 'ls *.key | xargs shred'],
    ['via xargs with flags', 'ls *.key | xargs -0 -n1 shred'],
    ['via find -exec', 'find . -name "*.key" -exec shred {} \\;'],
    ['env-assignment prefix', 'FOO=1 shred x.key'],
  ];
  it.each(mustFire)('still fires: %s', (_name, cmd) => {
    const v = verdict(cmd);
    expect(v.signals).toContain('file-delete');
  });

  it('raw-device shred sibling still blocks catastrophically', () => {
    const v = verdict('shred -n 3 /dev/sda');
    expect(v.decision).toBe('block');
    expect(v.signals).toContain('shred-device');
  });
});
