/**
 * #629: read-only inspection commands (search, print lines, list, count, PR
 * listing) must not be rated as the thing their ARGUMENTS merely mention.
 * Guarded verbs are assembled at run time from fragments, so this file does
 * not itself contain the command text the guard rates.
 */
import { describe, expect, it } from '@jest/globals';
import { evaluateToolCall, readOnlyInspectionMask } from '../tool-action-guard.js';

const bash = (command: string) => evaluateToolCall('Bash', { command });
const RM = ['r', 'm'].join('');
const RF = ['-r', 'f'].join('');
const WIPE = `${RM} ${RF}`;
const CRON = ['cron', 'tab'].join('');
const STOP = ['system', 'ctl stop'].join('');
const KILL = ['ki', 'll'].join('');
const SC = ['.shield', 'cortex'].join('');
const HOST_DIR = ['.cla', 'ude'].join('');
const HOST_FILE = ['sett', 'ings.json'].join('');

const FALSE_POSITIVES: Array<[string, string]> = [
  ['awk pattern holding a delete verb', `awk '/${WIPE}/ {print NR": "$0}' scripts/x.sh`],
  ['sed -n on a file named after guarded verbs', `sed -n '1,40p' scripts/foo-${RM}-${KILL}.sh`],
  ['find -name with a guarded word', `find src -name "*${KILL}*" -o -name "*${CRON}*" | head`],
  ['wc -l on files named after guarded verbs', `wc -l scripts/${RM}-guard.sh scripts/${STOP.replace(' ', '-')}.sh`],
  ['gh pr list --search with guarded words', `gh pr list --repo X/Y --search "${KILL} ${RM} ${CRON} config.json" --json number,title`],
];

const STILL_FLAGGED: Array<[string, string]> = [
  ['recursive force delete of a real path', `${WIPE} /etc`],
  ['crontab wipe', `${CRON} -r`],
  ['stop a service', STOP + ' nginx'],
  ['read piped into a shell', `cat scripts/${RM}.sh | sh`],
  ['read piped into bash -c', `sed -n '1,5p' x.sh | bash -c "${WIPE} /etc"`],
  ['sed in-place edit', `sed -i 's/a/b/' scripts/${RM}-x.sh && ${WIPE} /etc`],
  ['awk system()', `awk 'BEGIN{system("${WIPE} /etc")}'`],
  ['awk print redirect', `awk '{print > "/etc/passwd"}' x`],
  ['find -delete', `find / -name "*.log" -delete`],
  ['find -exec', `find src -name x -exec ${WIPE} {} +`],
  ['redirect writing a guard file', `grep x f > ~/${SC}/config.json`],
  ['tee into guard config', `cat f | tee ~/${SC}/config.json`],
  ['read of the host settings file beside a stop', `cat ~/${HOST_DIR}/${HOST_FILE}; ${STOP} nginx`],
  ['read of a credential file', `cat ~/.ssh/id_rsa`],
  ['gh api write', `gh api -X DELETE repos/x/y`],
  ['xargs writer', `grep -l x . | xargs ${WIPE}`],
];

describe('#629 read-only inspection false positives', () => {
  for (const [name, cmd] of FALSE_POSITIVES) {
    it(`allows: ${name}`, () => {
      const v = bash(cmd);
      expect(v.decision).toBe('allow');
      expect(v.severity).toBe('benign');
      expect(v.signals ?? []).toEqual([]);
    });
  }
});

describe('#629 real writes and unsafe forms stay gated', () => {
  for (const [name, cmd] of STILL_FLAGGED) {
    it(`flags: ${name}`, () => {
      const v = bash(cmd);
      expect(v.decision).not.toBe('allow');
      expect((v.signals ?? []).length).toBeGreaterThan(0);
    });
  }

  it('the mask never blanks a statement with a writing form', () => {
    for (const cmd of [
      `sed -i 's/a/b/' f`, `sed -n 'w out' f`, `sed -e p f`, `awk 'BEGIN{system("x")}'`,
      `awk '{print > "f"}' x`, `find . -delete`, `find . -name x -exec y {} +`, `cat f | sh`,
      `cat f > g`, `gh api repos/x/y`, `gh pr merge 1`, `cat ~/.ssh/id_rsa`,
      // GNU sed reorders options: flags AFTER the script still take effect
      `sed -n 1p -e 'e x' f`, `sed -n 1p f -i`, `sed -n 1p f --in-place`,
      `sed -n 1p --expression='1e x' f`, `sed -n 1p -f evil.sed f`,
      // awk: same trailing-option refusal
      `awk '{print}' f -f evil.awk`, `awk '{print}' f -i inplace`,
    ]) {
      expect(readOnlyInspectionMask(cmd, cmd, cmd)).toBeNull();
    }
  });

  it('plain sed/awk reads, with or without a -- operand marker, are still read-only', () => {
    for (const cmd of [`sed -n 1p f`, `sed -n 1p -- f`, `awk '{print $1}' f`, `awk -F: '{print $1}' -- f`]) {
      expect(readOnlyInspectionMask(cmd, cmd, cmd)).not.toBeNull();
    }
  });

  it('blanks only the read statement and keeps a sibling write visible', () => {
    const cmd = `grep ${RM} f; ${WIPE} /etc`;
    const m = readOnlyInspectionMask(cmd, cmd, cmd);
    expect(m).not.toBeNull();
    expect(m!.length).toBe(cmd.length);
    expect(m).toContain(WIPE);
    expect(bash(cmd).decision).not.toBe('allow');
  });
});
