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
  // #994 review: a program or pattern loaded FROM A FILE is the class the
  // sed/awk stages already refuse; the file operand must stay visible.
  ['jq program from a file named after a delete verb', `jq -f ${RM}.jq data.json`],
  ['jq --from-file of the same', `jq --from-file ${RM}.jq data.json`],
  ['jq -f inside a short cluster', `jq -rf ${RM}.jq data.json`],
  ['grep pattern file named after a delete verb', `grep -f ${RM}.pat f`],
  ['grep --file of the same', `grep --file ${RM}.pat f`],
  ['find -exec on a normal tree', `find src -name "*.sh" -exec ${WIPE} {} +`],
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

  // #994 review (CASE): the closed-set path refused only `--opt=value`, so a
  // jq/grep whose PROGRAM or PATTERN is loaded from a file was blanked and the
  // file operand hidden from every later rule. Every spelling: own word, long
  // form with and without `=`, glued, and anywhere inside a short cluster.
  it('the mask never blanks a jq/grep stage whose program or pattern comes from a file', () => {
    for (const cmd of [
      `jq -f p.jq d.json`, `jq --from-file p.jq d.json`, `jq --from-file=p.jq d.json`,
      `jq -rf p.jq d.json`, `jq -nf p.jq`, `jq -cfr p.jq d.json`,
      `jq -L lib -n 1`, `jq -Llib -n 1`, `jq --library-path lib -n 1`, `jq --library-path=lib -n 1`,
      `jq . d.json -f p.jq`,
      `grep -f pats f`, `grep --file pats f`, `grep --file=pats f`, `grep -fpats f`,
      `grep -rf pats .`, `grep -nf pats f`, `grep -if pats f`, `grep x f -f pats`,
      `egrep -f pats f`, `fgrep -f pats f`, `egrep --file pats f`, `fgrep -rf pats .`,
      `cat f | jq -f p.jq`, `cat f | grep -f pats`,
    ]) {
      expect(readOnlyInspectionMask(cmd, cmd, cmd)).toBeNull();
    }
  });

  it('jq/grep reads whose program or pattern is on the command line are still read-only', () => {
    for (const cmd of [
      `jq . d.json`, `jq -r .a d.json`, `jq -c '.a | length' d.json`,
      `grep -n x f`, `grep -e x f`, `grep -F x f`, `grep -L x f`, `grep -rn x src`,
      // after `--` a dash word is an operand (the pattern), not an option
      `grep -n -- -f f`,
    ]) {
      expect(readOnlyInspectionMask(cmd, cmd, cmd)).not.toBeNull();
    }
  });

  it('the mask ignores find -delete and -exec on a normal (non-root) tree', () => {
    for (const cmd of [
      `find src -name "x.log" -delete`, `find src -type f -name "x.log" -delete`,
      // braces quoted: an unquoted `{` is vetoed command-wide before the find
      // grammar runs, so these reach READONLY_FIND_PREDICATES and fail there
      `find src -type f -exec cat "{}" +`, `find src -name "x" -exec y "{}" ";"`,
      `find src -name "x.log" -execdir y "{}" +`, `find src -name "x.log" -ok y "{}" +`,
      `find src -type f -exec cat {} +`,
    ]) {
      expect(readOnlyInspectionMask(cmd, cmd, cmd)).toBeNull();
    }
    // ...while the same predicates in read-only form on the same tree are blanked.
    for (const cmd of [`find src -name "x.log"`, `find src -type f -name "x.log" -print`]) {
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

// Release review (v5.20.0, Grok B1): the mask was dropped only when the text
// left after blanking matched EXTERNAL_EGRESS (curl, wget, nc, scp, rsync, …).
// A print-only inspection statement whose arguments hold a destructive phrase,
// next to a sibling that reaches the network some other way (ssh, npx,
// openssl, git, socat, a python URL opener), was blocked on v5.19.0 and became
// an allow. The mask is now kept only when everything left after blanking is
// itself local (another closed-set read, a plain echo, pwd or true): any other
// sibling may reach the network, so the whole command is judged as before.
describe('release review G-B1 — no relaxation next to a sibling that can reach the network', () => {
  const SSH = ['s', 'sh'].join('');
  const NPX = ['n', 'px'].join('');
  const AWK_READ = `awk '/${WIPE}/ {print NR": "$0}' scripts/x.sh`;
  const GH_READ = `gh pr list --repo X/Y --search "${KILL} ${RM} ${CRON} config.json" --json number,title`;
  const FIND_READ = `find src -name "*${WIPE.replace(' ', '')}*" -print`;
  const SIBLINGS: Array<[string, string]> = [
    ['ssh', `${SSH} deploy@build.example.invalid`],
    ['npx', `${NPX} some-pkg`],
    ['openssl s_client', 'openssl s_client -connect example.invalid:443'],
    ['git push', 'git push origin main'],
    ['socat', 'socat - TCP:example.invalid:443'],
    ['python URL opener', `python3 -c "import urllib.request as u; u.urlopen('https://example.invalid')"`],
  ];
  const READS: Array<[string, string]> = [['awk', AWK_READ], ['gh pr list --search', GH_READ], ['find -name', FIND_READ]];

  for (const [readName, read] of READS) {
    for (const [sibName, sib] of SIBLINGS) {
      for (const sep of ['; ', ' && ']) {
        const cmd = `${read}${sep}${sib}`;
        it(`judges ${readName} beside ${sibName} (${sep.trim()}) as it did before the mask`, () => {
          const v = bash(cmd);
          expect(v.decision).not.toBe('allow');
          // ...exactly as the same command with the read left visible (v5.19.0's surface).
          const unmasked = bash(`${cmd} # keep`);
          expect(v.decision).toBe(unmasked.decision);
          expect(v.severity).toBe(unmasked.severity);
        });
      }
    }
  }

  it('the destructive phrase in the read is what still blocks (ssh and npx siblings, the reviewer\'s cases)', () => {
    const GH_WIPE_READ = `gh pr list --repo X/Y --search "${WIPE}" --json number,title`;
    const FIND_WIPE_READ = `find src -name "${WIPE}" -print`;
    for (const read of [AWK_READ, GH_WIPE_READ, FIND_WIPE_READ]) {
      expect(readOnlyInspectionMask(read, read, read)).not.toBeNull(); // the read alone is still relieved
      expect(bash(read).decision).toBe('allow');
      for (const sib of [`${SSH} deploy@build.example.invalid`, `${NPX} some-pkg`]) {
        const v = bash(`${read}; ${sib}`);
        expect(v.decision).toBe('block');
        expect(v.severity).toBe('catastrophic');
      }
    }
  });

  it('control: a curl sibling stays blocked, as before', () => {
    const v = bash(`${AWK_READ}; curl https://example.invalid/x`);
    expect(v.decision).toBe('block');
  });

  it('control: inspection alone, or beside a local sibling (read, echo, pwd, true), keeps the #629 relief', () => {
    for (const cmd of [
      AWK_READ, GH_READ, FIND_READ,
      `${AWK_READ}; echo done`, `${AWK_READ} && wc -l scripts/x.sh`, `${GH_READ}; pwd`, `${FIND_READ} | head; true`,
      `${AWK_READ}; ${GH_READ}`,
    ]) {
      const v = bash(cmd);
      expect(v.decision).toBe('allow');
      expect(v.signals ?? []).toEqual([]);
    }
  });
});
