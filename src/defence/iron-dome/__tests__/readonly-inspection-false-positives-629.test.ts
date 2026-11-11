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
      `grep -n x f`, `grep -F x f`, `grep -L x f`, `grep -rn x src`,
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

// #1051: a grep option that takes a value (or one the mask cannot name) means
// the guard cannot tell which word is the pattern and which a file, so the
// stage is never blanked. Only closed sets of no-argument short clusters and
// exact long options, plus the `--` terminator, keep the relief.
const GREPS = ['grep', 'egrep', 'fgrep'];
// An unquoted delete verb as the pattern: the file-delete rule rates it
// whenever its statement is not blanked (a quoted phrase is already data).
const GUARDED_PATTERN = RM;
// Each entry is the option word(s) placed before the pattern.
const GREP_VALUE_OR_UNKNOWN_OPTIONS = [
  '-A 2', '-A2', '-B 3', '-B3', '-C 1', '-C1', '-m 1', '-m1', '-e', '-d skip', '-D skip',
  '-nA2', '-iC1', '-nm1', '-rne', '-5', '-NUM',
  '--exclude-dir x', '--exclude x', '--include x', '--label x', '--max-count 1',
  '--after-context 2', '--before-context 2', '--context 1', '--regexp', '--binary-files text',
  '--devices skip', '--directories skip', '--exclude-from x', '--group-separator x',
  // abbreviations and unknown long options are not in the closed set either
  '--max 1', '--exc x', '--frobnicate', '--binary',
];
const GREP_STILL_MASKED = [
  '-n', '--', '-n --', '-rn', '-inw', '-c', '-l', '-L', '-F', '-E', '-o', '-v', '-x', '-H', '-h',
  '--color', '--colour', '--color -n', '--line-number', '--ignore-case --fixed-strings',
  '--recursive', '--count', '--files-with-matches', '--only-matching', '--invert-match',
];

describe('#1051 grep options the #629 mask cannot model decline the mask', () => {
  it('never blanks a grep/egrep/fgrep stage with a value-taking or unknown option', () => {
    for (const verb of GREPS) {
      for (const opt of GREP_VALUE_OR_UNKNOWN_OPTIONS) {
        for (const cmd of [`${verb} ${opt} P f`, `cat f | ${verb} ${opt} P`, `${verb} -n x f; ${verb} ${opt} P f`]) {
          const m = readOnlyInspectionMask(cmd, cmd, cmd);
          // the stage with the option must stay visible, whatever else is blanked
          expect(m === null ? cmd : m).toContain(`${verb} ${opt} P`);
        }
      }
    }
  });

  it('an option after the pattern still declines (GNU grep permutes options)', () => {
    for (const verb of GREPS) {
      for (const cmd of [`${verb} P f -A 2`, `${verb} P f -m1`, `${verb} -n P f --exclude-dir x`]) {
        expect(readOnlyInspectionMask(cmd, cmd, cmd)).toBeNull();
      }
    }
  });

  it('no-argument clusters, exact no-argument long options and -- keep the relief', () => {
    for (const verb of GREPS) {
      for (const opt of GREP_STILL_MASKED) {
        const cmd = `${verb} ${opt} P f`;
        expect(readOnlyInspectionMask(cmd, cmd, cmd)).toBe(' '.repeat(cmd.length));
      }
      // after `--` every word is an operand, dash-led or not
      for (const cmd of [`${verb} -n -- -A f`, `${verb} -- -m1 f`, `${verb} -- --exclude-dir f`]) {
        expect(readOnlyInspectionMask(cmd, cmd, cmd)).toBe(' '.repeat(cmd.length));
      }
    }
  });

  it('reviewer probes: a guarded pattern behind a value-taking option is rated', () => {
    const probes = [
      `grep -A 2 ${GUARDED_PATTERN} f`, `grep -A2 ${GUARDED_PATTERN} f`,
      `grep -B 3 ${GUARDED_PATTERN} f`, `grep -C1 ${GUARDED_PATTERN} f`,
      `grep -m 1 ${GUARDED_PATTERN} f`, `grep --exclude-dir x ${GUARDED_PATTERN} f`,
      `grep -e ${GUARDED_PATTERN} f`, `egrep -A 2 ${GUARDED_PATTERN} f`,
      `fgrep -m1 ${GUARDED_PATTERN} f`,
    ];
    for (const cmd of probes) {
      expect(readOnlyInspectionMask(cmd, cmd, cmd)).toBeNull();
      const v = bash(cmd);
      expect(v.decision).not.toBe('allow');
      expect((v.signals ?? []).length).toBeGreaterThan(0);
    }
  });

  it('the same pattern behind -n or -- is still relieved', () => {
    for (const verb of GREPS) {
      for (const cmd of [`${verb} -n ${GUARDED_PATTERN} f`, `${verb} -- ${GUARDED_PATTERN} f`,
        `${verb} --color -n ${GUARDED_PATTERN} f`]) {
        const v = bash(cmd);
        expect(v.decision).toBe('allow');
        expect(v.signals ?? []).toEqual([]);
      }
    }
  });
});

// #1015: a jq filter that loads a module reads a file from jq's search path
// the guard never sees, so the #629 mask declines it, matching the #874
// relief's CLOSED_READ_JQ_MODULE_RE. Ordinary data reads stay relieved.
describe('#1015 jq module forms decline the #629 mask', () => {
  const MODULE_FORMS = [
    `jq 'include "x"; .' d.json`, `jq 'import "x" as e; .' d.json`, `jq 'import "x" as $e; $e' d.json`,
    `jq -n 'modulemeta'`, `jq -n '"x" | modulemeta'`, `jq -r 'include "x"; .a' d.json`,
    `jq -c 'include"x";.' d.json`, `cat d.json | jq 'include "x"; .'`,
    `jq --arg n v 'include "x"; .' d.json`, `jq -n --args 'import "x" as e; .' a`,
    `jq . d.json; jq 'include "x"; .' d.json`,
  ];

  it('never blanks a jq stage whose filter can load a module', () => {
    for (const cmd of MODULE_FORMS) {
      const m = readOnlyInspectionMask(cmd, cmd, cmd);
      const stmt = cmd.includes('; jq') ? cmd.slice(cmd.indexOf('; jq') + 2) : cmd;
      expect(m === null ? cmd : m).toContain(stmt);
    }
  });

  it('-L/--library-path still declines', () => {
    for (const cmd of [`jq -L lib . d.json`, `jq -Llib . d.json`, `jq --library-path lib . d.json`]) {
      expect(readOnlyInspectionMask(cmd, cmd, cmd)).toBeNull();
    }
  });

  it('ordinary jq data reads stay masked', () => {
    for (const cmd of [`jq . d.json`, `jq -r '.imports[]' d.json`, `jq '.included' d.json`,
      `jq -c '.a | length' d.json`, `cat d.json | jq -r .name`]) {
      expect(readOnlyInspectionMask(cmd, cmd, cmd)).toBe(' '.repeat(cmd.length));
    }
  });

  it('decision level: a module-loading stage keeps its operands rated, a plain read is relieved', () => {
    // an operand spelled as a delete verb is rated whenever the stage is visible
    for (const cmd of [`jq 'include "x"; .' ${RM}`, `jq 'import "x" as e; .' ${RM}`,
      `jq '. | modulemeta' ${RM}`]) {
      expect(readOnlyInspectionMask(cmd, cmd, cmd)).toBeNull();
      const v = bash(cmd);
      expect(v.decision).not.toBe('allow');
      expect((v.signals ?? []).length).toBeGreaterThan(0);
    }
    const plain = bash(`jq . ${RM}`);
    expect(plain.decision).toBe('allow');
    expect(plain.signals ?? []).toEqual([]);
  });
});
