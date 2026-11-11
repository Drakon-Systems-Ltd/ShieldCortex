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
      // #1053 round 0: a value glued onto -e/-f
      `grep -erm f`, `grep -frm.pat f`,
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
  '--max 1', '--exc x', '--frobnicate', '--reg', '--ignore', '--line-num', '--bin',
  // #1053 review: a value glued to -e/-f, or a pattern-file cluster
  '-ePAT', '-fpats', '-rf pats',
  // #1053 round 1: unambiguous abbreviations GNU grep would expand
  '--fixed', '--no-group', '--unix',
];
const GREP_STILL_MASKED = [
  '-n', '--', '-n --', '-rn', '-inw', '-c', '-l', '-L', '-F', '-E', '-o', '-v', '-x', '-H', '-h',
  '--color', '--colour', '--color -n', '--line-number', '--ignore-case --fixed-strings',
  '--recursive', '--count', '--files-with-matches', '--only-matching', '--invert-match',
  // #1053 review (N1): exact GNU no-argument options (`--binary` is `-U`)
  '--binary', '--no-group-separator', '--unix-byte-offsets', '--fixed-regexp',
  // #1053 round 0 safe rows
  '--text', '-i',
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

// #1053 review (B1): jq's `--arg NAME VALUE`, `--indent N` (and the other
// value-taking options) take the next word as a value, so a `--` there is a
// VALUE, not the end of options: `-f p.jq` after it still loads the program
// (jq 1.7 runs the file and its `include`). Every such stage stays visible.
describe('#1053 jq -- consumed as an option value does not end option parsing', () => {
  const CONSUMED_DASH_DASH = [
    `jq --arg name -- -f p.jq d.json`, `jq --arg name -- --from-file p.jq d.json`,
    `jq --arg name -- -rf p.jq d.json`, `jq --arg name -- -nf p.jq`, `jq --indent -- -f p.jq d.json`,
    `jq --argjson name -- -f p.jq d.json`, `jq --slurpfile name -- -f p.jq d.json`,
    `jq --rawfile name -- -f p.jq d.json`, `jq --arg -- -- -f p.jq d.json`,
    `jq -r --arg name -- -L lib . d.json`, `jq --arg name -- --library-path lib . d.json`,
    // `--run-tests` reads programs from its file, so it is not in the closed table
    `jq --run-tests p.test`, `jq --arg name -- --run-tests p.test`,
  ];

  it('mask: the jq stage stays visible, alone, piped and beside another statement', () => {
    for (const stage of CONSUMED_DASH_DASH) {
      expect(readOnlyInspectionMask(stage, stage, stage)).toBeNull();
      const piped = `cat d.json | ${stage}`;
      expect(readOnlyInspectionMask(piped, piped, piped)).toBeNull();
      for (const cmd of [`jq . d.json; ${stage}`, `${stage}; jq . d.json`, `jq . d.json && ${stage}`]) {
        const m = readOnlyInspectionMask(cmd, cmd, cmd);
        expect(m === null ? cmd : m).toContain(stage);
      }
    }
  });

  it('decision: a delete-verb operand of such a stage is rated', () => {
    for (const cmd of [
      `jq --arg name -- -f p.jq ${RM}`, `jq --arg name -- --from-file p.jq ${RM}.json`,
      `jq --arg name -- -rf ${RM}.jq d.json`, `jq --arg name -- -nf ${RM}.jq`,
      `jq --indent -- -f ${RM}.jq d.json`, `cat d.json | jq --arg name -- -f ${RM}.jq`,
      `jq . d.json; jq --arg name -- -f ${RM}.jq d.json`, `jq --arg name -- -f ${RM}.jq d.json; jq . d.json`,
      `jq --run-tests ${RM}.test`,
    ]) {
      const v = bash(cmd);
      expect(v.decision).not.toBe('allow');
      expect((v.signals ?? []).length).toBeGreaterThan(0);
    }
  });

  it('a real -- terminator, and a consumed -- with no program file, keep the relief', () => {
    for (const cmd of [
      `jq -- .a d.json`, `jq -r -- .a d.json`, `jq --arg n v -- .a d.json`, `jq --arg name -- . d.json`,
      `jq --indent 2 . d.json`, `jq --tab --seq -S . d.json`, `jq -n --args '$ARGS' a b`,
      `jq --slurpfile s a.json --rawfile r b.txt -n '$s'`, `jq -rc --sort-keys .a d.json`,
      `cat d.json | jq --arg name -- .a`,
    ]) {
      expect(readOnlyInspectionMask(cmd, cmd, cmd)).toBe(' '.repeat(cmd.length));
    }
    for (const cmd of [`jq --arg name -- . ${RM}`, `jq -- .a ${RM}`, `jq --indent 2 .a ${RM}`]) {
      const v = bash(cmd);
      expect(v.decision).toBe('allow');
      expect(v.signals ?? []).toEqual([]);
    }
  });

  it('a jq option outside the closed table declines', () => {
    for (const cmd of [
      `jq --debug-dump-disasm . d.json`, `jq --from . d.json`, `jq --in-place . d.json`,
      `jq - . d.json`, `jq . d.json --arg n`, `jq --indent`, `jq -rL lib . d.json`,
      // reviewer rows: unknown, glued, abbreviated or `=` spellings
      `jq -nL lib . d.json`, `jq -Lrm . d.json`, `jq -r0 . d.json`, `jq -e1 d.json`, `jq -x . d.json`,
      `jq -b . d.json`, `jq --ar a b . d.json`, `jq --raw . d.json`, `jq --indent=2 . d.json`,
      `jq --foo . d.json`, `jq --debug-trace . d.json`,
      // a non-ASCII letter after the dash is an option to jq in some locales
      `jq -${String.fromCharCode(0xe9)}a d.json`,
    ]) {
      expect(readOnlyInspectionMask(cmd, cmd, cmd)).toBeNull();
    }
  });

  it('round 1 rows: no-value options keep the relief; an include beside any cluster does not', () => {
    for (const cmd of [`jq -e .a d.json`, `jq --exit-status .a d.json`, `jq --seq . d.json`,
      `jq --stream . d.json`, `jq --stream-errors . d.json`, `jq --tab .a d.json`, `jq --indent 3 . d.json`,
      `jq --indent -1 .a d.json`, `jq --argfile a d.json . d.json`]) {
      expect(readOnlyInspectionMask(cmd, cmd, cmd)).toBe(' '.repeat(cmd.length));
    }
    for (const cmd of [`jq -eC 'include "x"; .' ${RM}`, `jq -rc 'include "x"; .' ${RM}`,
      `jq -re 'include "x"; .' ${RM}`, `jq -n 'include "x"; .'`,
      // `--args`/`--jsonargs` do not end option parsing: a later -f is an option
      `jq -n --args '$ARGS' -f p.jq`, `jq -n --jsonargs '$ARGS' -f p.jq`]) {
      expect(readOnlyInspectionMask(cmd, cmd, cmd)).toBeNull();
    }
  });
});

// #1053 round 2 (B3): a `--` that jq reads AS AN OPTION ends option parsing,
// so every later word is an operand. A data file spelled `-f`, `-L` or
// `--from-file` there is read as JSON, never as a program (real jq 1.7 prints
// both files). Only words in option position are judged for a program file,
// so a word an option takes as its VALUE is data too.
describe('#1053 round 2: after a real jq -- terminator, loader-shaped words are data', () => {
  const AFTER_TERMINATOR = [
    `jq -- . ${RM}.json -f`, `jq --arg n -- -- . ${RM}.json -f`, `jq -- . ${RM}.json -rf`,
    `jq -- . ${RM}.json -L`, `jq -- . ${RM}.json --from-file`, `jq -- . ${RM}.json --library-path`,
    `jq -r -- . ${RM}.json -f`, `jq -- . ${RM} -f`, `jq -- -f ${RM}.json`, `jq -- -f p.jq d.json`,
    `jq -n -- -f`, `jq -n '$ARGS' --args a -- -f`, `jq -n --args '$ARGS' -- -f p.jq`,
    `jq --arg n -- -- . ${RM}.json -f p.jq`, `cat ${RM}.json | jq -- . -f`,
  ];
  const OPTION_VALUES = [
    `jq --arg value -f . ${RM}.json`, `jq --arg value -L . ${RM}.json`, `jq --arg value --from-file . ${RM}.json`,
    `jq --arg -f v . ${RM}.json`, `jq --arg v -Lx . ${RM}.json`, `jq --slurpfile x -f . ${RM}.json`,
    `jq --indent -f . ${RM}.json`, `jq --arg value -f . ${RM}`, `jq --arg value -L . ${RM}`,
    // the option takes `--run-tests` as its value, so `t.txt` is the filter
    `jq --indent --run-tests t.txt`, `jq --arg name --run-tests t.txt`,
  ];

  it('mask and decision: relieved, alone and beside another read', () => {
    for (const cmd of [...AFTER_TERMINATOR, ...OPTION_VALUES]) {
      expect(readOnlyInspectionMask(cmd, cmd, cmd)).toBe(' '.repeat(cmd.length));
      const v = bash(cmd);
      expect(v.decision).toBe('allow');
      expect(v.severity).toBe('benign');
      expect(v.signals ?? []).toEqual([]);
    }
    for (const cmd of [`jq . d.json; jq -- . ${RM}.json -f`, `jq -- . ${RM}.json -rf && jq . d.json`]) {
      expect(readOnlyInspectionMask(cmd, cmd, cmd)!.trim()).toMatch(/^[;&]*$/);
      expect(bash(cmd).decision).toBe('allow');
    }
  });

  it('a consumed -- is still not the terminator: a loader before the real one is rated', () => {
    for (const cmd of [
      `jq --arg n -- -f p.jq -- . ${RM}.json`, `jq --arg n -- -rf ${RM}.jq -- d.json`,
      `jq --indent -- --from-file p.jq -- ${RM}.json`, `jq --arg n -- -L lib -- . ${RM}`,
      `jq . ${RM}.json -f p.jq -- x`, `jq -n --args '$ARGS' -f ${RM}.jq`, `jq -n --jsonargs '$ARGS' -f ${RM}.jq`,
    ]) {
      expect(readOnlyInspectionMask(cmd, cmd, cmd)).toBeNull();
      const v = bash(cmd);
      expect(v.decision).not.toBe('allow');
      expect((v.signals ?? []).length).toBeGreaterThan(0);
    }
  });
});

// #1053 round 2 (B4): jq takes a word as an option only when the dash is
// followed by `-` or a letter, so `-1` and `-.a` are the FILTER (real jq 1.7
// prints -1). The filter is still lexed for module code, and an actual
// unknown option, a -f/-L option or a loader after the filter still declines.
describe('#1053 round 2: a negative jq filter is the filter, not an option', () => {
  it('decision: relieved with no signal', () => {
    for (const cmd of [`jq -1 ${RM}.json`, `jq -.a ${RM}.json`, `jq -1 ${RM}`, `jq -r -.a ${RM}.json`,
      `jq '-(.a)' ${RM}.json`, `jq -.a ${RM}.json -c`, `cat ${RM}.json | jq -.a`]) {
      expect(readOnlyInspectionMask(cmd, cmd, cmd)).toBe(' '.repeat(cmd.length));
      const v = bash(cmd);
      expect(v.decision).toBe('allow');
      expect(v.severity).toBe('benign');
      expect(v.signals ?? []).toEqual([]);
    }
  });

  it('the dash filter is still lexed, and real options around it are still judged', () => {
    for (const cmd of [`jq '-(modulemeta)' ${RM}`, `jq '-.a | modulemeta' ${RM}`, `jq '-1, (include)' ${RM}`,
      `jq -1 -x ${RM}`, `jq -1 ${RM} -f p.jq`, `jq -1 -L lib ${RM}`, `jq -rf p.jq -1 ${RM}`]) {
      expect(readOnlyInspectionMask(cmd, cmd, cmd)).toBeNull();
      const v = bash(cmd);
      expect(v.decision).not.toBe('allow');
      expect((v.signals ?? []).length).toBeGreaterThan(0);
    }
  });
});

// #1053 review (B2): only the FILTER can load a module, and only as code.
// A field selector, a string, an --arg value or a file name holding one of
// the words is data, and must keep the relief it had before #1015. Round 2:
// so is an object key (`{import: 1}`, `{import}`) or a variable (`$include`).
describe('#1053 jq module words that are data keep the relief', () => {
  const DATA_READS = [
    `jq '.import' ${RM}.json`, `jq '.include' ${RM}.json`, `jq '.modulemeta' ${RM}.json`,
    `jq --arg label import '.name' ${RM}.json`, `jq . import/${RM}.json`,
    `jq '.a.import' ${RM}.json`, `jq '.a1.include' ${RM}.json`, `jq '."import"' ${RM}.json`,
    `jq '.["modulemeta"]' ${RM}.json`, `jq 'select(.kind == "import")' ${RM}.json`,
    `jq '"\\(.include)"' ${RM}.json`, `jq --argjson v '"include"' .a ${RM}.json`,
    `jq --rawfile import x.txt .a ${RM}.json`, `jq -n --args '$ARGS' import include`,
    `jq '...import' ${RM}.json`, `jq '1.5.import' ${RM}.json`,
    // round 2 (B2): an object key or a variable is a name, never a directive or call
    `jq '{import: 1}' ${RM}.json`, `jq '{import}' ${RM}.json`, `jq '. as $include | 1' ${RM}.json`,
    `jq '. as $import | .' ${RM}.json`, `jq '{a: .b, include: 2}' ${RM}.json`,
    `jq '{"a": 1, modulemeta}' ${RM}.json`, `jq '. as {import: $x} | $x' ${RM}.json`,
    `jq --arg import v '{$import}' ${RM}.json`, `jq 'reduce .[] as $import (0; . + 1)' ${RM}.json`,
    `jq '{ include : 1 }' ${RM}.json`, `jq '{a: {modulemeta: 1}}' ${RM}.json`,
    // round 0 controls and round 1 string rows
    `jq '.name' ${RM}.json`, `jq '.imports' ${RM}.json`, `jq '"\\( "include" )"' ${RM}.json`,
    `jq '"\\\\(include)"' ${RM}.json`,
  ];

  it('mask: blanked whole, alone, piped and beside another read', () => {
    for (const cmd of DATA_READS) {
      expect(readOnlyInspectionMask(cmd, cmd, cmd)).toBe(' '.repeat(cmd.length));
    }
    for (const cmd of [`cat ${RM}.json | jq '.import'`, `jq . d.json; jq '.include' ${RM}.json`,
      `jq '.modulemeta' ${RM}.json && jq --arg label import '.name' ${RM}.json`]) {
      expect(readOnlyInspectionMask(cmd, cmd, cmd)!.trim()).toMatch(/^[;&]*$/);
    }
  });

  it('decision: the reviewer commands are allowed with no signal', () => {
    for (const cmd of [...DATA_READS, `cat ${RM}.json | jq '.import'`,
      `jq . d.json; jq '.include' ${RM}.json`]) {
      const v = bash(cmd);
      expect(v.decision).toBe('allow');
      expect(v.severity).toBe('benign');
      expect(v.signals ?? []).toEqual([]);
    }
  });

  it('a real directive or modulemeta call in the filter stays visible and rated', () => {
    const CODE = [
      `jq 'include "x"; .' ${RM}`, `jq 'import "x" as e; .' ${RM}`, `jq 'import "x" as $e; $e' ${RM}`,
      `jq 'module {}; include "x"; .' ${RM}`, `jq 'include"x";.' ${RM}`, `jq 'inc''lude "x"; .' ${RM}`,
      `jq '"m" | modulemeta' ${RM}`, `jq '.a | modulemeta' ${RM}`, `jq '"\\(modulemeta)"' ${RM}`,
      `jq '"\\("\\(modulemeta)")"' ${RM}`, `jq -- 'include "x"; .' ${RM}`,
      `jq --arg n v 'include "x"; .' ${RM}`, `jq -n --args 'import "x" as e; .' ${RM}`,
      // fail closed where the word is not provably a field, a `$variable`, an
      // object key closed by `:`, `,` or `}`, or string text
      `jq '1.import' ${RM}`, `jq '..import' ${RM}`, `jq '. import' ${RM}`,
      `jq '{a: modulemeta}' ${RM}`, `jq '{(import): 1}' ${RM}`, `jq '{import "x"}' ${RM}`,
      `jq '. as $ include | 1' ${RM}`, `jq '[1, include]' ${RM}`, `jq '1, modulemeta' ${RM}`,
      `jq '{a: [1, import]}' ${RM}`, `jq '{import::x: 1}' ${RM}`, `jq '"\\(1, modulemeta)"' ${RM}`,
      `jq '{a: 1} | modulemeta' ${RM}`, `jq 'include "x"; {import: 1}' ${RM}`, `jq 'def import: .; .' ${RM}`,
      // a keyword in an object value could open a construct with its own
      // commas, so no later comma of that object is trusted as a key position
      `jq '{a: if . then 1, modulemeta else 2 end}' ${RM}`, `jq '{a: try 1, include}' ${RM}`,
      `jq '"x' ${RM}`, `jq '(.a' ${RM}`, `jq '"\\(.a"' ${RM}`,
    ];
    for (const cmd of CODE) {
      expect(readOnlyInspectionMask(cmd, cmd, cmd)).toBeNull();
      const v = bash(cmd);
      expect(v.decision).not.toBe('allow');
      expect((v.signals ?? []).length).toBeGreaterThan(0);
    }
    // Comments are not modelled, so a word after `#` counts. Mask level only:
    // the file-delete rule stops reading at a quoted `#` whatever the mask does
    // (`cat '.a # x' <verb>` is allowed with no mask either).
    expect(readOnlyInspectionMask(`jq '.a # import' ${RM}`, `jq '.a # import' ${RM}`, `jq '.a # import' ${RM}`)).toBeNull();
    for (const stage of [`jq 'include "x"; .' ${RM}`, `jq '"m" | modulemeta' ${RM}`]) {
      for (const cmd of [`cat d.json | ${stage}`, `jq '.import' d.json; ${stage}`]) {
        const m = readOnlyInspectionMask(cmd, cmd, cmd);
        expect(m === null ? cmd : m).toContain(stage);
        expect(bash(cmd).decision).not.toBe('allow');
      }
    }
  });

  it('round 1 nit: a filter holding a line break is never blanked', () => {
    for (const f of [`# "\ninclude "m"; . # "`, `. # "\n| "m" | modulemeta # "`, `. # x\n| .a`, `.a\n| .import`]) {
      const cmd = `jq '${f}' ${RM}.json`;
      expect(readOnlyInspectionMask(cmd, cmd, cmd)).toBeNull();
    }
  });

  it('held: -L/--library-path and plain -f still decline and are rated', () => {
    for (const cmd of [`jq -L lib . ${RM}`, `jq -Llib . ${RM}`, `jq --library-path lib . ${RM}`,
      `jq -f p.jq ${RM}`, `jq --from-file p.jq ${RM}`, `jq -rf p.jq ${RM}`]) {
      expect(readOnlyInspectionMask(cmd, cmd, cmd)).toBeNull();
      expect(bash(cmd).decision).not.toBe('allow');
    }
  });
});

// #1053 review (N1) and held grep cases at the decision level.
describe('#1053 grep closed set at the decision level', () => {
  it('exact GNU no-argument long options keep the relief', () => {
    for (const opt of ['--binary', '--no-group-separator', '--unix-byte-offsets', '--fixed-regexp']) {
      const v = bash(`grep ${opt} ${RM} f`);
      expect(v.decision).toBe('allow');
      expect(v.signals ?? []).toEqual([]);
    }
  });

  it('value-taking options, glued values and abbreviations are rated', () => {
    for (const cmd of [`grep -A2 ${RM} f`, `grep -m1 ${RM} f`, `grep -ePAT ${RM}`, `grep -fpats ${RM}`,
      `grep -nA2 ${RM} f`, `grep -rne ${RM} f`, `grep --max 1 ${RM} f`, `grep --exc x ${RM} f`,
      `grep --reg ${RM} f`, `grep --ignore ${RM} f`, `grep --line-num ${RM} f`, `grep --bin ${RM} f`,
      `cat f | grep -A2 ${RM}`, `grep -n x f; grep -m1 ${RM} f`]) {
      const v = bash(cmd);
      expect(v.decision).not.toBe('allow');
      expect((v.signals ?? []).length).toBeGreaterThan(0);
    }
  });
});
