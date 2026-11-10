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
  // Final release review: long value-taking, abbreviated, and unknown flags
  // must not let a later file operand or guarded filename disappear.
  ...['grep', 'egrep', 'fgrep'].flatMap(verb => [
    [`${verb} group separator then short file`, `${verb} --group-separator -- -f pat-${String.fromCharCode(107, 105, 108, 108)}.txt f`],
    [`${verb} group separator then long file`, `${verb} --group-separator -- --file pat-${String.fromCharCode(107, 105, 108, 108)}.txt f`],
    [`${verb} exclude-from`, `${verb} --exclude-from pat-${String.fromCharCode(107, 105, 108, 108)}.txt x f`],
    [`${verb} abbreviated regexp then file`, `${verb} --rege -- -f pat-${String.fromCharCode(107, 105, 108, 108)}.txt f`],
    [`${verb} unknown long flag`, `${verb} --unrecognized pat-${String.fromCharCode(107, 105, 108, 108)}.txt f`],
  ] as Array<[string, string]>),
  ['jq arg then file program', `jq --arg a -- -f pat-${String.fromCharCode(107, 105, 108, 108)}.jq d.json`],
  ['jq slurpfile operand', `jq --slurpfile a pat-${String.fromCharCode(107, 105, 108, 108)}.json . d.json`],
  ...['--argjson', '--rawfile', '--indent', '--ar'].map(option =>
    [`jq long option ${option}`, `jq ${option} pat-${String.fromCharCode(107, 105, 108, 108)}.json . d.json`] as [string, string]),
  // GNU grep's colour WHEN is optional: the next flag remains a flag.
  ...['grep', 'egrep', 'fgrep'].flatMap(verb => ['--color', '--colour'].flatMap(colour =>
    ['-f', '--file'].map(file =>
      [`${verb} ${colour} then ${file}`, `${verb} ${colour} ${file} ${String.fromCharCode(114, 109)}.pat f`] as [string, string]))),
  ['grep attached colour then file', `grep --color=always -f ${String.fromCharCode(114, 109)}.pat f`],
  // A missing required value followed by a pattern-file flag must not hide it.
  ...['--max-count', '-C', '--include', '--binary-files', '--label'].flatMap(valueFlag =>
    ['-f', '--file'].map(file =>
      [`grep ${valueFlag} then ${file}`, `grep ${valueFlag} ${file} ${String.fromCharCode(114, 109)}.pat f`] as [string, string])),
  // A bare -- consumed as a grep pattern is not the option terminator.
  ...['-e', '--regexp'].flatMap(patternFlag => ['-f', '--file'].map(fileFlag =>
    [`grep ${patternFlag} -- then ${fileFlag}`, `grep ${patternFlag} -- ${fileFlag} ${String.fromCharCode(114, 109)}.pat f`] as [string, string])),
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
      ...['grep', 'egrep', 'fgrep'].flatMap(verb => ['-e', '--regexp'].flatMap(patternFlag =>
        ['-f', '--file'].map(fileFlag => `${verb} ${patternFlag} -- ${fileFlag} pats f`))),
      ...['grep', 'egrep', 'fgrep'].flatMap(verb => ['--color', '--colour'].flatMap(colour =>
        ['-f', '--file'].map(file => `${verb} ${colour} ${file} pats f`))),
      ...['--max-count', '-C', '--include', '--binary-files', '--label'].flatMap(flag =>
        ['-f', '--file'].map(file => `grep ${flag} ${file} pats f`)),
      `grep --color=always -f pats f`,
      ...['grep', 'egrep', 'fgrep'].flatMap(verb => [
        `${verb} --group-separator -- -f pats f`,
        `${verb} --group-separator -- --file pats f`,
        `${verb} --exclude-from exclusions x f`,
        `${verb} --rege -- -f pats f`,
        `${verb} --unrecognized x f`,
      ]),
      `jq --arg a -- -f program.jq data.json`,
      `jq --slurpfile a vars.json . data.json`,
      ...['--argjson', '--rawfile', '--indent', '--ar'].map(option => `jq ${option} x . d.json`),
      `cat f | jq -f p.jq`, `cat f | grep -f pats`,
    ]) {
      expect(readOnlyInspectionMask(cmd, cmd, cmd)).toBeNull();
    }
  });

  it('jq/grep reads whose program or pattern is on the command line are still read-only', () => {
    for (const cmd of [
      `jq . d.json`, `jq -r .a d.json`, `jq -c '.a | length' d.json`,
      `grep -n x f`, `grep -e x f`, `grep -F x f`, `grep -L x f`, `grep -rn x src`,
      `grep --color -n x f`, `grep --colour -n x f`,
      // after `--` a dash word is an operand (the pattern), not an option
      `grep -n -- -f f`, `grep -e x -- -f f`,
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
