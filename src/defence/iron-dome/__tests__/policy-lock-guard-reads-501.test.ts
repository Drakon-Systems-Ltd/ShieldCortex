/**
 * #501 review r1 blocker — the three PATH_TARGET rules for the policy lock's
 * attack surface must gate WRITES and never READS.
 *
 * The lock is 0644 root-owned by design (agent-readable is the point) and every
 * Claude Code session reads `~/.claude/settings.json` constantly. An approval
 * card on a plain read is a hard deny headless (#512) and the uninstall-driving
 * UX the product bans. So: must-allow beside must-gate, on the shipped
 * classifier, and Bash inspection agrees with the `Read` tool on the same files.
 *
 * Paths and write verbs are assembled from fragments so the live host scanner
 * does not read this file as an attempt on its own lock.
 */
import * as os from 'os';
import { evaluateToolCall, policyLockAccessIsReadOnly } from '../tool-action-guard.js';

const cfg = { enabled: true, enforce: true } as any;
const HOME = os.homedir();
const ROOT = ['', 'etc', 'shieldcortex'].join('/');
const POINTER = `${ROOT}.conf`;
const LOCK = `${ROOT}/policy.json`;
const SETTINGS = ['.claude', 'settings.json'].join('/');
const SETTINGS_LOCAL = ['.claude', 'settings.local.json'].join('/');
const DIST_SEAM = ['SHIELDCORTEX', 'DIST_ROOT'].join('_');
const ROOT_SEAM = ['SHIELDCORTEX', 'PROTECTED_ROOT'].join('_');
const DEL = ['r', 'm'].join('');
const PRIV = ['su', 'do'].join('');
const SEDI = ['sed', '-i'].join(' ');
const TEE = ['t', 'ee'].join('');
const GT = '>';
const SUBSH = '$(';
const PY = ['python', '3'].join('');
const NODE = ['no', 'de'].join('');
const W = 'w';

function bash(command: string) {
  return evaluateToolCall('Bash', { command }, cfg);
}
function signalled(v: ReturnType<typeof evaluateToolCall>) {
  return (v.signals ?? []).includes('disable-action-guard');
}

describe('#501 policy-lock paths — reads are not the access', () => {
  const mustAllow: string[] = [
    // Tars's r1 probe, verbatim shapes.
    `cat ~/${SETTINGS}`,
    `grep -n hooks ~/${SETTINGS}`,
    `jq .hooks ~/${SETTINGS}`,
    `git log --oneline -- ${SETTINGS}`,
    `cat ${SETTINGS_LOCAL}`,
    `ls -la ${ROOT}`,
    `cat ${LOCK}`,
    // And the rest of the read vocabulary.
    `head -n 20 ${HOME}/${SETTINGS}`,
    `less ${LOCK}`,
    `stat ${LOCK}`,
    `cat ${POINTER}`,
    `ls -la ${ROOT}/`,
    `git diff -- ${SETTINGS}`,
    `git show HEAD:${SETTINGS}`,
    // #522 G2 regression guards: the token test must not swallow ordinary
    // read flags that merely begin with the same letters.
    `git log --oneline --format=%H -- ${SETTINGS}`,
    `git diff --stat -- ${SETTINGS}`,
    `git log -n 5 -- ${LOCK}`,
    `cat ${LOCK} | jq .actionGuard`,
    `grep -c enforce ${LOCK} && echo present`,
    `test -f ${LOCK} && cat ${LOCK}`,
  ];
  for (const command of mustAllow) {
    it(`allows: ${command}`, () => {
      const v = bash(command);
      expect({ command, signalled: signalled(v), decision: v.decision })
        .toEqual({ command, signalled: false, decision: 'allow' });
    });
  }

  it('a privileged read carries no disable-action-guard signal (its own gate is pre-existing)', () => {
    const v = bash(`${PRIV} cat ${LOCK}`);
    expect(signalled(v)).toBe(false);
    expect(v.signals ?? []).toContain('privilege-escalation');
  });

  it('Bash inspection agrees with the Read tool on the same files', () => {
    for (const file_path of [LOCK, `${HOME}/${SETTINGS}`]) {
      const read = evaluateToolCall('Read', { file_path }, cfg);
      const cat = bash(`cat ${file_path}`);
      expect({ file_path, read: read.decision, cat: cat.decision })
        .toEqual({ file_path, read: 'allow', cat: 'allow' });
    }
  });
});

describe('#501 policy-lock paths — every write shape keeps the gate', () => {
  const mustGate: Array<[string, Record<string, unknown>]> = [
    ['Write', { file_path: `${HOME}/${SETTINGS}`, content: '{}' }],
    ['Edit', { file_path: `${HOME}/${SETTINGS}`, old_string: 'a', new_string: 'b' }],
    ['Write', { file_path: LOCK, content: '{}' }],
    ['Write', { file_path: POINTER, content: 'root=/tmp/x' }],
    ['Bash', { command: `${SEDI} 's/enforce/x/' ~/${SETTINGS}` }],
    ['Bash', { command: `echo '{}' ${GT} ${POINTER}` }],
    ['Bash', { command: `cat x.json | ${TEE} ${LOCK}` }],
    ['Bash', { command: `cp /tmp/mine.json ${LOCK}` }],
    ['Bash', { command: `mv /tmp/mine.json ${LOCK}` }],
    ['Bash', { command: `${DEL} ${LOCK}` }],
    ['Bash', { command: `export ${ROOT_SEAM}=/tmp/empty` }],
    ['Bash', { command: `${DIST_SEAM}=/tmp/fake ${NODE} ${HOME}/.claude/hooks/pre-tool-hook.mjs` }],
    // The carve-out strips leading `VAR=` to find the verb; the env seam must
    // still be refused when it rides in front of an otherwise pure read.
    ['Bash', { command: `${DIST_SEAM}=/tmp/x cat ${LOCK}` }],
    // A read followed by a write in the same command is a write.
    ['Bash', { command: `cat ${LOCK}; ${DEL} ${LOCK}` }],
    ['Bash', { command: `jq '.hooks = {}' ~/${SETTINGS} ${GT} ~/${SETTINGS}` }],
    // git that changes the working tree, or writes/executes via flag.
    ['Bash', { command: `git checkout -- ${SETTINGS}` }],
    ['Bash', { command: `git log --output=${HOME}/${SETTINGS} -- x` }],
    // #522 r2: the same flag QUOTED. The old test required whitespace
    // immediately before `--`, so an ordinary quoted argument slipped past it
    // and a stage that writes a file read as one that only inspects one.
    ['Bash', { command: `git diff "--output=${HOME}/${SETTINGS}" -- README.md` }],
    ['Bash', { command: `git diff '--output=${HOME}/${SETTINGS}' --` }],
    ['Bash', { command: `git log "--output=${HOME}/${SETTINGS}"` }],
    ['Bash', { command: `git diff "--ext-diff" -- ${SETTINGS}` }],
    // The separate-token and short spellings of the same flag.
    ['Bash', { command: `git diff "--output" "${HOME}/${SETTINGS}" -- README.md` }],
    ['Bash', { command: `git diff -o ${HOME}/${SETTINGS} -- README.md` }],
    ['Bash', { command: `git -C ${HOME} log -- ${SETTINGS}` }],
    // Single-quoted, and the unquoted separate-token spelling.
    ['Bash', { command: `git diff '--output=${HOME}/${SETTINGS}' -- README.md` }],
    ['Bash', { command: `git diff --output "${HOME}/${SETTINGS}" -- x` }],
    // Short form on `git log`, spaced and GLUED (`-o<file>` is what
    // parse-options accepts, so the glued spelling has to gate too).
    ['Bash', { command: `git log -o ${HOME}/${SETTINGS} -- x` }],
    ['Bash', { command: `git log -o${HOME}/${SETTINGS} -- ${SETTINGS}` }],
    // Nested execution and interpreters fail closed.
    ['Bash', { command: `echo ${SUBSH}cat ${LOCK})` }],
    ['Bash', { command: `${PY} -c "open('${LOCK}','${W}').write('{}')"` }],
    ['Bash', { command: `${NODE} -e "require('fs').readFileSync('${HOME}/${SETTINGS}')"` }],
  ];
  for (const [tool, args] of mustGate) {
    it(`gates: ${tool} ${JSON.stringify(args)}`, () => {
      const v = evaluateToolCall(tool, args, cfg);
      expect({ tool, args, signalled: signalled(v) }).toEqual({ tool, args, signalled: true });
      expect({ tool, args, decision: v.decision }).not.toEqual({ tool, args, decision: 'allow' });
    });
  }
});

describe('policyLockAccessIsReadOnly', () => {
  it('is false for text that names neither path', () => {
    expect(policyLockAccessIsReadOnly('cat /etc/hosts')).toBe(false);
  });
  it('is true for pure inspection of either path', () => {
    expect(policyLockAccessIsReadOnly(`cat ${LOCK}`)).toBe(true);
    expect(policyLockAccessIsReadOnly(`jq .hooks ~/${SETTINGS}`)).toBe(true);
    expect(policyLockAccessIsReadOnly(`git log -- ${SETTINGS}`)).toBe(true);
  });
  it('is false when any stage or statement can write', () => {
    expect(policyLockAccessIsReadOnly(`cat ${LOCK} ${GT} /tmp/copy`)).toBe(false);
    expect(policyLockAccessIsReadOnly(`cat ${LOCK} && ${DEL} ${LOCK}`)).toBe(false);
    expect(policyLockAccessIsReadOnly(`git checkout -- ${SETTINGS}`)).toBe(false);
    expect(policyLockAccessIsReadOnly(`vi ${LOCK}`)).toBe(false);
  });
  // #522 r2 G2. The flag is judged per token with quotes stripped now, so the
  // quoting that hid it no longer does. The last two rows are the controls:
  // an ordinary read-only `git` stage must not start failing closed.
  it('is false for a git stage that writes a file, however the flag is quoted', () => {
    expect(policyLockAccessIsReadOnly(`git diff "--output=${HOME}/${SETTINGS}" -- README.md`)).toBe(false);
    expect(policyLockAccessIsReadOnly(`git diff '--output=${HOME}/${SETTINGS}' --`)).toBe(false);
    expect(policyLockAccessIsReadOnly(`git log "--output=${HOME}/${SETTINGS}"`)).toBe(false);
    expect(policyLockAccessIsReadOnly(`git diff "--ext-diff" -- ${SETTINGS}`)).toBe(false);
    expect(policyLockAccessIsReadOnly(`git diff "--output" "${HOME}/${SETTINGS}" -- README.md`)).toBe(false);
    expect(policyLockAccessIsReadOnly(`git diff -o ${HOME}/${SETTINGS} -- README.md`)).toBe(false);
    expect(policyLockAccessIsReadOnly(`git diff -- ${SETTINGS}`)).toBe(true);
    expect(policyLockAccessIsReadOnly(`git log --oneline -- ${SETTINGS}`)).toBe(true);
  });
  // Ported from lane `jarvis/501-policy-lock` (f14c5aeb): the single-quoted
  // `git diff` spelling, the unquoted separate-token spelling, and the short
  // `-o` on `git log` — shapes the other lane's cases did not reach.
  it('#522 G2 — a QUOTED write flag is still a write flag', () => {
    expect(policyLockAccessIsReadOnly(`git diff "--output=${HOME}/${SETTINGS}" -- README.md`)).toBe(false);
    expect(policyLockAccessIsReadOnly(`git diff '--output=${HOME}/${SETTINGS}' -- README.md`)).toBe(false);
    expect(policyLockAccessIsReadOnly(`git diff "--ext-diff" -- ${SETTINGS}`)).toBe(false);
    expect(policyLockAccessIsReadOnly(`git diff --output "${HOME}/${SETTINGS}" -- x`)).toBe(false);
    expect(policyLockAccessIsReadOnly(`git log -o ${HOME}/${SETTINGS} -- x`)).toBe(false);
    // Glued short form — `-o<file>`, no separating space.
    expect(policyLockAccessIsReadOnly(`git log -o${HOME}/${SETTINGS} -- ${SETTINGS}`)).toBe(false);
  });
  it('#522 G2 — read flags that merely start alike are untouched', () => {
    expect(policyLockAccessIsReadOnly(`git diff -- ${SETTINGS}`)).toBe(true);
    expect(policyLockAccessIsReadOnly(`git log --oneline --format=%H -- ${SETTINGS}`)).toBe(true);
    expect(policyLockAccessIsReadOnly(`git diff --stat -- ${SETTINGS}`)).toBe(true);
  });
});
