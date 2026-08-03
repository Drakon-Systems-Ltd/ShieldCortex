import { describe, it, expect } from '@jest/globals';
import { evaluateToolCall } from '../tool-action-guard.js';

/**
 * Issue #195 — `git-force-push` fired on PROSE.
 *
 * #191 bounded the rule to one statement and to real force tokens. It left the
 * other half: the rule never required `git` to be a COMMAND. Any text
 * mentioning git, then push, then a `+` or `-f` armed it — `\bgit\b` matched
 * inside the hyphenated rule NAME.
 *
 * Reported by Friday, who hit it while logging the lesson from #191: writing up
 * a denial got denied. That is the failure mode worth killing on its own — the
 * standing family is every tool whose job is to write text about commands
 * (commit messages, `cortex capture`, `gh issue create`), so talking about a
 * bug triggers the bug and suppresses the record-keeping.
 *
 * Tokenising is what makes the fix precise: `tokeniseStatement` keeps a quoted
 * span whole, so `--what "… git push +1 …"` is ONE token that is not `git`,
 * while a real `git push -f` is three.
 */
const sig = (command: string): string[] =>
  evaluateToolCall('Bash', { command }, undefined, undefined).signals;

const FP = 'git-force-push';

describe('#195 — talking about a force-push is not performing one', () => {
  it.each([
    // Friday's live denial, verbatim shape.
    'python3 cortex.py capture --what "git-force-push misfire failed because the trimmed statement carried the arming token: the + in the +03-00 offset"',
    // The probe Friday asked for by name.
    'python3 log.py --note "the git push +1 went fine"',
    'git commit -m "fix the git push +1 bug"',
    'gh issue create --title "git push --force misfires" --body "the -f case"',
    'echo "never run git push --force on main"',
  ])('prose does not arm the rule: %s', cmd => {
    expect(sig(cmd)).not.toContain(FP);
  });

  it('Friday\'s backup chain — the +03-00 archive after a push (#191 + #195)', () => {
    // EVERY `openclaw backup create` archive is named …+03-00-…tar.gz, so a
    // push-then-cleanup chain touching one is a standing benign family.
    const cmd = 'which trash && cd ~/repo && trash 2026-07-25T05-00-07.442+03-00-openclaw-backup.tar.gz'
      + ' && git add -A && git commit -m "rotate backups, keep 7" --quiet && git push origin main --quiet'
      + ' && trash /tmp/staging/2026-08-03T09-29-40.692+03-00-openclaw-backup.tar.gz && echo DONE';
    expect(sig(cmd)).not.toContain(FP);
  });

  it.each([
    'git push --force origin main',
    'git push -f origin main',
    'git push --force-with-lease',
    'git push --force-if-includes origin main',
    'git push origin +main:main',
    'git push -fq origin main',            // clustered short flags — pre-existing gap, now closed
    'sudo git push -f origin main',
    'cd /repo && git push -f',
    'REPO=x git push --force',
  ])('a real force-push still gates: %s', cmd => {
    expect(sig(cmd)).toContain(FP);
  });

  it.each([
    ['eval reconstitutes it', 'eval "git push -f origin main"'],
    ['a variable hides the verb', '$GIT push -f origin main'],
    ['quoted inside bash -c', `bash -c 'git push --force origin main'`],
    ['nested one level deeper', `bash -c 'bash -c "git push -f"'`],
  ])('fails closed where argv cannot be read: %s', (_name, cmd) => {
    expect(sig(cmd)).toContain(FP);
  });

  it('does not disturb ordinary git mutation', () => {
    const s = sig('git add -A && git commit -m "ordinary work" && git push origin main');
    expect(s).not.toContain(FP);
  });
});
