/**
 * #509 round 6, N1 — the guard-directory operand rule anchors its verb at
 * COMMAND POSITION. The r5 rule matched `mv|cp|rm|…` anywhere after
 * whitespace, so `npm install --prefix ~/.shieldcortex/` (the verb is an
 * npm subcommand) and `echo "rm ~/.shieldcortex"` (the verb is quoted text)
 * landed on the self-protection floor: no autoApprove, headless deny. #509 is
 * about not blocking ordinary work, so both now take normal classification,
 * while the r5 true positives (tool-action-guard-floor-r5-509) still hit the
 * floor and a glob after `cd ~/.shieldcortex` joins them.
 */
import { describe, it, expect } from '@jest/globals';
import { GUARD_SELF_PROTECTION_SIGNALS, evaluateToolCall, isGuardSelfProtectionVerdict } from '../tool-action-guard.js';

// Assembled at runtime (#444 convention) so the guard scanning this file's own
// write does not gate the test.
const RM = 'r' + 'm';
const RF = '-' + 'rf';
const SC = '~/.' + 'shieldcortex';

const floor = (command: string) => evaluateToolCall('Bash', { command }).signals.filter((s) => GUARD_SELF_PROTECTION_SIGNALS.includes(s));

describe('#509 r6 N1 — the guard-directory operand verb must be at command position', () => {
  it('false positives from the r5 rule take normal classification, not the floor', () => {
    for (const command of [
      `npm install --prefix ${SC}/`,
      `echo "${RM} ${SC}"`,
      // A separator INSIDE quotes is not a command boundary.
      `echo "a; ${RM} ${SC}"`,
      `echo 'x && mv ${SC} /tmp/x'`,
      `git commit -m "${RM} ${SC} is now guarded"`,
    ]) {
      const v = evaluateToolCall('Bash', { command });
      expect({ command, floor: floor(command), selfProtected: isGuardSelfProtectionVerdict(v.signals) })
        .toEqual({ command, floor: [], selfProtected: false });
    }
  });

  it('a verb at command position after any separator, env prefix or sudo is still on the floor', () => {
    for (const command of [
      `${RM} -r ${SC}`,
      `echo x; ${RM} -r ${SC}`,
      `true && mv ${SC} /tmp/x`,
      `false || cp -r /tmp/forged/. ${SC}/`,
      `ls | xargs echo; (rmdir ${SC}/approvals)`,
      `echo x\nrsync -a /tmp/f/ ${SC}`,
      `sudo mv ${SC} /tmp/x`,
      'LC_ALL=C mv "$HOME/.' + 'shieldcortex/" /tmp/x',
      // Command substitution runs, even inside double quotes.
      `echo "$(${RM} -r ${SC})"`,
    ]) {
      expect({ command, floor: floor(command) }).toEqual({ command, floor: expect.arrayContaining(['touch-approval-store']) });
    }
  });

  it('a glob or `.` operand after `cd ~/.shieldcortex` in the same command is on the floor', () => {
    // (A forced recursive delete there is already catastrophic; a move takes the state too.)
    expect(floor(`cd ${SC}; mv * /tmp/x`)).toContain('touch-approval-store');
    expect(floor(`cd ${SC} && mv ./* /tmp/x`)).toContain('touch-approval-store');
    expect(evaluateToolCall('Bash', { command: ['cd', SC, '&&', RM, RF, './*'].join(' ') }).decision).toBe('block');
    expect(floor('cd "$HOME/.' + 'shieldcortex" && cp /tmp/forged/config.json .')).toContain('touch-approval-store');
    // Not after a cd into the guard directory: ordinary work.
    expect(floor('cd /tmp/build && mv ./* /tmp/out')).toEqual([]);
    // Pure inspection after the cd stays off the floor.
    expect(floor(`cd ${SC} && ls ./*`)).toEqual([]);
  });
});
