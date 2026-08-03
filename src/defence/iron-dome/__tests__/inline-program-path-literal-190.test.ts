import { describe, it, expect } from '@jest/globals';
import { evaluateToolCall, detectScriptInvocations } from '../tool-action-guard.js';

/**
 * Issue #190 — a path literal inside an inline interpreter program was read as
 * a path in COMMAND position, so the guard folded the data file that one-liner
 * opened and scanned its contents as shell.
 *
 * Found live on Friday-Mac (3 Aug 2026, 06:25Z). `grep -c "" <audit>.jsonl`
 * alone was ALLOWED; the same grep compounded with a `python3 -c` that opened
 * the same file was DENIED with three threats and matched:"sudo". Nothing in
 * the command text contained any of those tokens — they were in the .jsonl,
 * which is ShieldCortex's OWN audit log. Every past denial writes its trigger
 * tokens there, so the guard's telemetry denied the commands that read it.
 *
 * The boundary is the one #89 already draws: a sink-free inline program cannot
 * start a process, so it holds no invocations; one that can shell out does, and
 * its nested invocation must still be found.
 */
function stubResolver(files: Record<string, string>): (p: string) => string | null {
  return (p: string) => (Object.prototype.hasOwnProperty.call(files, p) ? files[p] : null);
}

const AUDIT = '/Users/michael/.shieldcortex/audit/realtime-2026-08-03.jsonl';

/** A real audit line, poisoned exactly as the live one was: it RECORDS the
 *  tokens of an earlier denial, it does not perform anything. */
const POISONED_AUDIT_LINE = JSON.stringify({
  type: 'intercept', tool: 'Bash', firewallResult: 'ACTION_GUARD',
  threats: ['privilege-escalation', 'modify-network-firewall', 'touch-sensitive-path'],
  preview: 'Bash :: command=python3 scripts/security-sentry.py',
  matched: 'expected_sudo, socketfilterfw, /Users/michael/.ssh/id_rsa',
});

describe('#190 — a path literal in an inline program is not an invocation', () => {
  it('does not fold the data file a sink-free one-liner opens', () => {
    const cmd = `python3 -c "import json; json.load(open('${AUDIT}'))"`;
    expect(detectScriptInvocations(cmd)).toEqual([]);
  });

  it('the live repro: reading the audit log back is allowed', () => {
    const cmd = `grep -c "" ${AUDIT}; echo "===="; python3 -c "import json\nfor l in open('${AUDIT}'): json.loads(l)"`;
    const v = evaluateToolCall('Bash', { command: cmd }, undefined, {
      resolveScriptSource: stubResolver({ [AUDIT]: POISONED_AUDIT_LINE }),
    });
    expect(v.decision).toBe('allow');
    expect(v.signals).not.toContain('touch-sensitive-path');
    expect(v.signals).not.toContain('privilege-escalation');
  });

  it('holds for the other read shapes and quotings', () => {
    for (const cmd of [
      `python3 -c 'for l in open("${AUDIT}"): print(l)'`,
      `node -e "require('fs').readFileSync('${AUDIT}')"`,
      `python3 -c "open('./config/baseline.json')"`,
      `perl -e "open(F, '${AUDIT}')"`,
    ]) {
      expect([cmd, detectScriptInvocations(cmd)]).toEqual([cmd, []]);
    }
  });

  it('STILL finds a real invocation nested in a program that can shell out', () => {
    // The sink keeps the region unmasked, so the path in its argument is still
    // read as the invocation it is. (A quoted `'bash /tmp/payload.sh'` — verb
    // AND argument in one token — was never detected here, before or after
    // this fix: the tokeniser keeps the quoted span whole and it matches no
    // interpreter. Out of scope for #190, recorded so it is not mistaken for a
    // regression; it is the fold-vs-detect gap tracked on the allowlist work.)
    const cmd = `python3 -c "import os; os.system('/tmp/payload.sh')"`;
    expect(detectScriptInvocations(cmd)).toContainEqual({ path: '/tmp/payload.sh', lang: 'sh' });

    const v = evaluateToolCall('Bash', { command: cmd }, undefined, {
      resolveScriptSource: stubResolver({ '/tmp/payload.sh': '#!/bin/bash\nrm -rf / --no-preserve-root\n' }),
    });
    expect(v.decision).not.toBe('allow');
  });

  it('leaves a plain shell invocation and `bash -c` recursion untouched', () => {
    expect(detectScriptInvocations('bash /tmp/x.sh')).toEqual([{ path: '/tmp/x.sh', lang: 'sh' }]);
    expect(detectScriptInvocations(`bash -c 'bash /tmp/x.sh'`)).toEqual([{ path: '/tmp/x.sh', lang: 'sh' }]);
    expect(detectScriptInvocations('python3 /tmp/s.py')).toEqual([{ path: '/tmp/s.py', lang: 'python' }]);
  });
});
