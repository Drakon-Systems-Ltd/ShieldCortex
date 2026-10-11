import { describe, it, expect } from '@jest/globals';
import {
  evaluateToolCall,
  isGuardSelfProtectionVerdict,
} from '../tool-action-guard.js';

/**
 * #629 (memory-markdown prose slice) — writing a memory note runs nothing.
 *
 * A DANGEROUS-tier command named in the bare prose of a non-executable memory
 * `.md` file is recorded as data: the write is allowed at the sensitive tier,
 * `write-content-scanned` plus the matched signal names stay on the verdict
 * (auditable, #95), and the path-tier rules still run afterwards.
 *
 * Everything else keeps today's gate, and is pinned below:
 *   - the catastrophic tier (pinned by write-content-scan-93 test 1, unchanged),
 *   - guard self-protection and sensitive-path names in the prose,
 *   - shebang bodies on a memory path,
 *   - script-like paths carrying the same prose,
 *   - path-tier policy for the memory file's own location,
 *   - running the memory file later, which the script fold scans again.
 *
 * This is NOT all of #629: ordinary docs were already unscanned, and the
 * written-script literal class and the Bash-plane reports are separate.
 */

const SUDO_NOTE = 'Ops note: the deploy user needs sudo for the nginx reload.';
const STOP_NOTE = 'Last week we had to systemctl stop nginx during the cert rotation.';
const FIREWALL_NOTE = 'We configured iptables on the host.';
const HISTORY_NOTE = 'Never clear .bash_history on the shared build hosts.';

function expectNamedMention(v: ReturnType<typeof evaluateToolCall>, signal: string): void {
  expect(v.decision).toBe('allow');
  expect(v.severity).toBe('sensitive');
  expect(v.signals).toContain('write-content-scanned');
  expect(v.signals).toContain(signal);
  expect(v.signals).not.toContain('write-content-dangerous');
  expect(v.signals).not.toContain('write-content-catastrophic');
  expect(isGuardSelfProtectionVerdict(v.signals)).toBe(false);
}

describe('#629 — dangerous-tier mentions in memory-markdown prose are named data', () => {
  it('Edit of MEMORY.md naming sudo is allowed with privilege-escalation named', () => {
    const v = evaluateToolCall('Edit', {
      file_path: 'MEMORY.md',
      old_string: '- (empty)',
      new_string: SUDO_NOTE,
    });
    expectNamedMention(v, 'privilege-escalation');
    expect(v.reason).toMatch(/memory-markdown prose/);
    expect(v.reason).toMatch(/privilege-escalation/);
    expect(v.matches?.some(m => m.signal === 'privilege-escalation')).toBe(true);
  });

  it('Write of CLAUDE.md naming a service stop is allowed with stop-process-or-service named', () => {
    const v = evaluateToolCall('Write', {
      file_path: '/home/u/project/CLAUDE.md',
      content: `# Notes\n\n${STOP_NOTE}\n`,
    });
    expectNamedMention(v, 'stop-process-or-service');
  });

  it('Edit of ~/.claude/memory/*.md naming a firewall tool is allowed with the signal named', () => {
    const v = evaluateToolCall('Edit', {
      file_path: '/home/u/.claude/memory/network.md',
      old_string: 'x',
      new_string: FIREWALL_NOTE,
    });
    expectNamedMention(v, 'modify-network-firewall');
  });

  it('Write of proj/memory/*.md naming history wiping is allowed with the signal named', () => {
    const v = evaluateToolCall('Write', {
      file_path: '/home/u/project/memory/hosts.md',
      content: HISTORY_NOTE,
    });
    expectNamedMention(v, 'wipe-history-or-logs');
  });

  it('several mentions in one note are all named', () => {
    const v = evaluateToolCall('Write', {
      file_path: 'MEMORY.md',
      content: `${SUDO_NOTE}\n${STOP_NOTE}\n`,
    });
    expectNamedMention(v, 'privilege-escalation');
    expect(v.signals).toContain('stop-process-or-service');
  });

  it('the same prose on an ordinary docs path is unchanged: allowed, benign, not content-scanned', () => {
    const v = evaluateToolCall('Write', { file_path: 'docs/ops.md', content: SUDO_NOTE });
    expect(v.decision).toBe('allow');
    expect(v.severity).toBe('benign');
    expect(v.signals).not.toContain('write-content-scanned');
    expect(v.signals).not.toContain('privilege-escalation');
  });
});

describe('#629 — floors named in memory prose still gate', () => {
  it('guard config named in MEMORY.md prose still requires approval on the self-protection floor', () => {
    const v = evaluateToolCall('Edit', {
      file_path: 'MEMORY.md',
      old_string: 'x',
      new_string: 'The guard settings live in ~/.shieldcortex/config.json on this host.',
    });
    expect(v.decision).toBe('require_approval');
    expect(v.signals).toContain('write-content-dangerous');
    expect(v.signals).toContain('touch-guard-config');
    expect(isGuardSelfProtectionVerdict(v.signals)).toBe(true);
    expect(v.reason).toMatch(/memory-write payload is a dangerous command/);
  });

  it('a sensitive path named in memory prose still requires approval', () => {
    const v = evaluateToolCall('Write', {
      file_path: '/home/u/.claude/memory/keys.md',
      content: 'The old id_rsa key on the build box was rotated.',
    });
    expect(v.decision).toBe('require_approval');
    expect(v.signals).toContain('write-content-dangerous');
    expect(v.signals).toContain('touch-sensitive-path');
  });

  it('a floor hit beside a mention keeps the whole of today\'s verdict, mention included', () => {
    const v = evaluateToolCall('Write', {
      file_path: 'MEMORY.md',
      content: `${SUDO_NOTE}\nThe guard settings live in ~/.shieldcortex/config.json.\n`,
    });
    expect(v.decision).toBe('require_approval');
    expect(v.signals).toContain('write-content-dangerous');
    expect(v.signals).toContain('touch-guard-config');
    expect(v.signals).toContain('privilege-escalation');
    expect(isGuardSelfProtectionVerdict(v.signals)).toBe(true);
  });
});

describe('#629 — script, shebang and path controls are unchanged', () => {
  it('a shebang body on a memory path still requires approval', () => {
    const v = evaluateToolCall('Write', {
      file_path: 'MEMORY.md',
      content: '#!/bin/bash\nsudo systemctl stop nginx\n',
    });
    expect(v.decision).toBe('require_approval');
    expect(v.signals).toContain('write-content-dangerous');
    expect(v.signals).toContain('privilege-escalation');
  });

  it('the same prose written to a .sh path still requires approval', () => {
    const v = evaluateToolCall('Write', { file_path: '/home/u/project/notes.sh', content: SUDO_NOTE });
    expect(v.decision).toBe('require_approval');
    expect(v.signals).toContain('write-content-dangerous');
    expect(v.signals).toContain('privilege-escalation');
  });

  it('the same prose written to a .py path still requires approval', () => {
    const v = evaluateToolCall('Write', { file_path: '/home/u/project/notes.py', content: `# ${STOP_NOTE}\n` });
    expect(v.decision).toBe('require_approval');
    expect(v.signals).toContain('write-content-dangerous');
    expect(v.signals).toContain('stop-process-or-service');
  });

  it('a memory note under a sensitive directory is still gated by the path tier (fall-through, not early allow)', () => {
    const v = evaluateToolCall('Write', {
      file_path: '/home/u/.ssh/memory/notes.md',
      content: SUDO_NOTE,
    });
    expect(v.decision).not.toBe('allow');
    expect(v.signals).toContain('touch-sensitive-path');
  });

  it('a memory note under the approval store is still on the self-protection floor via the path tier', () => {
    const v = evaluateToolCall('Write', {
      file_path: '/home/u/.shieldcortex/approvals/memory/notes.md',
      content: SUDO_NOTE,
    });
    expect(v.decision).not.toBe('allow');
    expect(v.signals).toContain('touch-approval-store');
    expect(isGuardSelfProtectionVerdict(v.signals)).toBe(true);
  });
});

describe('#629 — running a memory file is still scanned at invocation', () => {
  const FILES: Record<string, string> = {
    '/home/u/.claude/memory/ops.md': 'sudo systemctl stop nginx\n',
    '/home/u/project/MEMORY.md': 'sudo systemctl stop nginx\n',
  };
  const resolveScriptSource = (p: string): string | null => FILES[p] ?? null;

  it('the command-only memory note is writable as a note…', () => {
    const w = evaluateToolCall('Write', {
      file_path: '/home/u/.claude/memory/ops.md',
      content: FILES['/home/u/.claude/memory/ops.md'],
    });
    expect(w.decision).toBe('allow');
    expect(w.signals).toContain('privilege-escalation');
    expect(w.signals).toContain('stop-process-or-service');
  });

  it('…but bash <memory .md> folds the file and gates', () => {
    const x = evaluateToolCall('Bash', { command: 'bash /home/u/.claude/memory/ops.md' }, undefined, {
      resolveScriptSource,
    });
    expect(x.decision).not.toBe('allow');
    expect(x.signals).toContain('privilege-escalation');
  });

  it('…and source <MEMORY.md> folds the file and gates', () => {
    const x = evaluateToolCall('Bash', { command: 'source /home/u/project/MEMORY.md' }, undefined, {
      resolveScriptSource,
    });
    expect(x.decision).not.toBe('allow');
    expect(x.signals).toContain('stop-process-or-service');
  });

  it('the same vocabulary typed as a real command is unchanged', () => {
    const x = evaluateToolCall('Bash', { command: 'sudo systemctl stop nginx' });
    expect(x.decision).toBe('require_approval');
    expect(x.signals).toContain('privilege-escalation');
  });
});
