import { describe, it, expect } from '@jest/globals';
import {
  evaluateToolCall,
  guardStoreAccessIsReadOnly,
} from '../tool-action-guard.js';

/**
 * #89 residual (live 2026-08-14, Jarvis field report):
 * read-only diagnostics against ~/.shieldcortex/approvals were require_approval
 * on touch-approval-store — self-referential deadlock on enforced hosts.
 *
 * Mutating the store must STILL gate. Sensitive paths (.ssh/.env) are untouched.
 */

const gate = (command: string) => evaluateToolCall('Bash', { command });

describe('#89 — read-only inspection of guard stores is allowed', () => {
  it.each([
    ['ls approvals', 'ls -la ~/.shieldcortex/approvals'],
    ['ls leases', 'ls ~/.shieldcortex/leases'],
    ['cat DECISIONS', 'cat ~/.shieldcortex/DECISIONS.md'],
    ['grep approvals', 'grep -n hash ~/.shieldcortex/approvals/*'],
    ['head approvals', 'head -20 ~/.shieldcortex/approvals/approvals.json'],
    ['stat approvals', 'stat ~/.shieldcortex/approvals'],
    ['pipeline read', 'cat ~/.shieldcortex/approvals/approvals.json | jq .'],
    ['python read open', "python3 -c \"print(open('/home/u/.shieldcortex/approvals/approvals.json').read())\""],
    ['echo then ls', 'echo hi; ls ~/.shieldcortex/approvals'],
    ['find approvals', 'find ~/.shieldcortex/approvals -type f'],
  ])('ALLOWs %s', (_name, cmd) => {
    const v = gate(cmd);
    expect(v.signals).not.toContain('touch-approval-store');
    expect(v.signals).not.toContain('touch-decisions-ledger');
    expect(v.decision).toBe('allow');
  });
});

describe('#89 — mutating guard stores still gates (must-still-fire)', () => {
  it.each([
    ['redirect write', "echo '{}' > ~/.shieldcortex/approvals/approvals.json"],
    ['append DECISIONS', 'echo x >> ~/.shieldcortex/DECISIONS.md'],
    ['rm approvals', 'rm ~/.shieldcortex/approvals/approvals.json'],
    ['rm -rf approvals', 'rm -rf ~/.shieldcortex/approvals'],
    ['mv approvals', 'mv ~/.shieldcortex/approvals /tmp/x'],
    ['chmod approvals', 'chmod -R 777 ~/.shieldcortex/approvals'],
    ['touch new', 'touch ~/.shieldcortex/approvals/new'],
    ['tee write', 'echo x | tee ~/.shieldcortex/approvals/x.json'],
    ['python write', "python3 -c \"import json;json.dump({},open('/home/u/.shieldcortex/approvals/approvals.json','w'))\""],
    ['node write', "node -e \"require('fs').writeFileSync('/home/u/.shieldcortex/approvals/approvals.json','{}')\""],
    ['cp into store', 'cp /tmp/x ~/.shieldcortex/approvals/x.json'],
  ])('GATEs %s', (_name, cmd) => {
    const v = gate(cmd);
    expect(
      v.signals.includes('touch-approval-store')
      || v.signals.includes('touch-decisions-ledger')
      || v.decision !== 'allow',
    ).toBe(true);
    expect(v.decision).not.toBe('allow');
  });
});

describe('#89 — touch-sensitive-path is NOT relaxed by the store carve-out', () => {
  it('still gates reading ~/.ssh/id_rsa', () => {
    const v = gate('cat ~/.ssh/id_rsa');
    expect(v.signals).toContain('touch-sensitive-path');
    expect(v.decision).not.toBe('allow');
  });

  it('still gates reading a .env file', () => {
    const v = gate('cat /home/u/proj/.env');
    expect(v.signals).toContain('touch-sensitive-path');
  });
});

describe('#89 — guardStoreAccessIsReadOnly helper', () => {
  it('true for pure ls/cat', () => {
    expect(guardStoreAccessIsReadOnly('ls ~/.shieldcortex/approvals')).toBe(true);
    expect(guardStoreAccessIsReadOnly('cat ~/.shieldcortex/DECISIONS.md')).toBe(true);
  });
  it('false for redirects and rm', () => {
    expect(guardStoreAccessIsReadOnly('echo x > ~/.shieldcortex/approvals/a')).toBe(false);
    expect(guardStoreAccessIsReadOnly('rm ~/.shieldcortex/approvals/a')).toBe(false);
  });
  it('false when no store path present', () => {
    expect(guardStoreAccessIsReadOnly('ls /tmp')).toBe(false);
  });
});

describe('#89 — dual-review must-still-fire (Grok 4.6 / SOL)', () => {
  it.each([
    ['sed -i', "sed -i 's/a/b/' ~/.shieldcortex/approvals/approvals.json"],
    ['find -delete', 'find ~/.shieldcortex/approvals -delete'],
    ['find -exec rm', 'find ~/.shieldcortex/approvals -exec rm {} +'],
    ['python os.remove', "python3 -c \"import os;os.remove('/home/u/.shieldcortex/approvals/approvals.json')\""],
    ['python os.system touch', "python3 -c \"import os;os.system('touch ~/.shieldcortex/approvals/x')\""],
    ['python open r+', "python3 -c \"open('/home/u/.shieldcortex/approvals/approvals.json','r+').write('x')\""],
    ['python shutil.move', "python3 -c \"import shutil;shutil.move('/home/u/.shieldcortex/approvals/a','/tmp/a')\""],
    ['node unlinkSync', "node -e \"require('fs').unlinkSync('/home/u/.shieldcortex/approvals/approvals.json')\""],
    ['node execSync touch', "node -e \"require('child_process').execSync('touch ~/.shieldcortex/approvals/x')\""],
    ['node copyFileSync', "node -e \"require('fs').copyFileSync('/tmp/x','/home/u/.shieldcortex/approvals/x')\""],
    ['quoted redirect', 'echo x >"$HOME/.shieldcortex/approvals/x.json"'],
    ['perl -i', "perl -i -pe 's/a/b/' ~/.shieldcortex/approvals/approvals.json"],
  ])('GATEs %s', (_name, cmd) => {
    const v = gate(cmd);
    expect(v.decision).not.toBe('allow');
  });
});
