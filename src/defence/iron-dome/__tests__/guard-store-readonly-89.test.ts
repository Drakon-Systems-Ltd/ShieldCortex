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
 * Policy (Grok 4.6 + SOL floor): FAIL CLOSED. Only pure shell observation
 * verbs (ls/cat/grep/…) drop the gate. Interpreters stay gated when they
 * name the store — a mutation denylist can never be complete.
 */

const gate = (command: string) => evaluateToolCall('Bash', { command });

describe('#89 — read-only shell inspection of guard stores is allowed', () => {
  it.each([
    ['ls approvals', 'ls -la ~/.shieldcortex/approvals'],
    ['ls leases', 'ls ~/.shieldcortex/leases'],
    ['cat DECISIONS', 'cat ~/.shieldcortex/DECISIONS.md'],
    ['grep approvals', 'grep -n hash ~/.shieldcortex/approvals/*'],
    ['head approvals', 'head -20 ~/.shieldcortex/approvals/approvals.json'],
    ['stat approvals', 'stat ~/.shieldcortex/approvals'],
    ['pipeline read', 'cat ~/.shieldcortex/approvals/approvals.json | jq .'],
    ['echo then ls', 'echo hi; ls ~/.shieldcortex/approvals'],
    ['rg approvals', 'rg hash ~/.shieldcortex/approvals'],
  ])('ALLOWs %s', (_name, cmd) => {
    const v = gate(cmd);
    expect(v.signals).not.toContain('touch-approval-store');
    expect(v.signals).not.toContain('touch-decisions-ledger');
    expect(v.decision).toBe('allow');
  });
});

describe('#89 — interpreters naming the store stay gated (fail closed)', () => {
  it.each([
    ['python read open', "python3 -c \"print(open('/home/u/.shieldcortex/approvals/approvals.json').read())\""],
    ['python write', "python3 -c \"import json;json.dump({},open('/home/u/.shieldcortex/approvals/approvals.json','w'))\""],
    ['python os.remove', "python3 -c \"import os;os.remove('/home/u/.shieldcortex/approvals/approvals.json')\""],
    ['python os.system touch', "python3 -c \"import os;os.system('touch ~/.shieldcortex/approvals/x')\""],
    ['node read', "node -e \"console.log(require('fs').readFileSync('/home/u/.shieldcortex/approvals/approvals.json','utf8'))\""],
    ['node write', "node -e \"require('fs').writeFileSync('/home/u/.shieldcortex/approvals/approvals.json','{}')\""],
    ['node unlinkSync', "node -e \"require('fs').unlinkSync('/home/u/.shieldcortex/approvals/approvals.json')\""],
    ['find approvals', 'find ~/.shieldcortex/approvals -type f'],
    ['sed print', "sed -n '1,5p' ~/.shieldcortex/approvals/approvals.json"],
  ])('GATEs %s', (_name, cmd) => {
    const v = gate(cmd);
    expect(v.decision).not.toBe('allow');
    expect(
      v.signals.includes('touch-approval-store')
      || v.signals.includes('touch-decisions-ledger'),
    ).toBe(true);
  });
});

describe('#89 — shell mutations still gate (must-still-fire)', () => {
  it.each([
    ['redirect write', "echo '{}' > ~/.shieldcortex/approvals/approvals.json"],
    ['noclobber redirect', "echo '{}' >| ~/.shieldcortex/approvals/approvals.json"],
    ['quoted redirect', 'echo x >"$HOME/.shieldcortex/approvals/x.json"'],
    ['append DECISIONS', 'echo x >> ~/.shieldcortex/DECISIONS.md'],
    ['rm approvals', 'rm ~/.shieldcortex/approvals/approvals.json'],
    ['rm -rf approvals', 'rm -rf ~/.shieldcortex/approvals'],
    ['mv approvals', 'mv ~/.shieldcortex/approvals /tmp/x'],
    ['chmod approvals', 'chmod -R 777 ~/.shieldcortex/approvals'],
    ['touch new', 'touch ~/.shieldcortex/approvals/new'],
    ['tee write', 'echo x | tee ~/.shieldcortex/approvals/x.json'],
    ['cp into store', 'cp /tmp/x ~/.shieldcortex/approvals/x.json'],
    ['sed -i', "sed -i 's/a/b/' ~/.shieldcortex/approvals/approvals.json"],
    ['find -delete', 'find ~/.shieldcortex/approvals -delete'],
  ])('GATEs %s', (_name, cmd) => {
    const v = gate(cmd);
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
  it('false for redirects, rm, interpreters, find', () => {
    expect(guardStoreAccessIsReadOnly('echo x > ~/.shieldcortex/approvals/a')).toBe(false);
    expect(guardStoreAccessIsReadOnly("echo x >| ~/.shieldcortex/approvals/a")).toBe(false);
    expect(guardStoreAccessIsReadOnly('rm ~/.shieldcortex/approvals/a')).toBe(false);
    expect(guardStoreAccessIsReadOnly("python3 -c \"print(open('/home/u/.shieldcortex/approvals/a').read())\"")).toBe(false);
    expect(guardStoreAccessIsReadOnly('find ~/.shieldcortex/approvals -type f')).toBe(false);
  });
  it('false when no store path present', () => {
    expect(guardStoreAccessIsReadOnly('ls /tmp')).toBe(false);
  });
});

describe('#89 — round-4 Grok mint paths stay gated', () => {
  it.each([
    ['cmd subst python write', `echo $(python3 -c "open('/home/u/.shieldcortex/approvals/approvals.json','w').write('{}')")`],
    ['process subst write', `echo '{}' > >(python3 -c "open('/home/u/.shieldcortex/approvals/approvals.json','w').write(open(0).read())")`],
    ['path-smuggling pipeline', `echo ~/.shieldcortex/approvals/approvals.json | python3 -c "import sys; open(sys.stdin.read().strip(),'w').write('{}')"`],
    ['cat store | python writer', `cat ~/.shieldcortex/approvals/approvals.json | python3 -c "import pathlib; (pathlib.Path.home()/'.shieldcortex'/'approvals'/'approvals.json').write_text('{}')"`],
    ['yq -i', `yq -i '.x=1' ~/.shieldcortex/approvals/approvals.json`],
    ['backticks', 'echo `cat ~/.shieldcortex/approvals/approvals.json`'],
  ])('GATEs %s', (_name, cmd) => {
    const v = gate(cmd);
    expect(v.decision).not.toBe('allow');
  });

  it('cat store | jq still allows (every stage readonly)', () => {
    const v = gate('cat ~/.shieldcortex/approvals/approvals.json | jq .');
    expect(v.decision).toBe('allow');
    expect(v.signals).not.toContain('touch-approval-store');
  });
});
