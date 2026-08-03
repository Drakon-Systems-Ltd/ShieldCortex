import { describe, it, expect } from '@jest/globals';
import { evaluateToolCall } from '../tool-action-guard.js';
const deny: Record<string,string> = {
  force_long:    'git push --force origin main',
  force_short:   'git push -f origin main',
  force_lease:   'git push --force-with-lease origin main',
  force_refspec: 'git push origin +main:main',
  force_second:  'git status && git push origin main --force',
  force_C:       'git -C /repo push origin main -f',
};
const allow: Record<string,string> = {
  friday_chain:  'trash old.tar.gz && git add -A && git commit -m "Auto-backup" --quiet && git push origin main --quiet',
  rsync_f:       'git push origin main && rsync -f rules dst',
  trash_dash_f:  'git push origin main --quiet && trash old-f.tar.gz',
  echo_plus:     'git push origin main --quiet && echo "done+ok"',
  grep_f:        'git push origin main && grep -f pat.txt log',
  curl_f:        'git push origin main --quiet && curl -f https://example.com/ping',
};
describe('#191 git-force-push: statement-bounded, token-anchored', () => {
  it('still gates real force pushes', () => {
    for (const [k, cmd] of Object.entries(deny)) {
      const v: any = evaluateToolCall('Bash', { command: cmd });
      console.log(`DENY ${k} => ${v.decision} ${JSON.stringify(v.signals)}`);
      expect(v.signals).toContain('git-force-push');
    }
  });
  it('no longer gates non-force chains', () => {
    for (const [k, cmd] of Object.entries(allow)) {
      const v: any = evaluateToolCall('Bash', { command: cmd });
      console.log(`ALLOW ${k} => ${v.decision} ${JSON.stringify(v.signals)}`);
      expect(v.signals).not.toContain('git-force-push');
    }
  });
});
