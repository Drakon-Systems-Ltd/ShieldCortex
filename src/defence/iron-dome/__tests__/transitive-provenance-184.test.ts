/**
 * #184 — transitive verdicts must cite provenance.
 *
 * Field case (EDITH): `scripts/github-backup.sh` was auto-denied for
 * `recursive-force-delete` even though that file contains no `rm`. The guard
 * had followed a nested call into `resilience/sync-code-backup.sh` and matched
 * there — but the verdict named only the rule + span, so the operator opened
 * the parent script, found nothing, and concluded the guard was broken.
 *
 * Contract:
 * - A match inside a folded nested script names `source`, `line`, and `chain`
 * - The reason string includes `in: <file>:<line> (via <chain>)`
 * - Inline (non-folded) matches still omit source/chain
 * - Catastrophic transitive denial remains catastrophic (no silent downgrade)
 */
import { describe, it, expect } from '@jest/globals';
import { evaluateToolCall } from '../tool-action-guard.js';
import type { ToolGuardVerdict } from '../tool-action-guard.js';

function stubResolver(files: Record<string, string>): (p: string) => string | null {
  return (p: string) => (Object.prototype.hasOwnProperty.call(files, p) ? files[p] : null);
}

function verdictOf(command: string, files: Record<string, string>): ToolGuardVerdict {
  return evaluateToolCall(
    'Bash',
    { command },
    undefined,
    { resolveScriptSource: stubResolver(files) },
  );
}

describe('#184 — transitive catastrophic match cites nested provenance', () => {
  // EDITH shape: parent has no rm; child does the mirror refresh with rm -rf.
  const parent = [
    '#!/usr/bin/env bash',
    'set -euo pipefail',
    '# line 3 is prose only',
    'echo "starting backup"',
    'bash resilience/sync-code-backup.sh',
    'echo "done"',
    '',
  ].join('\n');

  const child = [
    '#!/usr/bin/env bash',
    'set -euo pipefail',
    'DEST="${1:-/var/backups/code}"',
    '# mirror refresh before re-copy — this is the real match site',
    'rm -rf "$DEST/scripts" "$DEST/skills"',
    'mkdir -p "$DEST"',
    '',
  ].join('\n');

  it('blocks and names the CHILD file, not only the parent command', () => {
    const v = verdictOf('bash scripts/github-backup.sh', {
      'scripts/github-backup.sh': parent,
      'resilience/sync-code-backup.sh': child,
    });

    expect(v.decision).toBe('block');
    expect(v.severity).toBe('catastrophic');
    expect(v.signals).toContain('recursive-force-delete');

    const match = v.matches?.find(m => m.signal === 'recursive-force-delete');
    expect(match).toBeDefined();
    expect(match!.source).toBe('resilience/sync-code-backup.sh');
    expect(match!.line).toBe(5);
    expect(match!.chain).toBe(
      'scripts/github-backup.sh → resilience/sync-code-backup.sh',
    );

    // Reason is what the operator reads in the denial UI.
    expect(v.reason).toMatch(/resilience\/sync-code-backup\.sh:5/);
    expect(v.reason).toMatch(/scripts\/github-backup\.sh → resilience\/sync-code-backup\.sh/);
    // Must not pretend the match is only "in the command" without a file.
    expect(v.reason).toMatch(/\bin:/);
  });

  it('a direct (non-nested) script match still cites that single file', () => {
    const v = verdictOf('bash resilience/sync-code-backup.sh', {
      'resilience/sync-code-backup.sh': child,
    });
    expect(v.decision).toBe('block');
    const match = v.matches?.find(m => m.signal === 'recursive-force-delete');
    expect(match?.source).toBe('resilience/sync-code-backup.sh');
    expect(match?.chain).toBe('resilience/sync-code-backup.sh');
    expect(v.reason).toMatch(/resilience\/sync-code-backup\.sh:5/);
    // Single-hop chain should not invent a "via" hop to itself.
    expect(v.reason).not.toMatch(/\(via /);
  });

  it('an inline command match does NOT invent a source path', () => {
    const v = evaluateToolCall('Bash', { command: 'rm -rf /var/lib/thing' });
    expect(v.decision).toBe('block');
    expect(v.signals).toContain('recursive-force-delete');
    const match = v.matches?.find(m => m.signal === 'recursive-force-delete');
    expect(match?.source).toBeUndefined();
    expect(match?.chain).toBeUndefined();
    expect(v.reason).not.toMatch(/\bin:/);
  });
});

describe('#184 — dangerous-tier transitive provenance', () => {
  it('require_approval from a nested script names the nested file', () => {
    const parent = '#!/bin/bash\nbash helpers/push.sh\n';
    const child = '#!/bin/bash\ngit push --force origin main\n';
    const v = verdictOf('bash scripts/release.sh', {
      'scripts/release.sh': parent,
      'helpers/push.sh': child,
    });
    expect(v.decision).toBe('require_approval');
    expect(v.signals).toContain('git-force-push');
    const match = v.matches?.find(m => m.signal === 'git-force-push');
    expect(match?.source).toBe('helpers/push.sh');
    expect(match?.chain).toBe('scripts/release.sh → helpers/push.sh');
    expect(v.reason).toMatch(/helpers\/push\.sh/);
    expect(v.reason).toMatch(/scripts\/release\.sh → helpers\/push\.sh/);
  });
});
