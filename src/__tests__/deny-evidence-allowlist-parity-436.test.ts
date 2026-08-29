/**
 * #436 — schema/effect signals and Claude control-plane tool names must
 * appear on both the hook and operator-notify allowlists.
 */
import { describe, expect, it } from '@jest/globals';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');

describe('#436 deny-evidence allowlist parity', () => {
  const hook = readFileSync(resolve(root, 'scripts/pre-tool-hook.mjs'), 'utf8');
  const notify = readFileSync(resolve(root, 'src/defence/iron-dome/operator-notify.ts'), 'utf8');

  it('control-plane tool names are quoted on both allowlists', () => {
    for (const name of ['BashOutput', 'KillShell', 'KillBash']) {
      expect(hook).toContain(`'${name}'`);
      expect(notify).toContain(`'${name}'`);
    }
  });

  it('schema/effect signals are quoted on both allowlists', () => {
    for (const signal of [
      'invalid-tool-input', 'unknown-keys', 'not-object', 'nested-invalid',
      'type-coercion', 'missing-handle', 'write-content-catastrophic',
      'write-content-dangerous', 'delete-critical-path', 'session-lease',
    ]) {
      expect(hook).toContain(`'${signal}'`);
      expect(notify).toContain(`'${signal}'`);
    }
  });
});
