/**
 * #224 — enforcement evidence must be bound: plane, instance, hook, plugin,
 * nonce, seq, and a stable action key. A record that cannot say what it is
 * about cannot feed Athena's acceptance contract or Veronica's FP benchmark.
 */
import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { mkdtempSync, rmSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  REQUIRED_BINDING_FIELDS,
  hasRequiredBinding,
  attachEnforcementBinding,
  actionKeyForToolCall,
  nextAuditSeq,
  resolveInstanceId,
  bindRuntimeInspectPayload,
  type EnforcementPlane,
} from '../enforcement-binding.js';

describe('#224 enforcement binding schema', () => {
  it('names every field the acceptance contract needs', () => {
    expect([...REQUIRED_BINDING_FIELDS].sort()).toEqual(
      ['actionKey', 'gatewayInstanceId', 'hookName', 'nonce', 'plane', 'pluginId', 'seq'].sort(),
    );
  });

  it('fails when any required field is dropped', () => {
    const full = attachEnforcementBinding(
      { type: 'intercept', tool: 'Bash' },
      { plane: 'action_guard', hookName: 'before_tool_call', pluginId: 'shieldcortex-realtime', tool: 'Bash', args: { command: 'git status' } },
    );
    expect(hasRequiredBinding(full)).toBe(true);
    for (const field of REQUIRED_BINDING_FIELDS) {
      const clone = { ...full };
      delete (clone as Record<string, unknown>)[field];
      expect(hasRequiredBinding(clone)).toBe(false);
    }
  });

  it('rejects an unknown plane', () => {
    const row = attachEnforcementBinding(
      {},
      { plane: 'not_a_plane' as EnforcementPlane, hookName: 'x', pluginId: 'p' },
    );
    expect(hasRequiredBinding(row)).toBe(false);
  });
});

describe('#224 action key — same intent collapses, different intents do not', () => {
  it('excludes the mutable description (and timeout) so retries of the same command collapse', () => {
    const a = actionKeyForToolCall('Bash', { command: 'git push origin feat/x', description: 'push the branch', timeout: 120000 });
    const b = actionKeyForToolCall('Bash', { command: 'git push origin feat/y', description: 'push again', timeout: 60000 });
    expect(a).toBe(b);
    expect(a).toContain('git');
    expect(a).not.toMatch(/description|push the branch|120000/);
  });

  it('classifies paths so /tmp/foo and /tmp/bar are one intent', () => {
    expect(actionKeyForToolCall('Bash', { command: 'rm -rf /tmp/clone-a' }))
      .toBe(actionKeyForToolCall('Bash', { command: 'rm -rf /tmp/clone-b' }));
    expect(actionKeyForToolCall('Bash', { command: 'rm -rf /tmp/clone-a' }))
      .not.toBe(actionKeyForToolCall('Bash', { command: 'rm -rf /etc/passwd' }));
  });

  it('classifies targeted PIDs so kill -9 4021 and kill -9 9999 collapse', () => {
    expect(actionKeyForToolCall('Bash', { command: 'kill -9 4021' }))
      .toBe(actionKeyForToolCall('Bash', { command: 'kill -9 9999' }));
    expect(actionKeyForToolCall('Bash', { command: 'kill -9 4021' }))
      .not.toBe(actionKeyForToolCall('Bash', { command: 'killall sshd' }));
  });

  it('keeps force vs merged-delete as different intents', () => {
    expect(actionKeyForToolCall('Bash', { command: 'git branch -D feat/a' }))
      .not.toBe(actionKeyForToolCall('Bash', { command: 'git branch -d feat/a' }));
    expect(actionKeyForToolCall('Bash', { command: 'git push --force origin main' }))
      .not.toBe(actionKeyForToolCall('Bash', { command: 'git push origin main' }));
  });

  it('does not treat a Write of different files as the same intent class as a Bash delete', () => {
    expect(actionKeyForToolCall('Write', { path: 'src/foo.ts' }))
      .not.toBe(actionKeyForToolCall('Bash', { command: 'rm -rf src/foo.ts' }));
  });
});

describe('#224 nonce / seq / instance', () => {
  let home: string;
  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), 'sc-224-'));
  });
  afterEach(() => {
    try { rmSync(home, { recursive: true, force: true }); } catch { /* best effort */ }
  });

  it('mints a unique nonce per record', () => {
    const a = attachEnforcementBinding({}, { plane: 'action_guard', hookName: 'PreToolUse', pluginId: 'claude-code-hook', home });
    const b = attachEnforcementBinding({}, { plane: 'action_guard', hookName: 'PreToolUse', pluginId: 'claude-code-hook', home });
    expect(a.nonce).toMatch(/^[0-9a-f]{32}$/);
    expect(a.nonce).not.toBe(b.nonce);
  });

  it('seq is monotonic and durable across process-equivalent calls', () => {
    const a = attachEnforcementBinding({}, { plane: 'conversation_firewall', hookName: 'llm_input', pluginId: 'shieldcortex-realtime', home });
    const b = attachEnforcementBinding({}, { plane: 'conversation_firewall', hookName: 'llm_input', pluginId: 'shieldcortex-realtime', home });
    expect(b.seq).toBe(a.seq + 1);
    expect(nextAuditSeq(home)).toBe(b.seq + 1);
  });

  it('instance id is stable on a home and is persisted', () => {
    const id1 = resolveInstanceId(home);
    const id2 = resolveInstanceId(home);
    expect(id1).toBe(id2);
    expect(id1).toMatch(/^[0-9a-f-]{36}$/);
    expect(existsSync(join(home, '.shieldcortex', 'instance-id'))).toBe(true);
    expect(readFileSync(join(home, '.shieldcortex', 'instance-id'), 'utf8').trim()).toBe(id1);
  });

  it('gatewayInstanceId names the instance, not "any gateway"', () => {
    const row = attachEnforcementBinding(
      {},
      { plane: 'action_guard', hookName: 'before_tool_call', pluginId: 'shieldcortex-realtime', home, gatewayPid: 4242 },
    );
    expect(row.gatewayInstanceId).toContain(resolveInstanceId(home));
    expect(row.gatewayInstanceId).toContain('4242');
  });
});

describe('#224 runtime inspect payload is bound to a host', () => {
  it('stamps configPath, pid and timestamp onto the inspect JSON', () => {
    const bound = bindRuntimeInspectPayload(
      { healthy: true, plugin: 'shieldcortex-realtime' },
      { configPath: '/tmp/scratch/openclaw.json', pid: 99, timestamp: '2026-08-13T16:00:00.000Z' },
    );
    expect(bound).toMatchObject({
      healthy: true,
      plugin: 'shieldcortex-realtime',
      configPath: '/tmp/scratch/openclaw.json',
      pid: 99,
      timestamp: '2026-08-13T16:00:00.000Z',
    });
  });

  it('still binds a non-object payload rather than dropping it', () => {
    const bound = bindRuntimeInspectPayload('blocked', { configPath: '/cfg', pid: 1, timestamp: 't' });
    expect(bound.configPath).toBe('/cfg');
    expect(bound.pid).toBe(1);
    expect(bound.payload).toBe('blocked');
  });
});
