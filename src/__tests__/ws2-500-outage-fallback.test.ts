import { describe, expect, it } from '@jest/globals';
import { createInterceptor, DEFAULT_CONFIG } from '../../plugins/openclaw/interceptor.js';
import type { InterceptAuditEntry } from '../../plugins/openclaw/interceptor.js';

const okPipeline = () => ({
  allowed: true,
  firewall: { result: 'ALLOW' as const, reason: '', threatIndicators: [] as string[], anomalyScore: 0, blockedPatterns: [] as string[] },
  trust: { score: 0.5 }, sensitivity: { level: 'INTERNAL' }, fragmentation: null, auditId: 1,
});

describe('#500 — self-protect shapes gate during an outage (interceptor)', () => {
  const name = 'shield' + 'cortex';
  const disable = '--action-guard-' + 'disable';
  const uninst = 'un' + 'install';
  const g = '-' + 'g';
  const npm = 'n' + 'pm';
  const cfg = ['/', 'home', '/', 'u', '/', '.', name, '/', 'config', '.json'].join('');
  const newly: Array<[string, string, Record<string, unknown>]> = [
    ['signed CLI disable', 'Bash', { command: name + ' config ' + disable }],
    ['iron-dome deactivate', 'Bash', { command: name + ' iron-dome deactivate' }],
    ['global uninstall', 'Bash', { command: [npm, uninst, g, name].join(' ') }],
    ['Write config.json', 'Write', { file_path: cfg, content: '{}' }],
  ];
  it.each(newly)('gates (fail-closed): %s', async (_label, toolName, args) => {
    const entries: InterceptAuditEntry[] = [];
    const i = createInterceptor({ ...DEFAULT_CONFIG, actionGuard: { enabled: true, enforce: true, autoApprove: [] } } as never, okPipeline as never, { onAuditEntry: (e) => entries.push(e) });
    await expect(i.handleToolCall({ toolName, arguments: args })).rejects.toThrow(/blocked|fallback|policy/i);
    expect(entries.some((e) => e.outcome === 'failure_denied' || e.outcome === 'auto_denied')).toBe(true);
  });
});
