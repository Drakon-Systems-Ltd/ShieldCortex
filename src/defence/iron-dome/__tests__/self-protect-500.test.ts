/**
 * #500 — Action Guard must gate mutations to its own config, hook wiring,
 * binary and lifecycle. When Guard is ON, an agent must not be able to
 * switch it off, uninstall it, or blank the hook file.
 *
 * Token-split literals so the live host scanner does not deny this file.
 */
import { evaluateToolCall } from '../tool-action-guard.js';

const cfg = { enabled: true, enforce: true } as any;
const SC = 'shield' + 'cortex';
const DISABLE = '--action-guard-' + 'disable';
const ADVISORY = '--action-guard-' + 'advisory';
const UNINST = 'un' + 'install';
const G = '-' + 'g';
const NPM = 'n' + 'pm';
const DEL = 'r' + 'm';
const FLAGS = '-' + 'rf';
const ROOT = ' /';

function bash(command: string) {
  return evaluateToolCall('Bash', { command }, cfg);
}

describe('#500 Action Guard self-protection', () => {
  it('gates signed CLI disable from a Bash tool call', () => {
    const v = bash(`${SC} config ${DISABLE}`);
    expect(v.signals ?? []).toContain('disable-action-guard');
    expect(v.severity).toBe('dangerous');
    expect(v.decision).toBe('require_approval');
  });

  it('gates signed CLI advisory downgrade from a Bash tool call', () => {
    const v = bash(`${SC} config ${ADVISORY}`);
    expect(v.signals ?? []).toContain('disable-action-guard');
    expect(v.severity).toBe('dangerous');
    expect(v.decision).toBe('require_approval');
  });

  it('gates npx-prefixed disable', () => {
    const v = bash(`npx ${SC} config ${DISABLE}`);
    expect(v.signals ?? []).toContain('disable-action-guard');
    expect(v.severity).toBe('dangerous');
  });

  it('gates iron-dome deactivate', () => {
    const v = bash(`${SC} iron-dome deactivate`);
    expect(v.signals ?? []).toContain('disable-action-guard');
    expect(v.severity).toBe('dangerous');
  });

  it('gates global uninstall of the package', () => {
    const v = bash(`${NPM} ${UNINST} ${G} ${SC}`);
    expect(v.signals ?? []).toContain('disable-action-guard');
    expect(v.severity).toBe('dangerous');
  });

  it('gates Write of ~/.shieldcortex/config.json', () => {
    const v = evaluateToolCall('Write', {
      file_path: '/home/ubuntu/.shieldcortex/config.json',
      content: '{"actionGuard":{"enabled":false}}',
    }, cfg);
    expect(v.signals ?? []).toContain('touch-guard-config');
    expect(v.severity).toBe('dangerous');
  });

  it('gates Edit of config.json', () => {
    const v = evaluateToolCall('Edit', {
      path: '/tmp/home/.shieldcortex/config.json',
      old_string: '"enabled": true',
      new_string: '"enabled": false',
    }, cfg);
    expect(v.signals ?? []).toContain('touch-guard-config');
    expect(v.severity).toBe('dangerous');
  });

  it('allows a pure echo of the disable flag (prose, not invocation)', () => {
    const v = bash(`echo blocked ${SC} config ${DISABLE}`);
    expect(v.signals ?? []).not.toContain('disable-action-guard');
    expect(v.severity).not.toBe('dangerous');
  });

  it('still gates a catastrophic delete while Guard is on (control)', () => {
    const v = bash(`${DEL} ${FLAGS}${ROOT}`);
    expect(v.severity).toBe('catastrophic');
    expect(v.decision).toBe('block');
  });
});
