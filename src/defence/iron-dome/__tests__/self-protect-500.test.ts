/**
 * #500 — Action Guard must gate tool-call mutations to its own config and
 * lifecycle. When Guard is ON, an agent must not be able to switch it off,
 * downgrade it, uninstall it globally, or rewrite config.json via a tool.
 * Hook-file wiring (.claude/settings.json) and same-UID writes outside the
 * tool surface are NOT in this PR (see #501).
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
const PRIV = 's' + 'u' + 'd' + 'o';
const RMV = 'r' + 'm';
const YES = '--' + 'yes';

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

  // GPT-6 r1: wrappers, absolute path, env assignment, node $(which), --location=global.
  it.each([
    ['absolute path', `/usr/bin/${SC} config ${DISABLE}`],
    ['env wrapper', `env ${SC} config ${DISABLE}`],
    ['env assignment prefix', `SHIELDCORTEX_CONFIG_DIR=/tmp/sc ${SC} config ${DISABLE}`],
    ['node $(which)', `node $(which ${SC}) config ${DISABLE}`],
    ['privilege wrapper', `${PRIV} ${SC} config ${DISABLE}`],
    ['npx auto-confirm', `npx ${YES} ${SC} config ${DISABLE}`],
    ['extra config flag before disable', `${SC} config --quiet ${DISABLE}`],
  ])('gates disable via: %s', (_label, command) => {
    const v = bash(command);
    expect(v.signals ?? []).toContain('disable-action-guard');
    expect(v.severity).toBe('dangerous');
  });

  it.each([
    ['--location=global', `${NPM} ${UNINST} --location=global ${SC}`],
    ['--global long flag', `${NPM} ${UNINST} --global ${SC}`],
    ['npm short alias', `${NPM} ${RMV} ${G} ${SC}`],
    ['scoped realtime plugin', `${NPM} ${UNINST} ${G} @drakon-systems/${SC}-realtime`],
    ['yarn global remove', `yarn global remove ${SC}`],
  ])('gates global uninstall via: %s', (_label, command) => {
    const v = bash(command);
    expect(v.signals ?? []).toContain('disable-action-guard');
    expect(v.severity).toBe('dangerous');
  });

  it('does not gate global uninstall of an unrelated package with a shared prefix', () => {
    const v = bash(`${NPM} ${UNINST} ${G} ${SC}-helper`);
    expect(v.signals ?? []).not.toContain('disable-action-guard');
  });

  it('does not gate a workspace-local uninstall', () => {
    const v = bash(`${NPM} ${UNINST} ${SC}`);
    expect(v.signals ?? []).not.toContain('disable-action-guard');
  });

  // GPT-6 r2: shell quotes around the subcommand / flag reach npm as the same argv.
  it.each([
    ['quoted uninstall verb', `${NPM} "${UNINST}" ${G} ${SC}`],
    ['single-quoted uninstall verb', `${NPM} '${UNINST}' ${G} ${SC}`],
    ['quoted package', `${NPM} ${UNINST} ${G} "${SC}"`],
    ['quoted global flag', `${NPM} ${UNINST} "${G}" ${SC}`],
  ])('gates global uninstall via: %s', (_label, command) => {
    const v = bash(command);
    expect(v.signals ?? []).toContain('disable-action-guard');
    expect(v.severity).toBe('dangerous');
  });
  it.each([
    ['quoted disable flag', `${SC} config "${DISABLE}"`],
    ['quoted deactivate', `${SC} 'iron-dome' 'deactivate'`],
  ])('gates disable via: %s', (_label, command) => {
    const v = bash(command);
    expect(v.signals ?? []).toContain('disable-action-guard');
    expect(v.severity).toBe('dangerous');
  });

  // GPT-6 r3 P2: removal vocabulary as a query ARGUMENT is not an uninstall.
  it.each([
    ['npm ls with uninstall as an argument', `${NPM} ls ${G} ${SC} ${UNINST}`],
    ['npm view of the package', `${NPM} view ${SC} version`],
    ['npm ls -g of the package', `${NPM} ls ${G} ${SC}`],
    ['npm outdated -g', `${NPM} outdated ${G}`],
  ])('does not gate a read-only query: %s', (_label, command) => {
    const v = bash(command);
    expect(v.signals ?? []).not.toContain('disable-action-guard');
  });
  it('still gates when a flag precedes the verb', () => {
    const v = bash(`${NPM} ${G} ${UNINST} ${SC}`);
    expect(v.signals ?? []).toContain('disable-action-guard');
  });

  // GPT-6 r3 P1 (cheap fold, disable flag only). Interior quotes in the
  // BINARY name (git-class) and general quote-normalization are #504.
  const IQ = String.fromCharCode(34);
  it.each([
    ['interior quote in disable', `${SC} config --action-guard-dis${IQ}able${IQ}`],
    ['backslash before able', `${SC} config --action-guard-dis\\able`],
  ])('gates disable via: %s', (_label, command) => {
    const v = bash(command);
    expect(v.signals ?? []).toContain('disable-action-guard');
    expect(v.severity).toBe('dangerous');
  });

  // GPT-6 r4: value-taking options before the verb; explicit --global=false.
  it.each([
    ['--loglevel silent before verb', `${NPM} --loglevel silent ${G} ${UNINST} ${SC}`],
    ['--prefix /opt before verb', `${NPM} --prefix /opt/n ${G} ${UNINST} ${SC}`],
    ['--global=true', `${NPM} ${UNINST} --global=true ${SC}`],
  ])('gates global uninstall via: %s', (_label, command) => {
    const v = bash(command);
    expect(v.signals ?? []).toContain('disable-action-guard');
    expect(v.severity).toBe('dangerous');
  });
  it.each([
    ['--global=false', `${NPM} ${UNINST} --global=false ${SC}`],
    ['--location=project', `${NPM} ${UNINST} --location=project ${SC}`],
  ])('does not gate an explicitly local uninstall: %s', (_label, command) => {
    const v = bash(command);
    expect(v.signals ?? []).not.toContain('disable-action-guard');
  });

  // r5 ReDoS tripwire: a (flag value?)* pre-verb group blew up to >60s on
  // this shape. Rule must stay linear on many flag/value pairs with no verb.
  it('stays fast on thousands of flag/value pairs before the package (ReDoS tripwire)', () => {
    const pairs = Array.from({ length: 4000 }, (_, i) => `--opt${i} val${i}`).join(' ');
    const t0 = Date.now();
    bash(`${NPM} ${pairs} ${G} ${SC}`);
    bash(`${NPM} ${'-a b '.repeat(10000)}${SC} ${G}`);
    expect(Date.now() - t0).toBeLessThan(300);
  });
});
