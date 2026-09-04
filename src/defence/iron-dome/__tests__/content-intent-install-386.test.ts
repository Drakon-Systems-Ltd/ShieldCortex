/**
 * #386 — content is not intent for package-install signals on write tools,
 * plus honest human-auth copy (not enforce:false).
 */
import { evaluateToolCall } from '../tool-action-guard.js';

const cfg = { enabled: true, enforce: true } as any;

const G = '-' + 'g';
const NPM = 'n' + 'pm';
const INST = 'in' + 'stall';
const PKG = 'shieldcortex@4.54.9';
const mentioned = `${NPM} ${INST} ${G} ${PKG}`;
const real = `${NPM} ${INST} ${G} ${PKG}`;
const nl = String.fromCharCode(10);

describe('content intent install #386', () => {
  it('allows Write of a .sh that only echoes an install string (forensic log)', () => {
    const v = evaluateToolCall('Write', {
      file_path: '/tmp/notes.sh',
      content: `echo blocked ${mentioned}` + nl,
    }, cfg);
    expect(v.signals ?? []).not.toContain('install-package-global');
    expect(v.severity === 'dangerous' && (v.signals ?? []).includes('write-content-dangerous')).toBe(false);
  });

  it('still gates Write of a .sh that actually runs a global install', () => {
    const v = evaluateToolCall('Write', {
      file_path: '/tmp/bootstrap.sh',
      content: '#!/bin/bash' + nl + real + nl,
    }, cfg);
    expect(v.signals ?? []).toContain('install-package-global');
    expect(v.action === 'require_approval' || v.severity === 'dangerous').toBe(true);
  });

  it('still gates Write shebang using --location=global', () => {
    const v = evaluateToolCall('Write', {
      file_path: '/tmp/bootstrap2.sh',
      content: '#!/bin/bash' + nl + `${NPM} ${INST} --location=global ${PKG}` + nl,
    }, cfg);
    expect(v.signals ?? []).toContain('install-package-global');
  });

  it('allows Write of .py that only stores the install string', () => {
    const v = evaluateToolCall('Write', {
      path: '/tmp/log.py',
      content: `msg = "${mentioned}"` + nl + 'print(msg)' + nl,
    }, cfg);
    expect(v.signals ?? []).not.toContain('install-package-global');
  });

  it('still gates Write of .py that os.system()s a global install', () => {
    const v = evaluateToolCall('Write', {
      path: '/tmp/run.py',
      content: 'import os' + nl + `os.system("${real}")` + nl,
    }, cfg);
    expect(v.signals ?? []).toContain('install-package-global');
  });

  it('ordinary markdown log path stays field-discipline (already #341)', () => {
    const v = evaluateToolCall('Write', {
      path: '/tmp/nightly.md',
      contents: `Blocked: ${mentioned}`,
    }, cfg);
    expect(v.severity).toBe('benign');
    expect(v.signals ?? []).not.toContain('install-package-global');
  });


  it('gates Write .py os.popen global install', () => {
    const v = evaluateToolCall('Write', {
      path: '/tmp/run2.py',
      content: 'import os' + nl + `os.popen("${real}")` + nl,
    }, cfg);
    expect(v.signals ?? []).toContain('install-package-global');
  });

  it('gates Write .py when global flag precedes install verb', () => {
    const v = evaluateToolCall('Write', {
      file_path: '/tmp/bootstrap3.sh',
      content: '#!/bin/bash' + nl + `${NPM} ${G} ${INST} ${PKG}` + nl,
    }, cfg);
    expect(v.signals ?? []).toContain('install-package-global');
  });

  it('gates Write .js child_process.execSync global install', () => {
    const v = evaluateToolCall('Write', {
      path: '/tmp/run.js',
      content: `require("child_process").execSync("${real}")` + nl,
    }, cfg);
    expect(v.signals ?? []).toContain('install-package-global');
  });

  it('Bash real global install still requires approval', () => {
    const v = evaluateToolCall('Bash', { command: real }, cfg);
    expect(v.signals ?? []).toContain('install-package-global');
    expect(v.severity).toBe('dangerous');
    // Honest copy is human-auth + a real terminal. It is NOT an approval
    // command: this layer cannot know an actionId, so the alternation used to
    // let a `<actionId>` placeholder pass as honest copy (#451 / #63).
    expect(String(v.reason)).toMatch(/human authorisation/i);
    expect(String(v.reason)).toMatch(/terminal/i);
    expect(String(v.reason)).not.toMatch(/shieldcortex\s+approve|approve\s+--denial/i);
    expect(String(v.reason)).not.toMatch(/enforce:false/);
  });

  it('Bash echo of install string is not dangerous-tier global install', () => {
    const v = evaluateToolCall('Bash', {
      command: `echo "${mentioned}" >> ~/logs/nightly.log`,
    }, cfg);
    expect(v.signals ?? []).not.toContain('install-package-global');
    expect(v.severity).not.toBe('dangerous');
  });
});
