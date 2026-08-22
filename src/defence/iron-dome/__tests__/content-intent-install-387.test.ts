/**
 * #387 leftover — system/pip install on Write must be an INVOCATION.
 * #386 closed the npm-global write-then-exec lane; pip/apt/brew/gem/cargo
 * stayed fail-open after the disposer dropped unconfirmed vocabulary.
 */
import { evaluateToolCall } from '../tool-action-guard.js';

const cfg = { enabled: true, enforce: true } as any;

const PIP = 'p' + 'ip';
const INST = 'in' + 'stall';
const REQ = 'req' + 'uests';
const APT = 'apt' + '-get';
const BREW = 'br' + 'ew';
const NL = String.fromCharCode(10);
const NPM = 'n' + 'pm';
const PKG = 'left' + 'pad';

function writePy(content: string) {
  return evaluateToolCall('Write', { path: '/tmp/run.py', content }, cfg);
}

function writeSh(content: string) {
  return evaluateToolCall('Write', { file_path: '/tmp/run.sh', content }, cfg);
}

describe('content intent install #387 leftover', () => {
  it('gates Write .py that os.system()s an unscoped pip install', () => {
    const v = writePy('import os' + NL + `os.system("${PIP} ${INST} ${REQ}")` + NL);
    expect(v.signals ?? []).toContain('install-package');
    expect(v.action === 'require_approval' || v.severity === 'dangerous').toBe(true);
  });

  it('gates Write .py cmd-indirection + os.system pip', () => {
    const v = writePy(
      'import os' + NL
      + `cmd = "${PIP} ${INST} ${REQ}"` + NL
      + 'os.system(cmd)' + NL,
    );
    expect(v.signals ?? []).toContain('install-package');
  });

  it('gates Write .py os.popen pip', () => {
    const v = writePy('import os' + NL + `os.popen("${PIP} ${INST} ${REQ}")` + NL);
    expect(v.signals ?? []).toContain('install-package');
  });

  it('gates Write .py subprocess.run argv-list pip', () => {
    const v = writePy(
      'import subprocess' + NL
      + `subprocess.run(["${PIP}", "${INST}", "${REQ}"])` + NL,
    );
    expect(v.signals ?? []).toContain('install-package');
  });

  it('gates Write .py cmd-indirection + os.system apt-get', () => {
    const v = writePy(
      'import os' + NL
      + `cmd = "${APT} ${INST} -y curl"` + NL
      + 'os.system(cmd)' + NL,
    );
    expect(v.signals ?? []).toContain('install-package');
  });

  it('gates Write .py child_process.execSync brew', () => {
    const v = evaluateToolCall('Write', {
      path: '/tmp/run.js',
      content: `require("child_process").execSync("${BREW} ${INST} wget")` + NL,
    }, cfg);
    expect(v.signals ?? []).toContain('install-package');
  });

  it('gates Write shebang .sh that actually runs pip', () => {
    const v = writeSh('#!/bin/bash' + NL + `${PIP} ${INST} ${REQ}` + NL);
    expect(v.signals ?? []).toContain('install-package');
  });

  it('gates abbreviated npm i --location=global', () => {
    const v = writeSh('#!/bin/bash' + NL + `${NPM} i --location=global ${PKG}` + NL);
    expect(v.signals ?? []).toContain('install-package-global');
  });

  it('allows Write .py that only stores the pip string', () => {
    const v = writePy(`msg = "${PIP} ${INST} ${REQ}"` + NL + 'print(msg)' + NL);
    expect(v.signals ?? []).not.toContain('install-package');
    expect(v.severity).not.toBe('dangerous');
  });

  it('allows Write .sh that only echoes the apt string', () => {
    const v = writeSh(`echo blocked ${APT} ${INST} -y curl` + NL);
    expect(v.signals ?? []).not.toContain('install-package');
    expect(v.severity === 'dangerous' && (v.signals ?? []).includes('write-content-dangerous')).toBe(false);
  });

  it('allows Write of venv-scoped pip install', () => {
    const v = writeSh('#!/bin/bash' + NL + `.venv/bin/${PIP} ${INST} -r requirements.txt` + NL);
    expect(v.signals ?? []).not.toContain('install-package');
  });

  it('allows Write of pip --target scoped install', () => {
    const v = writeSh('#!/bin/bash' + NL + `${PIP} ${INST} --target ./vendor ${REQ}` + NL);
    expect(v.signals ?? []).not.toContain('install-package');
  });
});
