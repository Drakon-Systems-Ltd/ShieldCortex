/**
 * #386 — content is not intent for package-install signals on write tools,
 * plus honest human-auth copy (not enforce:false).
 */
import { evaluateToolCall } from '../tool-action-guard.js';

const cfg = { enabled: true, enforce: true } as any;

// Split tokens so this test file itself is not an install invocation if scanned.
const G = '-' + 'g';
const NPM = 'n' + 'pm';
const INST = 'in' + 'stall';
const PKG = 'shieldcortex@4.54.9';
const mentioned = `${NPM} ${INST} ${G} ${PKG}`;
const real = `${NPM} ${INST} ${G} ${PKG}`;
const flagFirst = `${NPM} ${G} ${INST} evil`;
const locGlobal = '--loc' + 'ation=global';
const NPX = 'np' + 'x';
const CORE = 'core' + 'pack';
const nl = String.fromCharCode(10);

function gated(tool: string, args: Record<string, unknown>): boolean {
  const v = evaluateToolCall(tool, args, cfg);
  return (v.signals ?? []).includes('install-package-global');
}

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
    expect(gated('Write', {
      file_path: '/tmp/bootstrap2.sh',
      content: '#!/bin/bash' + nl + `${NPM} ${INST} ${locGlobal} ${PKG}` + nl,
    })).toBe(true);
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

  it('gates os.system with -g before install', () => {
    expect(gated('Write', {
      path: '/tmp/run2.py',
      content: 'import os' + nl + `os.system("${flagFirst}")` + nl,
    })).toBe(true);
  });

  it('gates os.popen of a global install', () => {
    expect(gated('Write', {
      path: '/tmp/run3.py',
      content: 'import os' + nl + `os.popen("${real}")` + nl,
    })).toBe(true);
  });

  it('gates subprocess.run list form with -g first', () => {
    expect(gated('Write', {
      path: '/tmp/run4.py',
      content: 'import subprocess' + nl + `subprocess.run(["${NPM}", "${G}", "${INST}", "evil"])` + nl,
    })).toBe(true);
  });

  it('gates os.system(var) when the payload also stores the install string', () => {
    expect(gated('Write', {
      path: '/tmp/run5.py',
      content: 'import os' + nl + `cmd = "${real}"` + nl + 'os.system(cmd)' + nl,
    })).toBe(true);
  });

  it('gates multiline os.system string', () => {
    expect(gated('Write', {
      path: '/tmp/ml.py',
      content: 'import os' + nl + 'os.system(' + nl + `  "${real}"` + nl + ')' + nl,
    })).toBe(true);
  });

  it('gates child_process.exec with -g first', () => {
    expect(gated('Write', {
      path: '/tmp/run.js',
      content: `const {exec}=require("child_process"); exec("${flagFirst}")` + nl,
    })).toBe(true);
  });

  it('gates spawn list form', () => {
    expect(gated('Write', {
      path: '/tmp/sp.js',
      content: `require("child_process").spawn("${NPM}", ["${INST}","${G}","evil"])` + nl,
    })).toBe(true);
  });

  it('gates subprocess.check_output shell=True', () => {
    expect(gated('Write', {
      path: '/tmp/co.py',
      content: 'import subprocess' + nl + `subprocess.check_output("${real}", shell=True)` + nl,
    })).toBe(true);
  });

  it('gates shebang launched via npx npm', () => {
    expect(gated('Write', {
      file_path: '/tmp/npx.sh',
      content: '#!/bin/bash' + nl + `${NPX} ${real}` + nl,
    })).toBe(true);
  });

  it('gates shebang launched via corepack npm', () => {
    expect(gated('Write', {
      file_path: '/tmp/corepack.sh',
      content: '#!/bin/bash' + nl + `${CORE} ${real}` + nl,
    })).toBe(true);
  });

  it('ordinary markdown log path stays field-discipline (already #341)', () => {
    const v = evaluateToolCall('Write', {
      path: '/tmp/nightly.md',
      contents: `Blocked: ${mentioned}`,
    }, cfg);
    expect(v.severity).toBe('benign');
    expect(v.signals ?? []).not.toContain('install-package-global');
  });

  it('Bash real global install still requires approval', () => {
    const v = evaluateToolCall('Bash', { command: real }, cfg);
    expect(v.signals ?? []).toContain('install-package-global');
    expect(v.severity).toBe('dangerous');
    expect(String(v.reason)).toMatch(/approve --denial|human authorisation|terminal/i);
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
