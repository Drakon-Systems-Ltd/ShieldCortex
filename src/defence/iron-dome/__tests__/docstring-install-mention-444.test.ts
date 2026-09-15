/**
 * #444 — a docstring/comment mention of a global install inside a folded
 * Python script is prose, not an invocation. `python3 scripts/patch.py` where
 * the file only edits text (no subprocess/os.system) must not deny on
 * `install-package-global`.
 *
 * Jarvis lost a repair path for ~12h: the script that restores dist patches
 * after an upgrade documents when to re-run it, and the documentation tripped
 * the guard. A control that teaches operators to strip their own docs is a
 * control people uninstall.
 *
 * Shell verbs are assembled at runtime so the guard scanning THIS file's write
 * does not deny the test itself.
 */
import { evaluateToolCall } from '../tool-action-guard.js';
import type { ToolGuardVerdict } from '../tool-action-guard.js';

const G = '-' + 'g';
const NPM = 'n' + 'pm';
const I = 'i';
const INST = 'in' + 'stall';
const nl = String.fromCharCode(10);
const bt = String.fromCharCode(96);
const cfg = { enabled: true, enforce: true } as any;

function stub(files: Record<string, string>): (p: string) => string | null {
  return (p: string) => (Object.prototype.hasOwnProperty.call(files, p) ? files[p] : null);
}

function verdictOf(command: string, files: Record<string, string>): ToolGuardVerdict {
  return evaluateToolCall('Bash', { command }, cfg, { resolveScriptSource: stub(files) });
}

// Jarvis's real shape: docstring names the re-run trigger; body edits files only.
const DOCSTRING_REPAIR = [
  '#!/usr/bin/env python3',
  '"""Patch vendored dist files after an OpenClaw upgrade.',
  '',
  `Idempotent. Re-run after every \`${NPM} ${I} ${G} openclaw\`; verify_dist_patches.py`,
  'checks the result.',
  '"""',
  'import pathlib',
  'p = pathlib.Path("dist/entry.js")',
  's = p.read_text()',
  's = s.replace("old", "new")',
  'p.write_text(s)',
].join(nl);

const HASH_COMMENT_REPAIR = [
  '#!/usr/bin/env python3',
  `# so it can be re-run safely after every \`${NPM} ${I} ${G} openclaw\`.`,
  'import pathlib',
  'pathlib.Path("dist/x.js").write_text("ok")',
].join(nl);

// Control: the same docstring PLUS a real sink that runs the install.
const DOCSTRING_PLUS_SINK = [
  '#!/usr/bin/env python3',
  `"""Re-run after every \`${NPM} ${I} ${G} openclaw\`."""`,
  'import os',
  `os.system("${NPM} ${INST} ${G} openclaw")`,
].join(nl);

describe('#444 — docstring mention of a global install in a folded .py is prose', () => {
  it('allows python3 <repair.py> whose docstring names the install trigger', () => {
    const v = verdictOf('python3 scripts/patch_sonnet5_cost_guard.py', {
      'scripts/patch_sonnet5_cost_guard.py': DOCSTRING_REPAIR,
    });
    expect(v.signals ?? []).not.toContain('install-package-global');
    expect(v.decision).not.toBe('block');
    expect(v.severity).not.toBe('dangerous');
  });

  it('allows a # comment mention too', () => {
    const v = verdictOf('python3 scripts/patch_claude_cli_catalog.py', {
      'scripts/patch_claude_cli_catalog.py': HASH_COMMENT_REPAIR,
    });
    expect(v.signals ?? []).not.toContain('install-package-global');
    expect(v.severity).not.toBe('dangerous');
  });

  it('still gates when the folded .py actually runs the install', () => {
    const v = verdictOf('python3 scripts/bootstrap.py', {
      'scripts/bootstrap.py': DOCSTRING_PLUS_SINK,
    });
    expect(v.signals ?? []).toContain('install-package-global');
    expect(v.severity).toBe('dangerous');
  });

  it('a bare Bash global install is unchanged', () => {
    const v = evaluateToolCall('Bash', { command: `${NPM} ${INST} ${G} openclaw` }, cfg);
    expect(v.signals ?? []).toContain('install-package-global');
    expect(v.severity).toBe('dangerous');
  });

  it('a Ruby backtick is still a real sink (backtick executes in Ruby)', () => {
    const v = verdictOf('ruby scripts/boot.rb', {
      'scripts/boot.rb': `puts ${bt}${NPM} ${INST} ${G} openclaw${bt}`,
    });
    expect(v.signals ?? []).toContain('install-package-global');
  });

  it('a Perl backtick is still a real sink', () => {
    const v = verdictOf('perl scripts/boot.pl', {
      'scripts/boot.pl': `my $out = ${bt}${NPM} ${INST} ${G} openclaw${bt};`,
    });
    expect(v.signals ?? []).toContain('install-package-global');
  });

  it('a JS template-literal MENTION is prose (backtick does not execute in JS)', () => {
    const v = verdictOf('node scripts/notes.mjs', {
      'scripts/notes.mjs': `const hint = ${bt}re-run after ${NPM} ${I} ${G} openclaw${bt};` + nl + 'console.log(hint);',
    });
    expect(v.signals ?? []).not.toContain('install-package-global');
  });
});
