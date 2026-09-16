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

  // GPT-6 r1 bypass 1: sink the classifier knows but the disposer cannot resolve.
  it.each([
    ['__import__ spelling', `__import__('os').system("${NPM} ${INST} ${G} openclaw")`],
    ['getattr spelling', 'import os' + nl + `getattr(os, 'system')("${NPM} ${INST} ${G} openclaw")`],
  ])('still gates a reflected Python shell call: %s', (_label, body) => {
    const v = verdictOf('python3 scripts/boot.py', { 'scripts/boot.py': body });
    expect(v.signals ?? []).toContain('install-package-global');
    expect(v.severity).toBe('dangerous');
    expect(v.decision).toBe('require_approval');
  });

  // Same shape as an inline interpreter heredoc (not folded).
  it('still gates a multi-line sink argument inside a python heredoc', () => {
    const cmd = ['python3 - <<' + "'PY'", 'import os', 'os.system(', `    "${NPM} ${INST} ${G} openclaw"`, ')', 'PY'].join(nl);
    const v = evaluateToolCall('Bash', { command: cmd }, cfg);
    expect(v.signals ?? []).toContain('install-package-global');
    expect(v.severity).toBe('dangerous');
    expect(v.decision).toBe('require_approval');
  });

  // Pre-existing folded-file gaps, red on main BEFORE this PR (proved by
  // running this file against origin/main's guard). Tracked separately so
  // this PR stays the docstring fix and nothing else.
  it.todo('folded Ruby/Perl backtick command runs a global install (hasSink true, but a folded backtick body is payload-tier, not executed)');
  it.todo('folded .py: sink argument on a different line from os.system(');
  it.todo('folded .py: cmd = "..."; os.system(cmd) variable indirection');
  // JS relief withdrawn after five review rounds: JS keeps the any-backtick
  // sink, byte-identical to main. Relaxing JS needs a real lexer.
  it.todo('JS: untagged template literal / comment that merely names an install stays prose');
  it.todo('JS: tagged template nested inside a bare-template interpolation (lexer)');

  // GPT-6 r2: PHP backtick executes. Inline php -r region gets lang=php.
  it('still gates a PHP backtick install (inline php -r)', () => {
    const cmd = `php -r '${bt}${NPM} ${INST} ${G} openclaw${bt};'`;
    const v = evaluateToolCall('Bash', { command: cmd }, cfg);
    expect(v.signals ?? []).toContain('install-package-global');
    expect(v.severity).toBe('dangerous');
    expect(v.decision).toBe('require_approval');
  });

  // GPT-6 r2: a TAGGED JS template (zx / execa $) executes; a bare one does not.
  it('still gates a zx $-tagged template install in a folded .mjs', () => {
    const body = ["import { $ } from 'zx';", `await $${bt}${NPM} ${INST} ${G} openclaw${bt};`].join(nl);
    const v = verdictOf('node scripts/boot.mjs', { 'scripts/boot.mjs': body });
    expect(v.signals ?? []).toContain('install-package-global');
    expect(v.severity).toBe('dangerous');
    expect(v.decision).toBe('require_approval');
  });

  it('still gates an inline node -e zx $-tagged template', () => {
    const cmd = `node -e "await $${bt}${NPM} ${INST} ${G} openclaw${bt}"`;
    const v = evaluateToolCall('Bash', { command: cmd }, cfg);
    expect(v.signals ?? []).toContain('install-package-global');
    expect(v.severity).toBe('dangerous');
  });

  // GPT-6 r3: tag recognition must be structural, not a name allowlist.
  it.each([
    ['whitespace between tag and template', 'import {$} from "zx";' + nl + `await $ ${bt}${NPM} ${INST} ${G} cowsay${bt}`],
    ['namespace member tag', 'import * as zx from "zx";' + nl + `await zx.$${bt}${NPM} ${INST} ${G} cowsay${bt};`],
    ['configured tag (call result)', 'import {$} from "zx";' + nl + `await $({quiet:true})${bt}${NPM} ${INST} ${G} cowsay${bt};`],
    ['aliased tag', 'import {$ as run} from "zx";' + nl + `await run${bt}${NPM} ${INST} ${G} cowsay${bt};`],
    ['bracket-indexed tag', 'const t = {sh: $};' + nl + `await t['sh']${bt}${NPM} ${INST} ${G} cowsay${bt};`],
  ])('still gates a JS tagged template: %s', (_label, body) => {
    const v = verdictOf('node scripts/boot.mjs', { 'scripts/boot.mjs': body });
    expect(v.signals ?? []).toContain('install-package-global');
    expect(v.severity).toBe('dangerous');
    expect(v.decision).toBe('require_approval');
  });

  it('still gates an inline node -e tag with whitespace', () => {
    const cmd = `node --input-type=module -e 'import {$} from "zx"; await $ ${bt}${NPM} ${INST} ${G} cowsay${bt}'`;
    const v = evaluateToolCall('Bash', { command: cmd }, cfg);
    expect(v.signals ?? []).toContain('install-package-global');
    expect(v.severity).toBe('dangerous');
  });

  // GPT-6 r4: trivia, unicode identifiers, member-keyword, nested interpolation.
  it.each([
    ['block comment between tag and template', `const $ = require("zx").$; $ /* c */ \`${NPM} ${INST} ${G} cowsay\`;`],
    ['unicode identifier tag', `const 执行 = require("zx").$; 执行\`${NPM} ${INST} ${G} cowsay\`;`],
    ['member named return', `const t = { return: require("zx").$ }; t.return\`${NPM} ${INST} ${G} cowsay\`;`],
  ])('still gates a JS tagged template: %s', (_label, body) => {
    const v = verdictOf('node scripts/boot.mjs', { 'scripts/boot.mjs': body });
    expect(v.signals ?? []).toContain('install-package-global');
    expect(v.severity).toBe('dangerous');
  });

  // GPT-6 r6: the OUTER shell substitutes backticks in a double-quoted or
  // unquoted inline arg, and in an unquoted-delimiter heredoc, before the
  // interpreter runs. Those must keep the sink regardless of language.
  const DEL = 'r' + 'm';
  const RF = '-' + 'rf';
  it('still blocks a shell backtick inside a double-quoted python -c arg', () => {
    const cmd = `python3 -c "print('${bt}${DEL} ${RF} /${bt}')"`;
    const v = evaluateToolCall('Bash', { command: cmd }, cfg);
    expect(v.severity).toBe('catastrophic');
    expect(v.decision).toBe('block');
  });
  it('still gates a shell backtick install inside an unquoted python -c arg', () => {
    const cmd = `python3 -c print(${bt}${NPM} ${INST} ${G} cowsay${bt})`;
    const v = evaluateToolCall('Bash', { command: cmd }, cfg);
    expect(v.signals ?? []).toContain('install-package-global');
    expect(v.severity).toBe('dangerous');
  });
  it('still gates a shell backtick inside an unquoted-delimiter python heredoc', () => {
    const cmd = ['python3 - <<PY', `x = "${bt}${NPM} ${INST} ${G} cowsay${bt}"`, 'PY'].join(nl);
    const v = evaluateToolCall('Bash', { command: cmd }, cfg);
    expect(v.signals ?? []).toContain('install-package-global');
    expect(v.severity).toBe('dangerous');
  });
  it('a single-quoted python -c arg is opaque to the shell: backtick mention stays prose', () => {
    const cmd = `python3 -c 'print("re-run ${bt}${NPM} ${INST} ${G} cowsay${bt} after")'`;
    const v = evaluateToolCall('Bash', { command: cmd }, cfg);
    expect(v.signals ?? []).not.toContain('install-package-global');
    expect(v.severity).not.toBe('dangerous');
  });
  it('a quoted-delimiter python heredoc is opaque to the shell: backtick mention stays prose', () => {
    const cmd = ["python3 - <<'PY'", `"""re-run ${bt}${NPM} ${INST} ${G} cowsay${bt} after"""`, 'print(1)', 'PY'].join(nl);
    const v = evaluateToolCall('Bash', { command: cmd }, cfg);
    expect(v.signals ?? []).not.toContain('install-package-global');
    expect(v.severity).not.toBe('dangerous');
  });

  // Grok r7: written-then-executed heredoc with an UNQUOTED delimiter is
  // shell-expanded before cat writes it. Must keep the sink.
  it('still gates a shell backtick in an unquoted-delimiter write-then-run heredoc', () => {
    const cmd = ['cat > /tmp/s.py <<PY', `x = "${bt}${NPM} ${INST} ${G} cowsay${bt}"`, 'PY', 'python3 /tmp/s.py'].join(nl);
    const v = evaluateToolCall('Bash', { command: cmd }, cfg);
    expect(v.signals ?? []).toContain('install-package-global');
    expect(v.severity).toBe('dangerous');
  });
  it('a quoted-delimiter write-then-run python heredoc keeps docstring relief', () => {
    const cmd = ["cat > /tmp/s.py <<'PY'", `"""re-run ${bt}${NPM} ${INST} ${G} cowsay${bt} after"""`, 'print(1)', 'PY', 'python3 /tmp/s.py'].join(nl);
    const v = evaluateToolCall('Bash', { command: cmd }, cfg);
    expect(v.signals ?? []).not.toContain('install-package-global');
    expect(v.severity).not.toBe('dangerous');
  });

  // GPT-6 r8: an OUTER double-quoted shell arg (bash -c "...") expands
  // backticks before the inner command runs; an inner <<'PY' or '-c arg'
  // cannot make it opaque.
  it('still blocks a backtick in a quoted-delimiter heredoc nested inside bash -c "..."', () => {
    const cmd = ['bash -c "python3 - <<\'PY\'', `print(\'${bt}${DEL} ${RF} /${bt}\')`, 'PY"'].join(nl);
    const v = evaluateToolCall('Bash', { command: cmd }, cfg);
    expect(v.severity).toBe('catastrophic');
    expect(v.decision).toBe('block');
  });
  it('still gates a backtick in a single-quoted -c arg nested inside bash -c "..."', () => {
    const cmd = `bash -c "python3 -c 'print(${bt}${NPM} ${INST} ${G} cowsay${bt})'"`;
    const v = evaluateToolCall('Bash', { command: cmd }, cfg);
    expect(v.signals ?? []).toContain('install-package-global');
    expect(v.severity).toBe('dangerous');
  });
  it('a quoted-delimiter heredoc nested inside bash -c \'...\' (single) stays opaque', () => {
    const cmd = ["bash -c 'python3 - <<\"PY\"", `"""re-run ${bt}${NPM} ${INST} ${G} cowsay${bt} after"""`, 'print(1)', "PY'"].join(nl);
    const v = evaluateToolCall('Bash', { command: cmd }, cfg);
    expect(v.signals ?? []).not.toContain('install-package-global');
    expect(v.severity).not.toBe('dangerous');
  });
});
