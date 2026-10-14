/**
 * #505 outage parity (review finding 1 on #578): the startup-file WRITE-target
 * gate existed only in `evaluateToolCallCore`; every fallback table carried the
 * shell verb+target regex alone, so with the dist missing a Write of a PATH
 * prepend to `.bashrc` fell open while the authorized_keys positive control
 * gated. Pins: the hook and the interceptor gate a write-family tool whose
 * path key names a startup file, a read-family tool on the same path fails
 * open as before, an ordinary code file fails open, and the three fallback
 * sources carry the same path regex. Nothing here loads the guard.
 */
import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { performance } from 'node:perf_hooks';
import { createInterceptor, DEFAULT_CONFIG, type InterceptAuditEntry } from '../../plugins/openclaw/interceptor.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(__dirname, '..', '..');
const HOOK_PATH = path.join(REPO, 'scripts', 'pre-tool-hook.mjs');

// Assembled at runtime (#444 convention) so the guard scanning this file's own
// write does not gate the test.
const RC = '.bash' + 'rc';
const FISH = '.config/fish/config.' + 'fish';
const AK = '.s' + 'sh/authorized' + '_keys';
const BENIGN = 'export PATH=/opt/tool/bin:$PATH\n';

const okPipeline = () => ({
  allowed: true,
  firewall: { result: 'ALLOW' as const, reason: '', threatIndicators: [] as string[], anomalyScore: 0, blockedPatterns: [] as string[] },
  trust: { score: 0.5 }, sensitivity: { level: 'INTERNAL' }, fragmentation: null, auditId: 1,
});

describe('#505 — OpenClaw interceptor fallback: startup-file write target', () => {
  const run = (toolName: string, args: Record<string, unknown>) => {
    const entries: InterceptAuditEntry[] = [];
    const i = createInterceptor({ ...DEFAULT_CONFIG, actionGuard: { enabled: true, enforce: true, autoApprove: [] } } as never, okPipeline as never, { onAuditEntry: (e) => entries.push(e) });
    return { p: i.handleToolCall({ toolName, arguments: args }), entries };
  };

  it.each([
    ['Write', { file_path: `/home/ubuntu/${RC}`, content: BENIGN }],
    ['Edit', { file_path: `~/${RC}`, old_string: 'a', new_string: BENIGN }],
    ['write', { path: `/home/ubuntu/${FISH}`, content: 'set -x PATH /tmp/evil $PATH\n' }],
    ['mcp__fs__write_file', { path: `/root/.zprofile`, content: BENIGN }],
    ['Write', { file_path: `/home/ubuntu/${AK}`, content: 'ssh-rsa AAAA x@y\n' }], // positive control (already gated)
  ])('%s with a startup-file target is denied while degraded', async (toolName, args) => {
    const { p, entries } = run(toolName, args);
    await expect(p).rejects.toThrow(/blocked|fallback|degraded|policy/i);
    const denied = entries.find((e) => e.outcome === 'auto_denied' || e.outcome === 'failure_denied');
    expect(denied?.firewallResult).toBe('ACTION_GUARD_FALLBACK');
  });

  it.each([
    ['Read', { file_path: `/home/ubuntu/${RC}` }],
    ['Grep', { pattern: 'PATH', path: `/home/ubuntu/${RC}` }],
    ['Write', { file_path: '/repo/src/cli.ts', content: 'console.log("hi");\n' }],
    ['Write', { file_path: `/home/ubuntu/${RC}.bak`, content: BENIGN }],
    ['Write', { file_path: '/home/ubuntu/.vimrc', content: 'set number\n' }],
  ])('%s fails open as before (audited gate_degraded)', async (toolName, args) => {
    const { p, entries } = run(toolName, args);
    await expect(p).resolves.toBeUndefined();
    expect(entries.find((e) => e.action === 'gate_degraded')?.outcome).toBe('failure_allowed');
  });
});

describe('#505 — OpenClaw interceptor fallback: tee operand run stops at the statement boundary', () => {
  const run = (command: string) => {
    const entries: InterceptAuditEntry[] = [];
    const i = createInterceptor({ ...DEFAULT_CONFIG, actionGuard: { enabled: true, enforce: true, autoApprove: [] } } as never, okPipeline as never, { onAuditEntry: (e) => entries.push(e) });
    return i.handleToolCall({ toolName: 'Bash', arguments: { command } });
  };
  it('a read of a startup file on the NEXT line is not a tee operand', async () => {
    await expect(run(`printf x | tee /tmp/log\ncat ~/${RC}`)).resolves.toBeUndefined();
    await expect(run(`printf x | tee /tmp/log; source ~/.profile`)).resolves.toBeUndefined();
    await expect(run(`printf x | tee /tmp/log ~/${RC}`)).rejects.toThrow(/blocked|fallback|degraded|policy/i);
    await expect(run(`printf x | tee -a \\\n  ~/${RC}`)).rejects.toThrow(/blocked|fallback|degraded|policy/i); // escaped newline = continuation
    await expect(run(`echo x | tee /tmp/a\\b ~/${RC}`)).rejects.toThrow(/blocked|fallback|degraded|policy/i); // #588 escaped operand
    await expect(run(`echo x > "/home/a b/${RC}"`)).rejects.toThrow(/blocked|fallback|degraded|policy/i); // quoted argv
  });
  it('recognises substitutions, comments, wrappers, eval and shell option clusters', async () => {
    const t = `~/${RC}`;
    for (const command of [
      'x=\x60echo x >> ' + t + '\x60', `echo "$(f() { echo x >> ${t}; }; f)"`,
      `# don't\necho x >> ${t}\n# it's`, `echo x | sudo -u root tee -a ${t}`,
      `echo x | env tee -a ${t}`, `eval "echo x >> ${t}"`,
      `eval 'echo x >> ${t}'`, `bash -lc 'echo x >> ${t}'`,
      `bash -c -- 'echo x >> ${t}'`, `bash <<EOF\necho x >> ${t}\nEOF`,
      `sh -s <<'EOF'\necho x >> ${t}\nEOF`, `cat <<'EOF' | sh\necho x >> ${t}\nEOF`,
      `cat <<'EOF'\necho x >> ${t}\nEOF | sh`,
    ]) await expect(run(command)).rejects.toThrow(/blocked|fallback|degraded|policy/i);
    for (const command of [`# echo x >> ${t}`, `cat <<'EOF'\necho x >> ${t}\nEOF`])
      await expect(run(command)).resolves.toBeUndefined();
  });

  it('bounds the 4096-character fallback surface', async () => {
    // A 4096-newline surface is left out on purpose: the pre-existing legacy
    // rows already take ~95 ms on it locally on main (well past 300 ms under a
    // loaded CI runner), so it would time those rows, not the #588 walker.
    // The Python mirror times the walker directly on that input.
    for (const text of ['\\'.repeat(4096), '\x60'.repeat(4096), '${'.repeat(2048), '/'.repeat(4096), "#'".repeat(2048), '/['.repeat(2048), '$('.repeat(2048), '('.repeat(4096), 'eval '.repeat(819), 'sudo '.repeat(819)]) {
      const start = performance.now();
      await run(text).catch(() => undefined);
      expect(performance.now() - start).toBeLessThan(300);
    }
  });
});

describe('#505 — Claude Code hook fallback: startup-file write target', () => {
  const originalHome = process.env.HOME;
  let tempHome: string;
  let emptyDist: string;
  beforeEach(() => {
    tempHome = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-505-fb-'));
    emptyDist = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-505-dist-'));
    process.env.HOME = tempHome;
    fs.mkdirSync(path.join(tempHome, '.shieldcortex'), { recursive: true });
    fs.writeFileSync(path.join(tempHome, '.shieldcortex', 'config.json'), JSON.stringify({ actionGuard: { enabled: true, enforce: true } }));
  });
  afterEach(() => {
    process.env.HOME = originalHome;
    fs.rmSync(tempHome, { recursive: true, force: true });
    fs.rmSync(emptyDist, { recursive: true, force: true });
  });
  function runHook(tool_name: string, tool_input: Record<string, unknown>): Promise<string> {
    return new Promise((res, rej) => {
      const child = spawn(process.execPath, [HOOK_PATH], {
        stdio: ['pipe', 'pipe', 'pipe'],
        env: { ...process.env, HOME: tempHome, SHIELDCORTEX_DIST_ROOT: emptyDist, SHIELDCORTEX_CONFIG_DIR: path.join(tempHome, '.shieldcortex') },
      });
      let stdout = '';
      child.stdout.on('data', (c) => { stdout += c.toString(); });
      child.on('error', rej);
      child.on('close', () => res(stdout));
      child.stdin.write(JSON.stringify({ permission_mode: 'default', tool_name, tool_input }));
      child.stdin.end();
    });
  }

  it('Write / Edit to a startup file asks; the same path on Read and an ordinary file fall open', async () => {
    const w = await runHook('Write', { file_path: `${tempHome}/${RC}`, content: BENIGN });
    expect(JSON.parse(w).hookSpecificOutput.permissionDecision).toBe('ask');
    const e = await runHook('Edit', { file_path: `~/${FISH}`, old_string: 'a', new_string: BENIGN });
    expect(JSON.parse(e).hookSpecificOutput.permissionDecision).toBe('ask');
    expect(await runHook('Read', { file_path: `${tempHome}/${RC}` })).toBe('');
    expect(await runHook('Write', { file_path: '/repo/src/cli.ts', content: 'console.log("hi");\n' })).toBe('');
  });
  it('recognises the #588 escaped tee operand and continued line', async () => {
    for (const command of [`echo x | tee /tmp/a\\b ~/${RC}`, `echo x | tee -a \\\n ~/${RC}`, `echo x > "/home/a b/${RC}"`]) {
      const result = await runHook('Bash', { command });
      expect(JSON.parse(result).hookSpecificOutput.permissionDecision).toBe('ask');
    }
  });
  it('mirrors the shell walker decisions', async () => {
    const t = `~/${RC}`;
    for (const command of [
      'x=\x60echo x >> ' + t + '\x60', `echo "$(f() { echo x >> ${t}; }; f)"`,
      `# don't\necho x >> ${t}\n# it's`, `echo x | sudo -u root tee -a ${t}`,
      `echo x | env tee -a ${t}`, `eval "echo x >> ${t}"`,
      `bash -lc 'echo x >> ${t}'`, `bash -c -- 'echo x >> ${t}'`,
    ]) expect(JSON.parse(await runHook('Bash', { command })).hookSpecificOutput.permissionDecision).toBe('ask');
    for (const command of [`# echo x >> ${t}`, `cat <<'EOF'\necho x >> ${t}\nEOF`])
      expect(await runHook('Bash', { command })).toBe('');
  });
});

describe('#505 — drift guard: the three fallbacks carry one startup-path rule', () => {
  const pick = (file: string, re: RegExp) => {
    const src = fs.readFileSync(path.join(REPO, file), 'utf8');
    const m = re.exec(src);
    expect([file, m !== null]).toEqual([file, true]);
    return m![1];
  };
  it('hook, interceptor and Hermes client name the same startup-file basenames', () => {
    const names = (s: string) => [...s.matchAll(/\b(bashrc|zshrc|zprofile|zshenv|zlogin|zlogout|profile|bash_profile|bash_login|bash_logout)\b/g)].map(m => m[1]).sort();
    const hook = pick('scripts/pre-tool-hook.mjs', /const FALLBACK_SHELL_STARTUP_PATH_RE = (\/.*\/i);/);
    const plug = pick('plugins/openclaw/interceptor.ts', /const FALLBACK_SHELL_STARTUP_PATH_RE = (\/.*\/i);/);
    const py = pick('plugins/hermes/shieldcortex/sc_client.py', /_FALLBACK_SHELL_STARTUP_PATH = re\.compile\(\s*r"([^"]+)"/);
    expect(plug).toBe(hook);
    expect(names(py)).toEqual(names(hook));
    expect(names(hook)).toHaveLength(10);
  });
});
