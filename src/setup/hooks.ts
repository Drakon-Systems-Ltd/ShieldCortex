/**
 * CLI handler for hook subcommands.
 * Spawns the actual hook scripts. PreToolUse buffers input so the launcher can
 * still deny catastrophic calls if the hook file itself cannot load.
 *
 * Built-in hooks: pre-compact, session-start, session-end, stop, prompt-recall
 * Custom hooks: user-defined in ~/.shieldcortex/config.json → customHooks
 */

import { spawn } from 'child_process';
import path from 'path';
import fs from 'fs';
import os from 'os';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Scripts are in ../scripts/ relative to dist/setup/
const SCRIPTS_DIR = path.resolve(__dirname, '..', '..', 'scripts');

// Independent of pre-tool-hook.mjs: that file may fail to parse or import.
// Keep these expressions identical to FALLBACK_CATASTROPHIC_PATTERNS there.
export const LAUNCHER_CATASTROPHIC_PATTERNS = [
  /\brm\b[^|;&\n]*?(?:(?<![\w.\/-])-\w*r\w*f\w*|(?<![\w.\/-])-\w*f\w*r\w*|(?=[^|;&\n]*--recursive)(?=[^|;&\n]*--force))/i,
  /\brm\b[^|;&\n]*\s(?:-\w+\s+)*(?:\/|~|\$HOME|\/\*|\*|\.\/\*)(?:\s|$)/i,
  /:\s*\(\s*\)\s*\{\s*:\s*\|\s*:?\s*&?\s*\}\s*;\s*:/,
  /\bmkfs(\.\w+)?\b/i,
  /\bdd\b[^|;&\n]*\bof=\/dev\/(sd|nvme|hd|disk|mmcblk|vd)/i,
  /\b(fdisk|parted|sgdisk|wipefs|blkdiscard)\b/i,
  /\b(?:curl|wget|fetch)\b[^\n|]*\|(?:[^\n|]*\|)*\s*(?:\w+=\S*\s+)*(?:sudo\s+)?(?:env\s+)?(?:\w+=\S*\s+)*(?:bash|sh|zsh|ksh|python\d?|perl|ruby|node)\b(?!(?:\s+-[a-z]+)*\s+-[cem]\b)/i,
  /\b(?:curl|wget|fetch)\b[^|\n]*\|[^\n]*\bpython\d?\b[^\n]*\s-m\s*(?:code|pty|pdb)(?![\w.])/i,
  /\bch(?:mod|own)\b[^|;&\n]*(?:-\w*R\w*|--recursive)\b[^|;&\n]*\s\/(?:\s|$)/i,
];

// Keep this field set and its order identical to FALLBACK_SURFACE_KEYS in the hook.
export const LAUNCHER_SURFACE_KEYS = [
  'command', 'cmd', 'script', 'code', 'input', 'shell', 'run',
  'path', 'file_path', 'filePath', 'file', 'target', 'destination', 'dir', 'directory',
  'url', 'uri', 'endpoint', 'href', 'host', 'to',
];

export function launcherExecSurface(toolInput: Record<string, unknown>): string {
  const parts: string[] = [];
  for (const k of LAUNCHER_SURFACE_KEYS) {
    const v = toolInput?.[k];
    if (typeof v === 'string' && v.length > 0) parts.push(v);
    else if (Array.isArray(v)) {
      const joined = v.filter((e): e is string => typeof e === 'string').join(' ');
      if (joined.length > 0) parts.push(joined);
    }
  }
  return parts.join('   ').slice(0, 4096);
}

function rawFallbackSurface(text: string): string {
  return text.slice(0, 4096).replace(/"/g, ' ');
}

export function launcherCatastrophicMatch(rawInput: string): boolean {
  let text: string;
  try {
    const parsed: unknown = JSON.parse(rawInput);
    if (parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed)
      && 'tool_input' in parsed && parsed.tool_input !== null
      && typeof parsed.tool_input === 'object' && !Array.isArray(parsed.tool_input)) {
      text = launcherExecSurface(parsed.tool_input as Record<string, unknown>);
      if (!text) return false;
    } else {
      text = rawFallbackSurface(rawInput);
    }
  } catch {
    text = rawFallbackSurface(rawInput);
  }
  return LAUNCHER_CATASTROPHIC_PATTERNS.some((pattern) => pattern.test(text));
}

// Exported for the packaging contract test: every script listed here must
// also be whitelisted in package.json "files", or the published tarball
// ships settings.json wiring that points at a missing file.
export const BUILT_IN_HOOKS: Readonly<Record<string, string>> = Object.freeze({
  'pre-compact': 'pre-compact-hook.mjs',
  'session-start': 'session-start-hook.mjs',
  'session-end': 'session-end-hook.mjs',
  'stop': 'stop-hook.mjs',
  'prompt-recall': 'prompt-recall-hook.mjs',
  'pre-tool': 'pre-tool-hook.mjs',
});

interface CustomHookConfig {
  command: string;    // path to script or command to run
  args?: string[];    // optional args
  description?: string;
}

function loadCustomHooks(): Record<string, CustomHookConfig> {
  try {
    const configPath = path.join(os.homedir(), '.shieldcortex', 'config.json');
    if (!fs.existsSync(configPath)) return {};
    const config = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
    if (!config.customHooks || typeof config.customHooks !== 'object') return {};
    return config.customHooks;
  } catch {
    return {};
  }
}

function runScript(scriptPath: string, args: string[] = []): void {
  const child = spawn(process.execPath, [scriptPath, ...args], {
    stdio: ['pipe', 'inherit', 'inherit'],
  });

  process.stdin.pipe(child.stdin);

  child.on('exit', (code) => {
    process.exit(code ?? 0);
  });
}

function runPreToolScript(scriptPath: string): void {
  const chunks: Buffer[] = [];
  process.stdin.on('data', (chunk: Buffer) => chunks.push(chunk));
  process.stdin.on('end', () => {
    const input = Buffer.concat(chunks);
    const child = spawn(process.execPath, [scriptPath], {
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    // A parse/import failure may close stdin before the buffered payload drains.
    child.stdin.on('error', () => {});
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk: Buffer) => { stdout += chunk.toString(); });
    child.stderr.on('data', (chunk: Buffer) => {
      stderr += chunk.toString();
      process.stderr.write(chunk);
    });
    child.on('error', (error) => {
      process.stderr.write(`[shieldcortex] pre-tool hook launch failed: ${error.message}\n`);
      if (launcherCatastrophicMatch(input.toString('utf8'))) {
        fs.writeSync(1, JSON.stringify({ hookSpecificOutput: {
          hookEventName: 'PreToolUse', permissionDecision: 'deny',
          permissionDecisionReason: 'ShieldCortex hook unavailable; catastrophic fallback matched',
        } }) + '\n');
        process.exit(0);
      }
      process.exit(1);
    });
    child.on('close', (code, signal) => {
      const loadError = /SyntaxError|ERR_MODULE_NOT_FOUND|Cannot find module|ERR_UNKNOWN_FILE_EXTENSION/.test(stderr);
      const failed = code !== 0 || signal !== null;
      if (failed) process.stderr.write(loadError
        ? '[shieldcortex] pre-tool hook load failed; checking catastrophic fallback\n'
        : '[shieldcortex] pre-tool hook failed; checking catastrophic fallback\n');
      if (failed && launcherCatastrophicMatch(input.toString('utf8'))) {
        fs.writeSync(1, JSON.stringify({ hookSpecificOutput: {
          hookEventName: 'PreToolUse', permissionDecision: 'deny',
          permissionDecisionReason: 'ShieldCortex hook unavailable; catastrophic fallback matched',
        } }) + '\n');
        process.exit(0);
      }
      if (stdout) fs.writeSync(1, stdout);
      process.exit(code ?? (signal ? 1 : 0));
    });
    child.stdin.end(input);
  });
}

function runCommand(command: string, args: string[] = []): void {
  const child = spawn(command, args, {
    stdio: ['pipe', 'inherit', 'inherit'],
    shell: true,
  });

  process.stdin.pipe(child.stdin);

  child.on('exit', (code) => {
    process.exit(code ?? 0);
  });
}

export async function handleHookCommand(hookName: string): Promise<void> {
  // Try built-in hooks first
  const scriptFile = BUILT_IN_HOOKS[hookName];
  if (scriptFile) {
    const scriptPath = path.join(SCRIPTS_DIR, scriptFile);
    if (hookName === 'pre-tool') runPreToolScript(scriptPath);
    else runScript(scriptPath);
    return;
  }

  // Try custom hooks from config
  const customHooks = loadCustomHooks();
  const custom = customHooks[hookName];
  if (custom) {
    const cmd = custom.command;
    const args = custom.args || [];

    // If it's a .mjs/.js file, run with Node
    if (cmd.endsWith('.mjs') || cmd.endsWith('.js')) {
      const resolved = cmd.startsWith('/') || cmd.startsWith('~')
        ? cmd.replace(/^~/, os.homedir())
        : path.resolve(cmd);
      runScript(resolved, args);
    } else {
      // Run as shell command
      runCommand(cmd, args);
    }
    return;
  }

  // Nothing matched
  const customNames = Object.keys(customHooks);
  const allHooks = [...Object.keys(BUILT_IN_HOOKS), ...customNames];
  console.error(`Unknown hook: ${hookName}`);
  console.log(`Available hooks: ${allHooks.join(', ')}`);
  if (customNames.length === 0) {
    console.log('\nTo register custom hooks, add to ~/.shieldcortex/config.json:');
    console.log(JSON.stringify({
      customHooks: {
        'instructions-loaded': {
          command: '~/.claude/hooks/instructions-loaded.mjs',
          description: 'Run on InstructionsLoaded event',
        },
      },
    }, null, 2));
  }
  process.exit(1);
}
