/**
 * CLI handler for hook subcommands.
 * Spawns the actual hook scripts with stdin/stdout passthrough.
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

const BUILT_IN_HOOKS: Record<string, string> = {
  'pre-compact': 'pre-compact-hook.mjs',
  'session-start': 'session-start-hook.mjs',
  'session-end': 'session-end-hook.mjs',
  'stop': 'stop-hook.mjs',
  'prompt-recall': 'prompt-recall-hook.mjs',
  'pre-tool': 'pre-tool-hook.mjs',
};

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
    runScript(scriptPath);
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
