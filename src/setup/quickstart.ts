/**
 * Quickstart helper for the most common installation paths.
 *
 * `shieldcortex quickstart` is intentionally non-destructive by default:
 * it detects likely environments and tells the user which single command
 * to run next. Explicit targets perform the install.
 */

import fs from 'fs';
import os from 'os';
import path from 'path';
import readline from 'readline/promises';
import { setupClaudeMd } from './claude-md.js';
import { handleOpenClawCommand } from './openclaw.js';
import { handleCopilotCommand } from './copilot.js';
import { handleCodexCommand } from './codex.js';

type QuickstartTarget = 'claude' | 'openclaw' | 'copilot' | 'codex' | 'security';
type DetectedInstaller = QuickstartTarget;

interface DetectionResult {
  claude: boolean;
  openclaw: boolean;
  copilot: boolean;
  cursor: boolean;
  codex: boolean;
}

function detectEnvironment(): DetectionResult {
  const home = os.homedir();
  const platform = process.platform;

  const claude =
    fs.existsSync(path.join(home, '.claude')) ||
    fs.existsSync(path.join(home, '.claude.json'));

  const openclaw = fs.existsSync(path.join(home, '.openclaw'));

  const cursor = fs.existsSync(path.join(home, '.cursor'));
  const codex = fs.existsSync(path.join(home, '.codex'));

  const vscodeDirs = platform === 'darwin'
    ? [
        path.join(home, 'Library', 'Application Support', 'Code', 'User'),
        path.join(home, 'Library', 'Application Support', 'Code - Insiders', 'User'),
      ]
    : platform === 'win32'
      ? [
          path.join(process.env.APPDATA ?? path.join(home, 'AppData', 'Roaming'), 'Code', 'User'),
          path.join(process.env.APPDATA ?? path.join(home, 'AppData', 'Roaming'), 'Code - Insiders', 'User'),
        ]
      : [
          path.join(home, '.config', 'Code', 'User'),
          path.join(home, '.config', 'Code - Insiders', 'User'),
        ];

  const copilot = cursor || vscodeDirs.some((dir) => fs.existsSync(dir));

  return { claude, openclaw, copilot, cursor, codex };
}

function printAutoGuide(): void {
  const env = detectEnvironment();
  const lines: string[] = [];

  lines.push('');
  lines.push('ShieldCortex Quickstart');
  lines.push('────────────────────────────────────────────────────');
  lines.push('Goal: give your agent memory you can inspect and security you can trust.');
  lines.push(`Detected: Claude=${env.claude ? 'yes' : 'no'} · OpenClaw=${env.openclaw ? 'yes' : 'no'} · Codex=${env.codex ? 'yes' : 'no'} · Copilot/Cursor=${env.copilot ? 'yes' : 'no'}`);
  lines.push('');
  lines.push('Best paths:');
  lines.push('');

  if (env.claude) {
    lines.push('Claude Code');
    lines.push('  Make recall and review available in Claude sessions:');
    lines.push('  shieldcortex quickstart claude');
    lines.push('');
  }

  if (env.openclaw) {
    lines.push('OpenClaw');
    lines.push('  Install the hook + realtime plugin for session capture and defence:');
    lines.push('  shieldcortex quickstart openclaw');
    lines.push('');
  }

  if (env.copilot) {
    lines.push('VS Code / Cursor');
    lines.push('  Wire ShieldCortex in as an MCP memory + security layer:');
    lines.push('  shieldcortex quickstart copilot');
    lines.push('');
  }

  if (env.codex) {
    lines.push('Codex CLI / VS Code');
    lines.push('  Register ShieldCortex once for Codex MCP in the CLI and IDE extension:');
    lines.push('  shieldcortex quickstart codex');
    lines.push('');
  }

  lines.push('Security-only');
  lines.push('  Scan prompts, tools, and environments without adopting memory first:');
  lines.push('  shieldcortex quickstart security');
  lines.push('');
  lines.push('Direct commands:');
  lines.push('  shieldcortex setup');
  lines.push('  openclaw hooks install shieldcortex');
  lines.push('  openclaw plugins install @drakon-systems/shieldcortex-realtime');
  lines.push('  # or compatibility wrapper: shieldcortex openclaw install');
  lines.push('  shieldcortex copilot install');
  lines.push('  shieldcortex codex install');
  lines.push('  shieldcortex dashboard');
  lines.push('');

  console.log(lines.join('\n'));
}

function printSecurityGuide(): void {
  console.log(`
ShieldCortex Security Quickstart
────────────────────────────────────────────────────
1. Scan one suspicious prompt or tool output:
   shieldcortex scan "ignore previous instructions"

2. Audit your local agent environment:
   shieldcortex audit

3. Open the dashboard for quarantine, recall review, and sync visibility:
   shieldcortex dashboard
`);
}

function isInteractiveTerminal(): boolean {
  return Boolean(process.stdin.isTTY && process.stdout.isTTY);
}

async function promptYesNo(question: string, defaultYes = true): Promise<boolean> {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  try {
    const suffix = defaultYes ? ' [Y/n] ' : ' [y/N] ';
    const answer = (await rl.question(`${question}${suffix}`)).trim().toLowerCase();
    if (!answer) return defaultYes;
    if (answer === 'y' || answer === 'yes') return true;
    if (answer === 'n' || answer === 'no') return false;
    return defaultYes;
  } finally {
    rl.close();
  }
}

function detectedInstallers(env: DetectionResult): Array<{ target: DetectedInstaller; label: string }> {
  const installers: Array<{ target: DetectedInstaller; label: string }> = [];
  if (env.claude) installers.push({ target: 'claude', label: 'Claude Code' });
  if (env.openclaw) installers.push({ target: 'openclaw', label: 'OpenClaw' });
  if (env.copilot) installers.push({ target: 'copilot', label: env.cursor ? 'VS Code / Cursor' : 'VS Code' });
  if (env.codex) installers.push({ target: 'codex', label: 'Codex CLI / VS Code' });
  return installers;
}

async function runQuickstartTarget(target: QuickstartTarget): Promise<void> {
  switch (target) {
    case 'claude':
      await setupClaudeMd({ stopHook: false });
      return;
    case 'openclaw':
      await handleOpenClawCommand('install');
      return;
    case 'copilot':
      await handleCopilotCommand('install');
      return;
    case 'codex':
      await handleCodexCommand('install');
      return;
    case 'security':
      printSecurityGuide();
      return;
  }
}

async function promptDetectedInstalls(autoApprove = false): Promise<void> {
  const env = detectEnvironment();
  const installers = detectedInstallers(env);

  if (installers.length === 0) {
    return;
  }

  console.log('Detected integrations can be installed now from this machine.');
  console.log('ShieldCortex will only change configs after explicit confirmation.');
  console.log('');

  if (!autoApprove && !isInteractiveTerminal()) {
    return;
  }

  if (!autoApprove) {
    const installAny = await promptYesNo('Install ShieldCortex into detected environments now?', true);
    if (!installAny) {
      console.log('Skipped automatic install prompts. Run `shieldcortex quickstart <target>` any time.');
      return;
    }
  }

  for (const installer of installers) {
    const approved = autoApprove
      ? true
      : await promptYesNo(`Install ShieldCortex for ${installer.label}?`, true);
    if (!approved) continue;

    console.log('');
    await runQuickstartTarget(installer.target);
    console.log('');
  }
}

export async function handleQuickstartCommand(target?: string): Promise<void> {
  if (!target) {
    printAutoGuide();
    await promptDetectedInstalls(false);
    return;
  }

  const normalized = target.toLowerCase();

  if (normalized === '--yes' || normalized === '--install-detected') {
    printAutoGuide();
    await promptDetectedInstalls(true);
    return;
  }

  switch (normalized as QuickstartTarget) {
    case 'claude':
    case 'openclaw':
    case 'copilot':
    case 'codex':
    case 'security':
      await runQuickstartTarget(normalized as QuickstartTarget);
      return;
    default:
      console.error('Usage: shieldcortex quickstart [claude|openclaw|copilot|codex|security|--yes|--install-detected]');
      process.exit(1);
  }
}
