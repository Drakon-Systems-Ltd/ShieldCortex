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
import { setupClaudeMd } from './claude-md.js';
import { handleOpenClawCommand } from './openclaw.js';
import { handleCopilotCommand } from './copilot.js';

type QuickstartTarget = 'claude' | 'openclaw' | 'copilot' | 'security';

interface DetectionResult {
  claude: boolean;
  openclaw: boolean;
  copilot: boolean;
  cursor: boolean;
}

function detectEnvironment(): DetectionResult {
  const home = os.homedir();
  const platform = process.platform;

  const claude =
    fs.existsSync(path.join(home, '.claude')) ||
    fs.existsSync(path.join(home, '.claude.json'));

  const openclaw = fs.existsSync(path.join(home, '.openclaw'));

  const cursor = fs.existsSync(path.join(home, '.cursor'));

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

  return { claude, openclaw, copilot, cursor };
}

function printAutoGuide(): void {
  const env = detectEnvironment();
  const lines: string[] = [];

  lines.push('');
  lines.push('ShieldCortex Quickstart');
  lines.push('────────────────────────────────────────────────────');
  lines.push(`Detected: Claude=${env.claude ? 'yes' : 'no'} · OpenClaw=${env.openclaw ? 'yes' : 'no'} · Copilot/Cursor=${env.copilot ? 'yes' : 'no'}`);
  lines.push('');

  if (env.claude) {
    lines.push('Best next step for persistent memory in Claude Code:');
    lines.push('  shieldcortex quickstart claude');
    lines.push('');
  }

  if (env.openclaw) {
    lines.push('Best next step for OpenClaw hook + realtime plugin:');
    lines.push('  shieldcortex quickstart openclaw');
    lines.push('');
  }

  if (env.copilot) {
    lines.push('Best next step for VS Code / Cursor MCP wiring:');
    lines.push('  shieldcortex quickstart copilot');
    lines.push('');
  }

  lines.push('Security-only workflow:');
  lines.push('  shieldcortex quickstart security');
  lines.push('');
  lines.push('You can also run one of these directly:');
  lines.push('  shieldcortex setup');
  lines.push('  shieldcortex openclaw install');
  lines.push('  shieldcortex copilot install');
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

3. Open the dashboard for quarantine, audit, and graph visibility:
   shieldcortex dashboard
`);
}

export async function handleQuickstartCommand(target?: string): Promise<void> {
  if (!target) {
    printAutoGuide();
    return;
  }

  switch (target.toLowerCase() as QuickstartTarget) {
    case 'claude':
      await setupClaudeMd({ stopHook: false });
      return;
    case 'openclaw':
      await handleOpenClawCommand('install');
      return;
    case 'copilot':
      await handleCopilotCommand('install');
      return;
    case 'security':
      printSecurityGuide();
      return;
    default:
      console.error('Usage: shieldcortex quickstart [claude|openclaw|copilot|security]');
      process.exit(1);
  }
}
