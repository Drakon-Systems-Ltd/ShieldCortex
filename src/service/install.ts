/**
 * Cross-platform service installer for persistent ShieldCortex background service.
 *
 * Supports:
 *  - macOS: LaunchAgent plist
 *  - Linux: systemd user service
 *  - Windows: VBS script in Startup folder
 */

import fs from 'fs';
import path from 'path';
import os from 'os';
import { execSync } from 'child_process';
import { fileURLToPath } from 'url';
import { launchdPlist, systemdUnit, windowsVbs, type ServiceConfig, type ServiceMode } from './templates.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

type Platform = 'macos' | 'linux' | 'windows';

interface ServiceOptions {
  mode?: ServiceMode;
}

function detectPlatform(): Platform {
  switch (process.platform) {
    case 'darwin': return 'macos';
    case 'win32': return 'windows';
    default: return 'linux';
  }
}

function detectDefaultServiceMode(platform: Platform): ServiceMode {
  if (platform === 'linux' && !process.env.DISPLAY && !process.env.WAYLAND_DISPLAY) {
    return 'worker';
  }
  return 'dashboard';
}

function getServiceConfig(mode: ServiceMode): ServiceConfig {
  const logsDir = path.join(os.homedir(), '.shieldcortex', 'logs');
  fs.mkdirSync(logsDir, { recursive: true });

  return {
    nodePath: process.execPath,
    nodeBinDir: path.dirname(process.execPath),
    entryPoint: path.resolve(__dirname, '..', 'index.js'),
    logsDir,
    mode,
  };
}

function inspectServiceEntryPoint(platform: Platform, servicePath: string): { entryPoint: string | null; stale: boolean; mode: ServiceMode | null } {
  if (!fs.existsSync(servicePath)) {
    return { entryPoint: null, stale: false, mode: null };
  }

  try {
    const content = fs.readFileSync(servicePath, 'utf-8');
    let entryPoint: string | null = null;
    let mode: ServiceMode | null = null;

    if (platform === 'macos') {
      const matches = [...content.matchAll(/<string>([^<]+)<\/string>/g)].map((match) => match[1]);
      entryPoint = matches.find((value) => value.endsWith('index.js')) ?? null;
      mode = (matches.find((value) => value === 'dashboard' || value === 'api' || value === 'worker') as ServiceMode | undefined) ?? null;
    } else if (platform === 'linux') {
      const match = content.match(/ExecStart=\S+\s+(\S+index\.js)/);
      entryPoint = match?.[1] ?? null;
      const modeMatch = content.match(/ExecStart=\S+\s+\S+index\.js\s+--mode\s+(dashboard|api|worker)/);
      mode = (modeMatch?.[1] as ServiceMode | undefined) ?? null;
    } else {
      const match = content.match(/Run\s+\"\"[^\"]+\"\"\s+\"\"([^\"]+index\.js)\"\"/);
      entryPoint = match?.[1] ?? null;
      const modeMatch = content.match(/--mode\s+(dashboard|api|worker)/);
      mode = (modeMatch?.[1] as ServiceMode | undefined) ?? null;
    }

    const currentEntryPoint = getServiceConfig(detectDefaultServiceMode(platform)).entryPoint;
    const stale = !!entryPoint && (entryPoint.includes('/.npm/_npx/') || entryPoint !== currentEntryPoint);
    return { entryPoint, stale, mode };
  } catch {
    return { entryPoint: null, stale: false, mode: null };
  }
}

function getServicePath(platform: Platform): string {
  switch (platform) {
    case 'macos':
      return path.join(os.homedir(), 'Library', 'LaunchAgents', 'com.shieldcortex.dashboard.plist');
    case 'linux':
      return path.join(os.homedir(), '.config', 'systemd', 'user', 'shieldcortex-dashboard.service');
    case 'windows': {
      const appData = process.env.APPDATA || path.join(os.homedir(), 'AppData', 'Roaming');
      return path.join(appData, 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup', 'shieldcortex-dashboard.vbs');
    }
  }
}

function summarizeServiceMode(mode: ServiceMode): string {
  switch (mode) {
    case 'worker':
      return 'headless worker (recommended for servers and always-on cloud devices)';
    case 'api':
      return 'API service';
    default:
      return 'dashboard + API';
  }
}

function tryEnableLinuxLinger(): void {
  const username = process.env.USER || os.userInfo().username;
  try {
    execSync(`loginctl enable-linger "${username}"`, { stdio: 'ignore' });
    console.log('Enabled systemd linger for persistent background service.');
  } catch {
    console.log('Note: systemd linger was not enabled automatically.');
    console.log(`      On headless Linux servers, run: sudo loginctl enable-linger ${username}`);
  }
}

export async function installService(options: ServiceOptions = {}): Promise<void> {
  const platform = detectPlatform();
  const mode = options.mode ?? detectDefaultServiceMode(platform);
  const config = getServiceConfig(mode);
  const servicePath = getServicePath(platform);

  fs.mkdirSync(path.dirname(servicePath), { recursive: true });

  let content: string;
  switch (platform) {
    case 'macos':
      content = launchdPlist(config);
      break;
    case 'linux':
      content = systemdUnit(config);
      break;
    case 'windows':
      content = windowsVbs(config);
      break;
  }

  fs.writeFileSync(servicePath, content, 'utf-8');
  console.log(`Service file written to: ${servicePath}`);

  try {
    switch (platform) {
      case 'macos':
        execSync(`launchctl load -w "${servicePath}"`, { stdio: 'inherit' });
        console.log('Service loaded via launchctl.');
        break;
      case 'linux':
        execSync('systemctl --user daemon-reload', { stdio: 'inherit' });
        execSync('systemctl --user enable --now shieldcortex-dashboard.service', { stdio: 'inherit' });
        if (mode === 'worker' || mode === 'api') {
          tryEnableLinuxLinger();
        }
        console.log('Service enabled via systemd.');
        break;
      case 'windows':
        console.log('Service installed. It will start on next login.');
        console.log('To start now, run the VBS script or reboot.');
        break;
    }
  } catch (err: any) {
    console.error(`Failed to enable service: ${err.message}`);
    console.log(`The service file was written to ${servicePath} — you can enable it manually.`);
    return;
  }

  console.log(`\nShieldCortex ${summarizeServiceMode(mode)} will now auto-start.`);
  if (mode === 'dashboard') {
    console.log('  API:       http://localhost:3001');
    console.log('  Dashboard: http://localhost:3030');
  } else if (mode === 'api') {
    console.log('  API:       http://localhost:3001');
  } else {
    console.log('  Heartbeat: keeps the device online in ShieldCortex Cloud');
    console.log('  Sync:      processes background memory/graph sync retries');
  }
}

export async function repairService(options: ServiceOptions = {}): Promise<void> {
  await uninstallService();
  await installService(options);
}

function cleanLogsDirectory(): void {
  const logsDir = path.join(os.homedir(), '.shieldcortex', 'logs');
  if (fs.existsSync(logsDir)) {
    fs.rmSync(logsDir, { recursive: true, force: true });
    console.log(`Logs cleaned: ${logsDir}`);
  }
}

export async function uninstallService(options?: { cleanLogs?: boolean }): Promise<void> {
  const platform = detectPlatform();
  const servicePath = getServicePath(platform);

  if (!fs.existsSync(servicePath)) {
    console.log('No service installed.');
    return;
  }

  try {
    switch (platform) {
      case 'macos':
        execSync(`launchctl unload -w "${servicePath}"`, { stdio: 'inherit' });
        break;
      case 'linux':
        execSync('systemctl --user disable --now shieldcortex-dashboard.service', { stdio: 'inherit' });
        break;
      case 'windows':
        break;
    }
  } catch {
    // Service may not be loaded, continue to delete file
  }

  fs.unlinkSync(servicePath);
  console.log(`Service removed: ${servicePath}`);

  if (options?.cleanLogs) {
    cleanLogsDirectory();
  }
}

export async function serviceStatus(): Promise<void> {
  const platform = detectPlatform();
  const servicePath = getServicePath(platform);
  const installed = fs.existsSync(servicePath);
  const inspection = inspectServiceEntryPoint(platform, servicePath);

  console.log(`Platform:  ${platform}`);
  console.log(`Installed: ${installed ? 'yes' : 'no'}`);
  console.log(`Path:      ${servicePath}`);
  if (inspection.entryPoint) {
    console.log(`Entry:     ${inspection.entryPoint}`);
    console.log(`Mode:      ${inspection.mode ?? 'unknown'}`);
    console.log(`Healthy:   ${inspection.stale ? 'no (repair recommended)' : 'yes'}`);
  }

  if (!installed) return;

  try {
    switch (platform) {
      case 'macos': {
        const uid = process.getuid?.();
        const domain = typeof uid === 'number' ? `gui/${uid}/com.shieldcortex.dashboard` : 'gui/501/com.shieldcortex.dashboard';
        const out = execSync(`launchctl print ${domain} 2>&1`, { encoding: 'utf-8' });
        const pidMatch = out.match(/\bpid\s*=\s*(\d+)/i);
        const running = /\bstate\s*=\s*running\b/i.test(out) || Boolean(pidMatch);
        console.log(`Running:   ${running ? `yes${pidMatch ? ` (PID ${pidMatch[1]})` : ''}` : 'no'}`);
        break;
      }
      case 'linux': {
        const out = execSync('systemctl --user is-active shieldcortex-dashboard.service 2>&1', { encoding: 'utf-8' }).trim();
        console.log(`Running:   ${out === 'active' ? 'yes' : 'no'}`);
        break;
      }
      case 'windows':
        console.log('Running:   (check Task Manager for node.exe)');
        break;
    }
  } catch {
    console.log('Running:   no');
  }

  if (inspection.stale) {
    console.log('Repair:    shieldcortex service repair');
  }
}

function parseServiceModeArgs(args: string[]): ServiceMode | undefined {
  if (args.includes('--dashboard')) return 'dashboard';
  if (args.includes('--api')) return 'api';
  if (args.includes('--headless') || args.includes('--worker')) return 'worker';
  return undefined;
}

export async function handleServiceCommand(subcommand: string, args: string[] = []): Promise<void> {
  switch (subcommand) {
    case 'install':
      await installService({ mode: parseServiceModeArgs(args) });
      break;
    case 'repair':
      await repairService({ mode: parseServiceModeArgs(args) });
      break;
    case 'uninstall':
      await uninstallService({ cleanLogs: process.argv.includes('--clean-logs') });
      break;
    case 'status':
      await serviceStatus();
      break;
    default:
      console.log('Usage: shieldcortex service <install|repair|uninstall|status> [--dashboard|--api|--headless]');
      process.exit(1);
  }
}
