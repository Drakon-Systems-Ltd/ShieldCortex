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

export function detectStaleAppendLogs(content: string): { stale: boolean; missingPath: string | null } {
  // Pre-v4.12.10 Linux units used `StandardOutput=append:/abs/path/...`.
  // If that absolute path no longer exists, systemd will fail to open it
  // before any ExecStart* runs (exit 209/STDOUT) and the service will
  // crash-loop forever. Detect this so `service status` can suggest
  // `service repair`, which rewrites the unit to the journald template.
  const match = content.match(/^Standard(?:Output|Error)=append:(\S+)/m);
  if (!match) return { stale: false, missingPath: null };
  const logFile = match[1];
  const logDir = path.dirname(logFile);
  if (!fs.existsSync(logDir)) {
    return { stale: true, missingPath: logDir };
  }
  return { stale: false, missingPath: null };
}

function inspectServiceEntryPoint(platform: Platform, servicePath: string): { entryPoint: string | null; stale: boolean; mode: ServiceMode | null; staleReason: string | null } {
  if (!fs.existsSync(servicePath)) {
    return { entryPoint: null, stale: false, mode: null, staleReason: null };
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
    const entryPointStale = !!entryPoint && (entryPoint.includes('/.npm/_npx/') || entryPoint !== currentEntryPoint);

    let logDirStale = false;
    let staleReason: string | null = null;
    if (platform === 'linux') {
      const appendCheck = detectStaleAppendLogs(content);
      if (appendCheck.stale) {
        logDirStale = true;
        staleReason = `unit logs to missing dir ${appendCheck.missingPath} (pre-v4.12.10 append: format)`;
      }
    }
    if (entryPointStale && !staleReason) {
      staleReason = 'unit points at a stale npm/npx entry point';
    }

    return { entryPoint, stale: entryPointStale || logDirStale, mode, staleReason };
  } catch {
    return { entryPoint: null, stale: false, mode: null, staleReason: null };
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

type ExecFn = (command: string, options?: Parameters<typeof execSync>[1]) => unknown;

const MACOS_SERVICE_LABEL = 'com.shieldcortex.dashboard';
const LINUX_SERVICE_UNIT = 'shieldcortex-dashboard.service';

function macosGuiDomain(): string {
  const uid = process.getuid?.();
  return typeof uid === 'number' ? `gui/${uid}` : 'gui/501';
}

/**
 * Load (or reload) the LaunchAgent via the modern bootstrap API.
 *
 * The legacy `launchctl load -w` lies on an already-loaded service: it prints
 * "Load failed: 5: Input/output error" to stderr yet exits 0, so install
 * claimed success while the old process kept running with the old service
 * definition (launchd caches the plist at load time). bootout + bootstrap
 * returns real exit codes and applies the plist that was just written.
 */
export async function activateMacosService(
  servicePath: string,
  opts: { exec?: ExecFn; retryDelayMs?: number; drainTimeoutMs?: number } = {},
): Promise<{ reloaded: boolean }> {
  const exec = opts.exec ?? execSync;
  const retryDelayMs = opts.retryDelayMs ?? 500;
  const drainTimeoutMs = opts.drainTimeoutMs ?? 30_000;
  const domain = macosGuiDomain();
  const target = `${domain}/${MACOS_SERVICE_LABEL}`;

  const isLoaded = (): boolean => {
    try {
      exec(`launchctl print ${target}`, { stdio: 'ignore' });
      return true;
    } catch {
      return false;
    }
  };

  const wasLoaded = isLoaded();

  if (wasLoaded) {
    try {
      exec(`launchctl bootout ${target}`, { stdio: 'inherit' });
    } catch {
      // Job vanished between the probe and the bootout (concurrent teardown).
      // Already-gone is the state we wanted; fall through to bootstrap.
    }
    // bootout initiates teardown and returns in milliseconds, but launchd
    // refuses to bootstrap the same label (EIO) until the old instance fully
    // drains — ~5s under SIGTERM→SIGKILL escalation, up to the api server's
    // 10s force-exit. `launchctl print` exits 0 while draining and non-zero
    // once gone, so poll it rather than blind-retrying bootstrap.
    const deadline = Date.now() + drainTimeoutMs;
    while (isLoaded() && Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, retryDelayMs));
    }
  }

  // Replaces the persistence bit that `load -w` used to clear.
  exec(`launchctl enable ${target}`, { stdio: 'inherit' });

  // Safety net behind the drain poll. Gives up honestly — the caller reports
  // the failure instead of claiming success.
  const attempts = wasLoaded ? 3 : 1;
  for (let attempt = 1; ; attempt++) {
    try {
      exec(`launchctl bootstrap ${domain} "${servicePath}"`, { stdio: 'inherit' });
      break;
    } catch (err) {
      if (attempt >= attempts) throw err;
      await new Promise((resolve) => setTimeout(resolve, retryDelayMs));
    }
  }
  return { reloaded: wasLoaded };
}

/**
 * `enable --now` is a no-op start on an already-running unit, so reinstalls
 * kept the old process (and old code) running. enable + restart covers both
 * fresh installs and reinstalls.
 */
export function activateLinuxService(exec: ExecFn = execSync): void {
  exec('systemctl --user daemon-reload', { stdio: 'inherit' });
  exec(`systemctl --user enable ${LINUX_SERVICE_UNIT}`, { stdio: 'inherit' });
  exec(`systemctl --user restart ${LINUX_SERVICE_UNIT}`, { stdio: 'inherit' });
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
      case 'macos': {
        const { reloaded } = await activateMacosService(servicePath);
        console.log(reloaded
          ? 'Service was already loaded — restarted with the new configuration.'
          : 'Service loaded via launchctl.');
        break;
      }
      case 'linux':
        activateLinuxService();
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
    if (platform === 'macos') {
      // Common over ssh: no GUI session means no gui/<uid> domain to load
      // into. The LaunchAgent still auto-starts at the next GUI login.
      console.log(`The service file was written to ${servicePath} — it will auto-start at the next GUI login, or load it now with:`);
      console.log(`  launchctl bootstrap gui/$(id -u) "${servicePath}"`);
    } else {
      console.log(`The service file was written to ${servicePath} — you can enable it manually.`);
    }
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
    if (inspection.stale && inspection.staleReason) {
      console.log(`Reason:    ${inspection.staleReason}`);
    }
  }

  if (!installed) return;

  try {
    switch (platform) {
      case 'macos': {
        const domain = `${macosGuiDomain()}/${MACOS_SERVICE_LABEL}`;
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
