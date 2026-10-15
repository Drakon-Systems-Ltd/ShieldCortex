/**
 * Cross-platform service installer for persistent ShieldCortex background service.
 *
 * Supports:
 *  - macOS: LaunchAgent plist
 *  - Linux: systemd user service
 *  - Windows: VBS script in Startup folder
 */

import fs from 'fs';
import { mkdirSecure } from '../setup/state-permissions.js';
import path from 'path';
import os from 'os';
import { execSync } from 'child_process';
import { fileURLToPath } from 'url';
import { launchdPlist, systemdUnit, windowsVbs, type ServiceConfig, type ServiceMode } from './templates.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

type Platform = 'macos' | 'linux' | 'windows';

type ExecFn = (command: string, options?: Parameters<typeof execSync>[1]) => unknown;

interface ServiceOptions {
  mode?: ServiceMode;
  /**
   * Runs the systemctl / launchctl activation and query commands. Tests inject
   * a stub so nothing real is spawned. (The best-effort linger step still
   * calls execSync directly.)
   */
  exec?: ExecFn;
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
  mkdirSecure(logsDir);

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

/**
 * The CLI verb that runs the same mode in the foreground. `shieldcortex
 * worker|dashboard|api` select exactly the `--mode <mode>` the unit's
 * ExecStart would have run (parseArgs in src/index.ts).
 */
function foregroundCommand(mode: ServiceMode): string {
  return `shieldcortex ${mode}`;
}

/** The install flag that selects `mode`, for a repair hint; empty when the unit's mode is unknown. */
function modeFlag(mode: ServiceMode | null): string {
  switch (mode) {
    case 'worker':
      return ' --headless';
    case 'api':
      return ' --api';
    case 'dashboard':
      return ' --dashboard';
    default:
      return '';
  }
}

/**
 * True when the activation failure says systemctl itself is unusable on this
 * host, as opposed to systemd rejecting the unit: the binary is missing (the
 * shell exits 127, or ENOENT when spawned directly) or there is no user bus
 * or no systemd init to talk to (#768, clean container / node:slim image).
 */
function isSystemdUnavailable(err: unknown): boolean {
  const e = (err ?? {}) as { code?: unknown; status?: unknown; message?: unknown; stdout?: unknown; stderr?: unknown };
  if (e.code === 'ENOENT' || e.status === 127) return true;
  const text = [e.message, e.stdout, e.stderr]
    .filter((v): v is string | Buffer => typeof v === 'string' || Buffer.isBuffer(v))
    .map((v) => String(v))
    .join('\n');
  return /systemctl: (?:command )?not found|Failed to connect to bus|System has not been booted with systemd/i.test(text);
}

const MACOS_SERVICE_LABEL = 'com.shieldcortex.dashboard';
const LINUX_SERVICE_UNIT = 'shieldcortex-dashboard.service';
const SERVICE_USAGE = 'Usage: shieldcortex service <install|repair|uninstall|status> [--dashboard|--api|--headless]';

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
  const exec = options.exec ?? execSync;
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
        const { reloaded } = await activateMacosService(servicePath, { exec });
        console.log(reloaded
          ? 'Service was already loaded — restarted with the new configuration.'
          : 'Service loaded via launchctl.');
        break;
      }
      case 'linux':
        activateLinuxService(exec);
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
    // #768: automation reads this exit code. A unit that could not be
    // activated is not an installed service, however far the file work got.
    process.exitCode = 1;
    console.error(`Failed to enable service: ${err.message}`);
    const foreground = foregroundCommand(mode);
    if (platform === 'macos') {
      // Common over ssh: no GUI session means no gui/<uid> domain to load
      // into. The LaunchAgent still auto-starts at the next GUI login.
      console.error(`The service file was written to ${servicePath} — it will auto-start at the next GUI login, or load it now with:`);
      console.error(`  launchctl bootstrap gui/$(id -u) "${servicePath}"`);
      console.error(`To run the same mode in the foreground instead: ${foreground}`);
    } else if (isSystemdUnavailable(err)) {
      console.error('systemd user services are not available on this host (systemctl is missing or there is no user bus), so the service cannot be enabled here.');
      console.error(`The unit file stays at ${servicePath}. To run the same mode in the foreground instead: ${foreground}`);
    } else {
      console.error(`The unit file stays at ${servicePath}. Inspect with: systemctl --user status ${LINUX_SERVICE_UNIT}`);
      console.error(`If this host has no systemd user session, run the same mode in the foreground instead: ${foreground}`);
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
  await uninstallService({ exec: options.exec });
  await installService(options);
}

function cleanLogsDirectory(): void {
  const logsDir = path.join(os.homedir(), '.shieldcortex', 'logs');
  if (fs.existsSync(logsDir)) {
    fs.rmSync(logsDir, { recursive: true, force: true });
    console.log(`Logs cleaned: ${logsDir}`);
  }
}

export async function uninstallService(options?: { cleanLogs?: boolean; exec?: ExecFn }): Promise<void> {
  const platform = detectPlatform();
  const exec = options?.exec ?? execSync;
  const servicePath = getServicePath(platform);

  if (!fs.existsSync(servicePath)) {
    console.log('No service installed.');
    return;
  }

  try {
    switch (platform) {
      case 'macos':
        exec(`launchctl unload -w "${servicePath}"`, { stdio: 'inherit' });
        break;
      case 'linux':
        exec(`systemctl --user disable --now ${LINUX_SERVICE_UNIT}`, { stdio: 'inherit' });
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

export async function serviceStatus(options: { exec?: ExecFn } = {}): Promise<void> {
  const platform = detectPlatform();
  const exec = options.exec ?? execSync;
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

  if (!installed) {
    console.log('Install:   shieldcortex service install [--dashboard|--api|--headless]');
    process.exitCode = 1;
    return;
  }

  const mode = inspection.mode ?? detectDefaultServiceMode(platform);
  // "Activated" means the platform supervisor knows the unit and is running
  // it. A stale-but-running unit stays activated (exit 0): the service is up,
  // and the Healthy/Repair lines already carry the advice.
  let activated = true;
  // The query itself failed (no systemctl, no user bus): repair cannot help.
  let unqueryable = false;

  switch (platform) {
    case 'macos': {
      const domain = `${macosGuiDomain()}/${MACOS_SERVICE_LABEL}`;
      let out: string | null = null;
      let detail = '';
      try {
        out = String(exec(`launchctl print ${domain} 2>&1`, { encoding: 'utf-8' }) ?? '');
      } catch (err: any) {
        // 2>&1 puts launchd's own line ("Could not find service ...") in stdout.
        detail = String(err?.stdout || err?.message || err).trim().split('\n')[0];
      }
      if (out === null) {
        console.log('Loaded:    no');
        console.log('Running:   no');
        console.log(`Error:     launchctl print ${domain}: ${detail}`);
        activated = false;
        break;
      }
      const pidMatch = out.match(/\bpid\s*=\s*(\d+)/i);
      const running = /\bstate\s*=\s*running\b/i.test(out) || Boolean(pidMatch);
      console.log('Loaded:    yes');
      console.log(`Running:   ${running ? `yes${pidMatch ? ` (PID ${pidMatch[1]})` : ''}` : 'no'}`);
      if (!running) activated = false;
      break;
    }
    case 'linux': {
      const enabled = queryLinuxUnitState(exec, 'is-enabled');
      // If the first query never reached systemd, the second cannot either.
      const active = enabled.error === null ? queryLinuxUnitState(exec, 'is-active') : enabled;
      const problem = enabled.error ?? active.error;
      if (problem !== null) {
        console.log('Enabled:   unknown');
        console.log('Running:   unknown');
        console.log(`Error:     could not query systemd user services: ${problem}`);
        console.log(`Hint:      if this host has no systemd user services, run the same mode in the foreground: ${foregroundCommand(mode)}`);
        activated = false;
        unqueryable = true;
        break;
      }
      const isEnabled = enabled.state === 'enabled';
      const isActive = active.state === 'active';
      console.log(`Enabled:   ${isEnabled ? 'yes' : `no (${enabled.state})`}`);
      console.log(`Running:   ${isActive ? 'yes' : `no (${active.state})`}`);
      if (!isEnabled || !isActive) activated = false;
      break;
    }
    case 'windows':
      console.log('Running:   (check Task Manager for node.exe)');
      break;
  }

  if (inspection.stale || (!activated && !unqueryable)) {
    console.log(`Repair:    shieldcortex service repair${modeFlag(inspection.mode)}`);
  }
  if (!activated) process.exitCode = 1;
}

/**
 * One `systemctl --user is-enabled|is-active` answer. systemctl replies to
 * these verbs with exactly one lowercase word (enabled, disabled, active,
 * inactive, failed, not-found, ...) and a non-zero exit for the negative
 * ones, so the word is read from stdout either way (2>&1 keeps it there).
 * Anything that is not one word ("systemctl: not found", "Failed to connect
 * to bus: ...") means the query never reached systemd.
 */
function queryLinuxUnitState(exec: ExecFn, verb: 'is-enabled' | 'is-active'): { state: string | null; error: string | null } {
  const command = `systemctl --user ${verb} ${LINUX_SERVICE_UNIT} 2>&1`;
  let out: string;
  let message = '';
  try {
    out = String(exec(command, { encoding: 'utf-8' }) ?? '').trim();
  } catch (err: any) {
    out = String(err?.stdout ?? '').trim();
    message = String(err?.message ?? err);
  }
  if (/^[a-z][a-z-]*$/.test(out)) return { state: out, error: null };
  const detail = (out || message || 'no output').split('\n')[0];
  return { state: null, error: detail };
}

function parseServiceModeArgs(args: string[]): ServiceMode | undefined {
  if (args.includes('--dashboard')) return 'dashboard';
  if (args.includes('--api')) return 'api';
  if (args.includes('--headless') || args.includes('--worker')) return 'worker';
  return undefined;
}

export async function handleServiceCommand(
  subcommand: string,
  args: string[] = [],
  deps: { exec?: ExecFn } = {},
): Promise<void> {
  const { exec } = deps;
  switch (subcommand) {
    case 'install':
      await installService({ mode: parseServiceModeArgs(args), exec });
      break;
    case 'repair':
      await repairService({ mode: parseServiceModeArgs(args), exec });
      break;
    case 'uninstall':
      await uninstallService({ cleanLogs: process.argv.includes('--clean-logs'), exec });
      break;
    case 'status':
      await serviceStatus({ exec });
      break;
    case '--help':
    case '-h':
      // Help is not an error.
      console.log(SERVICE_USAGE);
      break;
    default:
      console.log(SERVICE_USAGE);
      process.exit(1);
  }
}
