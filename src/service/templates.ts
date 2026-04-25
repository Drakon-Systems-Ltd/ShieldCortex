/**
 * Platform-specific service file templates for auto-starting ShieldCortex.
 */

export type ServiceMode = 'dashboard' | 'api' | 'worker';

export interface ServiceConfig {
  nodePath: string;
  nodeBinDir: string;
  entryPoint: string;
  logsDir: string;
  mode: ServiceMode;
}

function modeLabel(mode: ServiceMode): string {
  switch (mode) {
    case 'worker':
      return 'Worker';
    case 'api':
      return 'API';
    default:
      return 'Dashboard';
  }
}

export function launchdPlist(config: ServiceConfig): string {
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.shieldcortex.dashboard</string>
  <key>ProgramArguments</key>
  <array>
    <string>${config.nodePath}</string>
    <string>${config.entryPoint}</string>
    <string>--mode</string>
    <string>${config.mode}</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>${config.logsDir}/dashboard-stdout.log</string>
  <key>StandardErrorPath</key>
  <string>${config.logsDir}/dashboard-stderr.log</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>PATH</key>
    <string>${config.nodeBinDir}:/usr/local/bin:/usr/bin:/bin</string>
  </dict>
</dict>
</plist>`;
}

export function systemdUnit(config: ServiceConfig): string {
  // Logs go to journald rather than absolute file paths.
  // History: pre-v4.12.10 used `StandardOutput=append:~/.shieldcortex/logs/...`,
  // which crash-looped with exit 209/STDOUT if that dir was ever removed
  // (e.g. by `uninstall --clean-logs` or any cleanup of ~/.shieldcortex).
  // systemd opens the StandardOutput file before any ExecStart*, so an
  // ExecStartPre=mkdir cannot recover it. journald has no filesystem
  // dependency and works on every systemd version we support.
  // Inspect with: journalctl --user -u shieldcortex-dashboard.service
  return `[Unit]
Description=ShieldCortex ${modeLabel(config.mode)}
After=network.target

[Service]
Type=simple
ExecStart=${config.nodePath} ${config.entryPoint} --mode ${config.mode}
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=shieldcortex-${config.mode}
Environment=PATH=${config.nodeBinDir}:/usr/local/bin:/usr/bin:/bin

[Install]
WantedBy=default.target`;
}

export function windowsVbs(config: ServiceConfig): string {
  // VBS script runs node hidden (no console window)
  const nodePath = config.nodePath.replace(/\//g, '\\');
  const entryPoint = config.entryPoint.replace(/\//g, '\\');
  return `Set WshShell = CreateObject("WScript.Shell")
WshShell.Run """${nodePath}"" ""${entryPoint}"" --mode ${config.mode}", 0, False`;
}
