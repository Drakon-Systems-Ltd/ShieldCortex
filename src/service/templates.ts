/**
 * Platform-specific service file templates for auto-starting Claude Cortex dashboard.
 */

export interface ServiceConfig {
  nodePath: string;
  nodeBinDir: string;
  entryPoint: string;
  logsDir: string;
}

export function launchdPlist(config: ServiceConfig): string {
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.claude-cortex.dashboard</string>
  <key>ProgramArguments</key>
  <array>
    <string>${config.nodePath}</string>
    <string>${config.entryPoint}</string>
    <string>--mode</string>
    <string>dashboard</string>
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
  return `[Unit]
Description=Claude Cortex Dashboard
After=network.target

[Service]
Type=simple
ExecStart=${config.nodePath} ${config.entryPoint} --mode dashboard
Restart=on-failure
RestartSec=5
StandardOutput=append:${config.logsDir}/dashboard-stdout.log
StandardError=append:${config.logsDir}/dashboard-stderr.log
Environment=PATH=${config.nodeBinDir}:/usr/local/bin:/usr/bin:/bin

[Install]
WantedBy=default.target`;
}

export function windowsVbs(config: ServiceConfig): string {
  // VBS script runs node hidden (no console window)
  const nodePath = config.nodePath.replace(/\//g, '\\');
  const entryPoint = config.entryPoint.replace(/\//g, '\\');
  return `Set WshShell = CreateObject("WScript.Shell")
WshShell.Run """${nodePath}"" ""${entryPoint}"" --mode dashboard", 0, False`;
}
