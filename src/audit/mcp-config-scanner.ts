/**
 * MCP Config Scanner
 *
 * Scans MCP server configuration files for:
 *   - Known-vulnerable MCP servers (e.g., mcp-remote CVE-2025-6514)
 *   - Suspicious server configurations (external URLs, unknown servers)
 *   - Servers with overly permissive permissions
 */

import { existsSync, readFileSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';
import type { AuditFinding, ScannerResult } from './types.js';

const LEARN_MORE = 'https://shieldcortex.ai/docs/threats/mcp-security';

// ── Known Vulnerable Servers ──

interface VulnerableServer {
  name: string;
  cve?: string;
  severity: 'critical' | 'high' | 'medium';
  description: string;
  /** If set, only versions matching this are vulnerable */
  versionPattern?: RegExp;
}

const KNOWN_VULNERABLE_SERVERS: VulnerableServer[] = [
  {
    name: 'mcp-remote',
    cve: 'CVE-2025-6514',
    severity: 'critical',
    description: 'mcp-remote allows arbitrary OS command execution when connecting to untrusted servers (CVSS 9.6). Update to latest version.',
  },
  {
    name: '@anthropic/mcp-remote',
    cve: 'CVE-2025-6514',
    severity: 'critical',
    description: 'mcp-remote allows arbitrary OS command execution when connecting to untrusted servers (CVSS 9.6). Update to latest version.',
  },
];

// ── Suspicious Patterns ──

const SUSPICIOUS_URL_PATTERNS = [
  { pattern: /https?:\/\/\d+\.\d+\.\d+\.\d+/i, reason: 'MCP server connects to raw IP address' },
  { pattern: /https?:\/\/[^/]*\.(ru|cn|xyz|top|buzz|quest)\//i, reason: 'MCP server connects to suspicious TLD' },
  { pattern: /ngrok\.io|serveo\.net|localhost\.run|loca\.lt/i, reason: 'MCP server connects to tunnelling service' },
];

const DANGEROUS_FLAGS = [
  { flag: '--dangerously-skip-permissions', severity: 'critical' as const, description: 'Disables all permission checks — agent can execute any tool without confirmation' },
  { flag: '--no-verify', severity: 'high' as const, description: 'Skips verification checks' },
  { flag: '--trust-all-tools', severity: 'critical' as const, description: 'Trusts all tools without verification' },
  { flag: '--yolo', severity: 'critical' as const, description: 'Disables safety checks' },
  { flag: 'dangerouslyDisableSandbox', severity: 'critical' as const, description: 'Disables sandbox protection' },
];

// ── Config Locations ──

interface ConfigLocation {
  path: string;
  name: string;
}

function getConfigLocations(): ConfigLocation[] {
  const home = homedir();
  const cwd = process.cwd();

  return [
    // Claude Code / OpenClaw
    { path: join(home, '.claude', 'mcp.json'), name: 'Claude Code (global)' },
    { path: join(cwd, '.claude', 'mcp.json'), name: 'Claude Code (project)' },
    { path: join(home, '.claude.json'), name: 'Claude Code (~/.claude.json)' },
    { path: join(cwd, '.claude.json'), name: 'Claude Code (project .claude.json)' },
    { path: join(home, '.openclaw', 'mcp.json'), name: 'OpenClaw (global)' },
    // Claude Desktop
    { path: join(home, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json'), name: 'Claude Desktop' },
    // VS Code / Copilot
    { path: join(home, '.vscode', 'mcp.json'), name: 'VS Code (global)' },
    { path: join(cwd, '.vscode', 'mcp.json'), name: 'VS Code (project)' },
    // Cursor
    { path: join(home, '.cursor', 'mcp.json'), name: 'Cursor (global)' },
    { path: join(cwd, '.cursor', 'mcp.json'), name: 'Cursor (project)' },
    // Windsurf
    { path: join(home, '.windsurf', 'mcp.json'), name: 'Windsurf (global)' },
    // Codex
    { path: join(home, '.codex', 'config.toml'), name: 'Codex (global)' },
  ];
}

function parseTomlMcpServers(content: string): Record<string, unknown> {
  const servers: Record<string, unknown> = {};
  const sectionPattern = /^\[mcp_servers\.([^\]]+)\]\s*$/gm;
  const matches = [...content.matchAll(sectionPattern)];

  for (let i = 0; i < matches.length; i++) {
    const match = matches[i];
    const serverName = match[1];
    const sectionStart = match.index! + match[0].length;
    const sectionEnd = i + 1 < matches.length ? matches[i + 1].index! : content.length;
    const body = content.slice(sectionStart, sectionEnd);

    const commandMatch = body.match(/^\s*command\s*=\s*"([^"]+)"/m);
    const argsMatch = body.match(/^\s*args\s*=\s*\[([\s\S]*?)\]/m);
    const envMatch = body.match(/^\s*env\s*=\s*\{([\s\S]*?)\}/m);

    servers[serverName] = {
      command: commandMatch?.[1],
      args: argsMatch?.[1] ?? '',
      env: envMatch?.[1] ?? '',
    };
  }

  return servers;
}

/**
 * Parse and scan a single MCP config file.
 */
function scanConfigFile(location: ConfigLocation): AuditFinding[] {
  const findings: AuditFinding[] = [];

  let content: string;
  try {
    content = readFileSync(location.path, 'utf-8');
  } catch {
    return findings;
  }

  let servers: Record<string, unknown> = {};
  if (location.path.endsWith('.toml')) {
    servers = parseTomlMcpServers(content);
  } else {
    let config: Record<string, unknown>;
    try {
      config = JSON.parse(content);
    } catch {
      findings.push({
        scanner: 'mcp-config',
        severity: 'medium',
        title: 'Malformed MCP config',
        description: `${location.name} MCP config file contains invalid JSON — may have been tampered with.`,
        filePath: location.path,
        learnMoreUrl: LEARN_MORE,
      });
      return findings;
    }

    // Extract servers from various config formats
    servers = extractServers(config);
  }

  for (const [serverName, serverConfig] of Object.entries(servers)) {
    const configStr = JSON.stringify(serverConfig);

    // Check against known vulnerable servers
    for (const vuln of KNOWN_VULNERABLE_SERVERS) {
      if (serverName === vuln.name || configStr.includes(vuln.name)) {
        findings.push({
          scanner: 'mcp-config',
          severity: vuln.severity,
          title: `Known vulnerable MCP server: ${vuln.name}`,
          description: `${vuln.description}${vuln.cve ? ` (${vuln.cve})` : ''}`,
          filePath: location.path,
          learnMoreUrl: LEARN_MORE,
        });
      }
    }

    // Check for suspicious URLs
    for (const { pattern, reason } of SUSPICIOUS_URL_PATTERNS) {
      if (pattern.test(configStr)) {
        const match = configStr.match(pattern);
        findings.push({
          scanner: 'mcp-config',
          severity: 'medium',
          title: reason,
          description: `Server "${serverName}" in ${location.name} connects to a potentially unsafe endpoint.`,
          filePath: location.path,
          matchedText: match?.[0]?.slice(0, 80),
          learnMoreUrl: LEARN_MORE,
        });
      }
    }

    // Check for dangerous flags in args
    for (const { flag, severity, description } of DANGEROUS_FLAGS) {
      if (configStr.includes(flag)) {
        findings.push({
          scanner: 'mcp-config',
          severity,
          title: `Dangerous flag in MCP config: ${flag}`,
          description: `Server "${serverName}" in ${location.name}: ${description}`,
          filePath: location.path,
          matchedText: flag,
          learnMoreUrl: LEARN_MORE,
        });
      }
    }
  }

  return findings;
}

/**
 * Extract server definitions from various MCP config formats.
 * Handles both { mcpServers: {...} } and { servers: {...} } formats.
 */
function extractServers(config: Record<string, unknown>): Record<string, unknown> {
  if (config.mcpServers && typeof config.mcpServers === 'object') {
    return config.mcpServers as Record<string, unknown>;
  }
  if (config.servers && typeof config.servers === 'object') {
    return config.servers as Record<string, unknown>;
  }
  return {};
}

// ── Structured Server Discovery (reused by the tools scanner) ──
//
// The config scanner above only needs a stringified blob of each server entry
// to pattern-match dangerous flags / known CVEs. The tools scanner needs to
// actually SPAWN each server, so it needs the command + args + env as proper
// typed values. `discoverMcpServers()` reuses the same config-location list and
// the same JSON/TOML parsers, then normalises each entry into a spawnable
// descriptor. Stdio servers only — remote (url/sse/http) servers cannot be
// spawned locally and are skipped.

export interface DiscoveredMcpServer {
  /** Server key from the config (e.g. "memory", "github") */
  name: string;
  /** Config file this server was discovered in */
  source: string;
  /** Config file path */
  sourcePath: string;
  /** Executable to spawn */
  command: string;
  /** Arguments passed to the command */
  args: string[];
  /** Extra environment variables for the child */
  env: Record<string, string>;
}

function asStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.filter((v): v is string => typeof v === 'string');
}

function asStringRecord(value: unknown): Record<string, string> {
  if (!value || typeof value !== 'object') return {};
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    if (typeof v === 'string') out[k] = v;
    else if (typeof v === 'number' || typeof v === 'boolean') out[k] = String(v);
  }
  return out;
}

/**
 * Parse a TOML `[mcp_servers.<name>]` block into structured command/args/env.
 * Deliberately small — handles the common `command = "..."`,
 * `args = ["a", "b"]`, `env = { KEY = "val" }` forms emitted by Codex.
 */
function parseTomlServersStructured(content: string): Record<string, { command?: string; args: string[]; env: Record<string, string> }> {
  const servers: Record<string, { command?: string; args: string[]; env: Record<string, string> }> = {};
  const sectionPattern = /^\[mcp_servers\.([^\]]+)\]\s*$/gm;
  const matches = [...content.matchAll(sectionPattern)];

  for (let i = 0; i < matches.length; i++) {
    const match = matches[i];
    const serverName = match[1];
    const sectionStart = match.index! + match[0].length;
    const sectionEnd = i + 1 < matches.length ? matches[i + 1].index! : content.length;
    const body = content.slice(sectionStart, sectionEnd);

    const commandMatch = body.match(/^\s*command\s*=\s*"([^"]+)"/m);
    const argsMatch = body.match(/^\s*args\s*=\s*\[([\s\S]*?)\]/m);
    const envMatch = body.match(/^\s*env\s*=\s*\{([\s\S]*?)\}/m);

    const args: string[] = [];
    if (argsMatch) {
      for (const m of argsMatch[1].matchAll(/"([^"]*)"/g)) args.push(m[1]);
    }
    const env: Record<string, string> = {};
    if (envMatch) {
      for (const m of envMatch[1].matchAll(/([A-Za-z_][\w]*)\s*=\s*"([^"]*)"/g)) env[m[1]] = m[2];
    }

    servers[serverName] = { command: commandMatch?.[1], args, env };
  }

  return servers;
}

/**
 * Discover all configured, locally-spawnable (stdio) MCP servers across every
 * known config location. Reuses `getConfigLocations()` + `extractServers()` so
 * path logic lives in exactly one place.
 *
 * Servers are de-duplicated by name (first config wins) so the same logical
 * server defined in both a global and project config isn't scanned twice.
 */
export function discoverMcpServers(): DiscoveredMcpServer[] {
  const out: DiscoveredMcpServer[] = [];
  const seen = new Set<string>();

  for (const location of getConfigLocations()) {
    if (!existsSync(location.path)) continue;

    let content: string;
    try {
      content = readFileSync(location.path, 'utf-8');
    } catch {
      continue;
    }

    if (location.path.endsWith('.toml')) {
      const servers = parseTomlServersStructured(content);
      for (const [name, cfg] of Object.entries(servers)) {
        if (!cfg.command || seen.has(name)) continue;
        seen.add(name);
        out.push({ name, source: location.name, sourcePath: location.path, command: cfg.command, args: cfg.args, env: cfg.env });
      }
      continue;
    }

    let config: Record<string, unknown>;
    try {
      config = JSON.parse(content);
    } catch {
      continue;
    }

    for (const [name, raw] of Object.entries(extractServers(config))) {
      if (seen.has(name) || !raw || typeof raw !== 'object') continue;
      const entry = raw as Record<string, unknown>;
      const command = typeof entry.command === 'string' ? entry.command : undefined;
      // Skip remote servers (url/sse/http) — they can't be spawned locally.
      if (!command) continue;
      seen.add(name);
      out.push({
        name,
        source: location.name,
        sourcePath: location.path,
        command,
        args: asStringArray(entry.args),
        env: asStringRecord(entry.env),
      });
    }
  }

  return out;
}

/**
 * Run the MCP config scanner.
 */
export function scanMcpConfigs(): ScannerResult {
  const start = Date.now();
  const locations = getConfigLocations();
  const existingLocations = locations.filter(l => existsSync(l.path));

  if (existingLocations.length === 0) {
    return {
      name: 'MCP Config Scanner',
      itemsScanned: 0,
      findings: [],
      durationMs: Date.now() - start,
      skipped: true,
      skipReason: 'No MCP configuration files found',
    };
  }

  const allFindings: AuditFinding[] = [];
  for (const location of existingLocations) {
    allFindings.push(...scanConfigFile(location));
  }

  return {
    name: 'MCP Config Scanner',
    itemsScanned: existingLocations.length,
    findings: allFindings,
    durationMs: Date.now() - start,
  };
}
