/**
 * One host table for setup, update, uninstall, and doctor.
 *
 * Presence is a home-dir probe, except OpenClaw also requires a real
 * `openclaw` binary — leftover ~/.openclaw after migrating off OpenClaw
 * is not an install. Wired is an artefact probe. Bound vs memory-only
 * is a product fact, not a live Guard measurement.
 *
 * Never enables Action Guard. Never grants conversation access. Never
 * invents an OpenClaw plugin entry. Never imports native memory.
 */
import { execSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import readline from 'readline/promises';

export type HostId = 'claude' | 'openclaw' | 'hermes' | 'codex' | 'copilot';

export type HostKind = 'bound' | 'memory-only';

export interface HostRow {
  id: HostId;
  label: string;
  kind: HostKind;
  present: boolean;
  wired: boolean;
  wireCommand: string;
  unwireCommand: string;
}

export interface HostTable {
  home: string;
  rows: HostRow[];
}

/** Live Action Guard planes for the HOSTS headline. Product fact, not a switch. */
export type OpenClawGatePosture = 'enforcing' | 'observe-only' | 'off' | 'unknown';

export interface HostGatePlanes {
  /** Signed config is enabled AND enforce (warn-mode is not Enforce). */
  signedEnforce: boolean;
  /** Signed config enabled, even in warn-mode. OpenClaw liveGating uses this today. */
  signedEnabled: boolean;
  claudeWired: boolean;
  openclaw: OpenClawGatePosture;
}

export type GuardHeadline = 'off' | 'on' | 'mixed';

export interface HostTableDeps {
  openclawBinaryPresent?: (home: string) => boolean;
}

function labelFor(id: HostId): string {
  switch (id) {
    case 'claude': return 'Claude Code';
    case 'openclaw': return 'OpenClaw';
    case 'hermes': return 'Hermes';
    case 'codex': return 'Codex';
    case 'copilot': return 'Cursor / VS Code';
  }
}

function kindFor(id: HostId): HostKind {
  return id === 'codex' || id === 'copilot' ? 'memory-only' : 'bound';
}

function wireCommand(id: HostId): string {
  switch (id) {
    case 'claude': return 'shieldcortex setup';
    case 'openclaw': return 'shieldcortex openclaw install';
    case 'hermes': return 'shieldcortex hermes install';
    case 'codex': return 'shieldcortex codex install';
    case 'copilot': return 'shieldcortex copilot install';
  }
}

function unwireCommand(id: HostId): string {
  switch (id) {
    case 'claude': return 'shieldcortex setup uninstall';
    case 'openclaw': return 'shieldcortex openclaw uninstall';
    case 'hermes': return 'shieldcortex hermes uninstall';
    case 'codex': return 'shieldcortex codex uninstall';
    case 'copilot': return 'shieldcortex copilot uninstall';
  }
}

export function resolveTableHome(homeArg?: string): string {
  if (homeArg && homeArg.trim()) return path.resolve(homeArg);
  const oc = process.env.OPENCLAW_HOME;
  // OPENCLAW_HOME is the OpenClaw override, not the table home. Table home
  // stays os.homedir() so Claude/Hermes/Codex stay on the operator home.
  void oc;
  return os.homedir();
}

function openclawOperatorHome(home: string): string {
  const explicit = process.env.OPENCLAW_HOME?.trim();
  if (explicit) {
    if (/^~($|[\\/])/.test(explicit)) {
      const fallback = process.env.HOME?.trim() || process.env.USERPROFILE?.trim() || home;
      if (fallback && path.isAbsolute(fallback)) {
        return path.resolve(explicit.replace(/^~(?=$|[\\/])/, fallback));
      }
    } else if (path.isAbsolute(explicit)) {
      return path.resolve(explicit);
    }
  }
  return home;
}

function openclawHome(home: string): string {
  return path.join(openclawOperatorHome(home), '.openclaw');
}

function dirExists(p: string): boolean {
  try {
    return fs.existsSync(p);
  } catch {
    return false;
  }
}

function readText(p: string): string {
  try {
    return fs.readFileSync(p, 'utf8');
  } catch {
    return '';
  }
}

function claudePresent(home: string): boolean {
  return dirExists(path.join(home, '.claude')) || dirExists(path.join(home, '.claude.json'));
}

function claudeWired(home: string): boolean {
  const raw = readText(path.join(home, '.claude', 'settings.json'));
  if (!raw) return false;
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return false;
  }
  if (!parsed || typeof parsed !== 'object') return false;
  const hooks = (parsed as { hooks?: unknown }).hooks;
  if (!hooks || typeof hooks !== 'object') return false;
  const pre = (hooks as { PreToolUse?: unknown }).PreToolUse;
  if (!Array.isArray(pre)) return false;
  return pre.some((entry) => {
    if (!entry || typeof entry !== 'object') return false;
    const inner = (entry as { hooks?: unknown }).hooks;
    if (!Array.isArray(inner)) return false;
    return inner.some((h) => {
      if (!h || typeof h !== 'object') return false;
      const cmd = (h as { command?: unknown }).command;
      return typeof cmd === 'string' && cmd.includes('shieldcortex');
    });
  });
}

/** Claude Code PreToolUse is a ShieldCortex command, not stray text + empty PreToolUse. */
export function claudeToolGateWired(homeArg?: string): boolean {
  return claudeWired(resolveTableHome(homeArg));
}

/**
 * Headline for the HOSTS table. `mixed` is one bound plane enforcing and
 * another bound plane observe-only/off — not "Guard off".
 */
export function guardHeadlineFromPlanes(planes: HostGatePlanes): GuardHeadline {
  const claudeEnforcing = planes.claudeWired && planes.signedEnforce;
  const ocEnforcing = planes.signedEnabled && planes.openclaw === 'enforcing';
  const ocObserve = planes.openclaw === 'observe-only' || planes.openclaw === 'off';
  if (claudeEnforcing && ocObserve) return 'mixed';
  if (claudeEnforcing || ocEnforcing) return 'on';
  return 'off';
}

export function claudePlaneEnforcing(planes: HostGatePlanes): boolean {
  return planes.claudeWired && planes.signedEnforce;
}

export function openclawPlaneEnforcing(planes: HostGatePlanes): boolean {
  return planes.signedEnabled && planes.openclaw === 'enforcing';
}

/**
 * Same candidate set as resolveOpenClawBinary, kept local so doctor table
 * scan does not load the OpenClaw installer. A leftover ~/.openclaw after
 * migrating to Hermes is not OpenClaw — TARS has the dir and no binary.
 */
function openclawBinaryPresent(home: string): boolean {
  const candidates = [
    path.join(home, '.npm-global', 'bin', 'openclaw'),
    '/usr/local/bin/openclaw',
    '/opt/homebrew/bin/openclaw',
    path.join(home, '.local', 'bin', 'openclaw'),
  ];
  if (candidates.some(dirExists)) return true;
  try {
    const found = execSync('which openclaw', {
      encoding: 'utf8',
      timeout: 5000,
      env: process.env,
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim();
    return Boolean(found && dirExists(found));
  } catch {
    return false;
  }
}

function openclawPresent(home: string, deps: HostTableDeps): boolean {
  const oc = openclawHome(home);
  if (!dirExists(path.join(oc, 'openclaw.json'))) return false;
  const probe = deps.openclawBinaryPresent ?? openclawBinaryPresent;
  return probe(openclawOperatorHome(home));
}

const OPENCLAW_PLUGIN_ID = 'shieldcortex-realtime';

function openclawPluginEnabled(config: unknown): boolean {
  if (!config || typeof config !== 'object') return false;
  const plugins = (config as { plugins?: unknown }).plugins;
  if (!plugins || typeof plugins !== 'object') return false;
  const entries = (plugins as { entries?: unknown }).entries;
  const allow = (plugins as { allow?: unknown }).allow;
  if (!entries || typeof entries !== 'object' || !Array.isArray(allow)) return false;
  const entry = (entries as Record<string, unknown>)[OPENCLAW_PLUGIN_ID];
  return Boolean(
    entry
    && typeof entry === 'object'
    && (entry as { enabled?: unknown }).enabled === true
    && allow.some((id) => id === OPENCLAW_PLUGIN_ID),
  );
}

function openclawPluginArtifactPresent(oc: string): boolean {
  const local = path.join(oc, 'extensions', OPENCLAW_PLUGIN_ID);
  if (
    dirExists(path.join(local, 'index.js'))
    && dirExists(path.join(local, 'openclaw.plugin.json'))
  ) return true;

  const projects = path.join(oc, 'npm', 'projects');
  try {
    return fs.readdirSync(projects).some((project) => dirExists(path.join(
      projects,
      project,
      'node_modules',
      '@drakon-systems',
      OPENCLAW_PLUGIN_ID,
      'package.json',
    )));
  } catch {
    return false;
  }
}

function openclawWired(home: string): boolean {
  const oc = openclawHome(home);
  let config: unknown;
  try {
    config = JSON.parse(readText(path.join(oc, 'openclaw.json')));
  } catch {
    return false;
  }
  // cortex-memory is a capture hook, not the tool gate. Require OpenClaw's
  // explicit enable+allow contract and plugin bytes it can actually resolve.
  return openclawPluginEnabled(config) && openclawPluginArtifactPresent(oc);
}

function hermesPresent(home: string): boolean {
  const root = path.join(home, '.hermes');
  if (!dirExists(root)) return false;
  // A leftover ~/.hermes/ekho-state dir is not Hermes. Require a real
  // agent home (config, profiles, or SOUL.md). Jarvis 5.0.5 false-presented
  // from ekho-state alone with no hermes binary.
  return dirExists(path.join(root, 'config.yaml'))
    || dirExists(path.join(root, 'config.yml'))
    || dirExists(path.join(root, 'profiles'))
    || dirExists(path.join(root, 'SOUL.md'));
}

function hermesWired(home: string): boolean {
  return dirExists(path.join(home, '.hermes', 'plugins', 'shieldcortex', 'plugin.yaml'));
}

function codexPresent(home: string): boolean {
  return dirExists(path.join(home, '.codex'));
}

function codexWired(home: string): boolean {
  const toml = readText(path.join(home, '.codex', 'config.toml'));
  return /mcp_servers\.shieldcortex-memory/.test(toml);
}

function vscodeUserDirs(home: string): string[] {
  const platform = process.platform;
  if (platform === 'darwin') {
    return [
      path.join(home, 'Library', 'Application Support', 'Code', 'User'),
      path.join(home, 'Library', 'Application Support', 'Code - Insiders', 'User'),
    ];
  }
  if (platform === 'win32') {
    const app = process.env.APPDATA ?? path.join(home, 'AppData', 'Roaming');
    return [
      path.join(app, 'Code', 'User'),
      path.join(app, 'Code - Insiders', 'User'),
    ];
  }
  return [
    path.join(home, '.config', 'Code', 'User'),
    path.join(home, '.config', 'Code - Insiders', 'User'),
  ];
}

function copilotPresent(home: string): boolean {
  if (dirExists(path.join(home, '.cursor'))) return true;
  return vscodeUserDirs(home).some((d) => dirExists(d));
}

function copilotWired(home: string): boolean {
  const files = [
    path.join(home, '.cursor', 'mcp.json'),
    ...vscodeUserDirs(home).map((d) => path.join(d, 'mcp.json')),
  ];
  return files.some((f) => {
    const t = readText(f);
    return t.includes('shieldcortex-memory') || (/shieldcortex/.test(t) && /mcpServers|"servers"/.test(t));
  });
}

function row(id: HostId, home: string, deps: HostTableDeps): HostRow {
  const present =
    id === 'claude' ? claudePresent(home) :
    id === 'openclaw' ? openclawPresent(home, deps) :
    id === 'hermes' ? hermesPresent(home) :
    id === 'codex' ? codexPresent(home) :
    copilotPresent(home);
  const wired =
    id === 'claude' ? claudeWired(home) :
    id === 'openclaw' ? openclawWired(home) :
    id === 'hermes' ? hermesWired(home) :
    id === 'codex' ? codexWired(home) :
    copilotWired(home);
  return {
    id,
    label: labelFor(id),
    kind: kindFor(id),
    present,
    wired: present && wired,
    wireCommand: wireCommand(id),
    unwireCommand: unwireCommand(id),
  };
}

export const HOST_IDS: readonly HostId[] = ['claude', 'openclaw', 'hermes', 'codex', 'copilot'];

export function scanHostTable(homeArg?: string, deps: HostTableDeps = {}): HostTable {
  const home = resolveTableHome(homeArg);
  return { home, rows: HOST_IDS.map((id) => row(id, home, deps)) };
}

export function presentUnwired(table: HostTable): HostRow[] {
  return table.rows.filter((r) => r.present && !r.wired);
}

export function wiredHosts(table: HostTable): HostRow[] {
  return table.rows.filter((r) => r.wired);
}

export function formatHostTable(table: HostTable, version?: string, planes?: HostGatePlanes): string[] {
  const lines: string[] = [];
  const headline = planes ? guardHeadlineFromPlanes(planes) : 'off';
  const guardLabel = headline === 'on' ? 'Guard on' : headline === 'mixed' ? 'Guard mixed' : 'Guard off';
  lines.push(version ? `ShieldCortex  ${version}    ${guardLabel}` : `ShieldCortex    ${guardLabel}`);
  lines.push('');
  const width = Math.max(...table.rows.map((r) => r.label.length), 10);
  for (const r of table.rows) {
    const present = r.present ? 'present' : 'absent ';
    const wired = !r.present ? '—' : r.wired ? 'wired   ' : 'not wired';
    const kind = r.kind === 'bound' ? 'memory + tool gate' : 'memory only — not a gate';
    const posture = rowGatePosture(r, planes);
    lines.push(`  ${r.label.padEnd(width)}  ${present}  ${wired}  ${kind}${posture ? `  ${posture}` : ''}`);
  }
  const todo = presentUnwired(table);
  if (todo.length > 0) {
    lines.push('');
    lines.push('Unwired hosts on this box:');
    for (const r of todo) lines.push(`  ${r.wireCommand}`);
  }
  return lines;
}

function rowGatePosture(r: HostRow, planes?: HostGatePlanes): string | undefined {
  if (!planes || !r.present || r.kind !== 'bound') return undefined;
  if (r.id === 'claude') {
    if (!planes.claudeWired) return undefined;
    return planes.signedEnforce ? 'enforcing' : 'off';
  }
  if (r.id === 'openclaw') {
    if (planes.openclaw === 'unknown') return undefined;
    return planes.openclaw;
  }
  return undefined;
}

export function isInteractiveTerminal(
  stdinIsTTY = Boolean(process.stdin.isTTY),
  stdoutIsTTY = Boolean(process.stdout.isTTY),
): boolean {
  return stdinIsTTY && stdoutIsTTY;
}

export async function promptYesNo(question: string, defaultYes = true): Promise<boolean> {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
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

export const NAMED_REPAIR_JOBS = [
  'wire-claude',
  'wire-openclaw',
  'wire-hermes',
  'wire-codex',
  'wire-copilot',
] as const;

export type NamedRepairJob = typeof NAMED_REPAIR_JOBS[number];

export function repairJobsFor(table: HostTable): NamedRepairJob[] {
  const jobs: NamedRepairJob[] = [];
  for (const r of presentUnwired(table)) {
    jobs.push(`wire-${r.id}` as NamedRepairJob);
  }
  return jobs;
}

export async function wireHost(id: HostId): Promise<void> {
  switch (id) {
    case 'claude': {
      const { setupClaudeMd } = await import('./claude-md.js');
      await setupClaudeMd({});
      return;
    }
    case 'openclaw': {
      const { handleOpenClawCommand } = await import('./openclaw.js');
      await handleOpenClawCommand('install');
      return;
    }
    case 'hermes': {
      const { installHermes } = await import('./hermes.js');
      await installHermes();
      return;
    }
    case 'codex': {
      const { installCodex } = await import('./codex.js');
      await installCodex();
      return;
    }
    case 'copilot': {
      const { installCopilot } = await import('./copilot.js');
      await installCopilot();
      return;
    }
  }
}

export async function offerUnwiredHosts(opts: {
  autoApprove?: boolean;
  mode: 'setup' | 'update';
  home?: string;
}): Promise<HostId[]> {
  const table = scanHostTable(opts.home);
  const todo = presentUnwired(table);
  if (todo.length === 0) return [];

  const wired: HostId[] = [];
  const tty = isInteractiveTerminal();
  if (!tty && !opts.autoApprove) {
    console.log('');
    console.log(opts.mode === 'update'
      ? 'Update does not silently wire new hosts. Present but not wired:'
      : 'Non-interactive: not wiring. Present but not wired:');
    for (const r of todo) console.log(`  ${r.label}  →  ${r.wireCommand}`);
    console.log('Run `shieldcortex setup` in a terminal, or pass --install-detected.');
    return [];
  }

  if (!opts.autoApprove) {
    const any = await promptYesNo('Wire the unwired hosts?', true);
    if (!any) {
      console.log('Skipped. Re-run `shieldcortex setup` any time.');
      return [];
    }
  }
  for (const r of todo) {
    const ok = opts.autoApprove
      ? true
      : await promptYesNo(`Install ShieldCortex for ${r.label}?`, true);
    if (!ok) continue;
    console.log('');
    await wireHost(r.id);
    wired.push(r.id);
    console.log('');
  }
  return wired;
}

export function writeRepairAgentBrief(jobs: NamedRepairJob[], dest: string): void {
  const body = [
    '# ShieldCortex bounded repair brief',
    '',
    'Action Guard stays off. Do not enable it. Do not grant conversation access.',
    'Do not import native memory. Do not restart a live gateway unless the operator is idle and asked.',
    '',
    'Named jobs only:',
    ...jobs.map((j) => `- ${j}`),
    '',
    'If a job is not in this list, stop.',
    '',
  ].join('\n');
  fs.mkdirSync(path.dirname(dest), { recursive: true });
  fs.writeFileSync(dest, body, { mode: 0o600 });
}

export async function runNamedRepairJobs(jobs: NamedRepairJob[]): Promise<HostId[]> {
  const done: HostId[] = [];
  for (const job of jobs) {
    const id = job.replace(/^wire-/, '') as HostId;
    if (!HOST_IDS.includes(id)) continue;
    await wireHost(id);
    done.push(id);
  }
  return done;
}
