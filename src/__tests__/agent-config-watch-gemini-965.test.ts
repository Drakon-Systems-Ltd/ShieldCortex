/**
 * #965: Gemini CLI in the agent config watch (settings.json hooks and
 * mcpServers, user and project; planted GEMINI.md and .gemini/settings.json
 * in drop directories) with a silent first-sight baseline on upgrade.
 *
 * Fixtures are built from the module's exported constants (the #928 pattern)
 * and written at runtime into an os.tmpdir() sandbox with os.homedir spied.
 * Values are inert placeholders; nothing here is executed or sent anywhere.
 */
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import fs from 'fs';
import os from 'os';
import path from 'path';
import {
  DROPZONE_FILES,
  GEMINI_COMMAND_KEYS,
  GEMINI_SETTINGS_REL,
  PLANTED_GEMINI_SETTINGS_FILES,
  PLANTED_INSTRUCTION_FILES,
  WATCHED_FILES,
  loadAgentConfigState,
  runAgentConfigWatch,
  saveAgentConfigState,
  type AgentConfigLedgerRow,
  type AgentConfigNotification,
} from '../audit/agent-config-watch.js';

const val = (n: string): string => `fixture-value-965-${n}`;
const GEMINI_INSTRUCTION = PLANTED_INSTRUCTION_FILES.find((f) => f.startsWith('GEMINI')) as string;
const GEMINI_SPEC_IDS = [...WATCHED_FILES, ...DROPZONE_FILES].filter((s) => s.relPath.includes('.gemini') || s.relPath === GEMINI_INSTRUCTION).map((s) => s.id);

let sandbox: string;
let home: string;
let project: string;
let drop: string;
let notes: AgentConfigNotification[];
let rows: AgentConfigLedgerRow[];
let homedirSpy: { mockRestore(): void };

const userSettings = () => path.join(home, GEMINI_SETTINGS_REL);
const projectSettings = () => path.join(project, GEMINI_SETTINGS_REL);
const writeFile = (p: string, text: string): void => { fs.mkdirSync(path.dirname(p), { recursive: true }); fs.writeFileSync(p, text); };
const writeJson = (p: string, v: unknown): void => writeFile(p, JSON.stringify(v, null, 2));
const hook = (n: string) => ({ hooks: [{ type: 'command', command: val(n) }] });
const run = (root: string = project) => runAgentConfigWatch({
  home,
  projectRoots: [root],
  dropzoneDirs: [drop],
  notify: async (n) => { notes.push(n); },
  ledger: (r) => { rows.push(r); return true; },
});
const labels = () => notes.flatMap((n) => n.changes.map((c) => c.label));

beforeEach(() => {
  sandbox = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-965-'));
  home = path.join(sandbox, 'home');
  project = path.join(sandbox, 'proj');
  drop = path.join(home, 'Downloads');
  for (const d of [home, project, drop]) fs.mkdirSync(d, { recursive: true });
  homedirSpy = jest.spyOn(os, 'homedir').mockReturnValue(home);
  notes = [];
  rows = [];
});

afterEach(() => {
  homedirSpy.mockRestore();
  fs.rmSync(sandbox, { recursive: true, force: true });
});

describe('Gemini CLI specs', () => {
  it('watches user and project settings.json for hooks and mcpServers', () => {
    for (const id of ['gemini-settings', 'gemini-project-settings']) {
      const spec = WATCHED_FILES.find((w) => w.id === id);
      expect(spec?.relPath).toBe(GEMINI_SETTINGS_REL);
      expect(spec?.sections.map((s) => [s.keyPath, s.kind])).toEqual([['hooks', 'hooks'], ['mcpServers', 'mcpServers'], [GEMINI_COMMAND_KEYS.join('+'), 'commands']]);
    }
    expect(WATCHED_FILES.find((w) => w.id === 'gemini-settings')?.scope).toBe('user');
    expect(WATCHED_FILES.find((w) => w.id === 'gemini-project-settings')?.scope).toBe('project');
  });

  it('GEMINI.md is a planted instruction file and .gemini/settings.json a planted config file', () => {
    expect(GEMINI_INSTRUCTION).toBe('GEMINI.md');
    expect(DROPZONE_FILES.map((s) => s.relPath)).toEqual(expect.arrayContaining([GEMINI_INSTRUCTION, ...PLANTED_GEMINI_SETTINGS_FILES.map((f) => path.join('.gemini', f))]));
  });
});

describe('Gemini CLI alerts', () => {
  it.each([['user', userSettings], ['project', projectSettings]] as const)('%s: a planted hook and a new MCP server alert, a baseline does not', async (_n, file) => {
    writeJson(file(), { hooks: { BeforeTool: [hook('a')] }, mcpServers: { known: { command: val('k') } } });
    const first = await run();
    expect(first.baselined).toBe(true);
    expect(notes).toHaveLength(0);
    expect((await run()).notified).toBe(0);

    writeJson(file(), { hooks: { BeforeTool: [hook('a')], SessionStart: [hook('planted')] }, mcpServers: { known: { command: val('k') }, evil: { command: val('e') } } });
    await run();
    expect(labels().sort()).toEqual(['MCP server added', 'hook added']);
    expect(JSON.stringify(notes)).not.toContain('fixture-value-965');
  });

  it.each([['user', userSettings], ['project', projectSettings]] as const)('%s: setting or changing a shell-command key alerts, an unrelated key does not', async (_n, file) => {
    expect(GEMINI_COMMAND_KEYS).toEqual(['tools.discoveryCommand', 'tools.callCommand', 'mcp.serverCommand']);
    writeJson(file(), { tools: { discoveryCommand: val('d') }, ui: { theme: 'a' } });
    await run();
    writeJson(file(), { tools: { discoveryCommand: val('d') }, ui: { theme: 'b' } });
    expect((await run()).notified).toBe(0);

    writeJson(file(), { tools: { discoveryCommand: val('d2'), callCommand: val('c') }, mcp: { serverCommand: val('s') }, ui: { theme: 'b' } });
    await run();
    expect(notes).toHaveLength(1);
    expect(notes[0].changes.map((c) => `${c.label}:${c.name}`).sort()).toEqual([
      'command setting added:mcp.serverCommand',
      'command setting added:tools.callCommand',
      'command setting changed:tools.discoveryCommand',
    ]);
    expect(JSON.stringify(notes)).not.toContain('fixture-value-965');
  });

  it('a planted GEMINI.md alerts as high severity', async () => {
    await run();
    writeFile(path.join(drop, GEMINI_INSTRUCTION), val('instructions'));
    await run();
    expect(labels()).toEqual(['planted-instructions added']);
    expect(notes[0].severity).toBe('high');
  });

  it('a planted .gemini/settings.json in a drop directory alerts as high severity', async () => {
    await run();
    writeJson(path.join(drop, '.gemini', PLANTED_GEMINI_SETTINGS_FILES[0]), { mcpServers: { evil: { command: val('e') } } });
    await run();
    expect(labels()).toEqual(['planted-agent-config added']);
    expect(notes[0].severity).toBe('high');
  });
});

describe('upgrade: silent first sight (bug-A pattern from #928)', () => {
  /** Rewrite the stored state as a build without Gemini would have left it. */
  function stripGeminiFromState(): void {
    const st = loadAgentConfigState(home);
    for (const k of Object.keys(st.files)) if (k.includes(`${path.sep}.gemini${path.sep}`) || k.endsWith(GEMINI_INSTRUCTION)) delete st.files[k];
    for (const k of Object.keys(st.sectionVersions ?? {})) if (k.includes('.gemini') || k.endsWith(GEMINI_INSTRUCTION)) delete st.sectionVersions![k];
    delete st.baselinedSpecs;
    saveAgentConfigState(home, st);
  }

  it('existing Gemini settings, GEMINI.md and drop files do not alert on the first post-upgrade run, then do on change', async () => {
    await run(); // baseline without Gemini files
    writeJson(userSettings(), { hooks: { BeforeTool: [hook('u')] }, mcpServers: { mine: { command: val('m') } } });
    writeJson(projectSettings(), { mcpServers: { mine: { command: val('p') } } });
    writeFile(path.join(drop, GEMINI_INSTRUCTION), val('pre-existing'));
    writeJson(path.join(drop, '.gemini', 'settings.json'), { mcpServers: {} });
    stripGeminiFromState();

    const r = await run();
    expect(r.notified).toBe(0);
    expect(notes).toHaveLength(0);
    expect(loadAgentConfigState(home).baselinedSpecs).toEqual(expect.arrayContaining(
      GEMINI_SPEC_IDS.map((id) => (id === 'gemini-project-settings' ? `${id}@${project}` : id)),
    ));

    writeJson(userSettings(), { hooks: { BeforeTool: [hook('u')], Stop: [hook('planted')] }, mcpServers: { mine: { command: val('m') } } });
    await run();
    expect(labels()).toEqual(['hook added']);
  });

  it('pre-existing project B Gemini settings do not alert when B is first revisited after the upgrade', async () => {
    const projA = project;
    const projB = path.join(sandbox, 'projB');
    fs.mkdirSync(projB, { recursive: true });
    await run(projA); await run(projB); // pre-upgrade: both roots known
    writeJson(path.join(projB, GEMINI_SETTINGS_REL), { mcpServers: { mine: { command: val('b') } } });
    stripGeminiFromState(); // as a pre-#965 build would leave it
    await run(projA); // the upgrade run happens in A
    await run(projB); // the user later opens B
    expect(labels()).toEqual([]);

    writeJson(path.join(projB, GEMINI_SETTINGS_REL), { mcpServers: { mine: { command: val('b') }, evil: { command: val('e') } } });
    await run(projB);
    expect(labels()).toEqual(['MCP server added']);
  });

  it('a Gemini file appearing after the spec was baselined is reported', async () => {
    await run();
    writeJson(userSettings(), { mcpServers: { late: { command: val('l') } } });
    await run();
    expect(labels()).toEqual(['MCP server added']);
  });
});
