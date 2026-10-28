/**
 * #916 scope extension (PR #928): Claude endpoint-redirect keys, Codex
 * sandbox / trust / provider settings, planted instruction files in drop
 * directories, plus the two fixes found in review:
 *  - bug A: an upgrade must not alert on settings the user already had;
 *  - bug B: tests never scan the real /tmp (a default drop directory).
 *
 * Fixtures are built from the watched-key constants the detector module
 * exports (one source of truth) and written at runtime into an os.tmpdir()
 * sandbox with os.homedir spied (an env swap does not reach os.homedir).
 * Values are inert placeholders; nothing here is executed or sent anywhere.
 */
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import fs from 'fs';
import os from 'os';
import path from 'path';
import {
  API_KEY_HELPER_KEY,
  CODEX_PROVIDER_KEY,
  CODEX_PROVIDER_URL_KEY,
  CODEX_SANDBOX_KEYS,
  CODEX_TRUST_KEY,
  DROPZONE_FILES,
  PLANTED_CLAUDE_SETTINGS_FILES,
  PLANTED_CODEX_DIR,
  PLANTED_INSTRUCTION_FILES,
  REDIRECT_ENV_KEYS,
  WATCHED_FILES,
  defaultDropzoneDirs,
  loadAgentConfigState,
  runAgentConfigWatch,
  saveAgentConfigState,
  snapshotContent,
  type AgentConfigLedgerRow,
  type AgentConfigNotification,
  type AgentConfigWatchState,
  type FileSnapshot,
  type WatchedFileSpec,
} from '../audit/agent-config-watch.js';
import { withOwnConfigWrite } from '../audit/agent-config-watch-own-write.js';

const VALUE_MARK = 'fixture-value-7c1e';
const val = (n: number | string): string => `${VALUE_MARK}-${n}`;

let sandbox: string;
let home: string;
let project: string;
let drop: string;
let notes: AgentConfigNotification[];
let rows: AgentConfigLedgerRow[];
let homedirSpy: { mockRestore(): void };

const claudeSettings = () => path.join(home, '.claude', 'settings.json');
const codexConfig = () => path.join(home, '.codex', 'config.toml');
const specById = (id: string): WatchedFileSpec => {
  const s = WATCHED_FILES.find((w) => w.id === id);
  if (!s) throw new Error(`no spec ${id}`);
  return s;
};

const writeFile = (p: string, text: string): string => { fs.mkdirSync(path.dirname(p), { recursive: true }); fs.writeFileSync(p, text); return text; };
const writeJson = (p: string, v: unknown): string => writeFile(p, JSON.stringify(v, null, 2));
const readJson = (p: string) => JSON.parse(fs.readFileSync(p, 'utf-8'));
const tomlStr = (s: string) => JSON.stringify(s);

/** Codex config text from parts; every key comes from the exported constants. */
function codexToml(o: { top?: Record<string, string>; profiles?: Record<string, Record<string, string>>; trust?: Record<string, string>; providers?: Record<string, string>; extra?: Record<string, string> }): string {
  const lines: string[] = [];
  for (const [k, v] of Object.entries({ ...(o.extra ?? {}), ...(o.top ?? {}) })) lines.push(`${k} = ${tomlStr(v)}`);
  for (const [name, kv] of Object.entries(o.profiles ?? {})) {
    lines.push('', `[profiles.${name}]`);
    for (const [k, v] of Object.entries(kv)) lines.push(`${k} = ${tomlStr(v)}`);
  }
  for (const [dir, level] of Object.entries(o.trust ?? {})) lines.push('', `[projects.${tomlStr(dir)}]`, `${CODEX_TRUST_KEY} = ${tomlStr(level)}`);
  for (const [name, url] of Object.entries(o.providers ?? {})) lines.push('', `[model_providers.${name}]`, `${CODEX_PROVIDER_URL_KEY} = ${tomlStr(url)}`);
  return `${lines.join('\n')}\n`;
}

const run = (over: Partial<Parameters<typeof runAgentConfigWatch>[0]> = {}) =>
  runAgentConfigWatch({
    home,
    projectRoots: [project],
    dropzoneDirs: [drop],
    notify: async (n) => { notes.push(n); },
    ledger: (r) => { rows.push(r); return true; },
    ...over,
  });

const labels = () => notes.flatMap((n) => n.changes.map((c) => c.label));
const names = () => notes.flatMap((n) => n.changes.map((c) => c.name));
const changeRows = () => rows.filter((r) => r.outcome === 'change');

/**
 * The stored state a build WITHOUT this extension would have written: Claude
 * settings with plain `env` (redirect keys inside it), Codex with only
 * `mcp_servers` / `hooks`, no drop directories and no section versions.
 */
function writeLegacyState(): void {
  const legacy = (spec: WatchedFileSpec, keep: Array<{ keyPath: string; kind: WatchedFileSpec['sections'][number]['kind'] }>, file: string): FileSnapshot => {
    let raw: string;
    try { raw = fs.readFileSync(file, 'utf-8'); } catch { return {}; }
    return snapshotContent(raw, { ...spec, sections: keep });
  };
  const files: Record<string, FileSnapshot> = {};
  for (const spec of WATCHED_FILES) {
    const file = spec.scope === 'user' ? path.join(home, spec.relPath) : path.join(project, spec.relPath);
    const legacyKeep = spec.id.startsWith('claude-') && spec.id.includes('settings')
      ? [{ keyPath: 'hooks', kind: 'hooks' as const }, { keyPath: 'env', kind: 'env' as const }, { keyPath: 'mcpServers', kind: 'mcpServers' as const }]
      : spec.sections.filter((s) => !s.version || s.version === 1).map(({ keyPath, kind }) => ({ keyPath, kind }));
    files[file] = legacy(spec, legacyKeep, file);
  }
  const state: AgentConfigWatchState = { version: 1, initialised: true, roots: [path.resolve(project)], files };
  saveAgentConfigState(home, state);
}

beforeEach(() => {
  sandbox = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-916-scope-'));
  home = path.join(sandbox, 'home');
  project = path.join(sandbox, 'proj');
  drop = path.join(home, 'Downloads');
  for (const d of [home, project, drop]) fs.mkdirSync(d, { recursive: true });
  homedirSpy = jest.spyOn(os, 'homedir').mockReturnValue(home);
  notes = [];
  rows = [];
  writeJson(claudeSettings(), { hooks: { SessionStart: [{ hooks: [{ type: 'command', command: 'echo baseline' }] }] }, env: { ORDINARY_FLAG: val('env') } });
  writeFile(codexConfig(), codexToml({ extra: { model: val('model') } }));
});

afterEach(() => {
  homedirSpy.mockRestore();
  fs.rmSync(sandbox, { recursive: true, force: true });
});

describe('exported watch lists (single source of truth)', () => {
  it('every redirect env key lands in the endpoint-redirect section, never in env', () => {
    const env = Object.fromEntries(REDIRECT_ENV_KEYS.map((k, i) => [k, val(i)]));
    const snap = snapshotContent(JSON.stringify({ env: { ...env, ORDINARY_FLAG: 'x' }, [API_KEY_HELPER_KEY]: val('helper') }), specById('claude-settings.json'));
    expect(Object.keys(snap.env).sort()).toEqual(['ORDINARY_FLAG']);
    expect(Object.keys(snap['env+apiKeyHelper (redirect)']).sort()).toEqual([...REDIRECT_ENV_KEYS, API_KEY_HELPER_KEY].sort());
  });

  it('the drop-directory specs are built from the exported file names', () => {
    const rel = DROPZONE_FILES.map((s) => s.relPath).sort();
    expect(rel).toEqual([
      ...PLANTED_INSTRUCTION_FILES,
      ...PLANTED_CLAUDE_SETTINGS_FILES.map((f) => path.join('.claude', f)),
      PLANTED_CODEX_DIR,
    ].sort());
  });
});

describe('Claude endpoint-redirect detector', () => {
  it.each(REDIRECT_ENV_KEYS.map((k) => [k]))('adding %s is a high-severity endpoint-redirect change, not an env change', async (key) => {
    await run();
    const s = readJson(claudeSettings());
    s.env[key] = val('new');
    writeJson(claudeSettings(), s);
    const r = await run();
    expect(r.notified).toBe(1);
    expect(notes[0].severity).toBe('high');
    expect(notes[0].changes).toEqual([{ label: 'endpoint-redirect added', name: key }]);
    expect(changeRows().every((x) => x.severity === 'high')).toBe(true);
  });

  it('a changed redirect value alerts as changed', async () => {
    const key = REDIRECT_ENV_KEYS[0];
    const s = readJson(claudeSettings());
    s.env[key] = val('a');
    writeJson(claudeSettings(), s);
    await run();
    s.env[key] = val('b');
    writeJson(claudeSettings(), s);
    await run();
    expect(labels()).toEqual(['endpoint-redirect changed']);
  });

  it('matches redirect keys case-insensitively', async () => {
    await run();
    const key = REDIRECT_ENV_KEYS[REDIRECT_ENV_KEYS.length - 2].toLowerCase();
    const s = readJson(claudeSettings());
    s.env[key] = val('lc');
    writeJson(claudeSettings(), s);
    await run();
    expect(labels()).toEqual(['endpoint-redirect added']);
  });

  it('the API key helper setting is part of the redirect section', async () => {
    await run();
    const s = readJson(claudeSettings());
    s[API_KEY_HELPER_KEY] = val('helper');
    writeJson(claudeSettings(), s);
    await run();
    expect(notes[0].changes).toEqual([{ label: 'endpoint-redirect added', name: API_KEY_HELPER_KEY }]);
    expect(notes[0].severity).toBe('high');
  });

  it('an ordinary env key stays a normal-severity env change', async () => {
    await run();
    const s = readJson(claudeSettings());
    s.env.ANOTHER_FLAG = val('x');
    writeJson(claudeSettings(), s);
    await run();
    expect(labels()).toEqual(['environment variable added']);
    expect(notes[0].severity).toBeUndefined();
  });

  it('removing a redirect key is reported', async () => {
    const s = readJson(claudeSettings());
    s.env[REDIRECT_ENV_KEYS[0]] = val('a');
    writeJson(claudeSettings(), s);
    await run();
    delete s.env[REDIRECT_ENV_KEYS[0]];
    writeJson(claudeSettings(), s);
    await run();
    expect(labels()).toEqual(['endpoint-redirect removed']);
  });

  it('high-severity changes are listed first even past the three shown', async () => {
    await run();
    const s = readJson(claudeSettings());
    for (let i = 0; i < 4; i++) s.env[`PLAIN_${i}`] = val(i);
    s.env[REDIRECT_ENV_KEYS[1]] = val('r');
    writeJson(claudeSettings(), s);
    await run();
    expect(notes[0].changeCount).toBe(5);
    expect(notes[0].changes[0]).toEqual({ label: 'endpoint-redirect added', name: REDIRECT_ENV_KEYS[1] });
  });

  it('covers project-scope settings and never puts a value in the note or ledger', async () => {
    const projSettings = path.join(project, '.claude', 'settings.local.json');
    writeJson(projSettings, { env: {} });
    await run();
    writeJson(projSettings, { env: { [REDIRECT_ENV_KEYS[0]]: val('secret') } });
    await run();
    expect(labels()).toEqual(['endpoint-redirect added']);
    expect(JSON.stringify({ notes, rows })).not.toContain(VALUE_MARK);
  });
});

describe('Codex sandbox / trust / provider detectors', () => {
  it.each(CODEX_SANDBOX_KEYS.map((k) => [k]))('adding top-level %s is a high-severity codex-sandbox change', async (key) => {
    await run();
    writeFile(codexConfig(), codexToml({ extra: { model: val('model') }, top: { [key]: val('loose') } }));
    await run();
    expect(notes[0].changes).toEqual([{ label: 'codex-sandbox added', name: key }]);
    expect(notes[0].severity).toBe('high');
  });

  it('a changed sandbox value alerts as changed', async () => {
    const key = CODEX_SANDBOX_KEYS[1];
    writeFile(codexConfig(), codexToml({ top: { [key]: val('a') } }));
    await run();
    writeFile(codexConfig(), codexToml({ top: { [key]: val('b') } }));
    await run();
    expect(labels()).toEqual(['codex-sandbox changed']);
  });

  it('a per-profile sandbox key is watched and named by profile', async () => {
    await run();
    writeFile(codexConfig(), codexToml({ profiles: { fast: { [CODEX_SANDBOX_KEYS[0]]: val('p') } } }));
    await run();
    expect(notes[0].changes).toContainEqual({ label: 'codex-sandbox added', name: `profiles.fast.${CODEX_SANDBOX_KEYS[0]}` });
  });

  it('a project trust level added for a path is a codex-trust change', async () => {
    await run();
    const target = path.join(sandbox, 'trusted');
    writeFile(codexConfig(), codexToml({ extra: { model: val('model') }, trust: { [target]: val('t') } }));
    await run();
    expect(notes[0].changes).toEqual([{ label: 'codex-trust added', name: target }]);
    expect(notes[0].severity).toBe('high');
  });

  it('a changed trust level alerts as changed', async () => {
    const target = path.join(sandbox, 'trusted');
    writeFile(codexConfig(), codexToml({ trust: { [target]: val('a') } }));
    await run();
    writeFile(codexConfig(), codexToml({ trust: { [target]: val('b') } }));
    await run();
    expect(labels()).toEqual(['codex-trust changed']);
  });

  it('the model provider selector is a codex-provider change', async () => {
    writeFile(codexConfig(), codexToml({ top: { [CODEX_PROVIDER_KEY]: val('a') } }));
    await run();
    writeFile(codexConfig(), codexToml({ top: { [CODEX_PROVIDER_KEY]: val('b') } }));
    await run();
    expect(notes[0].changes).toEqual([{ label: 'codex-provider changed', name: CODEX_PROVIDER_KEY }]);
    expect(notes[0].severity).toBe('high');
  });

  it('a provider endpoint added is a codex-provider change', async () => {
    await run();
    writeFile(codexConfig(), codexToml({ extra: { model: val('model') }, providers: { relay: val('url') } }));
    await run();
    expect(notes[0].changes).toEqual([{ label: 'codex-provider added', name: `model_providers.relay.${CODEX_PROVIDER_URL_KEY}` }]);
  });

  it('an unwatched Codex key changing does not alert', async () => {
    await run();
    writeFile(codexConfig(), codexToml({ extra: { model: val('other-model') } }));
    const r = await run();
    expect(r.notified).toBe(0);
    expect(notes).toHaveLength(0);
  });
});

describe('planted instruction files in drop directories', () => {
  it.each(PLANTED_INSTRUCTION_FILES.map((f) => [f]))('%s appearing in a known drop directory is high severity', async (name) => {
    await run();
    writeFile(path.join(drop, name), `${val('instructions')}\n`);
    await run();
    expect(notes[0].changes).toEqual([{ label: 'planted-instructions added', name }]);
    expect(notes[0].severity).toBe('high');
    expect(JSON.stringify({ notes, rows })).not.toContain(VALUE_MARK);
  });

  it('an edited planted file alerts; its removal is silent', async () => {
    const f = path.join(drop, PLANTED_INSTRUCTION_FILES[0]);
    writeFile(f, val('a'));
    await run();
    writeFile(f, val('b'));
    await run();
    expect(labels()).toEqual(['planted-instructions changed']);
    fs.rmSync(f);
    const r = await run();
    expect(r.notified).toBe(0);
    expect(notes).toHaveLength(1);
  });

  it.each(PLANTED_CLAUDE_SETTINGS_FILES.map((f) => [f]))('a planted .claude/%s is planted-agent-config', async (name) => {
    await run();
    writeJson(path.join(drop, '.claude', name), { env: {} });
    await run();
    expect(labels()).toEqual(['planted-agent-config added']);
    expect(notes[0].severity).toBe('high');
  });

  it('a new entry in a planted .codex directory is planted-agent-config', async () => {
    await run();
    writeFile(path.join(drop, PLANTED_CODEX_DIR, 'config.toml'), codexToml({}));
    await run();
    expect(notes[0].changes).toEqual([{ label: 'planted-agent-config added', name: 'config.toml' }]);
  });

  it('the home directory is a drop directory for instruction files only', async () => {
    await run({ dropzoneDirs: [home] });
    writeFile(path.join(home, PLANTED_INSTRUCTION_FILES[0]), val('x'));
    const s = readJson(claudeSettings());
    s.hooks.Stop = [{ hooks: [{ type: 'command', command: 'echo x' }] }];
    writeJson(claudeSettings(), s);
    await run({ dropzoneDirs: [home] });
    expect(labels().sort()).toEqual(['hook added', 'planted-instructions added']);
  });

  it('a drop directory seen for the first time is baselined silently', async () => {
    await run();
    const other = path.join(home, 'Desktop');
    writeFile(path.join(other, PLANTED_INSTRUCTION_FILES[0]), val('x'));
    const r = await run({ dropzoneDirs: [drop, other] });
    expect(r.notified).toBe(0);
    writeFile(path.join(other, PLANTED_INSTRUCTION_FILES[0]), val('y'));
    await run({ dropzoneDirs: [drop, other] });
    expect(labels()).toEqual(['planted-instructions changed']);
  });
});

describe('bug A: upgrading from a pre-extension baseline is silent', () => {
  function seedExistingUserSettings(): void {
    const s = readJson(claudeSettings());
    for (const [i, k] of REDIRECT_ENV_KEYS.entries()) s.env[k] = val(i);
    s[API_KEY_HELPER_KEY] = val('helper');
    writeJson(claudeSettings(), s);
    writeFile(codexConfig(), codexToml({
      top: { [CODEX_SANDBOX_KEYS[0]]: val('a'), [CODEX_SANDBOX_KEYS[1]]: val('b'), [CODEX_PROVIDER_KEY]: val('p') },
      profiles: { fast: { [CODEX_SANDBOX_KEYS[1]]: val('pf') } },
      trust: { [project]: val('t') },
      providers: { relay: val('u') },
    }));
    for (const f of PLANTED_INSTRUCTION_FILES) writeFile(path.join(drop, f), val(f));
    writeFile(path.join(home, PLANTED_INSTRUCTION_FILES[0]), val('home'));
  }

  it('existing redirect env, Codex settings and drop-directory files raise no alert on the first run after upgrade', async () => {
    seedExistingUserSettings();
    writeLegacyState();
    const r = await run({ dropzoneDirs: [drop, home] });
    expect(r.baselined).toBe(false);
    expect(r.notified).toBe(0);
    expect(notes).toEqual([]);
    expect(changeRows()).toEqual([]);
    expect((await run({ dropzoneDirs: [drop, home] })).notified).toBe(0);
  });

  it('an existing redirect key is not reported as env-removed plus endpoint-redirect-added', async () => {
    const s = readJson(claudeSettings());
    s.env[REDIRECT_ENV_KEYS[0]] = val('kept');
    writeJson(claudeSettings(), s);
    writeLegacyState();
    await run();
    expect(labels()).not.toContain('environment variable removed');
    expect(labels()).not.toContain('endpoint-redirect added');
    expect(notes).toHaveLength(0);
  });

  it('after the upgrade run, the new detectors are armed', async () => {
    seedExistingUserSettings();
    writeLegacyState();
    await run();
    const s = readJson(claudeSettings());
    s.env[REDIRECT_ENV_KEYS[0]] = val('moved');
    writeJson(claudeSettings(), s);
    writeFile(codexConfig(), codexToml({ top: { [CODEX_SANDBOX_KEYS[0]]: val('changed') } }));
    await run();
    expect(labels()).toContain('endpoint-redirect changed');
    expect(labels()).toContain('codex-sandbox changed');
  });

  it('a real change to an old section is still reported on the upgrade run', async () => {
    seedExistingUserSettings();
    writeLegacyState();
    const s = readJson(claudeSettings());
    s.hooks.Stop = [{ hooks: [{ type: 'command', command: 'echo x' }] }];
    s.env.ORDINARY_FLAG = val('edited');
    writeJson(claudeSettings(), s);
    await run();
    expect(labels().sort()).toEqual(['environment variable changed', 'hook added']);
    expect(names()).not.toContain(REDIRECT_ENV_KEYS[0]);
  });

  it('the env split migrates exactly: a redirect value edited before the upgrade run still alerts', async () => {
    const s = readJson(claudeSettings());
    s.env[REDIRECT_ENV_KEYS[0]] = val('old');
    writeJson(claudeSettings(), s);
    writeLegacyState();
    s.env[REDIRECT_ENV_KEYS[0]] = val('new');
    s.env[REDIRECT_ENV_KEYS[1]] = val('added');
    writeJson(claudeSettings(), s);
    await run();
    expect(notes).toHaveLength(1);
    expect(notes[0].changes).toEqual(expect.arrayContaining([
      { label: 'endpoint-redirect changed', name: REDIRECT_ENV_KEYS[0] },
      { label: 'endpoint-redirect added', name: REDIRECT_ENV_KEYS[1] },
    ]));
    expect(notes[0].changeCount).toBe(2);
  });

  it('records section versions, and a file absent from the stored state is not migrated', async () => {
    writeLegacyState();
    await run();
    const st = loadAgentConfigState(home);
    expect(st.sectionVersions?.[claudeSettings()]).toMatchObject({ env: 2, 'env+apiKeyHelper (redirect)': 2, hooks: 1 });
    // A watched file the old baseline never listed, created with a redirect key: reported.
    const local = path.join(home, '.claude', 'settings.local.json');
    const legacy = loadAgentConfigState(home);
    delete legacy.files[local];
    if (legacy.sectionVersions) delete legacy.sectionVersions[local];
    saveAgentConfigState(home, legacy);
    writeJson(local, { env: { [REDIRECT_ENV_KEYS[0]]: val('x') } });
    await run();
    expect(labels()).toEqual(['endpoint-redirect added']);
  });

  it('an unparseable legacy file records no versions, so it still migrates once it parses again', async () => {
    const s = readJson(claudeSettings());
    s.env[REDIRECT_ENV_KEYS[0]] = val('kept');
    writeJson(claudeSettings(), s);
    writeLegacyState();
    const good = fs.readFileSync(claudeSettings(), 'utf-8');
    writeFile(claudeSettings(), '{ not json');
    // Undelivered: the legacy baseline is kept for this file.
    await run({ notify: async () => { throw Object.assign(new Error('down'), { code: 'ECONNREFUSED' }); } });
    expect(loadAgentConfigState(home).sectionVersions?.[claudeSettings()]).toBeUndefined();
    writeFile(claudeSettings(), good);
    const r = await run();
    expect(r.notified).toBe(0);
    expect(notes).toEqual([]);
  });

  it('an own write records current section versions', async () => {
    await run();
    const st = loadAgentConfigState(home);
    delete st.sectionVersions;
    saveAgentConfigState(home, st);
    withOwnConfigWrite(claudeSettings(), () => {
      const t = readJson(claudeSettings());
      t.hooks.PreToolUse = [{ hooks: [{ type: 'command', command: 'shieldcortex hook pre-tool' }] }];
      return writeJson(claudeSettings(), t);
    });
    expect(loadAgentConfigState(home).sectionVersions?.[claudeSettings()]).toMatchObject({ env: 2 });
  });
});

describe('bug B: tests never scan the real /tmp', () => {
  it('the production default includes the shared temp directory, so tests must pass their own', () => {
    if (process.platform === 'win32') return;
    expect(defaultDropzoneDirs(home)).toContain('/tmp');
  });

  it('explicit drop directories replace the defaults entirely', async () => {
    const seen: string[] = [];
    await run({ dropzoneDirs: [], snapshot: (file) => { seen.push(file); return {}; } });
    expect(seen.length).toBeGreaterThan(0);
    const inside = (f: string) => [home, project].some((root) => !path.relative(root, f).startsWith('..'));
    expect(seen.filter((f) => !inside(f))).toEqual([]);
  });

  it('every agent-config-watch suite passes explicit drop directories to the check', () => {
    const dir = path.dirname(new URL(import.meta.url).pathname);
    const suites = fs.readdirSync(dir).filter((f) => /^agent-config-watch.*\.test\.ts$/.test(f));
    expect(suites.length).toBeGreaterThanOrEqual(4);
    for (const f of suites) {
      const src = fs.readFileSync(path.join(dir, f), 'utf-8');
      const calls = src.split('runAgentConfigWatch({').length - 1;
      const explicit = (src.match(/runAgentConfigWatch\(\{[^]*?dropzoneDirs:/g) ?? []).length;
      expect({ f, explicit }).toEqual({ f, explicit: calls });
    }
  });
});
