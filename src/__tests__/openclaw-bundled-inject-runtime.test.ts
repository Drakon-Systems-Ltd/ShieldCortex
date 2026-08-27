import fs from 'fs';
import os from 'os';
import path from 'path';
import { pathToFileURL } from 'url';
import Database from 'better-sqlite3';
import { afterEach, describe, expect, it, jest } from '@jest/globals';
import ts from 'typescript';

const repoRoot = path.resolve(process.cwd());

describe('bundled OpenClaw hook — start-pack runtime', () => {
  const originalEnv = { ...process.env };
  let tmpHome: string | null = null;
  let tmpSourceDir: string | null = null;

  afterEach(() => {
    process.env = { ...originalEnv };
    jest.resetModules();
    if (tmpHome) fs.rmSync(tmpHome, { recursive: true, force: true });
    if (tmpSourceDir) fs.rmSync(tmpSourceDir, { recursive: true, force: true });
    tmpHome = null;
    tmpSourceDir = null;
  });

  it('emits only for a legal start bus from a skills-only source sandbox', async () => {
    tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-bundled-inject-'));
    process.env.HOME = tmpHome;
    process.env.USERPROFILE = tmpHome;
    process.env.SHIELDCORTEX_SKIP_SELF_HEAL = '1';

    const scDir = path.join(tmpHome, '.shieldcortex');
    process.env.SHIELDCORTEX_CONFIG_DIR = scDir;
    const fakePackage = path.join(tmpHome, 'shieldcortex-package');
    fs.mkdirSync(path.join(fakePackage, 'dist'), { recursive: true });
    fs.mkdirSync(path.join(fakePackage, 'scripts', 'lib'), { recursive: true });
    fs.mkdirSync(scDir, { recursive: true });
    fs.writeFileSync(path.join(fakePackage, 'dist', 'index.js'), '#!/usr/bin/env node\n');
    fs.copyFileSync(
      path.join(repoRoot, 'scripts', 'lib', 'inject-pack.mjs'),
      path.join(fakePackage, 'scripts', 'lib', 'inject-pack.mjs'),
    );

    const db = new Database(path.join(scDir, 'memories.db'));
    db.exec(`
      CREATE TABLE memories (
        id INTEGER PRIMARY KEY,
        title TEXT,
        content TEXT,
        content_form TEXT,
        status TEXT,
        sensitivity_level TEXT,
        trust_score REAL,
        defence_verdict TEXT,
        source_attested INTEGER,
        pinned INTEGER,
        quarantined INTEGER,
        in_quarantine INTEGER,
        host_id TEXT,
        agent_id TEXT,
        project TEXT,
        transferable INTEGER,
        salience REAL,
        source TEXT,
        created_at TEXT
      );
      INSERT INTO memories (
        title, content, content_form, status, sensitivity_level, trust_score,
        defence_verdict, source_attested, pinned, quarantined, in_quarantine,
        host_id, agent_id, project, transferable, salience, source, created_at
      ) VALUES (
        'Runtime fact', 'The bundled handler emits the defended start pack.', 'fact',
        'active', 'INTERNAL', 0.9, 'allow', 1, 0, 0, 0,
        'host-a', 'agent-a', NULL, 0, 0.8, 'test', datetime('now')
      );
    `);
    db.close();

    const writeConfig = (inject: Record<string, unknown>): void => {
      fs.writeFileSync(path.join(scDir, 'config.json'), JSON.stringify({
        binaryPath: path.join(fakePackage, 'dist', 'index.js'),
        memory: { inject },
      }, null, 2));
    };
    writeConfig({ mode: 'start', nativeContract: 'sc_only', hostId: 'host-a', agentId: 'agent-a' });

    // OpenClaw jiti-loads handler.ts. Transpile that exact bundled source into
    // this isolated skills-only directory, preserving its runtime.mjs sibling,
    // then execute the resulting module rather than a test double.
    // Keep the transient module under the repo so its bare better-sqlite3
    // import resolves exactly as the packaged hook's does.
    tmpSourceDir = fs.mkdtempSync(path.join(repoRoot, '.jest-bundled-hook-'));
    const skillsDir = tmpSourceDir;
    const bundledDir = path.join(repoRoot, 'skills', 'shieldcortex', 'bundled', 'cortex-memory-hook');
    const transpiled = ts.transpileModule(
      fs.readFileSync(path.join(bundledDir, 'handler.ts'), 'utf-8'),
      { compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 } },
    ).outputText;
    fs.writeFileSync(path.join(skillsDir, 'handler.mjs'), transpiled);
    fs.copyFileSync(path.join(bundledDir, 'runtime.mjs'), path.join(skillsDir, 'runtime.mjs'));

    jest.resetModules();
    const handlerUrl = pathToFileURL(path.join(skillsDir, 'handler.mjs')).href;
    const { default: handler } = await import(handlerUrl);
    const run = async (sessionKey: string): Promise<Array<Record<string, unknown>>> => {
      const bootstrapFiles: Array<Record<string, unknown>> = [];
      await handler({
        type: 'agent',
        action: 'bootstrap',
        sessionKey,
        context: { workspaceDir: tmpHome, bootstrapFiles },
      });
      return bootstrapFiles.filter((f) => f.name === 'SHIELDCORTEX_INJECT_PACK.md');
    };

    const start = await run('start');
    expect(start).toHaveLength(1);
    expect(start[0].content).toMatch(/ShieldCortex memory pack/);
    expect(start[0].content).toMatch(/bundled handler emits the defended start pack/i);

    writeConfig({ mode: 'both', nativeContract: 'sc_only', hostId: 'host-a', agentId: 'agent-a' });
    expect(await run('both')).toHaveLength(1);

    for (const [label, inject] of [
      ['off', { mode: 'off', nativeContract: 'sc_only', hostId: 'host-a', agentId: 'agent-a' }],
      ['turn', { mode: 'turn', nativeContract: 'sc_only', hostId: 'host-a', agentId: 'agent-a' }],
      ['no-contract', { mode: 'start', hostId: 'host-a', agentId: 'agent-a' }],
    ] as const) {
      writeConfig(inject);
      expect(await run(label)).toHaveLength(0);
    }
  });
});
