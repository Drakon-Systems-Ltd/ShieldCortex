import { spawnSync } from 'child_process';
import crypto from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { collectPostureRecords, postureSelfReportDir } from '../collect.js';
import {
  DEFAULT_MAX_AGE_MS,
  SELF_REPORT_SCHEMA,
  SELF_REPORT_VERSION,
  parseSelfReport,
  summarisePosture,
} from '../posture-record.js';
import { buildPolicyEvidence } from '../../cli/policy-evidence.js';
import { checkRuntimePosture } from '../../cli/doctor.js';

/**
 * #613 — the filesystem collector against a fake home.
 *
 * Every test builds its own home and config dir under a temp root. Nothing
 * here touches the real home, and no `openclaw` / `hermes` binary is ever
 * consulted: the OpenClaw binary probe is injected.
 */

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(__dirname, '..', '..', '..');
const NOW = Date.parse('2026-09-29T12:00:00.000Z');
const iso = (ms: number) => new Date(ms).toISOString();

let root: string;
let home: string;
let configDir: string;

beforeEach(() => {
  root = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-posture-613-'));
  home = path.join(root, 'home');
  configDir = path.join(home, '.shieldcortex');
  fs.mkdirSync(configDir, { recursive: true });
  fs.writeFileSync(path.join(configDir, 'config.json'), JSON.stringify({ actionGuard: { enabled: true, enforce: true } }));
});

afterEach(() => {
  fs.rmSync(root, { recursive: true, force: true });
});

const noOpenClawBinary = { openclawBinaryPresent: () => false };

function collect(over: { nowMs?: number; maxAgeMs?: number } = {}) {
  return collectPostureRecords({ home, configDir, nowMs: over.nowMs ?? NOW, maxAgeMs: over.maxAgeMs, hostDeps: noOpenClawBinary });
}

function write(rel: string, content: string): void {
  const full = path.join(home, rel);
  fs.mkdirSync(path.dirname(full), { recursive: true });
  fs.writeFileSync(full, content);
}

function hermesInstalled(): void {
  write('.hermes/config.yaml', 'memory:\n  memory_enabled: false\n');
  write('.hermes/plugins/shieldcortex/plugin.yaml', 'name: shieldcortex\n');
}

function selfReport(runtime: string, profile: string, over: Record<string, unknown> = {}): void {
  const body = {
    schema: SELF_REPORT_SCHEMA,
    version: SELF_REPORT_VERSION,
    runtime,
    profile,
    plane: 'tool-gate',
    loaded: true,
    configured_posture: 'enforce',
    scanner: 'available',
    policy_hash: `sha256:${'c'.repeat(64)}`,
    runtime_version: null,
    plugin_id: 'shieldcortex',
    plugin_version: '0.1.0',
    plugin_hash: null,
    instance_id: 'pid:77',
    written_at: iso(NOW - 30_000),
    last_denial_at: null,
    degraded_intervals: [],
    ...over,
  };
  const dir = postureSelfReportDir(configDir);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, `${runtime}--${profile}.json`), JSON.stringify(body));
}

/** Every path under `dir` with its mtime and content hash (dirs: mtime only). */
function snapshot(dir: string): Record<string, string> {
  const out: Record<string, string> = {};
  const walk = (p: string) => {
    const st = fs.lstatSync(p);
    if (st.isDirectory()) {
      out[p] = `dir:${st.mtimeMs}:${fs.readdirSync(p).sort().join(',')}`;
      for (const e of fs.readdirSync(p)) walk(path.join(p, e));
    } else if (st.isSymbolicLink()) {
      out[p] = `link:${fs.readlinkSync(p)}`;
    } else {
      out[p] = `file:${st.mtimeMs}:${st.mode}:${crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex')}`;
    }
  };
  walk(dir);
  return out;
}

describe('#613 acceptance: Hermes directory present, plugin not loaded', () => {
  it('installed yes, runtime_loaded is not yes, summary not green', () => {
    hermesInstalled();
    const recs = collect();
    const hermes = recs.filter((r) => r.runtime === 'hermes');
    expect(hermes).toHaveLength(1);
    expect(hermes[0].installed).toBe('yes');
    expect(hermes[0].runtime_loaded).not.toBe('yes');
    expect(hermes[0].runtime_loaded).toBe('unobserved');
    expect(summarisePosture(recs).green).toBe(false);
  });

  it('Hermes home with no SC plugin: installed no, still not green', () => {
    write('.hermes/config.yaml', 'model: x\n');
    const hermes = collect().filter((r) => r.runtime === 'hermes');
    expect(hermes).toHaveLength(1);
    expect(hermes[0].installed).toBe('no');
    expect(hermes[0].runtime_loaded).toBe('unobserved');
    expect(summarisePosture(hermes).green).toBe(false);
  });

  it('a fresh Hermes self-report makes it loaded; each reporting profile is its own record', () => {
    hermesInstalled();
    selfReport('hermes', 'default');
    selfReport('hermes', 'work', { configured_posture: 'advisory' });
    const hermes = collect().filter((r) => r.runtime === 'hermes');
    expect(hermes.map((r) => r.profile).sort()).toEqual(['default', 'work']);
    const byProfile = Object.fromEntries(hermes.map((r) => [r.profile, r]));
    expect(byProfile.default.runtime_loaded).toBe('yes');
    expect(byProfile.default.configured_posture).toBe('enforce');
    expect(byProfile.work.configured_posture).toBe('advisory');
    expect(summarisePosture(hermes).green).toBe(false);
  });
});

describe('#613 acceptance: stale self-report → unknown', () => {
  it('a report older than max_age is unknown on every process-side field', () => {
    hermesInstalled();
    selfReport('hermes', 'default', { written_at: iso(NOW - DEFAULT_MAX_AGE_MS - 60_000) });
    const [rec] = collect().filter((r) => r.runtime === 'hermes');
    expect(rec.runtime_loaded).toBe('unknown');
    expect(rec.configured_posture).toBe('unknown');
    expect(rec.observed_denial).toBe('unknown');
    expect(rec.stale).toBe(true);
  });

  it('max_age is honoured when supplied', () => {
    hermesInstalled();
    selfReport('hermes', 'default', { written_at: iso(NOW - 10 * 60_000) });
    const [rec] = collectPostureRecords({ home, configDir, nowMs: NOW, maxAgeMs: 5 * 60_000, hostDeps: noOpenClawBinary })
      .filter((r) => r.runtime === 'hermes');
    expect(rec.runtime_loaded).toBe('unknown');
    expect(rec.probe.max_age_ms).toBe(5 * 60_000);
  });
});

describe('#613 self-report file is untrusted', () => {
  it('unknown version → unknown, not guessed', () => {
    hermesInstalled();
    selfReport('hermes', 'default', { version: 99 });
    const [rec] = collect().filter((r) => r.runtime === 'hermes');
    expect(rec.runtime_loaded).toBe('unknown');
  });

  it('a report whose content names another runtime or profile than its file is rejected', () => {
    hermesInstalled();
    selfReport('hermes', 'default', { runtime: 'claude_code' });
    const [rec] = collect().filter((r) => r.runtime === 'hermes');
    expect(rec.runtime_loaded).toBe('unknown');
  });

  it('oversize report → unknown', () => {
    hermesInstalled();
    const dir = postureSelfReportDir(configDir);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'hermes--default.json'), ' '.repeat(64 * 1024));
    const [rec] = collect().filter((r) => r.runtime === 'hermes');
    expect(rec.runtime_loaded).toBe('unknown');
  });

  it('a symlinked report is not followed', () => {
    hermesInstalled();
    const elsewhere = path.join(root, 'elsewhere.json');
    fs.writeFileSync(elsewhere, '{}');
    const dir = postureSelfReportDir(configDir);
    fs.mkdirSync(dir, { recursive: true });
    fs.symlinkSync(elsewhere, path.join(dir, 'hermes--default.json'));
    const [rec] = collect().filter((r) => r.runtime === 'hermes');
    expect(rec.runtime_loaded).toBe('unknown');
  });

  it('files with names outside the closed runtime/profile grammar are ignored', () => {
    hermesInstalled();
    const dir = postureSelfReportDir(configDir);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'evil--../x.json'.replace('/', '_')), '{}');
    fs.writeFileSync(path.join(dir, 'notaruntime--default.json'), '{}');
    const recs = collect();
    expect(recs.every((r) => ['claude_code', 'openclaw', 'hermes', 'codex', 'copilot'].includes(r.runtime))).toBe(true);
    expect(recs.filter((r) => r.runtime === 'hermes').map((r) => r.profile)).toEqual(['default']);
  });
});

describe('#613 acceptance: memory-only runtime', () => {
  it('Codex present → capability memory-only on the memory plane, and no tool-gate record for it', () => {
    write('.codex/config.toml', '[mcp_servers.shieldcortex-memory]\ncommand = "x"\n');
    const recs = collect();
    const codex = recs.filter((r) => r.runtime === 'codex');
    expect(codex).toHaveLength(1);
    expect(codex[0].capability).toBe('memory-only');
    expect(codex[0].plane).toBe('memory');
    expect(recs.some((r) => r.runtime === 'codex' && r.plane === 'tool-gate')).toBe(false);
    expect(recs.some((r) => r.capability === 'memory-only' && r.plane === 'tool-gate')).toBe(false);
  });

  it('runtimes with no trace on the box produce no record at all', () => {
    expect(collect()).toEqual([]);
  });
});

describe('#613 acceptance: the collector changes no config file and no consent state', () => {
  it('collect, policy-evidence and the doctor rows leave every file under home byte- and mtime-identical', async () => {
    hermesInstalled();
    write('.claude/settings.json', JSON.stringify({ hooks: {} }));
    write('.codex/config.toml', '');
    write('.openclaw/openclaw.json', JSON.stringify({ plugins: { entries: {} } }));
    fs.writeFileSync(path.join(configDir, '.config-sig'), 'sig');
    fs.mkdirSync(path.join(configDir, 'consent'), { recursive: true });
    fs.writeFileSync(path.join(configDir, 'consent', 'live-canary.json'), '{"granted":false}');
    selfReport('hermes', 'default');
    const before = snapshot(home);

    collect();
    buildPolicyEvidence({ home, configDir, nowMs: NOW, hostDeps: noOpenClawBinary });
    await checkRuntimePosture({ home, configDir, nowMs: NOW, hostDeps: noOpenClawBinary });

    expect(snapshot(home)).toEqual(before);
  });

  it('does not create the posture directory when it is missing', () => {
    hermesInstalled();
    collect();
    expect(fs.existsSync(postureSelfReportDir(configDir))).toBe(false);
  });
});

describe('#613 cross-runtime schema contract: the Hermes writer output passes the CLI validator', () => {
  const python = spawnSync('python3', ['--version']).status === 0;
  (python ? it : it.skip)('posture.py writes a report parseSelfReport accepts', () => {
    const pkg = path.join(REPO, 'plugins', 'hermes');
    const script = [
      'import sys',
      `sys.path.insert(0, ${JSON.stringify(pkg)})`,
      'from shieldcortex import posture',
      `ok = posture.write_self_report(${JSON.stringify(configDir)}, profile="work", configured_posture="advisory", scanner="available", policy={"enforce": False})`,
      'print("ok" if ok else "fail")',
    ].join('\n');
    const r = spawnSync('python3', ['-c', script], {
      env: { PATH: '/usr/bin:/bin', HOME: home },
      encoding: 'utf8',
    });
    expect(r.stdout.trim()).toBe('ok');
    const file = path.join(postureSelfReportDir(configDir), 'hermes--work.json');
    const text = fs.readFileSync(file, 'utf8');
    const parsed = parseSelfReport(text, Buffer.byteLength(text));
    expect(parsed.kind).toBe('valid');
    if (parsed.kind === 'valid') {
      expect(parsed.report.runtime).toBe('hermes');
      expect(parsed.report.configured_posture).toBe('advisory');
      expect(parsed.report.policy_hash).toMatch(/^sha256:[0-9a-f]{64}$/);
    }
  });
});
