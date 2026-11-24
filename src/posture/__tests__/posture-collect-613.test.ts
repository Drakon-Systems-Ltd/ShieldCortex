import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import { collectPostureRecords, linuxPidNamespace, linuxProcessStart, pidNsSidecarPath, postureSelfReportDir, readSelfReportFile } from '../collect.js';
import { legacyGateRejects, legacyListInstances } from './legacy-self-report-gate.js';
import { DEFAULT_MAX_AGE_MS, MAX_INSTANCES_PER_PROFILE, SELF_REPORT_MAX_BYTES, STALE_NOT_SEEN_MS, parseSelfReport, summarisePosture } from '../posture-record.js';
import {
  INSTANCE,
  LIVE,
  NOW,
  PID_NS,
  hermesHome,
  hermesPluginArtefacts,
  iso,
  otherInstance,
  processTable,
  reportBody,
  writeRaw,
  writeReport,
} from './self-report-fixture.js';

/**
 * #613 — the filesystem collector against a fake home.
 *
 * Every test builds its own home and config dir under a temp root. Nothing
 * here touches the real home, and no `openclaw` / `hermes` binary is ever
 * consulted: the OpenClaw binary probe is injected. The Tars r2.1 §1 firing
 * cases live in posture-firing-613.test.ts.
 */

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(__dirname, '..', '..', '..');

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
  return collectPostureRecords({ home, configDir, nowMs: over.nowMs ?? NOW, maxAgeMs: over.maxAgeMs, hostDeps: noOpenClawBinary, deps: LIVE });
}

function hermesInstalled(): void {
  hermesHome(home);
  hermesPluginArtefacts(home);
}

describe('#613 acceptance: Hermes plugin artefacts present, plugin not loaded', () => {
  it('installed yes, runtime_loaded is not yes, summary not green', () => {
    hermesInstalled();
    const recs = collect();
    const hermes = recs.filter((r) => r.runtime === 'hermes');
    expect(hermes).toHaveLength(1);
    expect(hermes[0].installed.value).toBe('yes');
    expect(hermes[0].runtime_loaded.value).not.toBe('yes');
    expect(hermes[0].runtime_loaded.value).toBe('unobserved');
    expect(summarisePosture(recs).green).toBe(false);
  });

  it('Hermes home with no SC plugin: installed no, still not green', () => {
    hermesHome(home);
    const hermes = collect().filter((r) => r.runtime === 'hermes');
    expect(hermes).toHaveLength(1);
    expect(hermes[0].installed.value).toBe('no');
    expect(hermes[0].runtime_loaded.value).toBe('unobserved');
    expect(summarisePosture(hermes).green).toBe(false);
  });

  it('a fresh Hermes self-report makes it loaded; each reporting profile is its own record', () => {
    hermesInstalled();
    writeReport(configDir, reportBody());
    writeReport(configDir, reportBody({ profile: 'work', configured_posture: 'advisory' }));
    const hermes = collect().filter((r) => r.runtime === 'hermes');
    expect(hermes.map((r) => r.profile).sort()).toEqual(['default', 'work']);
    const byProfile = Object.fromEntries(hermes.map((r) => [r.profile, r]));
    expect(byProfile.default.runtime_loaded.value).toBe('yes');
    expect(byProfile.default.configured_posture.value).toBe('enforce');
    expect(byProfile.work.configured_posture.value).toBe('advisory');
    expect(summarisePosture(hermes).green).toBe(false);
  });

  it('a profile-scoped plugin install counts for that profile', () => {
    hermesHome(home);
    hermesPluginArtefacts(home, path.join(home, '.hermes', 'profiles', 'ops'));
    writeReport(configDir, reportBody({ profile: 'ops' }));
    const [rec] = collect().filter((r) => r.runtime === 'hermes');
    expect(rec.profile).toBe('ops');
    expect(rec.installed.value).toBe('yes');
  });
});

describe('#613 acceptance: stale self-report → unknown', () => {
  it('a heartbeat older than max_age is unknown on every process-side field', () => {
    hermesInstalled();
    writeReport(configDir, reportBody({ heartbeat_at: iso(NOW - DEFAULT_MAX_AGE_MS - 60_000) }));
    const [rec] = collect().filter((r) => r.runtime === 'hermes');
    expect(rec.runtime_loaded.value).toBe('unknown');
    expect(rec.configured_posture.value).toBe('unknown');
    expect(rec.observed_denial.value).toBe('unknown');
    expect(rec.membership).toBe('unobserved');
  });

  it('max_age is honoured when supplied', () => {
    hermesInstalled();
    writeReport(configDir, reportBody({ heartbeat_at: iso(NOW - 10 * 60_000) }));
    const [rec] = collect({ maxAgeMs: 5 * 60_000 }).filter((r) => r.runtime === 'hermes');
    expect(rec.runtime_loaded.value).toBe('unknown');
    expect(rec.runtime_loaded.max_age_ms).toBe(5 * 60_000);
  });
});

describe('#613 self-report file is untrusted', () => {
  it('unknown version → unknown, not guessed', () => {
    hermesInstalled();
    writeReport(configDir, reportBody({ version: 99 }));
    const [rec] = collect().filter((r) => r.runtime === 'hermes');
    expect(rec.runtime_loaded.value).toBe('unknown');
  });

  it('a report whose content names another runtime than its path is rejected', () => {
    hermesInstalled();
    const body = reportBody({ runtime: 'claude_code' });
    writeRaw(configDir, 'hermes', 'default', String((body.instance as { key: string }).key), JSON.stringify(body));
    const [rec] = collect().filter((r) => r.runtime === 'hermes');
    expect(rec.runtime_loaded.value).toBe('unknown');
    expect(rec.notes.join(' ')).toMatch(/different runtime/);
  });

  it('files with names outside the closed runtime/profile/instance grammar are ignored', () => {
    hermesInstalled();
    const dir = postureSelfReportDir(configDir);
    fs.mkdirSync(path.join(dir, 'hermes', 'default'), { recursive: true, mode: 0o700 });
    fs.mkdirSync(path.join(dir, 'notaruntime', 'default'), { recursive: true, mode: 0o700 });
    fs.mkdirSync(path.join(dir, 'hermes', 'Bad Profile'), { recursive: true, mode: 0o700 });
    fs.writeFileSync(path.join(dir, 'notaruntime', 'default', 'p1-s1.json'), '{}', { mode: 0o600 });
    fs.writeFileSync(path.join(dir, 'hermes', 'Bad Profile', 'p1-s1.json'), '{}', { mode: 0o600 });
    fs.writeFileSync(path.join(dir, 'hermes', 'default', 'x.tmp-1-ab'), '{}', { mode: 0o600 });
    fs.writeFileSync(path.join(dir, 'hermes', 'default', 'UPPER.json'), '{}', { mode: 0o600 });
    const recs = collect();
    expect(recs.every((r) => ['claude_code', 'openclaw', 'hermes', 'codex', 'copilot'].includes(r.runtime))).toBe(true);
    const hermes = recs.filter((r) => r.runtime === 'hermes');
    expect(hermes.map((r) => r.profile)).toEqual(['default']);
    expect(hermes[0].key.instance).toBeNull();
  });

  it('reads at most the cap of instance files per profile, newest first, and says so', () => {
    hermesInstalled();
    const total = MAX_INSTANCES_PER_PROFILE + 3;
    for (let i = 0; i < total; i++) {
      const f = writeReport(configDir, reportBody({ instance: otherInstance(1000 + i, String(i + 1)) }));
      const t = new Date(NOW - (total - i) * 1000);
      fs.utimesSync(f, t, t);
    }
    const all = collect().filter((r) => r.runtime === 'hermes');
    // #970: every one of these pids has exited, so the present Hermes also keeps its one no-current-report record.
    expect(all.filter((r) => r.key.instance === null).map((r) => r.stale)).toEqual([false]);
    const hermes = all.filter((r) => r.key.instance !== null);
    expect(hermes).toHaveLength(MAX_INSTANCES_PER_PROFILE);
    expect(hermes.some((r) => r.key.instance === `p${1000 + total - 1}-s${total}`)).toBe(true);
    expect(hermes.some((r) => r.key.instance === 'p1000-s1')).toBe(false);
    expect(hermes[0].notes.join(' ')).toMatch(/3 further instance report/);
  });
});

describe('#613 acceptance: memory-only runtime', () => {
  it('Codex present → capability memory-only on the memory plane, and no tool-gate record for it', () => {
    fs.mkdirSync(path.join(home, '.codex'), { recursive: true });
    fs.writeFileSync(path.join(home, '.codex', 'config.toml'), '[mcp_servers.shieldcortex-memory]\ncommand = "x"\n');
    const recs = collect();
    const codex = recs.filter((r) => r.runtime === 'codex');
    expect(codex).toHaveLength(1);
    expect(codex[0].capability.value).toBe('memory-only');
    expect(codex[0].plane).toBe('memory');
    expect(recs.some((r) => r.runtime === 'codex' && r.plane === 'tool-gate')).toBe(false);
    expect(recs.some((r) => r.capability.value === 'memory-only' && r.plane === 'tool-gate')).toBe(false);
  });

  it('runtimes with no trace on the box produce no record at all', () => {
    expect(collect()).toEqual([]);
  });
});

describe('#613 process-start check (Linux /proc)', () => {
  const linux = process.platform === 'linux';
  (linux ? it : it.skip)('reads this process\'s own start token, and null for a pid that does not exist', () => {
    const mine = linuxProcessStart(process.pid);
    expect(mine).toMatch(/^[0-9]+$/);
    expect(linuxProcessStart(2 ** 22 + 12345)).toBeNull();
  });

  (linux ? it : it.skip)('reads this process\'s own PID namespace id (#970)', () => {
    const ns = linuxPidNamespace();
    expect(ns).toMatch(/^[0-9]+$/);
    expect(fs.readlinkSync('/proc/self/ns/pid')).toBe(`pid:[${ns}]`);
  });

  (linux ? it : it.skip)('the real check: this process alive, a mismatched start token ended (same PID namespace)', () => {
    hermesInstalled();
    const start = linuxProcessStart(process.pid)!;
    const ns = linuxPidNamespace();
    writeReport(configDir, reportBody({ instance: { ...otherInstance(process.pid, start), pid_ns: ns } }));
    writeReport(configDir, reportBody({ profile: 'reuse', instance: { ...otherInstance(process.pid, `${start}9`), pid_ns: ns } }));
    writeReport(configDir, reportBody({ profile: 'foreign', instance: { ...otherInstance(process.pid, `${start}9`), pid_ns: `${ns}9` } }));
    const recs = collectPostureRecords({ home, configDir, nowMs: NOW, hostDeps: noOpenClawBinary })
      .filter((r) => r.runtime === 'hermes' && r.key.instance !== null);
    const byProfile = Object.fromEntries(recs.map((r) => [r.profile, r]));
    expect(byProfile.default.liveness.value).toBe('alive');
    expect(byProfile.default.membership).toBe('current');
    expect(byProfile.reuse.liveness.value).toBe('ended');
    // #970: in another PID namespace the same pid number is a different process.
    expect(byProfile.foreign.liveness.value).toBe('unverified');
  });

  it('with no start token reported, a live pid cannot be told from a reused one: unverified', () => {
    hermesInstalled();
    writeReport(configDir, reportBody({ instance: { ...otherInstance(4242, '100'), key: 'p4242-rabcd', process_start: null } }));
    const [rec] = collectPostureRecords({ home, configDir, nowMs: NOW, hostDeps: noOpenClawBinary, deps: processTable({ 4242: '100' }) })
      .filter((r) => r.runtime === 'hermes');
    expect(rec.liveness.value).toBe('unverified');
    expect(rec.runtime_loaded.value).toBe('unknown');
  });
});

describe('#613 cross-runtime schema contract: the Hermes writer output passes the CLI validator', () => {
  const python = spawnSync('python3', ['--version']).status === 0;
  (python ? it : it.skip)('posture.py writes a report parseSelfReport accepts, and its exited process reads as ended', () => {
    const pkg = path.join(REPO, 'plugins', 'hermes');
    const script = [
      'import sys',
      `sys.path.insert(0, ${JSON.stringify(pkg)})`,
      'from shieldcortex import posture',
      `ok = posture.write_self_report(${JSON.stringify(configDir)}, profile="work", configured_posture="advisory", scanner="available", policy={"enforce": False}, denial=True, denial_path="pre_tool_call:terminal")`,
      `print(posture.report_path(${JSON.stringify(configDir)}, "work") if ok else "fail")`,
    ].join('\n');
    const r = spawnSync('python3', ['-c', script], {
      env: { PATH: '/usr/bin:/bin', HOME: home },
      encoding: 'utf8',
    });
    const file = r.stdout.trim();
    expect(file).toMatch(/hermes\/work\/p\d+-[sr][0-9a-f]+\.json$/);
    const text = fs.readFileSync(file, 'utf8');
    const parsed = parseSelfReport(text, Buffer.byteLength(text));
    expect(parsed.kind).toBe('valid');
    if (parsed.kind === 'valid') {
      expect(parsed.report.runtime).toBe('hermes');
      expect(parsed.report.configured_posture).toBe('advisory');
      expect(parsed.report.policy_hash).toMatch(/^sha256:[0-9a-f]{64}$/);
      expect(parsed.report.instance.liveness).toBe('process');
      expect(parsed.report.denials.blocked_action!.tested_path).toBe('pre_tool_call:terminal');
      expect(parsed.report.denials.blocked_action_count).toBe(1);
    }
    expect(fs.statSync(file).mode & 0o077).toBe(0);
    expect(fs.statSync(path.dirname(file)).mode & 0o077).toBe(0);
    // #970: a closed v1 report a pre-#970 CLI lists and reads as before; the
    // PID namespace (the collector's own, here) rides in the sidecar it never lists.
    const key = path.basename(file, '.json');
    expect(legacyGateRejects(text)).toBeNull();
    expect(legacyListInstances(path.dirname(file))).toEqual([key]);
    expect(fs.readdirSync(path.dirname(file)).sort()).toEqual([`${key}.json`, `${key}.pidns`]);
    expect(fs.statSync(pidNsSidecarPath(file)).mode & 0o077).toBe(0);
    const joined = readSelfReportFile(file, { runtime: 'hermes', profile: 'work', instance: key }, process.getuid?.());
    expect(joined.kind === 'valid' && joined.report.instance.pid_ns).toBe(process.platform === 'linux' ? linuxPidNamespace() : null);
    // The python process has exited: on Linux the real check says so.
    if (process.platform === 'linux') {
      hermesHome(home);
      hermesPluginArtefacts(home, path.join(home, '.hermes', 'profiles', 'work'));
      const [rec] = collectPostureRecords({ home, configDir, nowMs: Date.now(), hostDeps: noOpenClawBinary })
        .filter((x) => x.runtime === 'hermes' && x.profile === 'work');
      expect(rec.membership).toBe('ended');
      expect(rec.runtime_loaded.value).toBe('unobserved');
    }
  });
});

/**
 * #1153: trust and content-rejection age come from the opened descriptor.
 * Metadata disagreements are synthetic stats on that descriptor. The path
 * lstat stays real. No production seam.
 */
describe('#1153 opened descriptor', () => {
  const HOUR = 60 * 60 * 1000;
  const EIGHT_DAYS = STALE_NOT_SEEN_MS + 24 * HOUR;
  const posixIt = process.platform === 'win32' ? it.skip : it;
  const expectSpec = { runtime: 'hermes' as const, profile: 'default', instance: INSTANCE };

  function patchedStat(real: fs.Stats, over: Partial<fs.Stats> & { isFile?: () => boolean }): fs.Stats {
    return new Proxy(real, {
      get(target, prop, receiver) {
        if (Object.prototype.hasOwnProperty.call(over, prop)) return (over as Record<PropertyKey, unknown>)[prop];
        const value = Reflect.get(target, prop, receiver);
        return typeof value === 'function' ? (value as (...args: unknown[]) => unknown).bind(target) : value;
      },
    });
  }

  function withOpenedStat(
    file: string,
    patch: (real: fs.Stats, call: number) => (Partial<fs.Stats> & { isFile?: () => boolean }) | null,
    run: () => void,
  ): void {
    const fds = new Map<number, string>();
    const calls = new Map<number, number>();
    const realOpen = fs.openSync;
    const realFstat = fs.fstatSync;
    const openSpy = jest.spyOn(fs, 'openSync').mockImplementation(((...args: Parameters<typeof fs.openSync>) => {
      const fd = Reflect.apply(realOpen, fs, args) as number;
      fds.set(fd, String(args[0]));
      return fd;
    }) as typeof fs.openSync);
    const fstatSpy = jest.spyOn(fs, 'fstatSync').mockImplementation(((fd: number, opts?: { bigint?: boolean }) => {
      const real = Reflect.apply(realFstat, fs, [fd, opts]) as fs.Stats;
      if (opts?.bigint || fds.get(fd) !== file) return real;
      const n = (calls.get(fd) ?? 0) + 1;
      calls.set(fd, n);
      const over = patch(real, n);
      return over ? patchedStat(real, over) : real;
    }) as typeof fs.fstatSync);
    try {
      run();
    } finally {
      openSpy.mockRestore();
      fstatSpy.mockRestore();
    }
  }

  function readReport(file: string, uid: number | undefined = process.getuid?.()) {
    return readSelfReportFile(file, expectSpec, uid);
  }

  function expectTrust(read: { kind: string; rejection?: string; reason?: string; observedMtimeMs?: number | null }, reason: string): void {
    expect(read.kind).not.toBe('valid');
    expect(read.rejection).not.toBe('content');
    expect(read).toMatchObject({ kind: 'invalid', rejection: 'trust', reason });
    expect(read.observedMtimeMs).toBeUndefined();
  }

  it('a descriptor that agrees with the pre-open stat stays valid and the sidecar still joins', () => {
    const file = writeReport(configDir, reportBody());
    const read = readReport(file);
    expect(read.kind).toBe('valid');
    if (read.kind !== 'valid') return;
    // writeReport lays a digit sidecar on every platform, so the join is PID_NS
    // here. Real writers record null off Linux; that path is locked by the writer suites.
    expect(read.report.instance.pid_ns).toBe(PID_NS);
  });

  it('descriptor isFile false is not a regular file', () => {
    const file = writeReport(configDir, reportBody());
    withOpenedStat(file, () => ({ isFile: () => false }), () => {
      expectTrust(readReport(file), 'not a regular file');
    });
  });

  posixIt('descriptor mode with group or other bits is the owner-only rejection', () => {
    const file = writeReport(configDir, reportBody());
    withOpenedStat(file, (real) => ({ mode: real.mode | 0o040 }), () => {
      expectTrust(readReport(file), 'readable or writable by group or others (must be owner-only)');
    });
  });

  posixIt('descriptor uid different from the uid argument is owned by another user', () => {
    const uid = process.getuid?.();
    expect(typeof uid).toBe('number');
    const file = writeReport(configDir, reportBody());
    withOpenedStat(file, (real) => ({ uid: real.uid + 1 }), () => {
      expectTrust(readReport(file, uid), 'owned by another user');
    });
  });

  it('descriptor dev different from the pre-open stat is unreadable', () => {
    const file = writeReport(configDir, reportBody());
    withOpenedStat(file, (real) => ({ dev: real.dev + 1 }), () => {
      expectTrust(readReport(file), 'unreadable');
    });
  });

  it('descriptor ino different from the pre-open stat is unreadable', () => {
    const file = writeReport(configDir, reportBody());
    withOpenedStat(file, (real) => ({ ino: real.ino + 1 }), () => {
      expectTrust(readReport(file), 'unreadable');
    });
  });

  it('descriptor size above the cap is the existing oversize rejection', () => {
    const file = writeReport(configDir, reportBody());
    const size = SELF_REPORT_MAX_BYTES + 1;
    withOpenedStat(file, () => ({ size }), () => {
      expectTrust(readReport(file), `size ${size} bytes exceeds the ${SELF_REPORT_MAX_BYTES}-byte cap`);
    });
  });

  it('a second descriptor stat with a different size discards the parse', () => {
    const file = writeReport(configDir, reportBody());
    withOpenedStat(file, (real, call) => (call === 1 ? null : { size: real.size + 1 }), () => {
      const read = readReport(file);
      expect(read.kind).not.toBe('valid');
      expect(read).not.toMatchObject({ rejection: 'content' });
      expectTrust(read, 'unreadable');
    });
  });

  it('a second descriptor stat with a different ino discards the parse', () => {
    const file = writeReport(configDir, reportBody());
    withOpenedStat(file, (real, call) => (call === 1 ? null : { ino: real.ino + 1 }), () => {
      const read = readReport(file);
      expect(read.kind).not.toBe('valid');
      expect(read).not.toMatchObject({ rejection: 'content' });
      expectTrust(read, 'unreadable');
    });
  });

  it('content-rejection age follows a recent descriptor mtime when the path stat is old', () => {
    const file = writeReport(configDir, { ...reportBody(), extra: 1 });
    fs.utimesSync(file, new Date(NOW - EIGHT_DAYS), new Date(NOW - EIGHT_DAYS));
    const recent = NOW - HOUR;
    withOpenedStat(file, () => ({ mtimeMs: recent }), () => {
      expect(readReport(file)).toMatchObject({
        kind: 'invalid', rejection: 'content', reason: 'unknown keys', observedMtimeMs: recent,
      });
      const [rec] = collect().filter((r) => r.runtime === 'hermes');
      expect(rec.stale).toBe(false);
      expect(rec.runtime_loaded.value).toBe('unknown');
      expect(rec.liveness.value).toBe('not-applicable');
    });
  });

  it('content-rejection age follows an old descriptor mtime when the path stat is recent', () => {
    const file = writeReport(configDir, { ...reportBody(), extra: 1 });
    fs.utimesSync(file, new Date(NOW - HOUR), new Date(NOW - HOUR));
    const old = NOW - EIGHT_DAYS;
    withOpenedStat(file, () => ({ mtimeMs: old }), () => {
      const [rec] = collect().filter((r) => r.runtime === 'hermes');
      expect(rec.stale).toBe(true);
      expect(rec.stale_reason).toBe('not-seen');
      expect(rec.runtime_loaded.value).toBe('unknown');
      expect(rec.liveness.value).toBe('not-applicable');
    });
  });

  it('a non-finite descriptor mtime does not age a content rejection', () => {
    const file = writeReport(configDir, { ...reportBody(), extra: 1 });
    fs.utimesSync(file, new Date(NOW - EIGHT_DAYS), new Date(NOW - EIGHT_DAYS));
    withOpenedStat(file, () => ({ mtimeMs: Number.NaN }), () => {
      const [rec] = collect().filter((r) => r.runtime === 'hermes');
      expect(rec.stale).toBe(false);
      expect(rec.liveness.value).toBe('not-applicable');
    });
  });

  function expectSidecarUnknown(patch: (real: fs.Stats) => Partial<fs.Stats> & { isFile?: () => boolean }): void {
    const file = writeReport(configDir, reportBody());
    withOpenedStat(pidNsSidecarPath(file), (real) => patch(real), () => {
      const read = readReport(file);
      expect(read.kind).toBe('valid');
      if (read.kind === 'valid') expect(read.report.instance.pid_ns).toBeNull();
      const [rec] = collectPostureRecords({
        home,
        configDir,
        nowMs: NOW,
        hostDeps: noOpenClawBinary,
        deps: processTable({}),
      }).filter((r) => r.runtime === 'hermes');
      expect(rec.liveness.value).toBe('unverified');
      expect(rec.notes.join(' ')).not.toMatch(/self-report rejected/);
    });
  }

  it('a sidecar descriptor that is not a regular file stays namespace-unknown', () => {
    expectSidecarUnknown(() => ({ isFile: () => false }));
  });

  posixIt('a sidecar descriptor with group or other bits stays namespace-unknown', () => {
    expectSidecarUnknown((real) => ({ mode: real.mode | 0o040 }));
  });

  it('a sidecar descriptor dev mismatch stays namespace-unknown', () => {
    expectSidecarUnknown((real) => ({ dev: real.dev + 1 }));
  });

  it('aging does not call a path lstat and fileMtimeMs is gone', () => {
    const src = fs.readFileSync(path.join(REPO, 'src/posture/collect.ts'), 'utf8');
    expect(src.includes('fileMtimeMs')).toBe(false);
    const aging = src.slice(src.indexOf('rejectionMayAge(read)'));
    expect(aging.startsWith('rejectionMayAge(read)')).toBe(true);
    expect(aging.slice(0, 220)).not.toContain('lstatSync');
  });
});
