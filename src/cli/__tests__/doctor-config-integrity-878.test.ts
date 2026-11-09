/**
 * #878 item 4 — doctor reads the config without changing it, and renders an
 * unknown signed posture as unknown.
 *
 * Structural: EVERY doctor check that reads config.json — directly, or through
 * any helper it calls — is run against fixtures whose ordinary read WOULD
 * write: an unsigned file (adopted: `.integrity-key` + `.config-sig`), an
 * embedded `_sig` with no key beside it (the key is minted), a stale embedded
 * `_sig` the legacy sig still authenticates (self-healed), the unsigned and
 * the signed-no-key shapes behind a live symlink, and a dangling symlink. The
 * complete config directory (names, link targets, modes, mtimes, bytes) must
 * be unchanged afterwards. Which checks are in that set is not a matter of
 * memory: the `runDoctor` check list is parsed from doctor.ts, and every entry
 * must be either run here or listed exempt with the reason it reads no
 * config.json. A new check that is neither fails; a new reader in a run check
 * that forgets the read-only contract fails the snapshot.
 *
 * Rendering: on an unsigned file behind a live link, Action Guard's posture,
 * notify, policy-lock and integrity rows say unknown — never "off in signed
 * config", "warn-mode", "disabled", or a pass promising adoption.
 *
 * Isolation: per-test HOME (with `os.homedir()` answering it — jest's
 * in-process homedir otherwise ignores HOME), SHIELDCORTEX_CONFIG_DIR at
 * `<home>/.shieldcortex` (the path the checks that hard-code it read too),
 * protected root and OPENCLAW_HOME, all under os.tmpdir(); a fresh module
 * registry per test. `fs` and `os` are pass-throughs owned by this test:
 * copyFileSync can run a hook after a config backup is copied, and homedir
 * answers the fixture home. Nothing in shipped code knows either exists.
 */
import * as realFs from 'fs';
import * as realOs from 'os';
import path from 'path';
import { fileURLToPath } from 'url';
import { createHmac, randomBytes } from 'crypto';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import { PROTECTED_ROOT_ENV } from '../../defence/iron-dome/protected-root.js';

const auditSpy = jest.fn();
const guardSyncSpy = jest.fn(() => ({ status: 'skipped' as const, reason: 'no-entry' as const }));
jest.unstable_mockModule('../../defence/iron-dome/audit.js', () => ({ logIronDomeAudit: auditSpy }));
jest.unstable_mockModule('../../setup/openclaw-plugin-guard-sync.js', () => ({
  syncOpenClawPluginActionGuard: guardSyncSpy,
}));

let afterBackupCopy: (() => void) | null = null;
const hookedCopyFileSync = ((src: unknown, dest: unknown, ...rest: unknown[]) => {
  (realFs.copyFileSync as (...args: unknown[]) => unknown)(src, dest, ...rest);
  if (typeof dest === 'string' && path.basename(dest).includes('.bak-fix-209-') && afterBackupCopy) {
    const hook = afterBackupCopy;
    afterBackupCopy = null;
    hook();
  }
}) as typeof realFs.copyFileSync;
const hookedFs = { ...realFs, copyFileSync: hookedCopyFileSync };
jest.unstable_mockModule('fs', () => ({ ...hookedFs, default: hookedFs }));

let home = '';
const homedOs = { ...realOs, homedir: () => home };
jest.unstable_mockModule('os', () => ({ ...homedOs, default: homedOs }));

const fs = realFs;
const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const DOCTOR_SRC = () => fs.readFileSync(path.join(REPO, 'src', 'cli', 'doctor.ts'), 'utf-8');

let configDir: string;
let scratch: string[];
let saved: Record<string, string | undefined>;

const file = (name: string) => path.join(configDir, name);
const configFile = () => file('config.json');
const bytes = (obj: Record<string, unknown>) => JSON.stringify(obj, null, 2) + '\n';

/** The whole config directory: names, link targets, modes, mtimes and bytes. */
function snapshot(): string[] {
  return fs.readdirSync(configDir).sort().map((name) => {
    const p = file(name);
    const st = fs.lstatSync(p);
    if (st.isSymbolicLink()) return `${name} -> ${fs.readlinkSync(p)}`;
    if (st.isDirectory()) return `${name}/ ${st.mode.toString(8)}`;
    return `${name} ${st.mode.toString(8)} ${st.mtimeMs} ${fs.readFileSync(p).toString('base64')}`;
  });
}

/**
 * Every config-reading path the checks have, in one body: the threat graph
 * returns at its config gate (no database), Action Guard is enforce-when-ready
 * (so the readiness check goes past its precheck into the shared summaries),
 * and the memory block declares the honest-sidecar posture (so both memory
 * rows reach the signed-posture trust decision).
 */
const BODY = {
  defenceMode: 'balanced',
  threatGraph: { enabled: false },
  actionGuard: { enabled: true, enforce: true, readinessGate: true },
  memory: { hostContract: { posture: 'mcp_sidecar_no_inject' }, inject: { mode: 'off' } },
};

/** Bytes whose embedded `_sig` is stale while the legacy whole-file sig validates them. */
function selfHealBytes(): string {
  const key = randomBytes(32).toString('hex');
  fs.writeFileSync(file('.integrity-key'), key, { mode: 0o600 });
  const content = bytes({ ...BODY, _sig: '0'.repeat(64) });
  fs.writeFileSync(file('.config-sig'), createHmac('sha256', key).update(content, 'utf-8').digest('hex'));
  return content;
}

const SIGNED_NO_KEY = () => bytes({ ...BODY, _sig: 'a'.repeat(64) });

const fixtures: Record<string, () => void> = {
  'regular unsigned (the ordinary read adopts it)': () => {
    fs.writeFileSync(configFile(), bytes(BODY));
  },
  'regular, embedded _sig, no .integrity-key (the ordinary signature check mints one)': () => {
    fs.writeFileSync(configFile(), SIGNED_NO_KEY());
  },
  'regular, stale embedded _sig, legacy sig valid (the ordinary read self-heals it)': () => {
    fs.writeFileSync(configFile(), selfHealBytes());
  },
  'live symlink to an unsigned target': () => {
    fs.writeFileSync(file('target.json'), bytes(BODY));
    fs.symlinkSync(file('target.json'), configFile());
  },
  'live symlink to a signed target with no .integrity-key': () => {
    fs.writeFileSync(file('target.json'), SIGNED_NO_KEY());
    fs.symlinkSync(file('target.json'), configFile());
  },
  'dangling symlink': () => {
    fs.symlinkSync(file(path.join('missing', 'config.json')), configFile());
  },
};

type Doctor = typeof import('../doctor.js');
type Config = typeof import('../../cloud/config.js');

async function fresh(): Promise<{ doctor: Doctor; config: Config }> {
  jest.resetModules();
  const config = await import('../../cloud/config.js');
  const doctor = await import('../doctor.js');
  return { doctor, config };
}

/**
 * The checks in `runDoctor`'s list that read config.json (directly or through
 * a helper), each run the way runDoctor runs it — or, where the entry is not
 * exported, through the exported function it delegates to with the same
 * config read. Keyed by the name in runDoctor's list.
 */
const RUN: Record<string, (doctor: Doctor) => Promise<unknown>> = {
  // Not exported; delegates to runMemoryStatsCheck, whose default config
  // argument is the config read (resolveMemoryConfig, read-only).
  checkMemoryStats: async (d) => d.runMemoryStatsCheck(path.join(home, 'no-such.db')),
  checkAutoMemoryHooks: (d) => d.checkAutoMemoryHooks(),
  checkAutoMemorySampling: (d) => d.checkAutoMemorySampling(),
  checkMemoryPlaneEmptyBrain: (d) => d.checkMemoryPlaneEmptyBrain(),
  checkMemoryPlaneDrift: (d) => d.checkMemoryPlaneDrift(),
  checkMemoryHostContract: (d) => d.checkMemoryHostContract(),
  checkStatePermissions: (d) => d.checkStatePermissions(),
  checkActionGuard: (d) => d.checkActionGuard(),
  checkRuntimePosture: (d) => d.checkRuntimePosture(),
  checkActionGuardReadiness: (d) => d.checkActionGuardReadiness(),
  checkThreatGraph: (d) => d.checkThreatGraph(),
  // Run as on a box with no database (it returns at the prerequisite). Its
  // config read behind an open database is pinned by the call-site test
  // below and by resolveLedgerConfig's own read-only test
  // (config-integrity-followups-878).
  checkChainedLedger: (d) => d.checkChainedLedger(),
  checkAgentConfigWatch: (d) => d.checkAgentConfigWatch(home),
};

/** runDoctor's own config reads outside the check list (the HOSTS header). */
const HEADER: Array<(doctor: Doctor) => unknown> = [
  (d) => d.readHostGatePlanesWithPosture(home),
  (d) => d.policyLockRows(),
];

/**
 * Entries in runDoctor's list that read no config.json, by any path (static
 * import sweep of each check's modules, #878 round-1 fold). Adding a config
 * read to one of these means moving it to RUN.
 */
const EXEMPT: Record<string, string> = {
  checkNodeRuntime: 'process.version only',
  checkNativeEngineCompat: 'native binding probe only',
  checkDatabase: 'SQLite only',
  checkSchema: 'SQLite only',
  checkWritePath: 'SQLite round-trip only (migrations module reaches no config reader)',
  checkSemanticCoverage: 'embedding model cache + SQLite only',
  checkHooks: 'Claude settings.json and hook-name constants only',
  checkHookTimeouts: 'hook-timeout constants only',
  checkRecallLanePin: 'process.env only',
  checkRecallRepetition: 'recall history only',
  checkMemoryCaptureDist: 'checks dist exports exist; calls nothing that reads config',
  checkBrainWorker: 'worker/process probes only',
  checkProjectKeyConsistency: 'SQLite scan only (the config-reading migrator loads only for --fix-project-keys)',
  checkProcesses: 'process table only',
  checkDashboardFreshness: 'dashboard build artefacts only',
  checkDiskUsage: 'directory sizes only',
  checkLockFile: 'lock file only',
  checkOpenClawConfigValid: 'openclaw.json only',
  checkOpenClawResidue: 'OpenClaw install tree only',
  checkOpenClawHookFreshness: 'OpenClaw hook files only',
  checkOpenClawPluginVersion: 'OpenClaw plugin package only',
  checkOpenClawSkillVersion: 'OpenClaw skill files only',
  checkOpenClawPluginLoadState: 'OpenClaw plugin state only',
  checkOpenClawConversationScanning: 'openclaw.json only',
  checkOpenClawRunningPluginVersion: 'running OpenClaw plugin only',
  checkPluginStartupIntent: 'plugin startup intent file only',
  checkOpenClawPluginPackage: 'OpenClaw plugin package only',
  checkOpenClawDuplicateInstalls: 'OpenClaw install trees only',
  checkHermesPluginShadowing: 'Hermes plugin roots only',
  checkHermesPluginFreshness: 'Hermes plugin files only',
  checkOpenClawManagedPinDrift: 'OpenClaw managed pin only',
  checkOpenClawApprovalButtons: 'openclaw.json only',
  checkDefenceCanary: 'instruction detector only (no defence-pipeline config read)',
  checkIronDomeProfile: 'SQLite (or the in-process peek) only',
  checkCronDenials: 'cron denial audit files only',
  checkAttestationCoverage: 'SQLite only',
  checkStaleShieldCortexCopies: 'install-copy scan only',
  checkClaudeCodeVersion: 'claude binary version only',
  checkModelCache: 'model cache directory only',
};

/** The identifiers in runDoctor's `checks` array, parsed from the source. */
function runDoctorCheckList(): string[] {
  const src = DOCTOR_SRC();
  const start = src.indexOf('const checks: Array<() => Promise<CheckResult | CheckResult[]>> = [');
  expect(start).toBeGreaterThan(-1);
  const end = src.indexOf('\n  ];', start);
  const block = src.slice(start, end).split('\n').slice(1).map((l) => l.replace(/\/\/.*$/, '')).join('\n');
  return [...new Set([...block.matchAll(/\b((?:check|run)[A-Z]\w*)\b/g)].map((m) => m[1]))];
}

async function runEveryConfigReader(doctor: Doctor): Promise<void> {
  for (const read of HEADER) await read(doctor);
  for (const run of Object.values(RUN)) await run(doctor);
}

beforeEach(() => {
  const mk = (tag: string) => fs.mkdtempSync(path.join(realOs.tmpdir(), `sc-878-doc-${tag}-`));
  home = mk('home');
  configDir = path.join(home, '.shieldcortex');
  fs.mkdirSync(configDir, { mode: 0o700 });
  const protectedRoot = mk('root');
  const openclawHome = mk('oc');
  scratch = [home, protectedRoot, openclawHome];
  saved = {
    SHIELDCORTEX_CONFIG_DIR: process.env.SHIELDCORTEX_CONFIG_DIR,
    [PROTECTED_ROOT_ENV]: process.env[PROTECTED_ROOT_ENV],
    OPENCLAW_HOME: process.env.OPENCLAW_HOME,
    HOME: process.env.HOME,
    CLAUDE_MEMORY_DB: process.env.CLAUDE_MEMORY_DB,
  };
  process.env.SHIELDCORTEX_CONFIG_DIR = configDir;
  process.env[PROTECTED_ROOT_ENV] = protectedRoot;
  process.env.OPENCLAW_HOME = openclawHome;
  process.env.HOME = home;
  delete process.env.CLAUDE_MEMORY_DB;
  afterBackupCopy = null;
  jest.spyOn(console, 'error').mockImplementation(() => undefined);
  jest.spyOn(console, 'warn').mockImplementation(() => undefined);
  jest.spyOn(console, 'log').mockImplementation(() => undefined);
});

afterEach(() => {
  jest.restoreAllMocks();
  for (const [k, v] of Object.entries(saved)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  for (const dir of scratch) fs.rmSync(dir, { recursive: true, force: true });
});

describe('#878 item 4: doctor writes nothing to the config directory', () => {
  it('every entry in runDoctor\'s check list is either run below or exempt with a reason', () => {
    const listed = runDoctorCheckList();
    expect(listed.length).toBeGreaterThan(40);
    const classified = [...Object.keys(RUN), ...Object.keys(EXEMPT)];
    expect(listed.filter((name) => !classified.includes(name))).toEqual([]);
    expect(classified.filter((name) => !listed.includes(name))).toEqual([]);
    expect(Object.keys(RUN).filter((name) => name in EXEMPT)).toEqual([]);
  });

  it('checkChainedLedger reads its config read-only (every resolveLedgerConfig call in doctor.ts)', () => {
    const calls = [...DOCTOR_SRC().matchAll(/resolveLedgerConfig\(([^)]*)\)/g)].map((m) => m[1].trim());
    expect(calls.length).toBeGreaterThan(0);
    expect(calls.filter((args) => args !== '{ readOnly: true }')).toEqual([]);
  });

  for (const [name, setup] of Object.entries(fixtures)) {
    it(`${name}: every config-reading doctor check leaves the directory byte-identical`, async () => {
      setup();
      const before = snapshot();
      const { doctor } = await fresh();
      await runEveryConfigReader(doctor);
      expect(snapshot()).toEqual(before);
    });
  }

  it('control: the same unsigned fixture IS adopted by the ordinary getter, so the check above is sensitive', async () => {
    fixtures['regular unsigned (the ordinary read adopts it)']();
    const before = snapshot();
    const { config } = await fresh();
    config.getActionGuardCoreConfig();
    expect(snapshot()).not.toEqual(before);
    expect(fs.readdirSync(configDir).sort()).toEqual(['.config-sig', '.integrity-key', 'config.json']);
  });

  it('control: the same self-heal fixture IS rewritten by the ordinary getter', async () => {
    fixtures['regular, stale embedded _sig, legacy sig valid (the ordinary read self-heals it)']();
    const before = snapshot();
    const { config } = await fresh();
    config.getActionGuardCoreConfig();
    expect(snapshot()).not.toEqual(before);
  });

  it('control: the signed-no-key fixture IS given a minted key by the ordinary signature check', async () => {
    fixtures['regular, embedded _sig, no .integrity-key (the ordinary signature check mints one)']();
    const { config } = await fresh();
    config.getActionGuardCoreConfig();
    expect(fs.existsSync(file('.integrity-key'))).toBe(true);
  });

  for (const name of [
    'regular unsigned (the ordinary read adopts it)',
    'regular, stale embedded _sig, legacy sig valid (the ordinary read self-heals it)',
  ]) {
    it(`${name}: the readiness check reaches the shared summaries (not its precheck), read-only`, async () => {
      fixtures[name]();
      const before = snapshot();
      const { doctor } = await fresh();
      const rows = await doctor.checkActionGuardReadiness();
      // Pushed only after buildReadinessSummaries answered enforce-when-ready.
      expect(rows.map((r) => r.label)).toContain('Action guard readiness (Hermes plugin)');
      expect(snapshot()).toEqual(before);
    });
  }

  it('both memory rows reach the signed-posture trust decision; an un-keyed `_sig` is untrusted and mints nothing', async () => {
    fixtures['regular, embedded _sig, no .integrity-key (the ordinary signature check mints one)']();
    const { doctor } = await fresh();
    const drift = await doctor.checkMemoryPlaneDrift();
    expect(drift.message).toMatch(/untrusted sidecar posture/);
    await doctor.checkMemoryHostContract();
    expect(fs.existsSync(file('.integrity-key'))).toBe(false);
  });
});

describe('#878 design: an unknown signed posture is rendered unknown, never off', () => {
  const LINKED =
    'config.json is a symbolic link to a file with no signature, which is never adopted (nothing is written beside a link)';
  const UNKNOWN_FIX =
    'The signed Action Guard posture is unknown until config.json can be adopted (see the config integrity row); ' +
    'the runtime holds the strict fail-closed posture meanwhile. Resolve that row first. This row names no posture ' +
    'command and does not enable Action Guard.';

  function linkTo(guard: Record<string, unknown>): void {
    fs.writeFileSync(file('target.json'), bytes({ defenceMode: 'balanced', actionGuard: guard }));
    fs.symlinkSync(file('target.json'), configFile());
  }

  for (const [name, guard] of [
    ['Guard off (enabled:false)', { enabled: false }],
    ['watch-only (enabled:true, enforce:false)', { enabled: true, enforce: false }],
  ] as const) {
    it(`${name} behind a live link: checkActionGuard's posture, notify, lock and integrity rows say unknown`, async () => {
      linkTo(guard);
      const before = snapshot();
      const { doctor } = await fresh();
      const rows = await doctor.checkActionGuard();
      const row = (label: string) => {
        const found = rows.find((r) => r.label === label);
        expect(found).toBeDefined();
        return found!;
      };

      expect(row('Action guard posture')).toEqual({
        label: 'Action guard posture',
        status: 'warn',
        message:
          `signed posture unknown (integrity: unverified — ${LINKED}; the runtime holds the strict fail-closed ` +
          'posture); no gate plane is installed on this box',
        fix: UNKNOWN_FIX,
        postureUnknown: true,
      });

      expect(row('Action guard notify')).toEqual({
        label: 'Action guard notify',
        status: 'warn',
        message:
          `Action Guard's signed posture is unknown (${LINKED}; see the config integrity row), and whatever it ` +
          'resolves to, it would run with no denial-capable notify sink (actionGuard.notify.webhookUrl unset, ' +
          'notify.enabled is not true) — unattended denials stay in the audit log and session-guard index only. ' +
          'The #242 cron incidents were this shape.',
        fix:
          'The signed Action Guard posture is unknown until config.json can be adopted: resolve the config ' +
          'integrity row first. Do not enable Action Guard from this line.',
        postureUnknown: true,
      });

      const lock = row('Action guard policy lock');
      expect(lock.status).toBe('warn');
      expect(lock.message).toMatch(
        / — the signed Action Guard posture is unknown \(see the config integrity row\), so doctor does not call it off\.$/,
      );
      expect(lock.fix).toBe(
        'Do not run protect from this warning. A root lock is optional; resolve the config integrity row first. Do not uninstall.',
      );

      const integrity = row('Action guard config integrity');
      expect(integrity.status).toBe('warn');
      expect(integrity.message.startsWith(
        `verdict: unverified — ${LINKED}. The file's own Action Guard values are not reported as in force: the ` +
        'signed posture is unknown, and the runtime holds the strict fail-closed posture. Nothing is adopted or ' +
        'signed while this lasts. Note this HMAC is a CORRUPTION detector',
      )).toBe(true);
      expect(integrity.fix).toBe(
        'Replace the config.json symlink with the file it points to; the next read then adopts it and the next ' +
        'write signs it. Then re-run doctor.',
      );

      // None of the file's own values leaks out as the posture, anywhere.
      const all = rows.map((r) => `${r.message}\n${r.fix ?? ''}`).join('\n');
      expect(all).not.toMatch(/off in signed config|warn-mode|is disabled|Guard is off|adopts it as trusted|That is the default/);
      expect(snapshot()).toEqual(before);
    });
  }

  it('guard posture (the CLI view) says signed: unknown for the same fixture', async () => {
    linkTo({ enabled: false });
    await fresh();
    const { readGuardPosture, formatGuardPostureLines } = await import('../../guard/posture-switch.js');
    const report = readGuardPosture({ home });
    expect(report.signed).toBeNull();
    expect(report.integrity).toBe('unverified');
    expect(report.integrityAdoption).toBe('linked');
    expect(report.graded).toBe('enforce'); // the strict posture the runtime holds
    expect(formatGuardPostureLines(report)[0]).toContain('signed: unknown (integrity: unverified)');
  });

  it('a .integrity-key directory: the integrity row names the failed adoption; no row grades the file as off', async () => {
    fs.writeFileSync(configFile(), bytes({ defenceMode: 'balanced', actionGuard: { enabled: false } }));
    fs.mkdirSync(file('.integrity-key'));
    const before = snapshot();
    const { doctor, config } = await fresh();
    expect(config.inspectConfigIntegrity()).toMatchObject({ verdict: 'unverified', adoption: 'fails' });
    const rows = await doctor.checkActionGuard();
    const integrity = rows.find((r) => r.label === 'Action guard config integrity')!;
    expect(integrity.status).toBe('warn');
    expect(integrity.message).toMatch(/^verdict: unverified — .*\.integrity-key\) is a directory.*strict fail-closed posture is/s);
    // The file says enabled:false; the runtime reads it tampered (strict), so
    // no row grades that value. (The lock row's "Guard is off on this host"
    // is about live planes — none is installed here — and reads the same for
    // a valid signed-enforce file, so it is not asserted against.)
    const all = rows.map((r) => `${r.message}\n${r.fix ?? ''}`).join('\n');
    expect(all).not.toMatch(/off in signed config|is disabled|warn-mode|adopts it as trusted/);
    expect(rows.find((r) => r.label === 'Action guard notify')?.message).toMatch(/^Action Guard is enforcing with/);
    expect(doctor.fixActionGuardConfig()).toMatchObject({
      changed: false,
      message: expect.stringMatching(/not migrating.*Nothing was changed/s),
    });
    expect(snapshot()).toEqual(before);
  });

  it('live link to an unsigned Guard-off target: planes are signedUnknown, the header says Guard unknown', async () => {
    fixtures['live symlink to an unsigned target']();
    const { doctor } = await fresh();
    const planes = doctor.readHostGatePlanes(home);
    expect(planes.signedUnknown).toBe(true);
    expect(planes.signedEnabled).toBe(false);
    const { guardHeadlineFromPlanes, formatHostTable } = await import('../../setup/host-table.js');
    expect(guardHeadlineFromPlanes(planes)).toBe('unknown');
    expect(formatHostTable({ rows: [] } as never, '0.0.0', planes)[0]).toContain('Guard unknown');
    expect(guardHeadlineFromPlanes({ ...planes, claudeWired: true })).toBe('unknown');
  });

  it('the readiness row says not evaluated for the same fixture', async () => {
    fixtures['live symlink to an unsigned target']();
    const { doctor } = await fresh();
    const readiness = await doctor.checkActionGuardReadiness();
    expect(readiness).toHaveLength(1);
    expect(readiness[0].message).toMatch(/not evaluated.*unknown/);
  });

  it('control: an unobstructed unsigned regular file is rendered as it reads, and its integrity row promises adoption', async () => {
    fs.writeFileSync(configFile(), bytes({ defenceMode: 'balanced', actionGuard: { enabled: false } }));
    const { doctor } = await fresh();
    const planes = doctor.readHostGatePlanes(home);
    expect(planes.signedUnknown).toBeUndefined();
    expect(planes.signedEnabled).toBe(false);
    const rows = await doctor.checkActionGuard();
    expect(rows.find((r) => r.label === 'Action guard posture')?.message).toMatch(/Action Guard is off in signed config/);
    expect(rows.find((r) => r.label === 'Action guard config integrity')).toMatchObject({
      status: 'pass',
      message: expect.stringMatching(/^verdict: unsigned — .*the next read adopts it as trusted/),
    });
  });

  it('self-heal behind a link: the integrity row does not promise a re-sign that the read layer will not make', async () => {
    fs.writeFileSync(file('target.json'), selfHealBytes());
    fs.symlinkSync(file('target.json'), configFile());
    const { doctor } = await fresh();
    const integrity = doctor.policyLockRows().find((r) => r.label === 'Action guard config integrity')!;
    expect(integrity.message).toMatch(/^verdict: self-heal — .*NOT re-signed while config\.json is a symbolic link/s);
  });
});

describe('#878 r2: the human report prints an unknown-posture row own fix, never "Guard is off"', () => {
  const HONESTY_OFF = 'Guard is off or the plugin is off';
  const NOTIFY_UNKNOWN_FIX =
    'The signed Action Guard posture is unknown until config.json can be adopted: resolve the config ' +
    'integrity row first. Do not enable Action Guard from this line.';
  const asRoot = typeof process.getuid === 'function' && process.getuid() === 0;

  /** The default and --verbose human reports, the way runDoctor builds them, whitespace-collapsed. */
  async function reports(rows: Awaited<ReturnType<Doctor['checkActionGuard']>>): Promise<Record<string, string>> {
    const { formatDoctorReport, sanitiseDoctorRowsForDisplay } = await import('../doctor-report.js');
    const display = sanitiseDoctorRowsForDisplay(rows);
    const render = (verbose: boolean) =>
      formatDoctorReport(display, { verbose, width: 240, color: false }).join('\n').replace(/\s+/g, ' ');
    return { default: render(false), verbose: render(true) };
  }

  async function expectUnknownRendered(): Promise<void> {
    const { doctor } = await fresh();
    const rows = await doctor.checkActionGuard();
    const notify = rows.find((r) => r.label === 'Action guard notify')!;
    expect(notify).toMatchObject({ status: 'warn', fix: NOTIFY_UNKNOWN_FIX, postureUnknown: true });
    // The trap: the unknown message still names the notify sink, which the
    // text-matched honesty guidance reads as "Guard is off".
    expect(notify.message).toMatch(/denial-capable/);
    const marked = rows.filter((r) => r.postureUnknown && r.status === 'warn');
    expect(marked.map((r) => r.label).sort()).toEqual([
      'Action guard config integrity',
      'Action guard notify',
      'Action guard policy lock',
      'Action guard posture',
    ]);
    for (const [mode, out] of Object.entries(await reports(rows))) {
      expect({ mode, honestyOff: out.includes(HONESTY_OFF) }).toEqual({ mode, honestyOff: false });
      expect({ mode, notifyFix: out.includes(NOTIFY_UNKNOWN_FIX) }).toEqual({ mode, notifyFix: true });
      // Every unknown-posture warn prints its own fix (backticks stripped, as the report does).
      for (const r of marked) {
        expect({ mode, label: r.label, printed: out.includes(r.fix!.replace(/`/g, '').replace(/\s+/g, ' ').trim()) })
          .toEqual({ mode, label: r.label, printed: true });
      }
    }
  }

  function linkTo(guard: Record<string, unknown>): void {
    fs.writeFileSync(file('target.json'), bytes({ defenceMode: 'balanced', actionGuard: guard }));
    fs.symlinkSync(file('target.json'), configFile());
  }

  it('live symlink to an unsigned enabled:false target', async () => {
    linkTo({ enabled: false });
    await expectUnknownRendered();
  });

  it('live symlink to an unsigned enabled:true target', async () => {
    linkTo({ enabled: true });
    await expectUnknownRendered();
  });

  (asRoot ? it.skip : it)('an unwritable config directory over an unsigned regular file', async () => {
    fs.writeFileSync(configFile(), bytes({ defenceMode: 'balanced', actionGuard: { enabled: false } }));
    fs.chmodSync(configDir, 0o500);
    try {
      const { config } = await fresh();
      expect(config.inspectConfigIntegrity()).toMatchObject({ verdict: 'unverified', adoption: 'unknown' });
      await expectUnknownRendered();
    } finally {
      fs.chmodSync(configDir, 0o700);
    }
  });

  it('control: a genuinely-off SIGNED config still prints the honesty guidance, unmarked', async () => {
    fs.writeFileSync(configFile(), bytes({ defenceMode: 'balanced', actionGuard: { enabled: false } }));
    (await fresh()).config.getActionGuardCoreConfig(); // adopt + sign, as the runtime would
    expect(fs.readdirSync(configDir).sort()).toEqual(['.config-sig', '.integrity-key', 'config.json']);
    const { doctor, config } = await fresh();
    expect(config.inspectConfigIntegrity().verdict).not.toBe('unverified');
    const rows = await doctor.checkActionGuard();
    expect(rows.filter((r) => r.postureUnknown)).toEqual([]);
    expect(rows.find((r) => r.label === 'Action guard notify')?.status).toBe('warn');
    const out = await reports(rows);
    // --verbose keeps the honesty guidance verbatim; the default report (#1014)
    // files the same rows under EXPECTED as plain phrases. Neither says unknown.
    expect(out.verbose).toContain(HONESTY_OFF);
    expect(out.default).toContain('EXPECTED ON THIS HOST');
    expect(out.default).toContain('Action Guard off');
    expect(out.default).toContain('Guard notifications not set');
    expect(out.default).not.toContain('TO FIX');
    for (const o of Object.values(out)) expect(o).not.toContain(NOTIFY_UNKNOWN_FIX);
  });
});

describe('#878 item 4: fixActionGuardConfig refusals', () => {
  const ALIAS = { interceptor: { actionGuard: { enforce: false } } };

  it('a symlinked config.json is refused BEFORE the backup copy: nothing at all is written', async () => {
    fs.writeFileSync(file('target.json'), bytes(ALIAS));
    fs.symlinkSync(file('target.json'), configFile());
    const before = snapshot();
    const { doctor } = await fresh();
    const result = doctor.fixActionGuardConfig();
    expect(result.changed).toBe(false);
    expect(result.message).toMatch(/symbolic link.*Nothing was changed/s);
    expect(snapshot()).toEqual(before);
  });

  it('a file that turns tampered between inspection and migration gets the specific message, config.json untouched', async () => {
    const { doctor, config } = await fresh();
    config.setCloudConfig({ cloudApiKey: 'k' });
    // Seed the alias through a signed write so the file inspects valid.
    const signed = JSON.parse(fs.readFileSync(configFile(), 'utf-8'));
    delete signed._sig;
    fs.writeFileSync(configFile(), bytes({ ...signed, ...ALIAS }));
    fs.rmSync(file('.config-sig'), { force: true });
    config.clearCloudConfigCache();
    config.readRawConfig(); // adopt (regular file): valid
    expect(config.inspectConfigIntegrity().verdict).toBe('valid');

    let tamperedBytes = '';
    afterBackupCopy = () => {
      const body = fs.readFileSync(configFile(), 'utf-8');
      tamperedBytes = body.replace('"cloudApiKey": "k"', '"cloudApiKey": "x"');
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 30); // coarse ctime clock
      fs.writeFileSync(configFile(), tamperedBytes);
      fs.writeFileSync(file('.config-sig'), '0'.repeat(64));
    };
    expect(() => doctor.fixActionGuardConfig()).toThrow(
      /changed during the migration.*verdict: tampered.*config\.json was not written.*bak-fix-209-/s,
    );
    expect(tamperedBytes).not.toBe('');
    expect(fs.readFileSync(configFile(), 'utf-8')).toBe(tamperedBytes);
  });

  it('regular-file control: the alias is migrated and the file re-signed', async () => {
    const { doctor, config } = await fresh();
    config.setCloudConfig({ cloudApiKey: 'k' });
    const signed = JSON.parse(fs.readFileSync(configFile(), 'utf-8'));
    delete signed._sig;
    fs.writeFileSync(configFile(), bytes({ ...signed, ...ALIAS }));
    config.clearCloudConfigCache();
    const result = doctor.fixActionGuardConfig();
    expect(result.changed).toBe(true);
    const after = JSON.parse(fs.readFileSync(configFile(), 'utf-8'));
    expect(after.actionGuard).toMatchObject({ enforce: false });
    expect(after.interceptor).toBeUndefined();
    expect(after._sig).toMatch(/^[0-9a-f]{64}$/);
  });
});
