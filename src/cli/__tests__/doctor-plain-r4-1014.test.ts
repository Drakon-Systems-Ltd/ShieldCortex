/**
 * #1014 r4 — the two remaining review blockers on #1041.
 *
 * ASTRA: a signed off / advisory posture carries the by-design fix even when
 * another plane could not be read (openclaw.json unreadable or malformed,
 * Hermes with no self-report). The default report filed the whole row under
 * EXPECTED ON THIS HOST as "Action Guard off", and the read error vanished.
 * The row now carries a structured `planeUnread` flag from guardPostureRow,
 * and a flagged row is a diagnosis: TO FIX, full message, own fix.
 *
 * GROK: several FAILs sharing one fix text collapse into one TO FIX item, but
 * the item printed one label and one message only, so two of three failed
 * checks were not in the default report at all. The item now lists every
 * collapsed check with its own label, message and id, the remedy once, and
 * the verdict counts checks, not items.
 *
 * Plus two nits: "not expected while Guard is off" is not by design, and the
 * bare-command scan honours a "do not" clause the way the backtick scan does.
 */
import { describe, expect, it } from '@jest/globals';
import {
  extractFixCommands,
  formatDoctorReport,
  groupItems,
  type DoctorReportItem,
} from '../doctor-report.js';
import { doctorRowId, formatDoctorExplain, isByDesignWarning, warnTier } from '../doctor-plain.js';
import { guardPostureRow, resolvePlanePostures, type PostureInputs } from '../../guard/posture-switch.js';

const render = (rows: DoctorReportItem[], verbose = false): string =>
  formatDoctorReport(rows, { width: 100, color: false, verbose }).join('\n');
const flat = (text: string): string => text.replace(/\s+/g, ' ');
const PLAIN = { bold: '', reset: '', green: '', yellow: '', red: '', cyan: '', dim: '' };

// ── ASTRA ────────────────────────────────────────────────────────────────────

const LOCK: PostureInputs['lock'] = { status: 'absent', path: '/etc/shieldcortex/policy.json' };
const OFF = { actionGuard: { enabled: false } };
const ADVISORY = { actionGuard: { enabled: true, enforce: false } };

function postureRow(over: Partial<PostureInputs>): DoctorReportItem {
  const inputs: PostureInputs = {
    signedRaw: OFF,
    integrity: 'valid',
    lock: LOCK,
    claudeWired: false,
    openclaw: { state: 'absent' },
    postureRecords: [],
    ...over,
  };
  return guardPostureRow(resolvePlanePostures(inputs));
}

const UNREADABLE = { state: 'unreadable', detail: 'EACCES' } as const;
const MALFORMED = { state: 'malformed' } as const;

/** The row is a TO FIX diagnosis: its own label, the plane's read error, and its own fix prose. */
function expectUnreadDiagnosis(row: DoctorReportItem, detail: RegExp): void {
  expect(row.status).toBe('warn');
  expect(row.planeUnread).toBe(true);
  const text = render([row]);
  expect(text).toMatch(/^TO FIX$/m);
  expect(text).toMatch(/1 thing to fix/);
  expect(text).not.toMatch(/EXPECTED ON THIS HOST|Healthy \| nothing to fix/);
  expect(flat(text)).toMatch(/OpenClaw plugin unknown/);
  expect(flat(text)).toMatch(detail);
  // The row's own fix is still the guidance; a warning never prints a guard-changing `$`.
  expect(flat(text)).toMatch(/Do not (?:enable Action Guard|run --action-guard-enforce) from this warning/);
  expect(text).not.toMatch(/^\s+\$ /m);
  expect(warnTier(groupItems([row], true)[0]!)).toBe('fix');
  expect(formatDoctorExplain([row], 'expected', { width: 100, style: PLAIN }).join('\n')).toMatch(/^No check with id/);
}

describe('#1014 r4 (Astra) — an unreadable or malformed gate plane is a diagnosis, whatever the signed posture says', () => {
  it('openclaw.json unreadable, no other plane: EACCES stays in the default report', () => {
    const row = postureRow({ openclaw: UNREADABLE });
    expect(row.message).toMatch(/no plane's posture could be read/);
    expectUnreadDiagnosis(row, /openclaw\.json could not be read \(EACCES\)/);
  });

  it('openclaw.json unreadable alongside the Claude Code hook: the uncompared plane stays in the default report', () => {
    const row = postureRow({ claudeWired: true, openclaw: UNREADABLE });
    expect(row.message).toMatch(/not compared: OpenClaw plugin unknown/);
    expectUnreadDiagnosis(row, /not compared: OpenClaw plugin unknown \(openclaw\.json could not be read \(EACCES\)\)/);
  });

  it('openclaw.json malformed, alone and alongside the hook', () => {
    expectUnreadDiagnosis(postureRow({ openclaw: MALFORMED }), /openclaw\.json is not valid JSON/);
    expectUnreadDiagnosis(postureRow({ claudeWired: true, openclaw: MALFORMED }), /not compared: .*openclaw\.json is not valid JSON/);
  });

  it('a valid signed advisory posture does not erase the unreadable plane either', () => {
    const row = postureRow({ signedRaw: ADVISORY, claudeWired: true, openclaw: UNREADABLE });
    expect(row.fix).toMatch(/^Action Guard is advisory\./);
    expectUnreadDiagnosis(row, /openclaw\.json could not be read \(EACCES\)/);
    expect(render([row])).not.toMatch(/Action Guard in watch only/);
  });

  it('controls: off or advisory with every present plane read stays EXPECTED, and absent planes are not "unread"', () => {
    const cases: Array<[Partial<PostureInputs>, RegExp]> = [
      [{ claudeWired: true }, /Action Guard off/],
      [{}, /Action Guard off/], // "no gate plane is installed on this box"
      [{ signedRaw: ADVISORY, claudeWired: true }, /Action Guard in watch only/],
    ];
    for (const [over, phrase] of cases) {
      const row = postureRow(over);
      expect(row.status).toBe('warn');
      expect(row.planeUnread).toBeUndefined();
      const text = render([row]);
      expect(text).toMatch(/Healthy \| nothing to fix/);
      expect(text).toMatch(/EXPECTED ON THIS HOST/);
      expect(text).toMatch(phrase);
      expect(text).not.toMatch(/^TO FIX$/m);
    }
  });

  it('--verbose and --explain print the flagged row in full, as before', () => {
    const row = postureRow({ claudeWired: true, openclaw: UNREADABLE });
    expect(flat(render([row], true))).toMatch(/openclaw\.json could not be read \(EACCES\)/);
    const explained = formatDoctorExplain([row], doctorRowId(row.label), { width: 100, style: PLAIN }).join('\n');
    expect(flat(explained)).toMatch(/openclaw\.json could not be read \(EACCES\)/);
  });
});

// ── GROK ─────────────────────────────────────────────────────────────────────

/** doctor.ts ownershipFix(), verbatim: the one remedy three real checks share. */
const OWNERSHIP_FIX =
  'Those paths exist but this user cannot read them — almost always ShieldCortex state owned by ' +
  'another user, typically root, left behind by one `sudo shieldcortex …` run. Restore ownership: ' +
  '`sudo chown -R "$USER" ~/.shieldcortex` (also `~/.claude-memory` on a legacy install), then ' +
  're-run `shieldcortex doctor`.';

const DENIED: DoctorReportItem[] = [
  { label: 'Database', status: 'fail', message: 'permission denied reading ~/.shieldcortex/memories.db (EACCES)', fix: OWNERSHIP_FIX },
  { label: 'Disk', status: 'fail', message: 'permission denied reading ~/.shieldcortex (EACCES)', fix: OWNERSHIP_FIX },
  { label: 'Brain worker', status: 'fail', message: 'permission denied reading ~/.shieldcortex/state/worker.json (EACCES)', fix: OWNERSHIP_FIX },
];

const dollarLines = (text: string): string[] => text.split('\n').filter((l) => /^\s+\$ /.test(l)).map((l) => l.trim());

describe('#1014 r4 (Grok) — every failed check collapsed under one fix is listed', () => {
  it('three permission-denied FAILs: each label, each path and each id, the chown once, the verdict counts three', () => {
    const text = render(DENIED);
    expect(text).toMatch(/^\[FAIL\] 3 failed checks \| 3 things to fix$/m);
    expect(text).toMatch(/^TO FIX$/m);
    expect(flat(text)).toMatch(/1\. 3 checks cannot read ShieldCortex files/);
    for (const r of DENIED) {
      expect(flat(text)).toContain(`${r.label}: ${r.message}`);
      expect(text).toContain(`[${doctorRowId(r.label)}]`);
    }
    // The shared remedy, once.
    expect(dollarLines(text)).toEqual(['$ sudo chown -R "$USER" ~/.shieldcortex', '$ shieldcortex doctor']);
    // The old item title spoke for the first label only.
    expect(text).not.toMatch(/The memory database cannot be opened|using more disk than its limit/);
    // There is exactly one numbered item.
    expect(text.match(/^ +\d+\. /gm)).toHaveLength(1);
  });

  it('two FAILs sharing any other fix: both labels and both messages, the command once', () => {
    const fix = 'Run `shieldcortex repair` to rebuild the installed dist.';
    const rows: DoctorReportItem[] = [
      { label: 'Hooks', status: 'fail', message: 'pre-tool hook points at a missing dist file', fix },
      { label: 'Attestation coverage', status: 'fail', message: 'the running build is not the installed one', fix },
    ];
    const text = render(rows);
    expect(text).toMatch(/2 failed checks \| 2 things to fix/);
    expect(flat(text)).toMatch(/1\. 2 checks need the same fix/);
    expect(flat(text)).toContain('Hooks: pre-tool hook points at a missing dist file');
    expect(flat(text)).toContain('Attestation coverage: the running build is not the installed one');
    expect(text).toContain('[hooks]');
    expect(text).toContain('[attestation-coverage]');
    expect(dollarLines(text)).toEqual(['$ shieldcortex repair']);
  });

  it('a lone permission-denied Disk FAIL is not described as a disk limit', () => {
    const text = render([DENIED[1]!]);
    expect(text).toMatch(/1 failed check \| 1 thing to fix/);
    expect(flat(text)).toMatch(/1\. Disk: permission denied reading ~\/\.shieldcortex \(EACCES\)/);
    expect(text).not.toMatch(/using more disk than its limit/);
  });

  it('a collapsed item mixes no other row in, and single-row items are unchanged', () => {
    const rows: DoctorReportItem[] = [
      ...DENIED,
      { label: 'Node runtime', status: 'fail', message: 'Node 16 is below the floor. Install Node 20 or newer.' },
    ];
    const text = render(rows);
    expect(text).toMatch(/4 failed checks \| 4 things to fix/);
    expect(text.match(/^ +\d+\. /gm)).toHaveLength(2);
    expect(flat(text)).toMatch(/2\. This Node.js version is not supported/);
  });

  it('--verbose still prints each failed check as its own block', () => {
    const text = render(DENIED, true);
    for (const r of DENIED) expect(text).toContain(r.message);
  });
});

// ── NITS ─────────────────────────────────────────────────────────────────────

describe('#1014 r4 — nits', () => {
  it('a negated by-design phrase is not by design', () => {
    expect(isByDesignWarning({ fixNote: 'This is not expected while Guard is off. Restore the sink.', why: 'the sink vanished' })).toBe(false);
    expect(isByDesignWarning({ fixNote: 'A root lock is not optional while Guard is off here.', why: 'x' })).toBe(false);
    expect(isByDesignWarning({ fixNote: 'Headless denials staying local is expected while Guard is off.', why: 'x' })).toBe(true);
    expect(isByDesignWarning({ fixNote: 'A root lock is optional while Guard is off.', why: 'x' })).toBe(true);
  });

  it('the bare-command scan honours a "do not" clause; a rejection-only fix yields no command', () => {
    expect(extractFixCommands('Do not run `shieldcortex config --action-guard-enable` from this warning.')).toEqual([]);
    expect(extractFixCommands('Do not run shieldcortex config --action-guard-enable from this warning.')).toEqual([]);
    expect(extractFixCommands('Do not panic. Run `shieldcortex setup claude`.')).toEqual(['shieldcortex setup claude']);
    expect(extractFixCommands('Never run shieldcortex repair here; run shieldcortex doctor --verbose instead.'))
      .toEqual(['shieldcortex doctor --verbose']);
  });
});
