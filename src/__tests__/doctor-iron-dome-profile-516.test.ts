import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';
import Database from 'better-sqlite3';
import { jest } from '@jest/globals';
import { checkIronDomeProfile, ironDomeProfileVerdict, IRON_DOME_PROFILE_LABEL } from '../cli/doctor.js';
import { extractFixCommands, formatDoctorReport } from '../cli/doctor-report.js';
import { DEFAULT_IRON_DOME_CONFIG, IRON_DOME_PROFILES, type IronDomeConfig } from '../defence/iron-dome/config.js';

const stock = (): IronDomeConfig => ({ ...DEFAULT_IRON_DOME_CONFIG, enabled: true });

describe('doctor Iron Dome profile (#516)', () => {
  it('reports an inactive Iron Dome as info', () => {
    expect(ironDomeProfileVerdict(DEFAULT_IRON_DOME_CONFIG)).toMatchObject({
      label: IRON_DOME_PROFILE_LABEL,
      status: 'info',
      message: 'Iron Dome not active — profile not checked',
    });
  });

  it('warns on stock defaults without exposing the kill phrase', () => {
    const result = ironDomeProfileVerdict(stock());
    expect(result.status).toBe('warn');
    expect(result.message).toContain('default kill phrase');
    expect(result.message).toContain('no PII rules');
    expect(result.message).toContain('no sub-agent blocks');
    expect(`${result.message} ${result.fix}`).not.toContain(DEFAULT_IRON_DOME_CONFIG.killPhrase);
    expect(extractFixCommands(result.fix)).toEqual([]);
    expect(result.fix).toContain('school, enterprise, personal or paranoid');
    expect(result.fix).toContain('replaces the whole Iron Dome config, including trusted channels');
    expect(result.fix).toContain('all rule lists');
    expect(result.fix).toContain('dashboard Iron Dome view');
    expect(result.fix).toContain('http://localhost:3030');
    expect(result.fix).toMatch(/3.{0,3}80 chars/);
    expect(result.fix).toMatch(/afterwards/);
  });

  it.each(Object.entries(IRON_DOME_PROFILES))('%s with a custom phrase passes', (_name, profile) => {
    const result = ironDomeProfileVerdict({ ...profile, enabled: true, killPhrase: 'my private stop trigger' });
    expect(result.status).toBe('pass');
    expect(result.message).toContain(profile.profile);
  });

  it('warns only about the phrase on the school profile', () => {
    const result = ironDomeProfileVerdict({ ...IRON_DOME_PROFILES.school, enabled: true });
    expect(result.status).toBe('warn');
    expect(result.message).toContain('default kill phrase');
    expect(result.message).not.toContain('no PII rules');
    expect(result.message).not.toContain('no sub-agent blocks');
    expect(extractFixCommands(result.fix)).toEqual([]);
    expect(result.fix).toContain('dashboard Iron Dome view');
    expect(result.fix).not.toContain('activate');
  });

  it('warns about missing PII rules with prose guidance', () => {
    const result = ironDomeProfileVerdict({ ...stock(), killPhrase: 'my private stop trigger' });
    expect(result.status).toBe('warn');
    expect(result.message).toContain('no PII rules');
    expect(result.message).not.toContain('default kill phrase');
    expect(extractFixCommands(result.fix)).toEqual([]);
    expect(result.fix).toContain('replaces the whole Iron Dome config, including trusted channels');
    expect(result.fix).toContain('dashboard Iron Dome view');
  });

  it.each([
    ['stock', stock()],
    ['school with only the default phrase', { ...IRON_DOME_PROFILES.school, enabled: true }],
  ])('renders %s warning without executable remediation', (_name, config) => {
    const result = ironDomeProfileVerdict(config);
    const report = formatDoctorReport([result], { width: 120 }).join('\n');
    expect(result.status).toBe('warn');
    expect(report).toContain('Iron Dome profile');
    expect(report).toMatch(/dashboard\s+Iron Dome view/);
    expect(report).not.toMatch(/^\s*\$ /m);
    expect(report).not.toContain('iron-dome activate');
    expect(report).not.toContain('curl');
    expect(report).not.toContain('api-token');
    expect(report).not.toContain(DEFAULT_IRON_DOME_CONFIG.killPhrase);
    const nextSection = report.split(/\nNEXT\n/)[1];
    if (nextSection) {
      expect(nextSection).not.toMatch(/iron-dome activate|curl|api-token/);
    }
  });

  it('treats only missing sub-agent blocks as informational within a pass', () => {
    const result = ironDomeProfileVerdict({ ...IRON_DOME_PROFILES.personal, enabled: true, killPhrase: 'my private stop trigger' });
    expect(result.status).toBe('pass');
    expect(result.message).toContain('no sub-agent blocks');
  });

  it('recognises the default phrase despite case and surrounding whitespace', () => {
    const result = ironDomeProfileVerdict({
      ...IRON_DOME_PROFILES.school,
      enabled: true,
      killPhrase: `  ${DEFAULT_IRON_DOME_CONFIG.killPhrase.toUpperCase()}  `,
    });
    expect(result.status).toBe('warn');
    expect(result.message).toContain('default kill phrase');
  });

  it('runs the check right after the action guard rows', () => {
    const source = fs.readFileSync(path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../cli/doctor.ts'), 'utf8');
    expect(source).toMatch(/checkActionGuard,\s*checkActionGuardReadiness,\s*checkIronDomeProfile,\s*checkCronDenials,/);
  });

  describe('reads the persisted config without the database singleton', () => {
    let dir: string;
    beforeEach(() => { dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-doctor-516-')); });
    afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

    function storeWith(config: Partial<IronDomeConfig> | null | string): string {
      const dbPath = path.join(dir, 'memories.db');
      const db = new Database(dbPath);
      db.exec('CREATE TABLE iron_dome_config (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT)');
      const value = typeof config === 'string' ? config : config && JSON.stringify(config);
      if (value) db.prepare('INSERT INTO iron_dome_config (key, value) VALUES (?, ?)').run('config', value);
      db.close();
      return dbPath;
    }

    describe('malformed stored config', () => {
      const MARKER = 'SC516LEAK';
      // V8 quotes this input back verbatim in its SyntaxError message.
      const MALFORMED = `{"killPhrase": ${MARKER}}`;

      it('reports a fixed diagnostic that never echoes the stored config', async () => {
        expect(() => JSON.parse(MALFORMED)).toThrow(MARKER); // the leak this guards against

        const logged: string[] = [];
        const capture = (...args: unknown[]) => { logged.push(args.map(String).join(' ')); };
        const spies = (['log', 'info', 'warn', 'error', 'debug'] as const)
          .map((m) => jest.spyOn(console, m).mockImplementation(capture));
        const stderr = jest.spyOn(process.stderr, 'write').mockImplementation((chunk: unknown) => { logged.push(String(chunk)); return true; });
        let result;
        try {
          result = await checkIronDomeProfile(storeWith(MALFORMED));
        } finally {
          spies.forEach((s) => s.mockRestore());
          stderr.mockRestore();
        }

        expect(result).toEqual({
          label: IRON_DOME_PROFILE_LABEL,
          status: 'info',
          message: 'could not read Iron Dome profile — stored config unreadable',
        });
        expect(logged.join('\n')).not.toContain(MARKER);

        const human = formatDoctorReport([result], { width: 200 }).join('\n');
        const verbose = formatDoctorReport([result], { width: 200, verbose: true }).join('\n');
        // Same mapping runDoctor uses for `--json`.
        const json = JSON.stringify({ results: [result].map((r) => ({ label: r.label, status: r.status, message: r.message, fix: r.fix })) });
        expect(verbose).toContain('stored config unreadable');
        for (const output of [human, verbose, json]) {
          expect(output).not.toContain(MARKER);
          expect(output).not.toContain('killPhrase');
          expect(output).not.toContain('is not valid JSON');
        }
      });
    });

    // `iron-dome activate` with no profile persists exactly this; doctor must see it.
    it('warns on an activated stock profile', async () => {
      const result = await checkIronDomeProfile(storeWith(stock()));
      expect(result.status).toBe('warn');
      expect(result.message).toContain('default kill phrase');
      expect(result.message).toContain('no PII rules');
    });

    it('passes on a configured profile', async () => {
      const result = await checkIronDomeProfile(storeWith({ ...IRON_DOME_PROFILES.school, enabled: true, killPhrase: 'my private stop trigger' }));
      expect(result.status).toBe('pass');
    });

    it('is informational when nothing is stored or the store is missing', async () => {
      expect((await checkIronDomeProfile(storeWith(null))).status).toBe('info');
      expect((await checkIronDomeProfile(path.join(dir, 'absent.db'))).status).toBe('info');
    });

    it('opens the store read-only', async () => {
      const dbPath = storeWith(stock());
      const before = fs.readFileSync(dbPath);
      await checkIronDomeProfile(dbPath);
      expect(fs.readFileSync(dbPath).equals(before)).toBe(true);
    });
  });
});
