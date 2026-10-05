import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';
import Database from 'better-sqlite3';
import { checkIronDomeProfile, ironDomeProfileVerdict, IRON_DOME_PROFILE_LABEL } from '../cli/doctor.js';
import { extractFixCommands } from '../cli/doctor-report.js';
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
    expect(result.fix).toContain('shieldcortex iron-dome activate --profile <school|enterprise|personal|paranoid>');
    const commands = extractFixCommands(result.fix);
    expect(commands).toContain('shieldcortex iron-dome activate --profile <school|enterprise|personal|paranoid>');
    const curl = commands.find((c) => c.startsWith('curl -X POST http://localhost:3001/api/iron-dome/config'));
    expect(curl).toBeDefined();
    // The API is bearer-gated: a fix command without the session token would 401.
    expect(curl).toContain('Authorization: Bearer $(cat ~/.shieldcortex/.api-token)');
    expect(curl).toContain(`-d '{"killPhrase":"<your phrase>"}'`);
    expect(result.fix).toContain('dashboard Iron Dome view');
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
  });

  it('warns about missing PII rules and gives the activation command', () => {
    const result = ironDomeProfileVerdict({ ...stock(), killPhrase: 'my private stop trigger' });
    expect(result.status).toBe('warn');
    expect(result.message).toContain('no PII rules');
    expect(result.message).not.toContain('default kill phrase');
    expect(result.fix).toContain('shieldcortex iron-dome activate --profile <school|enterprise|personal|paranoid>');
    expect(result.fix).toContain('curl -X POST http://localhost:3001/api/iron-dome/config');
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

  it('runs the check immediately after the action guard', () => {
    const source = fs.readFileSync(path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../cli/doctor.ts'), 'utf8');
    expect(source).toMatch(/checkActionGuard,\s*checkIronDomeProfile,\s*checkCronDenials,/);
  });

  describe('reads the persisted config without the database singleton', () => {
    let dir: string;
    beforeEach(() => { dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-doctor-516-')); });
    afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

    function storeWith(config: Partial<IronDomeConfig> | null): string {
      const dbPath = path.join(dir, 'memories.db');
      const db = new Database(dbPath);
      db.exec('CREATE TABLE iron_dome_config (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT)');
      if (config) db.prepare('INSERT INTO iron_dome_config (key, value) VALUES (?, ?)').run('config', JSON.stringify(config));
      db.close();
      return dbPath;
    }

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
