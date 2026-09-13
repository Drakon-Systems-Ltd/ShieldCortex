/**
 * #472 — setup openclaw must honour OPENCLAW_HOME.
 *
 * Friday's red-team harness found findExtensionsDir() / openClawConfigPath()
 * resolving the operator's real ~/.openclaw and ignoring OPENCLAW_HOME, so a
 * throwaway profile wrote into the live extensions dir. Doctor already
 * mirrors OpenClaw's home-dir.ts (OPENCLAW_HOME > HOME). The installer must
 * do the same.
 *
 * Relative / ~user OPENCLAW_HOME stays unresolvable — we do not probe the
 * process cwd. Relative HOME is allowed (Jest isolation).
 */
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'fs';
import { homedir, tmpdir } from 'os';
import { join } from 'path';

const openclaw = await import('../openclaw.js');

let prevHome: string | undefined;
let prevUserProfile: string | undefined;
let prevOpenclawHome: string | undefined;
let prevSudoUser: string | undefined;
let tmp: string;

beforeEach(() => {
  prevHome = process.env.HOME;
  prevUserProfile = process.env.USERPROFILE;
  prevOpenclawHome = process.env.OPENCLAW_HOME;
  prevSudoUser = process.env.SUDO_USER;
  tmp = mkdtempSync(join(tmpdir(), 'sc-472-home-'));
  delete process.env.SUDO_USER;
  delete process.env.OPENCLAW_HOME;
});

afterEach(() => {
  if (prevHome === undefined) delete process.env.HOME;
  else process.env.HOME = prevHome;
  if (prevUserProfile === undefined) delete process.env.USERPROFILE;
  else process.env.USERPROFILE = prevUserProfile;
  if (prevOpenclawHome === undefined) delete process.env.OPENCLAW_HOME;
  else process.env.OPENCLAW_HOME = prevOpenclawHome;
  if (prevSudoUser === undefined) delete process.env.SUDO_USER;
  else process.env.SUDO_USER = prevSudoUser;
  rmSync(tmp, { recursive: true, force: true });
});

describe('OPENCLAW_HOME override (#472)', () => {
  it('openClawConfigPath uses absolute OPENCLAW_HOME, not os.homedir()', () => {
    const isolated = join(tmp, 'oc-home');
    mkdirSync(join(isolated, '.openclaw'), { recursive: true });
    process.env.OPENCLAW_HOME = isolated;
    process.env.HOME = join(tmp, 'decoy-home');
    mkdirSync(process.env.HOME, { recursive: true });

    const configPath = openclaw.openClawConfigPath();
    expect(configPath).toBe(join(isolated, '.openclaw', 'openclaw.json'));
    expect(configPath).not.toContain(homedir());
    expect(configPath).not.toContain(join(tmp, 'decoy-home'));
  });

  it('findAllHooksDirs does not create ~/.openclaw under the real home when OPENCLAW_HOME is set', () => {
    const isolated = join(tmp, 'oc-home');
    mkdirSync(join(isolated, '.openclaw'), { recursive: true });
    process.env.OPENCLAW_HOME = isolated;
    process.env.HOME = join(tmp, 'decoy-home');
    mkdirSync(process.env.HOME, { recursive: true });

    const dirs = openclaw.findAllHooksDirs();
    expect(dirs.some((d) => d.startsWith(join(isolated, '.openclaw')))).toBe(true);
    expect(dirs.some((d) => d.includes(homedir()))).toBe(false);
  });

  it('relative OPENCLAW_HOME is ignored — never resolved against the process cwd', () => {
    process.env.OPENCLAW_HOME = 'oc-home';
    process.env.HOME = join(tmp, 'real-home');
    mkdirSync(process.env.HOME, { recursive: true });

    const configPath = openclaw.openClawConfigPath();
    expect(configPath).toBe(join(tmp, 'real-home', '.openclaw', 'openclaw.json'));
    expect(configPath).not.toContain('/oc-home/');
  });
});
