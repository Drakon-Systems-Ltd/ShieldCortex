/**
 * #815 S1: the inert three-state resolver. Nothing calls it yet. Every case
 * injects agentUid, lstat and platform; no real host, secret or config value.
 */
import { describe, expect, it } from '@jest/globals';
import {
  checkApproveTapArming,
  normaliseApproveTapConfig,
  resolveApproveTapState,
  type TapArmingDeps,
  type TapStat,
} from '../approve-tap.js';

const AGENT = 1000;
const BRIDGE = 1001;
const good = { enabled: true, approverTelegramUid: '123456', secretPath: '/fixture/approve.secret' };
const stat = (over: Partial<TapStat> = {}): (() => TapStat) => () => ({
  uid: BRIDGE, mode: 0o100600, isFile: true, isSymbolicLink: false, ...over,
});
const deps = (over: TapArmingDeps = {}): TapArmingDeps => ({
  agentUid: AGENT, lstat: stat(), platform: 'linux', ...over,
});
const errno = (code: string) => () => { throw Object.assign(new Error(code), { code }); };

describe('resolveApproveTapState (#815 S1, inert)', () => {
  it('T1 armed: strict true, approver, secret path, other non-root owner at 0600, notify chat', () => {
    expect(resolveApproveTapState(good, true, deps())).toMatchObject({ state: 'armed' });
  });

  it('T2 each single missing precondition names exactly that item', () => {
    const cases: Array<[string, unknown, boolean, TapArmingDeps, string]> = [
      ['no notify chat', good, false, deps(), 'no-notify-chat'],
      ['no approver', { ...good, approverTelegramUid: undefined }, true, deps(), 'no-approver'],
      ['no secret path', { ...good, secretPath: undefined }, true, deps(), 'no-secret-path'],
      ['same uid', good, true, deps({ lstat: stat({ uid: AGENT }) }), 'same-uid'],
      ['mode too wide', good, true, deps({ lstat: stat({ mode: 0o100644 }) }), 'secret-mode'],
      ['root owned', good, true, deps({ lstat: stat({ uid: 0 }) }), 'secret-root-owned'],
      ['symlink', good, true, deps({ lstat: stat({ isSymbolicLink: true }) }), 'secret-symlink'],
      ['missing file', good, true, deps({ lstat: errno('ENOENT') }), 'secret-missing'],
      ['agent is root', good, true, deps({ agentUid: 0 }), 'agent-is-root'],
      ['windows', good, true, deps({ platform: 'win32' }), 'unsupported-platform'],
    ];
    for (const [name, raw, notify, d, missing] of cases) {
      const r = resolveApproveTapState(raw, notify, d);
      expect({ name, state: r.state, missing: r.state === 'cannot-arm' ? r.missing : null })
        .toEqual({ name, state: 'cannot-arm', missing });
    }
  });

  it('T3 strict false is opted-out even when everything else is valid', () => {
    expect(resolveApproveTapState({ ...good, enabled: false }, true, deps())).toMatchObject({ state: 'opted-out' });
  });

  it('T4 absent enabled is cannot-arm/disabled today (S3 changes this one branch to auto)', () => {
    const { enabled: _enabled, ...absent } = good;
    expect(resolveApproveTapState(absent, true, deps())).toMatchObject({ state: 'cannot-arm', missing: 'disabled' });
    expect(resolveApproveTapState(undefined, true, deps())).toMatchObject({ state: 'cannot-arm', missing: 'disabled' });
  });

  it('T5 junk enabled never arms', () => {
    for (const junk of ['true', 1, null, {}]) {
      const r = resolveApproveTapState({ ...good, enabled: junk }, true, deps());
      expect(r).toMatchObject({ state: 'cannot-arm', missing: 'disabled' });
    }
  });

  it('T6 armed implies existing arming is armed and notify chat is present', () => {
    const blocks: unknown[] = [good, { ...good, enabled: false }, { ...good, enabled: 'true' }, { ...good, secretPath: undefined }, {}, null];
    const dependencies = [deps(), deps({ lstat: stat({ uid: AGENT }) }), deps({ lstat: errno('EACCES') }), deps({ agentUid: 0 })];
    for (const raw of blocks) {
      for (const d of dependencies) {
        for (const notify of [true, false]) {
          if (resolveApproveTapState(raw, notify, d).state === 'armed') {
            expect(notify).toBe(true);
            expect(checkApproveTapArming(normaliseApproveTapConfig(raw), d).armed).toBe(true);
          }
        }
      }
    }
  });

  it('T7 inert pins: normaliseApproveTapConfig still defaults enabled to false', () => {
    expect(normaliseApproveTapConfig({}).enabled).toBe(false);
    expect(normaliseApproveTapConfig({ enabled: false }).enabled).toBe(false);
  });

  it('T8 stat not permitted (EACCES) keeps today\'s meaning: armed, secret not visible', () => {
    expect(resolveApproveTapState(good, true, deps({ lstat: errno('EACCES') }))).toMatchObject({ state: 'armed' });
    expect(checkApproveTapArming(normaliseApproveTapConfig(good), deps({ lstat: errno('EACCES') })))
      .toMatchObject({ armed: true, secretVisible: false });
    expect(resolveApproveTapState({ ...good, enabled: 'true' }, true, deps({ lstat: errno('EACCES') })).state).toBe('cannot-arm');
    expect(resolveApproveTapState(good, false, deps({ lstat: errno('EACCES') }))).toMatchObject({ missing: 'no-notify-chat' });
  });
});
