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

  it('T3b own false is opted-out whatever else is missing (false-enabled, no notify chat)', () => {
    expect(resolveApproveTapState({ ...good, enabled: false }, false, deps())).toMatchObject({ state: 'opted-out' });
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

  it('T9 inherited enabled never arms and never opts out (own-property read only)', () => {
    const own = { approverTelegramUid: good.approverTelegramUid, secretPath: good.secretPath };
    const viaLiteral = { __proto__: { enabled: true, ...own } };
    const viaSetPrototype = Object.setPrototypeOf({ ...own }, { enabled: true });
    const inheritedFalse = { __proto__: { enabled: false } };
    for (const raw of [viaLiteral, viaSetPrototype, inheritedFalse]) {
      expect(resolveApproveTapState(raw, true, deps())).toMatchObject({ state: 'cannot-arm', missing: 'disabled' });
    }
  });

  it('T10 a JSON "__proto__" key assigned onto a plain object is an inherited enabled: disabled', () => {
    const parsed = JSON.parse('{"__proto__":{"enabled":true},"approverTelegramUid":"123456","secretPath":"/fixture/approve.secret"}');
    const assigned = Object.assign({}, parsed) as Record<string, unknown>;
    expect(Object.hasOwn(assigned, 'enabled')).toBe(false);
    expect(resolveApproveTapState(assigned, true, deps())).toMatchObject({ state: 'cannot-arm', missing: 'disabled' });
    // The raw JSON.parse result has no enabled of its own either.
    expect(resolveApproveTapState(parsed, true, deps())).toMatchObject({ state: 'cannot-arm', missing: 'disabled' });
  });

  it('T11 own false beats inherited true; own true with inherited false still arms', () => {
    const ownFalse = Object.setPrototypeOf({ ...good, enabled: false }, { enabled: true });
    expect(resolveApproveTapState(ownFalse, true, deps())).toMatchObject({ state: 'opted-out' });
    const ownTrue = Object.setPrototypeOf({ ...good, enabled: true }, { enabled: false });
    expect(resolveApproveTapState(ownTrue, true, deps())).toMatchObject({ state: 'armed' });
  });

  it('T12 enabled is read once: an accessor that flips after the first read cannot arm', () => {
    let reads = 0;
    const raw = { approverTelegramUid: good.approverTelegramUid, secretPath: good.secretPath };
    Object.defineProperty(raw, 'enabled', { enumerable: true, get: () => (++reads === 1 ? true : false) });
    const r = resolveApproveTapState(raw, true, deps());
    expect(reads).toBe(1);
    expect(r.state).toBe('armed');
    reads = 0;
    const flipUp = { approverTelegramUid: good.approverTelegramUid, secretPath: good.secretPath };
    Object.defineProperty(flipUp, 'enabled', { enumerable: true, get: () => (++reads === 1 ? 'false' : true) });
    expect(resolveApproveTapState(flipUp, true, deps())).toMatchObject({ state: 'cannot-arm', missing: 'disabled' });
    expect(reads).toBe(1);
  });

  it('T13 notify presence is strict: only boolean true counts', () => {
    for (const notify of [1, 'yes', {}, undefined, null] as unknown as boolean[]) {
      expect(resolveApproveTapState(good, notify, deps())).toMatchObject({ state: 'cannot-arm', missing: 'no-notify-chat' });
    }
  });
});
