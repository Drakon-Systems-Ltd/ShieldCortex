import { shouldAnimate, isCalm, setCalm } from './motion';

describe('CIC motion policy', () => {
  it('animates only when neither reduced-motion nor calm is set', () => {
    expect(shouldAnimate(false, false)).toBe(true);
  });

  it('does not animate when the user prefers reduced motion', () => {
    expect(shouldAnimate(true, false)).toBe(false);
  });

  it('does not animate when calm mode is on', () => {
    expect(shouldAnimate(false, true)).toBe(false);
  });

  it('does not animate when both are set', () => {
    expect(shouldAnimate(true, true)).toBe(false);
  });

  it('round-trips the calm flag through localStorage', () => {
    setCalm(true);
    expect(isCalm()).toBe(true);
    setCalm(false);
    expect(isCalm()).toBe(false);
  });
});
