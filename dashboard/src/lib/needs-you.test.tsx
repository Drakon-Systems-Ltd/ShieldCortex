import { needsYouBadge, sourceCountText, summarize, type CountedSource } from './needs-you';

const s = (status: CountedSource['status'], count: number | undefined, atLeast = false): CountedSource => ({ status, count, atLeast });

describe('Needs you counting rules (#692)', () => {
  it('all-clear needs every source confirmed, exact and zero', () => {
    expect(summarize([s('confirmed', 0), s('confirmed', 0), s('confirmed', 0)]).allClear).toBe(true);
    expect(summarize([s('confirmed', 0), s('stale', 0), s('confirmed', 0)]).allClear).toBe(false);
    expect(summarize([s('confirmed', 0), s('unavailable', undefined), s('confirmed', 0)]).allClear).toBe(false);
    expect(summarize([s('confirmed', 0), s('pending', undefined), s('confirmed', 0)]).allClear).toBe(false);
    expect(summarize([s('confirmed', 0), s('confirmed', 0, true), s('confirmed', 0)]).allClear).toBe(false);
  });

  it('never adds a stale count to the total', () => {
    const sum = summarize([s('confirmed', 2), s('stale', 5), s('confirmed', 1)]);
    expect(sum.confirmedTotal).toBe(3);
    expect(sum.exact).toBe(false);
    expect(needsYouBadge(sum)).toEqual({ text: '3+', label: 'at least 3 waiting' });
  });

  it('badge: exact N, floor N+, ? when nothing confirmed but something failed, none otherwise', () => {
    expect(needsYouBadge(summarize([s('confirmed', 2), s('confirmed', 1), s('confirmed', 0)]))).toEqual({ text: '3', label: '3 waiting' });
    expect(needsYouBadge(summarize([s('confirmed', 0), s('confirmed', 20, true), s('confirmed', 0)]))?.text).toBe('20+');
    expect(needsYouBadge(summarize([s('confirmed', 0), s('stale', 4), s('confirmed', 0)]))?.text).toBe('?');
    expect(needsYouBadge(summarize([s('confirmed', 0), s('confirmed', 0), s('confirmed', 0)]))).toBeUndefined();
    expect(needsYouBadge(summarize([s('pending', undefined), s('pending', undefined), s('pending', undefined)]))).toBeUndefined();
  });

  it('section text carries its unit, floors and staleness', () => {
    expect(sourceCountText(s('confirmed', 4), 'pairs')).toBe('4 pairs');
    expect(sourceCountText(s('confirmed', 20, true), 'pairs')).toBe('20+ pairs');
    expect(sourceCountText(s('stale', 4), 'new')).toBe('4 new · last known');
    expect(sourceCountText(s('unavailable', undefined), 'new')).toBe("couldn't load");
    expect(sourceCountText(s('pending', undefined), 'new')).toBe('…');
  });
});
