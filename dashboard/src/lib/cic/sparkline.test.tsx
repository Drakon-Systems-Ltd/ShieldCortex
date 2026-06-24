import { sparkline } from './sparkline';

describe('sparkline', () => {
  it('returns an empty string for no data', () => {
    expect(sparkline([])).toBe('');
  });

  it('renders one block per value', () => {
    expect(sparkline([1, 2, 3]).length).toBe(3);
  });

  it('maps the max value to the tallest block and uses only ramp glyphs', () => {
    const out = sparkline([0, 1, 2, 3, 4, 5, 6, 7]);
    expect(out.endsWith('█')).toBe(true);
    expect([...out].every((c) => '▁▂▃▄▅▆▇█'.includes(c))).toBe(true);
  });

  it('renders an all-zero series as the flat low ramp (no divide-by-zero)', () => {
    expect(sparkline([0, 0, 0])).toBe('▁▁▁');
  });

  it('renders a single value as one block', () => {
    expect(sparkline([5])).toBe('█');
  });
});
