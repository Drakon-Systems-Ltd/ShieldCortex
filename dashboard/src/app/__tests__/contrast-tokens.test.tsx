import fs from 'fs';
import path from 'path';

/**
 * WCAG AA on the `--sc-*` token values themselves (Opus design §3): text
 * 4.5:1, non-text (input borders, focus ring) 3:1, in both themes. Reads
 * globals.css so a token edit that breaks contrast fails here.
 */
const css = fs.readFileSync(path.join(__dirname, '../globals.css'), 'utf8');

function block(selector: string): Record<string, string> {
  const start = css.indexOf(`${selector} {`);
  if (start < 0) throw new Error(`no ${selector} block`);
  const body = css.slice(start, css.indexOf('\n}', start));
  const out: Record<string, string> = {};
  for (const m of body.matchAll(/(--sc-[a-z0-9-]+):\s*(#[0-9a-fA-F]{6})\b/g)) out[m[1]] = m[2];
  return out;
}

function luminance(hex: string): number {
  const c = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255);
  const [r, g, b] = c.map((v) => (v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4));
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

function contrast(a: string, b: string): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
}

const light = block(':root');
const dark = { ...light, ...block('.dark') };

describe.each([['dark', dark], ['light', light]] as const)('%s theme tokens', (_name, t) => {
  const surfaces = ['--sc-bg', '--sc-rail', '--sc-surface', '--sc-surface-2'];
  const text = ['--sc-text', '--sc-text-dim', '--sc-text-muted', '--sc-primary', '--sc-ok', '--sc-warn', '--sc-danger'];

  it.each(text)('%s meets 4.5:1 on every surface', (fg) => {
    const fails = surfaces.filter((bg) => !(contrast(t[fg], t[bg]) >= 4.5)).map((bg) => `${bg} ${contrast(t[fg], t[bg]).toFixed(2)}`);
    expect(fails).toEqual([]);
  });

  it('white button text meets 4.5:1 on the filled-button blue', () => {
    expect(contrast(t['--sc-primary-fg'], t['--sc-primary-fill'])).toBeGreaterThanOrEqual(4.5);
    expect(contrast(t['--sc-primary-fg'], t['--sc-primary-fill-hover'])).toBeGreaterThanOrEqual(4.5);
  });

  it('input borders and the focus ring meet 3:1 (non-text)', () => {
    for (const bg of surfaces) {
      expect(contrast(t['--sc-border-strong'], t[bg])).toBeGreaterThanOrEqual(3);
      expect(contrast(t['--sc-focus'], t[bg])).toBeGreaterThanOrEqual(3);
    }
  });
});

describe('dark is the brand default', () => {
  it('uses the Opus navy and muted-text values', () => {
    expect(dark['--sc-bg']).toBe('#0a0e1a');
    expect(dark['--sc-surface']).toBe('#141c30');
    expect(dark['--sc-text-muted']).toBe('#8fa0c2');
    expect(dark['--sc-primary-fill']).toBe('#2563eb');
  });
});
