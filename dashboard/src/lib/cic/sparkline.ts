const RAMP = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];

/**
 * Render a numeric series as a monospace block-char sparkline (fits the CIC
 * terminal — no SVG). Each value maps to one of eight ramp glyphs by its share
 * of the series max; an all-zero series renders flat-low (no divide-by-zero).
 */
export function sparkline(values: number[]): string {
  if (values.length === 0) return '';
  const max = Math.max(...values);
  if (max <= 0) return RAMP[0].repeat(values.length);
  return values
    .map((v) => RAMP[Math.round((Math.max(0, v) / max) * (RAMP.length - 1))])
    .join('');
}
