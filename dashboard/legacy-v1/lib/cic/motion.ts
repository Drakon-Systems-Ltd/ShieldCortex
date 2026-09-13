/**
 * CIC motion gate.
 *
 * The full-immersive effects (scanline sweep, boot sequence, stream-in, bloom
 * pulses) only run when the user neither prefers reduced motion NOR has enabled
 * the "calm" toggle. This keeps the console usable + accessible — non-negotiable
 * for a paid product.
 */
export const CALM_KEY = 'sc-cic-calm';

/** True if the OS/browser requests reduced motion. SSR/test-safe. */
export function prefersReducedMotion(): boolean {
  if (typeof window === 'undefined' || !window.matchMedia) return false;
  return window.matchMedia('(prefers-reduced-motion: reduce)').matches;
}

/** True if the user has turned on calm mode. SSR/test-safe. */
export function isCalm(): boolean {
  if (typeof window === 'undefined') return false;
  try {
    return window.localStorage.getItem(CALM_KEY) === '1';
  } catch {
    return false;
  }
}

/** Persist the calm preference. SSR/test-safe. */
export function setCalm(calm: boolean): void {
  if (typeof window === 'undefined') return;
  try {
    window.localStorage.setItem(CALM_KEY, calm ? '1' : '0');
    window.dispatchEvent(new Event('cic-calm-change'));
  } catch {
    /* storage unavailable — ignore */
  }
}

/** Pure policy: animate only when neither reduced-motion nor calm is set. */
export function shouldAnimate(reducedMotion: boolean, calm: boolean): boolean {
  return !reducedMotion && !calm;
}

/** Resolve the live decision from the current environment. */
export function cicShouldAnimate(): boolean {
  return shouldAnimate(prefersReducedMotion(), isCalm());
}
