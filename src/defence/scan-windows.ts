/**
 * Overlapping windowed scanning.
 *
 * Several detectors used to truncate input to the first SCAN_WINDOW_SIZE chars
 * before running their regex patterns. Because the surrounding scanners accept
 * much larger inputs (file-scanner allows up to 10MB), an attacker could prepend
 * >50KB of benign filler to push the real payload past the cap so it was never
 * scanned.
 *
 * These helpers scan the WHOLE input as a series of fixed-size windows. Each
 * window is at most SCAN_WINDOW_SIZE chars, so per-regex work stays bounded —
 * this preserves the same ReDoS guarantee the old truncation gave us. Windows
 * overlap by SCAN_WINDOW_OVERLAP so a pattern straddling a window boundary is
 * still caught (the largest patterns in the codebase span at most ~1000 chars
 * via [\s\S]{0,N} caps, well under the 2000-char overlap).
 *
 * The common small-input case (content <= SCAN_WINDOW_SIZE) calls the callback
 * exactly once on the whole string — no slicing, no allocation overhead.
 */

/** Maximum chars per window — keeps each regex test bounded (ReDoS guard). */
export const SCAN_WINDOW_SIZE = 50000;

/**
 * Overlap between consecutive windows. Must exceed the longest possible match so
 * a pattern straddling a boundary is fully contained in at least one window.
 */
export const SCAN_WINDOW_OVERLAP = 2000;

/** Stride between window starts. */
const STEP = SCAN_WINDOW_SIZE - SCAN_WINDOW_OVERLAP;

/**
 * Invoke `fn(window, start)` for each overlapping window of `content`, in order,
 * stopping early if `fn` returns `true`. `start` is the window's char offset in
 * the original content (so callers that need absolute positions — e.g. line
 * numbers — can recover them). Returns `true` if any window short-circuited.
 *
 * For the common small case (content <= SCAN_WINDOW_SIZE) the callback is called
 * once with the whole string and start = 0, avoiding any copy.
 */
export function forEachWindow(
  content: string,
  fn: (window: string, start: number) => boolean | void,
): boolean {
  if (content.length <= SCAN_WINDOW_SIZE) {
    return fn(content, 0) === true;
  }

  for (let start = 0; start < content.length; start += STEP) {
    const window = content.slice(start, start + SCAN_WINDOW_SIZE);
    if (fn(window, start) === true) {
      return true;
    }
    // The final window already reaches the end of content; stop so we don't
    // emit a redundant trailing window.
    if (start + SCAN_WINDOW_SIZE >= content.length) {
      break;
    }
  }
  return false;
}

/**
 * Returns `true` if `predicate` matches ANY window of `content`. Short-circuits
 * on the first matching window.
 */
export function someWindow(
  content: string,
  predicate: (window: string) => boolean,
): boolean {
  return forEachWindow(content, (window) => predicate(window));
}
