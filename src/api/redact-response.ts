import type { Request, Response, NextFunction } from 'express';
import { deepRedactRestrictedContent } from '../defence/trust/read-guard.js';

/**
 * Express middleware: deep-redact RESTRICTED (credential-class) memory content
 * from every JSON response the visualization API sends.
 *
 * The dashboard renders in a BROWSER, so a raw credential reaching the DOM is a
 * leak vector (screenshots, screen-shares, disk cache). Memories surface at many
 * nesting depths across the API (`{ memories: [...] }`, recall `results[].memory`,
 * openclaw `sessions[].memories[]`, review-queue `sections.stale[]`,
 * `contradictions[].memoryA`), so a single response interceptor that walks the
 * whole tree is the only way to guarantee none is missed. The row itself stays
 * intact (title/metadata) so the owner can still see/manage it; full content
 * remains available via the CLI, which is not a browser surface.
 */
export function redactRestrictedResponses(_req: Request, res: Response, next: NextFunction): void {
  const originalJson = res.json.bind(res);
  res.json = ((body: unknown) => originalJson(deepRedactRestrictedContent(body))) as typeof res.json;
  next();
}
