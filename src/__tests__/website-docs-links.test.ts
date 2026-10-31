/**
 * Every shieldcortex.ai docs link shipped in the product must target the
 * single-page docs (`/docs` or `/docs#anchor`). Sub-pages such as
 * `/docs/threats/...` or `/docs/integrations` do not exist on the site, so a
 * link to one is a dead "Learn more" in audit findings, SARIF output and the
 * dashboard. Pages that do exist are listed in KNOWN_DOCS_PAGES.
 */
import { readdirSync, readFileSync, statSync } from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..', '..');
const SCAN_DIRS = ['src', path.join('dashboard', 'src')];
const KNOWN_DOCS_PAGES = new Set(['/docs/install', '/docs/upgrading-5']);
const DOCS_LINK = /https:\/\/shieldcortex\.ai(\/docs[A-Za-z0-9/_-]*)/g;

function walk(dir: string, out: string[]): void {
  for (const name of readdirSync(dir)) {
    if (name === 'node_modules' || name === 'dist' || name.startsWith('.')) continue;
    const full = path.join(dir, name);
    if (statSync(full).isDirectory()) walk(full, out);
    else if (/\.(ts|tsx)$/.test(name)) out.push(full);
  }
}

describe('website docs links', () => {
  it('only point at /docs anchors or docs pages that exist', () => {
    const files: string[] = [];
    for (const d of SCAN_DIRS) walk(path.join(REPO_ROOT, d), files);
    expect(files.length).toBeGreaterThan(0);

    const bad: string[] = [];
    for (const f of files) {
      for (const m of readFileSync(f, 'utf8').matchAll(DOCS_LINK)) {
        const p = m[1].replace(/\/$/, '');
        if (p !== '/docs' && !KNOWN_DOCS_PAGES.has(p)) bad.push(`${path.relative(REPO_ROOT, f)}: ${m[0]}`);
      }
    }
    expect(bad).toEqual([]);
  });
});
