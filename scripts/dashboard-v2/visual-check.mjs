#!/usr/bin/env node
/**
 * Dashboard v2 visual verification harness (Playwright).
 *
 * Drives every dashboard route at the given themes and viewports against a
 * locally running fixture dashboard (see docs/design brief §11), captures
 * screenshots, and records console errors + failed requests per page.
 * Fails (exit 1) when any page logs a console error, unless --no-fail.
 *
 * Usage:
 *   node scripts/dashboard-v2/visual-check.mjs \
 *     --out docs/design/dashboard-v2-screenshots/baseline \
 *     --themes terminal,glass --label baseline
 *
 * Uses the machine-level Playwright install (/home/ubuntu/node_modules) —
 * nothing is installed into this repo.
 */

import { createRequire } from 'module';
import { mkdirSync, writeFileSync } from 'fs';
import { join, resolve } from 'path';

const require = createRequire('/home/ubuntu/node_modules/');
const { chromium } = require('playwright');

const args = process.argv.slice(2);
const opt = (name, dflt) => {
  const i = args.indexOf(`--${name}`);
  return i >= 0 && args[i + 1] ? args[i + 1] : dflt;
};
const outDir = resolve(opt('out', 'docs/design/dashboard-v2-screenshots/run'));
const base = opt('base', 'http://127.0.0.1:3030');
const themes = opt('themes', 'light,dark').split(',');
const label = opt('label', 'run');
const failOnError = !args.includes('--no-fail');
const routes = opt('routes',
  '/overview,/memory,/memory?tab=graph,/memory?tab=recall,/memory?tab=review,/memory?tab=timeline,/memory?tab=files,/memory/replay,/protection,/protection/intercepts,/protection/audit,/protection/quarantine,/protection/policies,/xray,/settings'
).split(',');
const viewports = [
  { name: '1440x900', width: 1440, height: 900 },
  { name: '390x844', width: 390, height: 844 },
];

const slug = (s) => s.replace(/[/?=&]+/g, '_').replace(/^_+|_+$/g, '') || 'root';

const run = async () => {
  mkdirSync(outDir, { recursive: true });
  const browser = await chromium.launch();
  const report = [];
  let errorCount = 0;

  for (const theme of themes) {
    for (const vp of viewports) {
      const context = await browser.newContext({
        viewport: { width: vp.width, height: vp.height },
        reducedMotion: 'no-preference',
      });
      // Persisted theme is applied pre-hydration from localStorage `sc-theme`.
      await context.addInitScript((t) => {
        try { window.localStorage.setItem('sc-theme', t); } catch { /* noop */ }
      }, theme);

      for (const route of routes) {
        const page = await context.newPage();
        const consoleErrors = [];
        const failedRequests = [];
        page.on('console', (msg) => {
          const text = msg.text();
          // next-dev HMR websocket handshake noise is a dev-server artifact,
          // not an app error; production (standalone) runs have no HMR.
          if (text.includes('_next/webpack-hmr')) return;
          if (msg.type() === 'error') consoleErrors.push(text.slice(0, 500));
        });
        page.on('pageerror', (err) => consoleErrors.push(`pageerror: ${String(err).slice(0, 500)}`));
        page.on('requestfailed', (req) => {
          failedRequests.push(`${req.method()} ${req.url()} :: ${req.failure()?.errorText}`);
        });

        const entry = { label, theme, viewport: vp.name, route, ok: false, consoleErrors, failedRequests };
        try {
          await page.goto(base + route, { waitUntil: 'networkidle', timeout: 45000 });
          await page.waitForTimeout(2500); // graph warm-up / late queries
          const file = join(outDir, `${slug(route)}--${theme}--${vp.name}.png`);
          await page.screenshot({ path: file, fullPage: false });
          entry.screenshot = file;
          // Token audit: no --cic-/--term- custom properties resolving on body.
          entry.residualLegacyTokens = await page.evaluate(() => {
            const styles = getComputedStyle(document.documentElement);
            const hits = [];
            for (const name of ['--cic-void', '--cic-cyan', '--term-bg', '--term-electric']) {
              if (styles.getPropertyValue(name).trim() !== '') hits.push(name);
            }
            return hits;
          });
          entry.ok = consoleErrors.length === 0;
        } catch (err) {
          entry.error = String(err).slice(0, 500);
        }
        if (!entry.ok) errorCount++;
        report.push(entry);
        console.log(`[visual] ${theme} ${vp.name} ${route} → ${entry.ok ? 'ok' : 'ERRORS'}${entry.error ? ' (' + entry.error.slice(0, 120) + ')' : ''}${consoleErrors.length ? ' console:' + consoleErrors.length : ''}`);
        await page.close();
      }
      await context.close();
    }
  }

  await browser.close();
  const reportPath = join(outDir, `report-${label}.json`);
  writeFileSync(reportPath, JSON.stringify(report, null, 2));
  const bad = report.filter((r) => !r.ok);
  console.log(`[visual] ${report.length} pages, ${bad.length} with errors → ${reportPath}`);
  if (bad.length && failOnError) process.exit(1);
};

run().catch((err) => { console.error(err); process.exit(1); });
