/**
 * Hermes plugin installer.
 *
 * Copies plugins/hermes/shieldcortex into ~/.hermes/plugins/shieldcortex
 * and tells the operator what is actually bound: pre_tool_call via the
 * local Action Guard API. Not a conversation gate. Not a freeze plane
 * until Hermes consults DECISIONS.md (it does not, today).
 */

import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';
import { scanHermesPluginCopies } from './hermes-plugins.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

function pluginSourceDir(): string {
  // dist/setup/hermes.js → repo-or-package root / plugins/hermes/shieldcortex
  return path.resolve(__dirname, '..', '..', 'plugins', 'hermes', 'shieldcortex');
}

function hermesHomeDir(home: string = os.homedir()): string {
  return path.join(home, '.hermes');
}

function pluginDestDir(home: string = os.homedir()): string {
  return path.join(hermesHomeDir(home), 'plugins', 'shieldcortex');
}

/**
 * #569: a copy of the plugin left beside the one we just wrote is loaded
 * INSTEAD of it. Hermes keys plugins on the manifest `name:`, walks `plugins/`
 * in sorted order, and lets the later manifest win silently — so
 * `plugins/shieldcortex.bak-pre510-<ts>/`, the obvious thing to make before an
 * upgrade, sorts after `plugins/shieldcortex/` and wins. The install then
 * reports success while the gateway keeps running the old code.
 *
 * WARN only, and only on Hermes' own discovery (#569 r4). The copies are the
 * operator's and which one they meant to keep is not ours to decide
 * mid-install; and where Hermes cannot be asked there is no answer to give, so
 * the installer stays SILENT rather than dressing a guess up as a caveat. An
 * operator who wants to know either way runs `shieldcortex doctor`, whose job
 * is to report "could not determine" and say how to fix that; the tail of an
 * install log is not the place to learn it.
 *
 * Scans the tree we just wrote to (`<home>/.hermes`), not `HERMES_HOME`,
 * because that is where `pluginDestDir` put the bytes — so the scan runs under
 * an environment with `HERMES_HOME` UNSET, and Hermes' own resolution then
 * lands on exactly that default home rather than wherever the operator's shell
 * points (#569 r5).
 *
 * Two things it is careful not to overstate (#569 r7). A copy that sorts
 * BEFORE `shieldcortex` — `old-shieldcortex` — does not win, so it is reported
 * as a duplicate to clear up rather than as an install that is not running. And
 * a copy in an enabled project directory DOES win, over every user root, so it
 * is named as the loaded one even though nothing here or in the doctor will
 * ever move it.
 */
function warnOnShadowingCopies(home: string): void {
  let scan: ReturnType<typeof scanHermesPluginCopies>;
  try {
    scan = scanHermesPluginCopies({ home, hermesHome: null });
  } catch {
    // A scan that cannot run must never fail an otherwise-good install.
    return;
  }
  if (!scan.fromHermes) return;
  const projectCopies = scan.project.enabled ? scan.project.copies : [];
  const shadowedRoots = scan.roots.filter((r) => r.shadowed && r.loaded !== null);
  if (shadowedRoots.length === 0 && projectCopies.length === 0) return;

  // Whether the copy Hermes loads is the one just installed (#569 r7 nit 3). A
  // backup named `old-shieldcortex` sorts BEFORE `shieldcortex`, so the install
  // does run — the duplicate is a trap for the next rename, not a live
  // downgrade, and saying otherwise sends an operator hunting a fault that is
  // not there. A project copy, on the other hand, outranks every user root.
  const misloading =
    shadowedRoots.some((r) => !r.loaded!.canonical) || projectCopies.length > 0;

  console.warn();
  console.warn(
    misloading
      ? '⚠️  Hermes is loading a different `shieldcortex` copy than the one just installed.'
      : '⚠️  Duplicate `shieldcortex` plugin copies are visible to Hermes.',
  );
  for (const rootScan of shadowedRoots) {
    for (const copy of rootScan.copies) {
      const mark = copy.dir === rootScan.loaded!.dir ? '  → LOADED BY HERMES' : '';
      console.warn(`      ${copy.dir}${mark}`);
    }
  }
  for (const copy of projectCopies) {
    console.warn(`      ${copy.dir}  → PROJECT PLUGIN, LOADED BY HERMES`);
  }
  console.warn('    Hermes keys plugins on the manifest `name:` and the last one in sorted');
  if (misloading) {
    console.warn('    order wins silently — so the copy marked above is what runs, not what');
    console.warn('    was just installed.');
  } else {
    console.warn('    order wins silently. The copy just installed is still the one loaded,');
    console.warn('    because the extras sort before it — but the next backup that sorts');
    console.warn('    after it would take over with nothing said.');
  }
  if (projectCopies.length > 0) {
    console.warn('    HERMES_ENABLE_PROJECT_PLUGINS is enabled, and Hermes scans the project');
    console.warn('    directory AFTER the user plugins. Nothing moves that copy for you:');
    console.warn('    what belongs in a project tree is the project owner\'s call.');
  }
  console.warn('    Fix:  shieldcortex doctor --fix-hermes-plugin-copies');
  console.warn('    Then restart the Hermes gateway — discovery only re-runs at start-up.');
  console.warn();
}

function copyDir(src: string, dest: string): void {
  fs.mkdirSync(dest, { recursive: true });
  for (const entry of fs.readdirSync(src, { withFileTypes: true })) {
    if (entry.name === '__pycache__' || entry.name === '.pytest_cache' || entry.name === 'tests') {
      continue;
    }
    const from = path.join(src, entry.name);
    const to = path.join(dest, entry.name);
    if (entry.isDirectory()) {
      copyDir(from, to);
    } else {
      fs.copyFileSync(from, to);
    }
  }
}

export function hermesPluginInstalled(home: string = os.homedir()): boolean {
  return fs.existsSync(path.join(pluginDestDir(home), 'plugin.yaml'));
}

export async function installHermes(home: string = os.homedir()): Promise<void> {
  const src = pluginSourceDir();
  if (!fs.existsSync(path.join(src, 'plugin.yaml'))) {
    console.error('Hermes plugin source not found. Package may be missing plugins/hermes.');
    console.error(`Expected: ${src}`);
    process.exit(1);
  }

  const dest = pluginDestDir(home);
  copyDir(src, dest);
  console.log(`✓ Hermes — plugin copied to ${dest}`);
  console.log();
  console.log('This is a tool gate (pre_tool_call → POST /api/v1/action-guard).');
  console.log('Action Guard stays off in ShieldCortex until you enable it on purpose.');
  console.log('Requires a running local API:  shieldcortex api   (http://127.0.0.1:3001)');
  console.log('Enable in Hermes:              hermes plugins enable shieldcortex');
  console.log('Conversation / freeze:         NOT bound on this plane.');

  // Last, so it is the final thing on screen rather than scrolled past.
  warnOnShadowingCopies(home);
}

export async function uninstallHermes(home: string = os.homedir()): Promise<void> {
  const dest = pluginDestDir(home);
  if (!fs.existsSync(dest)) {
    console.log('Hermes plugin was not installed.');
    return;
  }
  fs.rmSync(dest, { recursive: true, force: true });
  console.log(`✓ Hermes — removed ${dest}`);
}

export async function hermesStatus(home: string = os.homedir()): Promise<void> {
  const src = pluginSourceDir();
  const dest = pluginDestDir(home);
  console.log(`Hermes plugin dest: ${dest}`);
  console.log(`  Installed: ${hermesPluginInstalled(home) ? 'yes' : 'no'}`);
  console.log(`  Source: ${src}`);
  console.log(`  Source present: ${fs.existsSync(path.join(src, 'plugin.yaml')) ? 'yes' : 'no'}`);
  console.log('  Tool gate: bound after `hermes plugins enable shieldcortex` + local API up');
  console.log('  Turn gate / freeze: not bound');
}

export async function handleHermesCommand(subcommand: string): Promise<void> {
  console.log();
  switch (subcommand) {
    case 'install':
      await installHermes();
      break;
    case 'uninstall':
      await uninstallHermes();
      break;
    case 'status':
      await hermesStatus();
      break;
    default:
      console.log('Usage: shieldcortex hermes <install|uninstall|status>');
      console.log();
      console.log('Installs the Hermes pre_tool_call plugin (Action Guard).');
      console.log('This is a deny plane. Codex/Cursor MCP install is not.');
      process.exit(1);
  }
}
