#!/usr/bin/env node

import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const thisFile = fileURLToPath(import.meta.url);
const repoRoot = path.resolve(path.dirname(thisFile), '..');

const checkOnly = process.argv.includes('--check');

const rootPkgPath = path.join(repoRoot, 'package.json');
const pluginPkgPath = path.join(repoRoot, 'plugins', 'openclaw', 'package.json');
const pluginManifestPath = path.join(repoRoot, 'plugins', 'openclaw', 'openclaw.plugin.json');

async function readJson(filePath) {
  const raw = await fs.readFile(filePath, 'utf-8');
  return { raw, value: JSON.parse(raw) };
}

async function writeJson(filePath, value) {
  const serialised = JSON.stringify(value, null, 2) + '\n';
  await fs.writeFile(filePath, serialised, 'utf-8');
}

const rootPkg = await readJson(rootPkgPath);
const rootVersion = rootPkg.value.version;

if (typeof rootVersion !== 'string' || rootVersion.length === 0) {
  console.error('[sync-plugin-version] root package.json has no version field');
  process.exit(1);
}

const targets = [
  { label: 'plugins/openclaw/package.json', path: pluginPkgPath },
  { label: 'plugins/openclaw/openclaw.plugin.json', path: pluginManifestPath },
];

let drifted = false;
let changed = false;

for (const target of targets) {
  const current = await readJson(target.path);
  const currentVersion = current.value.version;

  if (currentVersion === rootVersion) {
    console.log(`[sync-plugin-version] ${target.label} in sync at ${rootVersion}`);
    continue;
  }

  drifted = true;

  if (checkOnly) {
    console.error(
      `[sync-plugin-version] ${target.label} out of sync: ${currentVersion} != root ${rootVersion}`,
    );
    continue;
  }

  current.value.version = rootVersion;
  await writeJson(target.path, current.value);
  changed = true;
  console.log(
    `[sync-plugin-version] changed: ${target.label} from ${currentVersion} to ${rootVersion}`,
  );
}

// SKILL.md (the ClawHub skill) is YAML-frontmatter-in-markdown, not JSON, so it
// was never covered above — its metadata.version silently drifted (stuck at 4.41.0
// across several releases). Keep it aligned too. The regex matches the single
// `<indent>version: <value>` frontmatter line; `minVersion:` does not match (the
// char before "version" there is "n", not whitespace).
const skillMdPath = path.join(repoRoot, 'skills', 'shieldcortex', 'SKILL.md');
const SKILL_VERSION_RE = /^(\s+)version:[ \t]*(.+)$/m;
try {
  const raw = await fs.readFile(skillMdPath, 'utf-8');
  const match = raw.match(SKILL_VERSION_RE);
  if (!match) {
    console.error('[sync-plugin-version] skills/shieldcortex/SKILL.md: no metadata version line found');
    process.exit(1);
  }
  const currentVersion = match[2].trim();
  if (currentVersion === rootVersion) {
    console.log(`[sync-plugin-version] skills/shieldcortex/SKILL.md in sync at ${rootVersion}`);
  } else {
    drifted = true;
    if (checkOnly) {
      console.error(
        `[sync-plugin-version] skills/shieldcortex/SKILL.md out of sync: ${currentVersion} != root ${rootVersion}`,
      );
    } else {
      await fs.writeFile(skillMdPath, raw.replace(SKILL_VERSION_RE, `$1version: ${rootVersion}`), 'utf-8');
      changed = true;
      console.log(
        `[sync-plugin-version] changed: skills/shieldcortex/SKILL.md from ${currentVersion} to ${rootVersion}`,
      );
    }
  }
} catch (err) {
  console.error(`[sync-plugin-version] could not read skills/shieldcortex/SKILL.md: ${err.message}`);
  process.exit(1);
}

if (checkOnly && drifted) {
  process.exit(1);
}

if (!checkOnly && !changed) {
  console.log(`[sync-plugin-version] all plugin files already at ${rootVersion}`);
}
