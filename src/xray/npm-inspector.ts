/**
 * X-Ray NPM Package Inspector
 *
 * Downloads package metadata from registry.npmjs.org, analyses it for risk
 * signals, and optionally scans the tarball contents (Pro/deep scan).
 * Uses only Node.js built-ins (https module) — no new dependencies.
 */

import https from 'https';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { createGunzip } from 'zlib';

import type { XRayFinding, XRayResult } from './types.js';
import { detectPatterns } from './patterns.js';
import { calculateTrustScore } from './trust-score.js';
import { scanFile } from './file-scanner.js';

// ── Constants ───────────────────────────────────────────────

/** Popular npm packages for typosquat comparison. */
const POPULAR_PACKAGES = [
  'react', 'express', 'lodash', 'axios', 'chalk', 'commander', 'debug',
  'webpack', 'typescript', 'next', 'vue', 'angular', 'moment', 'request',
  'underscore', 'async', 'bluebird', 'uuid', 'dotenv', 'cors', 'ws',
  'body-parser', 'mongoose', 'yargs', 'inquirer', 'glob', 'rimraf',
  'eslint', 'prettier', 'jest', 'mocha', 'chai', 'sinon', 'nodemon',
  'babel', 'rollup', 'vite', 'esbuild', 'fastify', 'koa', 'hapi',
  'socket.io', 'passport', 'jsonwebtoken', 'bcrypt', 'mysql', 'pg',
  'redis', 'mongodb', 'sequelize', 'prisma', 'graphql', 'apollo',
];

// ── Helpers ─────────────────────────────────────────────────

/**
 * Simple HTTPS GET returning the response body as a string.
 */
function httpsGet(url: string): Promise<string> {
  return new Promise((resolve, reject) => {
    https.get(url, { headers: { 'Accept': 'application/json' } }, (res) => {
      if (res.statusCode && res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        httpsGet(res.headers.location).then(resolve, reject);
        return;
      }
      if (res.statusCode !== 200) {
        reject(new Error(`HTTP ${res.statusCode} for ${url}`));
        res.resume();
        return;
      }
      const chunks: Buffer[] = [];
      res.on('data', (chunk: Buffer) => chunks.push(chunk));
      res.on('end', () => resolve(Buffer.concat(chunks).toString('utf-8')));
      res.on('error', reject);
    }).on('error', reject);
  });
}

/**
 * Download a tarball to a temp file and return the path.
 */
function downloadTarball(url: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const tmpFile = path.join(os.tmpdir(), `shieldcortex-xray-${Date.now()}.tgz`);
    const file = fs.createWriteStream(tmpFile);

    const doGet = (targetUrl: string) => {
      https.get(targetUrl, (res) => {
        if (res.statusCode && res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          doGet(res.headers.location);
          return;
        }
        if (res.statusCode !== 200) {
          reject(new Error(`HTTP ${res.statusCode} downloading tarball`));
          res.resume();
          return;
        }
        res.pipe(file);
        file.on('finish', () => {
          file.close();
          resolve(tmpFile);
        });
      }).on('error', reject);
    };

    doGet(url);
  });
}

/**
 * Extract a .tgz to a temp directory using Node built-ins (zlib + tar parsing).
 * Returns path to the extracted directory.
 */
async function extractTarball(tgzPath: string): Promise<string> {
  const extractDir = path.join(os.tmpdir(), `shieldcortex-xray-extract-${Date.now()}`);
  fs.mkdirSync(extractDir, { recursive: true });

  return new Promise((resolve, reject) => {
    const gunzip = createGunzip();
    const input = fs.createReadStream(tgzPath);
    const chunks: Buffer[] = [];

    input.pipe(gunzip);
    gunzip.on('data', (chunk: Buffer) => chunks.push(chunk));
    gunzip.on('end', () => {
      try {
        const tarData = Buffer.concat(chunks);
        extractTarBuffer(tarData, extractDir);
        resolve(extractDir);
      } catch (err) {
        reject(err);
      }
    });
    gunzip.on('error', reject);
    input.on('error', reject);
  });
}

/**
 * Minimal tar extraction from a buffer. Handles ustar format.
 */
function extractTarBuffer(buf: Buffer, outDir: string): void {
  let offset = 0;

  while (offset < buf.length - 512) {
    // Read header (512 bytes)
    const header = buf.subarray(offset, offset + 512);

    // Check for empty block (end of archive)
    if (header.every(b => b === 0)) break;

    // Extract filename (0-100 bytes, null-terminated)
    const nameEnd = header.indexOf(0, 0);
    const name = header.subarray(0, Math.min(nameEnd, 100)).toString('utf-8');

    // Extract file size (octal, bytes 124-136)
    const sizeStr = header.subarray(124, 136).toString('utf-8').trim();
    const size = parseInt(sizeStr, 8) || 0;

    // Extract type flag (byte 156)
    const typeFlag = header[156];

    // Prefix field for ustar (bytes 345-500)
    const prefixEnd = header.indexOf(0, 345);
    const prefix = header.subarray(345, Math.min(prefixEnd, 500)).toString('utf-8');

    const fullName = prefix ? `${prefix}/${name}` : name;

    // Path traversal protection: resolve and verify the target stays within outDir
    const filePath = path.resolve(outDir, fullName);
    const resolvedOutDir = path.resolve(outDir);
    if (!filePath.startsWith(resolvedOutDir + path.sep) && filePath !== resolvedOutDir) {
      // Malicious entry trying to escape extraction directory — skip it
      offset += 512 + Math.ceil(size / 512) * 512;
      continue;
    }

    offset += 512; // Move past header

    if (typeFlag === 48 || typeFlag === 0) { // Regular file ('0' or null)
      if (size > 0) {
        const dir = path.dirname(filePath);
        fs.mkdirSync(dir, { recursive: true });
        const fileData = buf.subarray(offset, offset + size);
        fs.writeFileSync(filePath, fileData);
      }
    } else if (typeFlag === 53) { // Directory ('5')
      fs.mkdirSync(filePath, { recursive: true });
    }

    // Advance past data blocks (rounded up to 512 boundary)
    offset += Math.ceil(size / 512) * 512;
  }
}

/**
 * Levenshtein edit distance between two strings.
 */
function editDistance(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));

  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] = a[i - 1] === b[j - 1]
        ? dp[i - 1][j - 1]
        : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
    }
  }

  return dp[m][n];
}

// ── Public API ──────────────────────────────────────────────

/**
 * Inspect an npm package for hidden risk.
 *
 * @param packageName - npm package name (e.g. "lodash", "@scope/pkg")
 * @param deep - If true, downloads and scans the tarball (Pro feature)
 */
export async function inspectNpmPackage(packageName: string, deep: boolean = false): Promise<XRayResult> {
  const startTime = Date.now();
  const findings: XRayFinding[] = [];
  let filesScanned = 0;

  // Fetch package metadata
  const encodedName = packageName.startsWith('@')
    ? `@${encodeURIComponent(packageName.slice(1))}`
    : encodeURIComponent(packageName);

  let meta: Record<string, unknown>;
  try {
    const raw = await httpsGet(`https://registry.npmjs.org/${encodedName}`);
    meta = JSON.parse(raw);
  } catch (err) {
    const errMsg = err instanceof Error ? err.message : String(err);
    findings.push({
      severity: 'info',
      category: 'dependency-risk',
      title: 'Failed to fetch package metadata',
      description: `Could not fetch metadata from npm registry: ${errMsg}`,
    });
    const { score, riskLevel } = calculateTrustScore(findings);
    return {
      target: packageName,
      trustScore: score,
      riskLevel,
      findings,
      filesScanned: 0,
      scannedAt: new Date(),
      deepScan: deep,
    };
  }

  // Check maintainer count
  const maintainers = meta.maintainers as Array<{ name: string }> | undefined;
  if (maintainers && maintainers.length === 1) {
    findings.push({
      severity: 'low',
      category: 'dependency-risk',
      title: 'Single maintainer',
      description: 'Package has only one maintainer, increasing bus factor risk.',
    });
  }

  // Check publish frequency / time
  const time = meta.time as Record<string, string> | undefined;
  if (time) {
    const versions = Object.keys(time).filter(k => k !== 'created' && k !== 'modified');
    const created = new Date(time.created || '');
    const lastPublish = versions.length > 0 ? new Date(time[versions[versions.length - 1]]) : null;

    // Recently created with very few versions — potential typosquat
    if (lastPublish && versions.length <= 2) {
      const ageMs = Date.now() - created.getTime();
      const ageDays = ageMs / (1000 * 60 * 60 * 24);
      if (ageDays < 30) {
        findings.push({
          severity: 'medium',
          category: 'dependency-risk',
          title: 'Very new package with few versions',
          description: `Package was created ${Math.round(ageDays)} days ago with only ${versions.length} version(s).`,
        });
      }
    }
  }

  // Check latest version metadata
  const distTags = meta['dist-tags'] as Record<string, string> | undefined;
  const latestVersion = distTags?.latest;
  const versions = meta.versions as Record<string, Record<string, unknown>> | undefined;
  const latestMeta = latestVersion && versions ? versions[latestVersion] : null;

  if (latestMeta) {
    // Check scripts
    const scripts = latestMeta.scripts as Record<string, string> | undefined;
    if (scripts) {
      for (const hook of ['preinstall', 'install', 'postinstall']) {
        if (scripts[hook]) {
          const val = scripts[hook];
          findings.push({
            severity: 'medium',
            category: 'persistence-hook',
            title: `Has ${hook} script`,
            description: `Package defines a "${hook}" lifecycle script.`,
            evidence: val.slice(0, 120),
          });

          if (/curl|wget|node\s+-e|bash\s+-c|powershell|https?:\/\/|eval|exec/i.test(val)) {
            findings.push({
              severity: 'high',
              category: 'persistence-hook',
              title: `Suspicious ${hook} script`,
              description: `The "${hook}" script executes potentially dangerous commands.`,
              evidence: val.slice(0, 120),
            });
          }
        }
      }
    }

    // Check description/keywords for AI directives
    const description = latestMeta.description as string | undefined;
    if (description) {
      const descFindings = detectPatterns(JSON.stringify({ description }));
      findings.push(...descFindings);
    }

    const keywords = latestMeta.keywords as string[] | undefined;
    if (keywords) {
      const kwFindings = detectPatterns(JSON.stringify({ keywords }));
      findings.push(...kwFindings);
    }

    // Check dependency count
    const deps = latestMeta.dependencies as Record<string, string> | undefined;
    if (deps && Object.keys(deps).length > 50) {
      findings.push({
        severity: 'low',
        category: 'dependency-risk',
        title: 'High dependency count',
        description: `Package has ${Object.keys(deps).length} direct dependencies, increasing attack surface.`,
      });
    }
  }

  // Typosquatting check
  const baseName = packageName.replace(/^@[^/]+\//, '');
  for (const popular of POPULAR_PACKAGES) {
    if (baseName === popular) break; // It IS the popular package
    const dist = editDistance(baseName, popular);
    if (dist > 0 && dist <= 2) {
      findings.push({
        severity: 'high',
        category: 'dependency-risk',
        title: 'Possible typosquat',
        description: `Package name "${packageName}" is ${dist} edit(s) from popular package "${popular}".`,
        evidence: `edit distance: ${dist}`,
      });
      break;
    }
  }

  // Deep scan: download and scan tarball
  if (deep && latestMeta) {
    const dist = latestMeta.dist as { tarball?: string } | undefined;
    if (dist?.tarball) {
      try {
        const tgzPath = await downloadTarball(dist.tarball);
        try {
          const extractDir = await extractTarball(tgzPath);
          try {
            // Walk and scan extracted files
            const extractedFiles = walkExtracted(extractDir);
            filesScanned = extractedFiles.length;

            for (const file of extractedFiles) {
              const fileFindings = await scanFile(file, true);
              for (const f of fileFindings) {
                // Make file paths relative to package
                f.file = f.file ? path.relative(extractDir, f.file) : f.file;
                findings.push(f);
              }
            }
          } finally {
            // Clean up extracted dir
            fs.rmSync(extractDir, { recursive: true, force: true });
          }
        } finally {
          // Clean up tarball
          fs.unlinkSync(tgzPath);
        }
      } catch {
        findings.push({
          severity: 'info',
          category: 'dependency-risk',
          title: 'Tarball scan failed',
          description: 'Could not download or extract the package tarball for deep scanning.',
        });
      }
    }
  }

  const { score, riskLevel } = calculateTrustScore(findings);

  return {
    target: packageName,
    trustScore: score,
    riskLevel,
    findings,
    filesScanned,
    scannedAt: new Date(),
    deepScan: deep,
  };
}

/**
 * Walk an extracted tarball directory and collect file paths.
 */
function walkExtracted(dir: string, files: string[] = []): string[] {
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return files;
  }

  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name !== 'node_modules') {
        walkExtracted(full, files);
      }
    } else if (entry.isFile()) {
      files.push(full);
    }
  }

  return files;
}
