/**
 * #1108 — a dropped optional ML package must not look like a healthy doctor run.
 *
 * Resolve is injected. These tests never import @huggingface/transformers, never
 * download a model, and never treat a cache fault as this install fault.
 * The default-resolver case is the one exception: it calls the real ESM
 * resolver against the package already present in this worktree, to prove the
 * helper follows import() rather than the CJS export. That is not a consumer
 * install receipt.
 *
 * The exports-target cases are private fixtures. A script inside the fixture
 * calls import.meta.resolve and does not import the package. On this Node that
 * call takes one argument and resolves from the calling module.
 */
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath, pathToFileURL } from 'url';
import { afterEach, describe, expect, it } from '@jest/globals';
import {
  checkModelCache,
  checkOptionalMlStack,
  checkSemanticCoverageAt,
  doctorExitCode,
  resolveOptionalMlPackage,
} from '../doctor.js';
import { formatModelCacheDoctorMessage, type ModelCacheInspection } from '../../embeddings/model-cache.js';

const MISSING = 'missing optional dependency: @huggingface/transformers';
const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const scratch: string[] = [];

function present(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-1108-present-'));
  scratch.push(dir);
  const file = path.join(dir, 'transformers.node.mjs');
  fs.writeFileSync(file, 'export {};\n');
  return pathToFileURL(file).href;
}

/**
 * Private package with the installed package's node.import / node.require
 * export shape. The resolver is that package's own import.meta.resolve, not a
 * hand-written path. It never imports the module and never downloads a model.
 */
function exportsFixture(esmFile: boolean): {
  resolve: (spec: string) => string;
  esmPath: string;
  cjsPath: string;
} {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-1108-exports-'));
  scratch.push(root);
  fs.mkdirSync(path.join(root, 'dist'), { recursive: true });
  fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({
    name: '@huggingface/transformers',
    private: true,
    type: 'module',
    exports: {
      node: {
        import: { default: './dist/transformers.node.mjs' },
        require: { default: './dist/transformers.node.cjs' },
      },
      default: { default: './dist/transformers.web.js' },
    },
  }));
  const esmPath = path.join(root, 'dist', 'transformers.node.mjs');
  const cjsPath = path.join(root, 'dist', 'transformers.node.cjs');
  if (esmFile) fs.writeFileSync(esmPath, 'export {};\n');
  const script = path.join(root, 'resolve-entry.mjs');
  fs.writeFileSync(script, 'process.stdout.write(import.meta.resolve(process.argv[2]));\n');
  const resolve = (spec: string): string => {
    const out = spawnSync(process.execPath, [script, spec], {
      encoding: 'utf8',
      cwd: root,
      env: { PATH: '/usr/bin:/bin' },
    });
    if (out.status !== 0 || typeof out.stdout !== 'string' || out.stdout.length === 0) {
      throw new Error(out.stderr || `could not resolve ${spec}`);
    }
    return out.stdout;
  };
  return { resolve, esmPath, cjsPath };
}

function absent(): string {
  throw new Error("Cannot find module '@huggingface/transformers'");
}

function cacheInspection(status: ModelCacheInspection['status'], detail?: string): ModelCacheInspection {
  return {
    status,
    cacheDir: '/tmp/sc-1108-not-a-real-cache',
    onnxPath: '/tmp/sc-1108-not-a-real-cache/onnx/model.onnx',
    expectedBytes: 1,
    expectedSha256: 'abc',
    ...(detail ? { detail } : {}),
  };
}

afterEach(() => {
  for (const dir of scratch.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
});

describe('#1108 optional ML doctor diagnosis', () => {
  it('missing package, embeddings expected: named fail and exit 1', async () => {
    const row = await checkOptionalMlStack({ env: {}, resolve: absent });
    expect(row.label).toBe('Optional ML stack');
    expect(row.status).toBe('fail');
    expect(row.message).toContain(MISSING);
    expect(row.message).toMatch(/semantic recall cannot load/);
    expect(row.message).toMatch(/not a model-cache miss/);
    expect(row.message).toMatch(/not database corruption/);
    expect(row.message).not.toMatch(/will download/);
    expect(row.message).not.toMatch(/embed-backfill/);
    expect(row.fix ?? '').not.toContain('ONNXRUNTIME_NODE_INSTALL_CUDA');
    expect(row.haltsRun).toBeUndefined();
    expect(doctorExitCode([row])).toBe(1);
    expect(doctorExitCode([row], { strict: true })).toBe(1);
  });

  it('missing package, intentional skip: info, no fail token, exit 0', async () => {
    const row = await checkOptionalMlStack({
      env: { SHIELDCORTEX_SKIP_EMBEDDINGS: '1' },
      resolve: absent,
    });
    expect(row.status).toBe('info');
    expect(row.message).not.toContain(MISSING);
    expect(row.message).toMatch(/SHIELDCORTEX_SKIP_EMBEDDINGS=1/);
    expect(row.message).toMatch(/intentionally disabled/);
    expect(row.message).toMatch(/semantic-analysis defence layer/);
    expect(row.message).not.toMatch(/judge|explainer|review copilot|Action Guard|Iron Dome/i);
    expect(row.fix ?? '').not.toContain('ONNXRUNTIME_NODE_INSTALL_CUDA');
    expect(doctorExitCode([row])).toBe(0);
    expect(doctorExitCode([row], { strict: true })).toBe(0);
  });

  it('present package, embeddings expected: pass, presence only', async () => {
    const row = await checkOptionalMlStack({ env: {}, resolve: present });
    expect(row.status).toBe('pass');
    expect(row.message).toMatch(/@huggingface\/transformers is installed/);
    expect(row.message).toMatch(/not checked/);
    expect(row.message).not.toContain(MISSING);
    expect(row.message).not.toMatch(/healthy|inference is working|cache ok|verified cache/i);
    expect(doctorExitCode([row])).toBe(0);
  });

  it('present package, intentional skip: info, not a fail', async () => {
    const row = await checkOptionalMlStack({
      env: { SHIELDCORTEX_SKIP_EMBEDDINGS: '1' },
      resolve: present,
    });
    expect(row.status).toBe('info');
    expect(row.message).not.toContain(MISSING);
    expect(row.message).toMatch(/installed/);
    expect(row.message).toMatch(/intentionally disabled/);
    expect(row.message).not.toMatch(/judge|explainer|review copilot|Action Guard/i);
    expect(doctorExitCode([row])).toBe(0);
    expect(doctorExitCode([row], { strict: true })).toBe(0);
  });

  it('only the exact skip value 1 is an opt-out', async () => {
    for (const value of ['0', 'true', 'yes', '', '1 ']) {
      const row = await checkOptionalMlStack({
        env: { SHIELDCORTEX_SKIP_EMBEDDINGS: value },
        resolve: absent,
      });
      expect(row.status).toBe('fail');
      expect(row.message).toContain(MISSING);
    }
  });

  it('a missing exported ESM entry is an unavailable install, not a present package', async () => {
    const fixture = exportsFixture(false);
    const resolved = fixture.resolve('@huggingface/transformers');
    expect(resolved).toContain('transformers.node.mjs');
    expect(resolved).not.toContain('transformers.node.cjs');
    expect(fs.existsSync(new URL(resolved))).toBe(false);
    expect(fs.existsSync(fixture.cjsPath)).toBe(false);

    const env = { SHIELDCORTEX_MODEL_DIR: path.join(os.tmpdir(), 'sc-1108-absent-cache') };
    const row = await checkOptionalMlStack({ env, resolve: fixture.resolve });
    expect(row.status).toBe('fail');
    expect(row.message).toContain(MISSING);
    expect(row.message).toMatch(/semantic recall cannot load/);
    expect(row.message).not.toMatch(/will download/);
    expect(doctorExitCode([row])).toBe(1);

    const cache = await checkModelCache({ env, resolve: fixture.resolve });
    expect(cache.status).toBe('info');
    expect(cache.message).not.toContain('will download');
    expect(cache.message).not.toMatch(/embed-backfill/);
    expect(cache.message).toMatch(/Optional ML stack/);

    const coverage = await checkSemanticCoverageAt(path.join(os.tmpdir(), 'no-such-1108.db'), {
      env,
      resolve: fixture.resolve,
    });
    expect(coverage.status).toBe('pass');
    expect(coverage.fix).toBeUndefined();
    expect(coverage.message).not.toMatch(/embed-backfill/);
    expect(coverage.message).not.toMatch(/will download|would download/);
    expect(coverage.message).toMatch(/Optional ML stack/);
  });

  it('exact skip=1 stays an informational opt-out when the exported ESM entry is missing', async () => {
    const fixture = exportsFixture(false);
    const row = await checkOptionalMlStack({
      env: { SHIELDCORTEX_SKIP_EMBEDDINGS: '1' },
      resolve: fixture.resolve,
    });
    expect(row.status).toBe('info');
    expect(row.message).not.toContain(MISSING);
    expect(row.message).toMatch(/SHIELDCORTEX_SKIP_EMBEDDINGS=1/);
    expect(doctorExitCode([row])).toBe(0);
    expect(doctorExitCode([row], { strict: true })).toBe(0);
    for (const value of ['0', 'true', 'yes', '', '1 ']) {
      const notSkip = await checkOptionalMlStack({
        env: { SHIELDCORTEX_SKIP_EMBEDDINGS: value },
        resolve: fixture.resolve,
      });
      expect(notSkip.status).toBe('fail');
      expect(notSkip.message).toContain(MISSING);
    }
  });

  it('a missing unused CJS entry does not hide a present ESM entry', async () => {
    const fixture = exportsFixture(true);
    const resolved = fixture.resolve('@huggingface/transformers');
    expect(resolved).toContain('transformers.node.mjs');
    expect(resolved).not.toContain('transformers.node.cjs');
    expect(fs.statSync(new URL(resolved)).isFile()).toBe(true);
    expect(fs.existsSync(fixture.cjsPath)).toBe(false);

    const row = await checkOptionalMlStack({ env: {}, resolve: fixture.resolve });
    expect(row.status).toBe('pass');
    expect(row.message).toMatch(/@huggingface\/transformers is installed/);
    expect(row.message).not.toContain(MISSING);
    expect(doctorExitCode([row])).toBe(0);
  });

  it('a resolved path is presence only when that local file exists', async () => {
    const missingUrl = pathToFileURL(path.join(os.tmpdir(), 'sc-1108-absent-entry.mjs')).href;
    const missing = await checkOptionalMlStack({ env: {}, resolve: () => missingUrl });
    expect(missing.status).toBe('fail');
    expect(missing.message).toContain(MISSING);

    const bare = await checkOptionalMlStack({
      env: {},
      resolve: () => '/virtual/transformers.node.cjs',
    });
    expect(bare.status).toBe('fail');
    expect(bare.message).toContain(MISSING);

    const empty = await checkOptionalMlStack({ env: {}, resolve: () => '' });
    expect(empty.status).toBe('fail');
    expect(empty.message).toContain(MISSING);

    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-1108-file-'));
    scratch.push(dir);
    const file = path.join(dir, 'transformers.node.mjs');
    fs.writeFileSync(file, 'export {};\n');
    const ok = await checkOptionalMlStack({ env: {}, resolve: () => pathToFileURL(file).href });
    expect(ok.status).toBe('pass');
  });

  it('embeddings row does not promise a download when the package is missing', async () => {
    const row = await checkModelCache({ env: {}, resolve: absent });
    expect(row.label).toBe('Embeddings');
    expect(row.status).toBe('info');
    expect(row.message).not.toContain('will download');
    expect(row.message).not.toMatch(/embed-backfill/);
    expect(row.message).toMatch(/Optional ML stack/);
    expect(row.message).toMatch(/not a corrupt cache/);
    expect(row.message).not.toContain(MISSING);
    expect(row.fix).toBeUndefined();
  });

  it('embeddings row does not promise a download when embeddings are intentionally disabled', async () => {
    const row = await checkModelCache({
      env: { SHIELDCORTEX_SKIP_EMBEDDINGS: '1' },
      resolve: present,
    });
    expect(row.status).toBe('info');
    expect(row.message).not.toContain('will download');
    expect(row.message).not.toMatch(/embed-backfill/);
    expect(row.message).toMatch(/Optional ML stack/);
    expect(row.message).not.toMatch(/corrupt/);
    expect(row.fix).toBeUndefined();
  });

  it('embeddings row keeps the real cache warning when the package is present and used', async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-1108-cache-'));
    scratch.push(root);
    const row = await checkModelCache({
      env: { SHIELDCORTEX_MODEL_DIR: root },
      resolve: present,
    });
    expect(row.label).toBe('Embeddings');
    expect(row.status).toBe('info');
    expect(row.message).toContain('will download on first recall');
  });

  it('a separately formatted missing or corrupt cache is not relabelled as a missing package', () => {
    const missingCache = formatModelCacheDoctorMessage(cacheInspection('missing'));
    expect(missingCache.status).toBe('info');
    expect(missingCache.message).toContain('will download on first recall');
    expect(missingCache.message).not.toContain(MISSING);

    const corrupt = formatModelCacheDoctorMessage(cacheInspection('sha_mismatch', 'sha mismatch'));
    expect(corrupt.status).toBe('warn');
    expect(corrupt.message).toMatch(/corrupt/);
    expect(corrupt.message).not.toContain(MISSING);
  });

  it('semantic coverage does not recommend a backfill when the package is missing', async () => {
    const row = await checkSemanticCoverageAt(path.join(os.tmpdir(), 'no-such-1108.db'), {
      env: {},
      resolve: absent,
    });
    expect(row.label).toBe('Semantic coverage');
    expect(row.status).toBe('pass');
    expect(row.fix).toBeUndefined();
    expect(row.message).not.toMatch(/embed-backfill/);
    expect(row.message).not.toMatch(/will download|would download/);
    expect(row.message).toMatch(/Optional ML stack/);
    expect(row.message).not.toContain(MISSING);
  });

  it('semantic coverage does not recommend a backfill when embeddings are intentionally disabled', async () => {
    const row = await checkSemanticCoverageAt(path.join(os.tmpdir(), 'no-such-1108.db'), {
      env: { SHIELDCORTEX_SKIP_EMBEDDINGS: '1' },
      resolve: present,
    });
    expect(row.status).toBe('pass');
    expect(row.fix).toBeUndefined();
    expect(row.message).not.toMatch(/embed-backfill/);
    expect(row.message).not.toMatch(/will download|would download/);
    expect(row.message).toMatch(/SHIELDCORTEX_SKIP_EMBEDDINGS=1/);
    expect(row.message).toMatch(/Optional ML stack/);
  });

  it('semantic coverage still names a download when the package is present and used and the cache is missing', async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-1108-cov-'));
    scratch.push(root);
    const row = await checkSemanticCoverageAt(path.join(os.tmpdir(), 'no-such-1108.db'), {
      env: { SHIELDCORTEX_MODEL_DIR: root },
      resolve: present,
    });
    expect(row.fix).toBeUndefined();
    expect(row.message).toMatch(/would download model\.onnx/);
    expect(row.message).not.toMatch(/Optional ML stack/);
  });

  it('does not promote the package out of optionalDependencies', () => {
    const pkg = JSON.parse(fs.readFileSync(path.join(repoRoot, 'package.json'), 'utf8')) as {
      dependencies: Record<string, string>;
      optionalDependencies: Record<string, string>;
    };
    expect(pkg.optionalDependencies['@huggingface/transformers']).toBe('^3.7.2');
    expect(pkg.dependencies['@huggingface/transformers']).toBeUndefined();
  });

  it('default resolver matches the ESM entry the worker imports, not the CJS require entry', () => {
    const resolved = resolveOptionalMlPackage();
    expect(resolved).toContain('transformers.node.mjs');
    expect(resolved).not.toContain('transformers.node.cjs');
  });

  it('the new row is registered immediately before the cache row and does not name the CI CUDA skip', () => {
    const src = fs.readFileSync(path.join(repoRoot, 'src', 'cli', 'doctor.ts'), 'utf8');
    expect(src).toMatch(/checkOptionalMlStack,\n\s*checkModelCache,/);
    expect(src).not.toContain('ONNXRUNTIME_NODE_INSTALL_CUDA');
    expect(src).not.toMatch(/from '@huggingface\/transformers'/);
    expect(src).not.toMatch(/import\('@huggingface\/transformers'\)/);
  });
});
