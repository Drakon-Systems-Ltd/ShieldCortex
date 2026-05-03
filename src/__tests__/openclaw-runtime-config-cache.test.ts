import { promises as fs } from 'fs';
import { mkdtempSync } from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';

/**
 * Verifies the mtime-gated cache in hooks/openclaw/cortex-memory/runtime.mjs.
 *
 * Before this fix, `loadShieldConfig()` cached the parsed config for the
 * runtime's lifetime. Toggling `openclawAutoMemory` or `proactiveRecall` from
 * the dashboard wrote the new value to disk but the OpenClaw plugin kept
 * serving the stale cached value until the gateway was restarted.
 *
 * The fix tracks the config file's mtime on every call and re-reads when the
 * file has been modified since the last read.
 */
describe('createOpenClawRuntime — loadShieldConfig mtime cache', () => {
  let tempDir: string;
  let configPath: string;

  beforeEach(async () => {
    tempDir = mkdtempSync(path.join(os.tmpdir(), 'sc-runtime-cache-'));
    configPath = path.join(tempDir, 'config.json');
  });

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  it('returns cached config on repeat calls when file is unchanged', async () => {
    await fs.writeFile(configPath, JSON.stringify({ openclawAutoMemory: true }));
    const { createOpenClawRuntime } = await import('../../hooks/openclaw/cortex-memory/runtime.mjs') as {
      createOpenClawRuntime: (opts?: { configPath?: string }) => {
        loadShieldConfig: () => Promise<Record<string, unknown>>;
      };
    };
    const runtime = createOpenClawRuntime({ configPath });

    const first = await runtime.loadShieldConfig();
    const second = await runtime.loadShieldConfig();

    expect(first).toEqual({ openclawAutoMemory: true });
    // Reference equality — runtime returns the same object until file changes.
    // The plugin layer relies on this identity check to invalidate its merged cache.
    expect(second).toBe(first);
  });

  it('re-reads when the config file mtime advances', async () => {
    await fs.writeFile(configPath, JSON.stringify({ openclawAutoMemory: false }));
    const { createOpenClawRuntime } = await import('../../hooks/openclaw/cortex-memory/runtime.mjs') as {
      createOpenClawRuntime: (opts?: { configPath?: string }) => {
        loadShieldConfig: () => Promise<Record<string, unknown>>;
      };
    };
    const runtime = createOpenClawRuntime({ configPath });

    const first = await runtime.loadShieldConfig();
    expect(first).toEqual({ openclawAutoMemory: false });

    // Write new content AND force mtime forward past macOS HFS 1-second granularity.
    await fs.writeFile(configPath, JSON.stringify({ openclawAutoMemory: true, proactiveRecall: true }));
    const future = new Date(Date.now() + 5000);
    await fs.utimes(configPath, future, future);

    const second = await runtime.loadShieldConfig();
    expect(second).toEqual({ openclawAutoMemory: true, proactiveRecall: true });
    expect(second).not.toBe(first);
  });

  it('returns empty object when config file is missing', async () => {
    const { createOpenClawRuntime } = await import('../../hooks/openclaw/cortex-memory/runtime.mjs') as {
      createOpenClawRuntime: (opts?: { configPath?: string }) => {
        loadShieldConfig: () => Promise<Record<string, unknown>>;
      };
    };
    const runtime = createOpenClawRuntime({ configPath });

    const result = await runtime.loadShieldConfig();
    expect(result).toEqual({});
  });
});
