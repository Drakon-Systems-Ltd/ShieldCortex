import { describe, it, expect } from '@jest/globals';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

/**
 * #679 review, finding 1 — the guard's hook adapters must type-check against
 * the real `@anthropic-ai/sdk` toolset classes (a devDependency only; nothing
 * here runs the SDK or calls the API). The fixture subclasses both abstract
 * toolsets and wires `confirm`, `urlPolicy`, `browserState` and the `execute`
 * override through the guard exactly as the quickstart documents.
 */
const FIXTURE = path.resolve(process.cwd(), 'src/integrations/__tests__/fixtures/claude-toolsets-sdk-conformance.ts');

describe('ToolsetGuard — SDK type conformance (#679 finding 1)', () => {
  it('a driver subclassing the SDK toolsets through the guard type-checks', () => {
    const compiler = path.resolve(process.cwd(), 'node_modules/typescript/lib/tsc.js');
    const result = spawnSync(process.execPath, [compiler,
      '--noEmit', '--strict', '--target', 'ES2022', '--module', 'NodeNext',
      '--moduleResolution', 'NodeNext', '--skipLibCheck', '--esModuleInterop', FIXTURE,
    ], { encoding: 'utf8', timeout: 120_000, maxBuffer: 10 * 1024 * 1024 });
    if (result.status !== 0) {
      throw new Error(`TypeScript exited ${result.status}: ${result.error?.message ?? ''}\n${result.stdout}${result.stderr}`);
    }
    expect(result.status).toBe(0);
  }, 120_000);
});
