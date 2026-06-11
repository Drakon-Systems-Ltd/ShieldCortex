import { afterEach, describe, expect, it } from '@jest/globals';
import { spawn, type ChildProcessWithoutNullStreams } from 'child_process';
import { mkdtempSync, rmSync, existsSync } from 'fs';
import { tmpdir } from 'os';
import path from 'path';

/**
 * MCP stdio protocol safety — stdout must carry ONLY JSON-RPC.
 *
 * Regression guard for the "Connection closed" bug: the in-process BrainWorker
 * (and any other code) was writing `[BrainWorker] …` lines to STDOUT while the
 * MCP server uses stdout as the JSON-RPC channel. The first non-JSON byte makes
 * a client's stdio transport fail. This spawns the REAL built server, drives an
 * `initialize` handshake, and asserts every stdout line parses as JSON.
 *
 * dist-gated (like no-bare-require-in-dist): skips on pure-source CI, runs when
 * `dist/` exists (always the case during prepublishOnly / a local build).
 */
const dist = path.join(process.cwd(), 'dist', 'index.js');

(existsSync(dist) ? describe : describe.skip)('MCP server stdout is pure JSON-RPC', () => {
  let child: ChildProcessWithoutNullStreams | null = null;
  let tempHome: string;

  afterEach(() => {
    if (child && !child.killed) {
      try { child.kill('SIGKILL'); } catch { /* already dead */ }
    }
    child = null;
    if (tempHome) rmSync(tempHome, { recursive: true, force: true });
  });

  it('emits no non-JSON (e.g. [BrainWorker]) lines on stdout during startup + initialize', async () => {
    tempHome = mkdtempSync(path.join(tmpdir(), 'sc-mcp-stdout-'));

    // Worker ENABLED on purpose (we are proving it does not pollute stdout);
    // embeddings skipped to keep startup fast and quiet.
    child = spawn(process.execPath, [dist], {
      env: {
        ...process.env,
        HOME: tempHome,
        USERPROFILE: tempHome,
        SHIELDCORTEX_CONFIG_DIR: path.join(tempHome, '.shieldcortex'),
        SHIELDCORTEX_SKIP_EMBEDDINGS: '1',
      },
      stdio: ['pipe', 'pipe', 'pipe'],
    }) as ChildProcessWithoutNullStreams;

    let stdout = '';
    child.stdout.setEncoding('utf-8');
    child.stdout.on('data', (c: string) => { stdout += c; });

    // Drive a real MCP initialize so the server produces its JSON-RPC response.
    child.stdin.write(
      JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'initialize',
        params: { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'purity-test', version: '0' } },
      }) + '\n',
    );

    // Let startup (incl. the in-process worker's start() logs) + the handshake
    // response flush. The worker's initial light tick is at +10s, so 3s is well
    // inside the window where only startup + initialize output appears.
    await new Promise((r) => setTimeout(r, 3000));

    const lines = stdout.split('\n').map((l) => l.trim()).filter((l) => l.length > 0);

    // We must have gotten the initialize response back.
    expect(lines.length).toBeGreaterThan(0);

    // Every line on stdout must be valid JSON — no stray log text.
    const nonJson = lines.filter((l) => {
      try { JSON.parse(l); return false; } catch { return true; }
    });
    expect(nonJson).toEqual([]);
    expect(stdout).not.toContain('[BrainWorker]');

    // Sanity: the JSON we got is the initialize result for our id.
    const parsed = lines.map((l) => JSON.parse(l));
    expect(parsed.some((m) => m.id === 1 && m.result?.serverInfo?.name === 'shieldcortex')).toBe(true);
  }, 20_000);
});
