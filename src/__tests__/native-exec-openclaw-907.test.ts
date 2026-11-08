/**
 * #907 PR 1 — adapter fixture for the OpenClaw interceptor: the REAL
 * `createInterceptor` with the REAL evaluator and the REAL `artifactLedger`
 * adapter from plugins/openclaw/index.ts, driven across separate tool calls
 * against real files under a test-owned config dir.
 *
 * Test-owned seams only: the defence module handed to the adapter is the real
 * one with `sessionKeyFor` pinned to a fixed salt (jest's os.homedir() is the
 * real home, so the default salt lookup must not run), and the store root is
 * pinned with SHIELDCORTEX_CONFIG_DIR. No production switch.
 */
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import * as defence from '../defence/index.js';
import { createInterceptor, DEFAULT_CONFIG, type InterceptAuditEntry } from '../../plugins/openclaw/interceptor.js';
import { artifactLedgerAdapter } from '../../plugins/openclaw/index.js';

const ELF_STUB = Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0, ...new Array(56).fill(0)]);
const SALT = 'ab'.repeat(32);

const okPipeline = () => ({
  allowed: true,
  firewall: { result: 'ALLOW' as const, reason: '', threatIndicators: [] as string[], anomalyScore: 0, blockedPatterns: [] as string[] },
  trust: { score: 0.5 }, sensitivity: { level: 'INTERNAL' }, fragmentation: null, auditId: 1,
});

describe('#907 native-exec floor through the OpenClaw interceptor', () => {
  let root: string;
  let work: string;
  let prevConfigDir: string | undefined;

  beforeEach(() => {
    root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'sc-907-oc-')));
    work = path.join(root, 'work');
    fs.mkdirSync(work, { recursive: true });
    prevConfigDir = process.env.SHIELDCORTEX_CONFIG_DIR;
    process.env.SHIELDCORTEX_CONFIG_DIR = path.join(root, 'state');
  });
  afterEach(() => {
    if (prevConfigDir === undefined) delete process.env.SHIELDCORTEX_CONFIG_DIR;
    else process.env.SHIELDCORTEX_CONFIG_DIR = prevConfigDir;
    fs.rmSync(root, { recursive: true, force: true });
  });

  const pinnedDefence = {
    ...defence,
    sessionKeyFor: (id: string | undefined) => defence.sessionKeyFor(id, { salt: SALT }),
  };

  function harness(id: string | null = 'oc-907-session') {
    const sessionId = id ?? undefined; // null = no session id (a default param would swallow undefined)
    const entries: InterceptAuditEntry[] = [];
    const i = createInterceptor(
      { ...DEFAULT_CONFIG, actionGuard: { enabled: true, enforce: true, autoApprove: [] } } as never,
      okPipeline as never,
      {
        evaluateToolCall: defence.evaluateToolCall as never,
        artifactLedger: artifactLedgerAdapter(pinnedDefence),
        onAuditEntry: (e) => entries.push(e),
      },
    );
    const call = (toolName: string, args: Record<string, unknown>) =>
      i.handleToolCall({ toolName, arguments: args, sessionId, cwd: work } as never);
    return { call, entries, saw: (sig: string) => JSON.stringify(entries).includes(sig) };
  }

  it('the adapter is wired from the real defence module', () => {
    expect(artifactLedgerAdapter(pinnedDefence)).toBeDefined();
    expect(artifactLedgerAdapter({})).toBeUndefined();
  });

  it('write → exec (row A) → blocked, naming exec-agent-written-native-bytes', async () => {
    const h = harness();
    const helper = path.join(work, 'helper');
    await expect(h.call('Write', { file_path: helper, content: 'stub' })).resolves.toBeUndefined();
    fs.writeFileSync(helper, ELF_STUB, { mode: 0o755 });
    await expect(h.call('Bash', { command: './helper' })).rejects.toThrow(/ShieldCortex/);
    expect(h.saw('exec-agent-written-native-bytes')).toBe(true);
  });

  it('failed write against an existing native file → exec → the door, never the floor', async () => {
    const h = harness();
    const tool = path.join(work, 'tool');
    fs.writeFileSync(tool, ELF_STUB, { mode: 0o755 });
    await h.call('Write', { file_path: tool, content: 'stub' });
    await h.call('Bash', { command: './tool' }).catch(() => undefined);
    expect(h.saw('unclassified-executable')).toBe(true);
    expect(h.saw('exec-agent-written-native-bytes')).toBe(false);
  });

  it('install-root write → exec (Rule H) → blocked; producing write → four failed writes → exec → blocked', async () => {
    const h = harness();
    const binDir = path.join(work, 'node_modules', '.bin');
    fs.mkdirSync(binDir, { recursive: true });
    const planted = path.join(binDir, 'tool');
    await h.call('Write', { file_path: planted, content: 'stub' });
    fs.writeFileSync(planted, ELF_STUB, { mode: 0o755 });
    for (let k = 0; k < 4; k++) await h.call('Edit', { file_path: planted, old_string: 'a', new_string: 'b' });
    fs.chmodSync(planted, 0o700);
    await expect(h.call('Bash', { command: planted })).rejects.toThrow(/ShieldCortex/);
    expect(h.saw('exec-agent-written-native-bytes')).toBe(true);
  });

  it('supported compile → exec (row B) → runs (Q1 = AUDIT)', async () => {
    const h = harness();
    await h.call('Bash', { command: 'cc helper.c -o helper' });
    fs.writeFileSync(path.join(work, 'helper'), ELF_STUB, { mode: 0o755 });
    await expect(h.call('Bash', { command: './helper' })).resolves.toBeUndefined();
    expect(h.saw('exec-agent-written-native-bytes')).toBe(false);
  });

  it('no session id → the write is not held; a native exec is the door', async () => {
    const h = harness(null);
    const helper = path.join(work, 'helper');
    await expect(h.call('Write', { file_path: helper, content: 'stub' })).resolves.toBeUndefined();
    fs.writeFileSync(helper, ELF_STUB, { mode: 0o755 });
    await h.call('Bash', { command: './helper' }).catch(() => undefined);
    expect(h.saw('unclassified-executable')).toBe(true);
  });
});
