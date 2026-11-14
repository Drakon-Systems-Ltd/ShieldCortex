import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { checkRuntimePosture, codexToolBoundaryRow, doctorExitCode, RUNTIME_POSTURE_LABEL } from '../doctor.js';
import { LIVE, NOW } from '../../posture/__tests__/self-report-fixture.js';

/**
 * #810 — owner decision 2026-10-27: Action Guard deny-holds are NOT enforced
 * on the Codex harness. Doctor must state the boundary truthfully: bare Codex
 * native tools are unguarded, the OpenClaw-embedded path is observed in
 * observe mode only, the native hook relay is unverified, and benign allows
 * leave no audit row. It must never claim Codex is gated or protected.
 * No shell payloads: these tests only read doctor rows and doc files.
 */

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(__dirname, '..', '..', '..');
const BOUNDARY = 'Codex tool boundary';
const hostDeps = { openclawBinaryPresent: () => false };
let root: string;
let home: string;
let configDir: string;

beforeEach(() => {
  root = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-doctor-codex-810-'));
  home = path.join(root, 'fx');
  configDir = path.join(home, '.shieldcortex');
  fs.mkdirSync(path.join(home, '.codex'), { recursive: true });
});

afterEach(() => {
  fs.rmSync(root, { recursive: true, force: true });
});

async function rows() {
  return checkRuntimePosture({ home, configDir, nowMs: NOW, hostDeps, deps: LIVE });
}

describe('#810 doctor states the Codex tool boundary', () => {
  it('a Codex host gets a boundary row', async () => {
    const row = (await rows()).find((r) => r.label === BOUNDARY);
    expect(row).toBeDefined();
  });

  it('says bare Codex native shell and apply_patch are unguarded and Codex is observe-only', async () => {
    const row = (await rows()).find((r) => r.label === BOUNDARY)!;
    expect(row.message).toMatch(/observe-only/);
    // Literal match: the `~/.codex` path contains a dot, so a [^.]* gap cannot span it.
    expect(row.message).toContain('Bare Codex (CLI, ~/.codex): native tools unguarded');
    expect(row.message).toMatch(/shell and apply_patch/);
    expect(row.message).toMatch(/installs no Codex hook/);
  });

  it('separates the OpenClaw-embedded path (observe mode only) from the unverified native hook relay', async () => {
    const row = (await rows()).find((r) => r.label === BOUNDARY)!;
    expect(row.message).toMatch(/Codex run by OpenClaw: OpenClaw-owned tools[^.]*before_tool_call/);
    expect(row.message).toMatch(/observe mode only/);
    expect(row.message).toMatch(/deny or hold on this path is untested/);
    expect(row.message).toMatch(/native hook relay: unverified/);
  });

  it('explains that benign allows write no audit row', async () => {
    const row = (await rows()).find((r) => r.label === BOUNDARY)!;
    expect(row.message).toMatch(/Benign allows normally write no audit row/);
  });

  it('never claims Codex is gated, guarded, protected or enforced', async () => {
    const row = (await rows()).find((r) => r.label === BOUNDARY)!;
    const text = `${row.message} ${row.fix ?? ''}`;
    expect(text).not.toMatch(/enforced|protected|proves/i);
    expect(text).not.toMatch(/\bguarded\b/i); // "unguarded" only
    expect(text).not.toMatch(/Codex is (a )?(tool )?gate/i);
  });

  it('is info-only and cannot change the doctor exit code, even under --strict', async () => {
    const all = await rows();
    const row = all.find((r) => r.label === BOUNDARY)!;
    expect(row.status).toBe('info');
    expect(doctorExitCode([row], { strict: true })).toBe(0);
  });

  it('leaves the existing #613 Codex memory-only row in place and first', async () => {
    const all = await rows();
    const codex = all.find((r) => r.label.startsWith(`${RUNTIME_POSTURE_LABEL}: Codex`))!;
    expect(codex.message).toMatch(/not a tool gate/);
    expect(all.findIndex((r) => r.label === BOUNDARY)).toBeGreaterThan(all.indexOf(codex));
  });

  it('an OpenClaw-only host (embedded Codex harness possible) also gets the row; other runtimes alone do not', () => {
    expect(codexToolBoundaryRow(['openclaw'])?.label).toBe(BOUNDARY);
    expect(codexToolBoundaryRow(['claude_code', 'hermes', 'copilot'])).toBeNull();
  });

  it('a host with no Codex and no OpenClaw gets no boundary row', async () => {
    fs.rmSync(path.join(home, '.codex'), { recursive: true });
    expect((await rows()).find((r) => r.label === BOUNDARY)).toBeUndefined();
  });
});

describe('#810 documentation of the Codex boundary', () => {
  const doc = path.join(REPO, 'docs', 'security', 'codex-boundary.md');

  it('the doctor row points at a doc that exists', async () => {
    const row = (await rows()).find((r) => r.label === BOUNDARY)!;
    expect(row.message).toMatch(/docs\/security\/codex-boundary\.md/);
    expect(fs.existsSync(doc)).toBe(true);
  });

  it('the doc distinguishes proven from unverified and does not claim native interception', () => {
    const text = fs.readFileSync(doc, 'utf8');
    expect(text).toMatch(/observe-only/);
    expect(text).toMatch(/Native tools are unguarded/);
    expect(text).toMatch(/CONFIRMED in \*\*observe mode only\*\*/);
    expect(text).toMatch(/UNVERIFIED/);
    expect(text).toMatch(/benign allow normally writes no row/i);
    expect(text).not.toMatch(/Codex[^.\n]*\b(is|are) (protected|enforced|guarded)\b/i);
  });

  it('the Codex quickstart links the boundary page', () => {
    const qs = fs.readFileSync(path.join(REPO, 'docs', 'quickstarts', 'codex.md'), 'utf8');
    expect(qs).toMatch(/\(\.\.\/security\/codex-boundary\.md\)/);
  });
});
