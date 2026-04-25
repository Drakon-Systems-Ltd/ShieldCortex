import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { detectStaleAppendLogs } from '../service/install';

/**
 * v4.12.10 — `service status` (and by extension `service repair` prompts)
 * must surface the pre-v4.12.10 broken state so operators on the affected
 * fleet (Jarvis, Tars, anyone who ran uninstall --clean-logs) can recognise
 * it without reading systemd journal output.
 *
 * The detector greps the unit text for `StandardOutput=append:/abs/path`
 * and checks whether the parent dir actually exists. If not — stale.
 */
describe('detectStaleAppendLogs — pre-v4.12.10 broken-unit recognition', () => {
  let tmpDir: string;
  let missingDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-stale-unit-'));
    missingDir = path.join(tmpDir, 'gone');
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('flags an append: unit pointing at a missing dir (the Jarvis/Tars bug)', () => {
    const unit = [
      '[Service]',
      'ExecStart=/usr/bin/node /opt/sc/index.js --mode worker',
      `StandardOutput=append:${missingDir}/dashboard-stdout.log`,
      `StandardError=append:${missingDir}/dashboard-stderr.log`,
    ].join('\n');

    const result = detectStaleAppendLogs(unit);
    expect(result.stale).toBe(true);
    expect(result.missingPath).toBe(missingDir);
  });

  it('does NOT flag an append: unit when the dir still exists', () => {
    fs.mkdirSync(missingDir, { recursive: true });
    const unit = `StandardOutput=append:${missingDir}/dashboard-stdout.log`;
    const result = detectStaleAppendLogs(unit);
    expect(result.stale).toBe(false);
    expect(result.missingPath).toBeNull();
  });

  it('does NOT flag a v4.12.10+ journald unit (no append: directive at all)', () => {
    const unit = [
      '[Service]',
      'StandardOutput=journal',
      'StandardError=journal',
      'SyslogIdentifier=shieldcortex-worker',
    ].join('\n');
    expect(detectStaleAppendLogs(unit).stale).toBe(false);
  });

  it('matches StandardError=append: too (not just StandardOutput)', () => {
    const unit = `StandardError=append:${missingDir}/x.log`;
    expect(detectStaleAppendLogs(unit).stale).toBe(true);
  });
});
