import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { checkOpenClawApprovalButtons } from '../cli/doctor.js';

/**
 * The doctor RECOMMENDS enabling Telegram inline approval buttons when OpenClaw
 * + Telegram are configured but the capability isn't set — it never rewrites the
 * host's channel config (that's the user's call). These pin that contract.
 */
describe('doctor — OpenClaw approval buttons recommendation', () => {
  let dir: string;
  beforeEach(() => { dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-ocbtn-')); });
  afterEach(() => { fs.rmSync(dir, { recursive: true, force: true }); });

  function writeCfg(obj: unknown): string {
    const p = path.join(dir, 'openclaw.json');
    fs.writeFileSync(p, JSON.stringify(obj));
    return p;
  }

  it('returns nothing when the OpenClaw config is absent', async () => {
    expect(await checkOpenClawApprovalButtons(path.join(dir, 'nope.json'))).toEqual([]);
  });

  it('stays silent when Telegram is not configured', async () => {
    expect(await checkOpenClawApprovalButtons(writeCfg({ channels: {} }))).toEqual([]);
  });

  it('recommends (info) when inlineButtons is unset', async () => {
    const res = await checkOpenClawApprovalButtons(writeCfg({ channels: { telegram: { enabled: true } } }));
    expect(res).toHaveLength(1);
    expect(res[0].status).toBe('info');
    expect(res[0].fix).toMatch(/inlineButtons/);
  });

  it('passes when inlineButtons enables a surface', async () => {
    const res = await checkOpenClawApprovalButtons(
      writeCfg({ channels: { telegram: { capabilities: { inlineButtons: 'all' } } } }),
    );
    expect(res).toHaveLength(1);
    expect(res[0].status).toBe('pass');
  });

  it('does not throw on an unparseable config', async () => {
    const p = path.join(dir, 'openclaw.json');
    fs.writeFileSync(p, '{ not json');
    expect(await checkOpenClawApprovalButtons(p)).toEqual([]);
  });
});
