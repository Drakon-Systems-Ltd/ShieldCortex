/**
 * 5.x compat for the #718 PERSONAL tier (5.7.0 audit R2).
 *
 * The exported `SensitivityLevel` / `SensitivityClassification` /
 * `redactForDisplay` are back to their 5.6.0 shapes, so every public return
 * path projects PERSONAL → CONFIDENTIAL. The library's own writers and wire
 * boundaries use the internal precise seam and keep PERSONAL exactly as 5.10.5.
 */
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import type { Request, Response } from 'express';
import { closeDatabase, getDatabase, initDatabase } from '../../../database/init.js';
import { classifySensitivity, classifySensitivityPrecise, redactForDisplay, redactForDisplayTier } from '../index.js';
import { projectSensitivityTier, toPublicSensitivity } from '../tier.js';
import { runDefencePipeline, runDefencePipelinePrecise, runDefencePipelineWithVerify } from '../../pipeline.js';
import { scanSkillContent, scanSkillContentPrecise, scanSkill, scanSkillPrecise } from '../../skill-scanner/scan-skill.js';
import { runDeepScan } from '../../skill-scanner/deep-scan.js';
import { scan, scanText } from '../../../scan-only.js';
import { ShieldCortexGuard } from '../../../integrations/langchain.js';
import { handleV1Scan, handleV1ScanBatch } from '../../../api/visualization-server.js';

const FAMILY_TITLE = 'Surprise family trip';
const FAMILY_CONTENT = 'Booked a surprise trip to the coast for Sam\'s birthday with the kids in May; do not tell her before the weekend.';
const PUBLIC_NOTE = 'Use the Inter font family for the dashboard.';
const EMAIL_NOTE = 'Contact the vendor at jane.doe@example.com about the invoice.';
const RESTRICTED_NOTE = 'password: hunter2xx for the staging box';
const FOUR = ['PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'RESTRICTED'];
const KEYS = ['level', 'confidence', 'detectedPatterns', 'redactionRequired'];
const user = { type: 'user' as const, identifier: 'sensitivity-compat-5x' };

function mockRes() {
  let body: unknown;
  let code = 200;
  const res = {
    json: (b: unknown) => { body = b; return res; },
    status: (c: number) => { code = c; return res; },
  };
  return { res: res as unknown as Response, get body() { return body; }, get code() { return code; } };
}

describe('5.x compat: precise tier vs public projection', () => {
  beforeEach(() => {
    closeDatabase();
    initDatabase(':memory:');
  });
  afterEach(() => closeDatabase());

  it('classifier: precise PERSONAL, public CONFIDENTIAL, same evidence, 5.6.0 key order, no aliasing', () => {
    const precise = classifySensitivityPrecise(FAMILY_CONTENT, FAMILY_TITLE);
    const pub = classifySensitivity(FAMILY_CONTENT, FAMILY_TITLE);
    expect(precise.level).toBe('PERSONAL');
    expect(pub.level).toBe('CONFIDENTIAL');
    expect(pub.confidence).toBe(precise.confidence);
    expect(pub.detectedPatterns).toEqual(precise.detectedPatterns);
    expect(pub.redactionRequired).toBe(precise.redactionRequired);
    expect(Object.keys(pub)).toEqual(KEYS);
    expect(Object.keys(precise)).toEqual(KEYS);
    const p2 = classifySensitivityPrecise(FAMILY_CONTENT, FAMILY_TITLE);
    const copy = toPublicSensitivity(p2);
    expect(copy.detectedPatterns).not.toBe(p2.detectedPatterns);
    expect(p2.level).toBe('PERSONAL');
  });

  it.each([
    [PUBLIC_NOTE, 'PUBLIC'],
    [EMAIL_NOTE, 'CONFIDENTIAL'],
    [RESTRICTED_NOTE, 'RESTRICTED'],
  ])('controls are identical on both seams: %s', (content, level) => {
    expect(classifySensitivityPrecise(content, 'note')).toEqual(classifySensitivity(content, 'note'));
    expect(classifySensitivity(content, 'note').level).toBe(level);
  });

  it('projection maps only PERSONAL, and never to INTERNAL', () => {
    expect(projectSensitivityTier('PERSONAL')).toBe('CONFIDENTIAL');
    for (const l of FOUR) expect(projectSensitivityTier(l as never)).toBe(l);
  });

  it('every public return path gives a four-value level and exactly four keys', async () => {
    const paths = [
      runDefencePipeline(FAMILY_CONTENT, FAMILY_TITLE, user).sensitivity,
      (await runDefencePipelineWithVerify(FAMILY_CONTENT, FAMILY_TITLE, user)).sensitivity,
      scan(FAMILY_CONTENT, { title: FAMILY_TITLE }).sensitivity,
      scanText(FAMILY_CONTENT).sensitivity,
      scanSkillContent(FAMILY_CONTENT).sensitivity,
      scanSkill('/nonexistent/compat/SKILL.md').sensitivity,
      new ShieldCortexGuard().scan(FAMILY_CONTENT, FAMILY_TITLE).sensitivity,
    ];
    for (const s of paths) {
      expect(FOUR).toContain(s.level);
      expect(Object.keys(s)).toEqual(KEYS);
    }
    expect(paths[0].level).toBe('CONFIDENTIAL');
    expect(paths[4].level).toBe('CONFIDENTIAL');
  });

  it('pipeline: public returns CONFIDENTIAL while its own defence_audit row keeps PERSONAL', () => {
    const pub = runDefencePipeline(FAMILY_CONTENT, FAMILY_TITLE, user);
    expect(pub.sensitivity.level).toBe('CONFIDENTIAL');
    const row = getDatabase().prepare('SELECT sensitivity_level FROM defence_audit WHERE id = ?').get(pub.auditId) as { sensitivity_level: string };
    expect(row.sensitivity_level).toBe('PERSONAL');
    expect(runDefencePipelinePrecise(FAMILY_CONTENT, FAMILY_TITLE, user).sensitivity.level).toBe('PERSONAL');
  });

  it('memory writer stores PERSONAL (addMemory uses the precise admission seam)', async () => {
    const { addMemory } = await import('../../../memory/store.js');
    const created = addMemory({ title: FAMILY_TITLE, content: FAMILY_CONTENT }, undefined, user);
    const row = getDatabase().prepare('SELECT sensitivity_level FROM memories WHERE id = ?').get(created.id) as { sensitivity_level: string };
    expect(row.sensitivity_level).toBe('PERSONAL');
  });

  it('skill scan: precise keeps PERSONAL; a missing file gives a complete four-key PUBLIC object on both seams', () => {
    expect(scanSkillContentPrecise(FAMILY_CONTENT).sensitivity.level).toBe('PERSONAL');
    const precise = scanSkillPrecise('/nonexistent/compat/SKILL.md');
    expect(precise.sensitivity.level).toBe('PUBLIC');
    expect(Object.keys(precise.sensitivity)).toEqual(KEYS);
    expect(scanSkill('/nonexistent/compat/SKILL.md').sensitivity).toEqual(precise.sensitivity);
  });

  it('redaction: public signature masks CONFIDENTIAL; PERSONAL passes through (untyped-JS parity)', () => {
    expect(redactForDisplay(EMAIL_NOTE, 'CONFIDENTIAL')).not.toBe(EMAIL_NOTE);
    expect(redactForDisplayTier(FAMILY_CONTENT, 'PERSONAL')).toBe(FAMILY_CONTENT);
    expect((redactForDisplay as (c: string, l: string) => string)(FAMILY_CONTENT, 'PERSONAL')).toBe(FAMILY_CONTENT);
    expect(redactForDisplay(RESTRICTED_NOTE, 'RESTRICTED')).toBe(redactForDisplayTier(RESTRICTED_NOTE, 'RESTRICTED'));
  });
});

describe('5.x compat: wire boundaries keep the 5.10.5 shape (B1)', () => {
  beforeEach(() => {
    closeDatabase();
    initDatabase(':memory:');
  });
  afterEach(() => closeDatabase());

  it('POST /api/v1/scan serializes PERSONAL with the 5.10.5 keys and no tier', () => {
    const r = mockRes();
    handleV1Scan({ body: { content: FAMILY_CONTENT, title: FAMILY_TITLE } } as unknown as Request, r.res);
    const body = JSON.parse(JSON.stringify(r.body)) as Record<string, any>;
    expect(body.sensitivity.level).toBe('PERSONAL');
    expect(body.sensitivity.detectedPatterns).toContain('personal-life-event');
    expect(Object.keys(body.sensitivity)).toEqual(KEYS);
    expect(Object.keys(body)).toEqual(['allowed', 'firewall', 'fragmentation', 'sensitivity', 'trust', 'auditId']);
    expect(JSON.stringify(r.body)).not.toContain('"tier"');
    // No mutation leaks into the public seam.
    expect(classifySensitivity(FAMILY_CONTENT, FAMILY_TITLE).level).toBe('CONFIDENTIAL');
  });

  it('POST /api/v1/scan/batch: mixed levels per item, invalid item unchanged, no tier', () => {
    const r = mockRes();
    handleV1ScanBatch({ body: { items: [
      { content: FAMILY_CONTENT, title: FAMILY_TITLE },
      { content: PUBLIC_NOTE },
      { content: EMAIL_NOTE },
      { content: RESTRICTED_NOTE },
      { content: 42 },
    ] } } as unknown as Request, r.res);
    const body = JSON.parse(JSON.stringify(r.body)) as { results: Array<Record<string, any>>; total: number };
    expect(body.results.slice(0, 4).map((x) => x.sensitivity.level)).toEqual(['PERSONAL', 'PUBLIC', 'CONFIDENTIAL', 'RESTRICTED']);
    for (const x of body.results.slice(0, 4)) expect(Object.keys(x.sensitivity)).toEqual(KEYS);
    expect(body.results[4]).toEqual({ error: 'content (string) is required', allowed: false });
    expect(JSON.stringify(r.body)).not.toContain('"tier"');
  });

  it('deep scan (POST /api/skills/deep-scan body) keeps PERSONAL in scanResults', async () => {
    const out = await runDeepScan([{ name: 'family.md', content: FAMILY_CONTENT }]);
    expect(out.scanResults[0].sensitivity.level).toBe('PERSONAL');
    expect(Object.keys(out.scanResults[0].sensitivity)).toEqual(KEYS);
    expect(JSON.stringify(out)).not.toContain('"tier"');
  });
});
