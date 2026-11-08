import fsSync from 'node:fs';
import os from 'node:os';
import nodePath from 'node:path';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';

import {
  closedSetPatternIds,
  injectionPatternIds,
  INJECTION_PATTERN_CAP,
  toAuditEntry,
} from '../audit-entry.js';
import { cloudSync } from '../cloud-sync.js';
import {
  scanRealtimeContent,
  scanLlmInput,
  __setDefenceModuleForTest,
  __setRuntimeForTest,
} from '../index.js';

const SPAN = 'SPAN_SHOULD_NOT_LEAK_9f3a';
const DESC = 'DESC_SHOULD_NOT_LEAK_9f3a';
const SAFE_ID = 'instruction_injection:system_prompt_override';

describe('injection pattern ids (#1010)', () => {
  it('keeps category:pattern, drops the span, and caps', () => {
    const detections = [
      { category: 'instruction_injection', pattern: 'system_prompt_override', match: SPAN, description: DESC },
      { category: 'Instruction_Injection', pattern: 'System_Prompt_Override', match: 'again' },
      { category: 'tool_injection', pattern: 'has a space', match: SPAN },
      { category: 'role_manipulation', pattern: 'x'.repeat(80), match: SPAN },
      {},
      null,
    ];
    expect(injectionPatternIds(detections)).toEqual([SAFE_ID]);

    const many = Array.from({ length: 20 }, (_, i) => ({
      category: 'instruction_injection',
      pattern: `rule_${i}`,
      match: SPAN,
    }));
    const ids = injectionPatternIds(many)!;
    expect(ids).toHaveLength(INJECTION_PATTERN_CAP);
    expect(ids.join(' ')).not.toContain(SPAN);
  });

  it('drops free text at the cloud boundary', () => {
    expect(closedSetPatternIds([
      SAFE_ID,
      SPAN,
      'ignore previous instructions',
      'instruction_injection:system_prompt_override',
      12,
    ])).toEqual([SAFE_ID]);
  });

  it('puts only safe ids on the canonical entry, never the span', () => {
    const entry = toAuditEntry({
      kind: 'realtime',
      hook: 'llm_input',
      reason: 'MEDIUM (1 detections)',
      injectionPatterns: [SAFE_ID, SPAN, 'not an id'],
    })!;
    expect(entry.threat_indicators).toEqual([SAFE_ID]);
    expect(entry.reason).toBe('MEDIUM (1 detections)');
    expect(JSON.stringify(entry)).not.toContain(SPAN);
  });

  it('keeps the summary as the indicator when there is no safe id', () => {
    const entry = toAuditEntry({
      kind: 'realtime',
      reason: 'MEDIUM (1 detections)',
      injectionPatterns: [SPAN],
    })!;
    expect(entry.threat_indicators).toEqual(['MEDIUM (1 detections)']);
  });
});

describe('cloudSync pattern ids (#1010)', () => {
  const realFetch = global.fetch;
  let calls: { body: string }[];

  beforeEach(() => {
    calls = [];
    // @ts-expect-error test stub
    global.fetch = (_url: string, init: { body: string }) => {
      calls.push({ body: init.body });
      return Promise.resolve({ ok: true });
    };
  });

  afterEach(() => {
    global.fetch = realFetch;
  });

  it('sends the ids and never the span, even when the local object carries one', async () => {
    cloudSync({
      hook: 'llm_input',
      reason: 'MEDIUM (1 detections)',
      injectionPatterns: [SAFE_ID, SPAN],
      preview: SPAN,
      content: SPAN,
      match: SPAN,
    }, {
      cloudEnabled: true,
      cloudApiKey: 'test-key',
      cloudBaseUrl: 'https://api.shieldcortex.ai',
    });
    await new Promise((r) => setTimeout(r, 0));
    expect(calls).toHaveLength(1);
    const body = calls[0].body;
    expect(body).toContain(SAFE_ID);
    expect(body).not.toContain(SPAN);
    expect(body).not.toContain('preview');
    expect(body).not.toContain('match');
  });
});

describe('llm_input audit row names the pattern (#1010)', () => {
  let auditRoot: string;
  let previousAuditDir: string | undefined;

  beforeEach(() => {
    previousAuditDir = process.env.SHIELDCORTEX_AUDIT_DIR;
    auditRoot = fsSync.mkdtempSync(nodePath.join(os.tmpdir(), 'sc-audit-1010-'));
    process.env.SHIELDCORTEX_AUDIT_DIR = auditRoot;
  });

  afterEach(() => {
    __setDefenceModuleForTest(undefined);
    __setRuntimeForTest(null);
    jest.restoreAllMocks();
    if (previousAuditDir === undefined) delete process.env.SHIELDCORTEX_AUDIT_DIR;
    else process.env.SHIELDCORTEX_AUDIT_DIR = previousAuditDir;
    fsSync.rmSync(auditRoot, { recursive: true, force: true });
  });

  it('writes injectionPatterns and not the matched span', async () => {
    __setRuntimeForTest({
      callCortex: async () => null,
      isOpenClawAutoMemoryEnabled: () => false,
      loadShieldConfig: async () => ({}),
    });
    __setDefenceModuleForTest({
      runDefencePipeline: () => ({}),
      scanToolResponse: () => ({
        clean: false,
        injection: {
          clean: false,
          riskLevel: 'MEDIUM',
          detections: [{
            category: 'instruction_injection',
            pattern: 'system_prompt_override',
            match: SPAN,
            description: DESC,
          }],
        },
      }),
    });
    jest.spyOn(console, 'warn').mockImplementation(() => {});

    const prompt = 'pattern probe token with enough length to scan';
    await scanLlmInput({
      runId: 'r-1010',
      sessionId: 's-1010',
      provider: 'test',
      model: 'test-model',
      prompt,
      historyMessages: [],
      imagesCount: 0,
    }, { agentId: 'openclaw' });

    const result = await scanRealtimeContent(prompt);
    expect(result.summary).toBe('MEDIUM (1 detections)');
    expect(result.injectionPatterns).toEqual([SAFE_ID]);

    const files = fsSync.readdirSync(auditRoot).filter(n => n.endsWith('.jsonl'));
    expect(files).toHaveLength(1);
    const row = JSON.parse(fsSync.readFileSync(nodePath.join(auditRoot, files[0]), 'utf8').trim());
    expect(row.hook).toBe('llm_input');
    expect(row.injectionPatterns).toEqual([SAFE_ID]);
    const raw = JSON.stringify(row);
    expect(raw).not.toContain(SPAN);
    expect(raw).not.toContain(DESC);
    expect(raw).not.toContain('match');
  });
});
