import { describe, expect, it } from '@jest/globals';
import {
  L1_SALIENCE_CAP,
  allowRegexFallback,
  failClosedDistill,
  resolveCaptureMode,
  resolveDistillProvider,
  resolveHermesOAuthProvider,
  parseDistillResponseText,
  extractCaptureMemories,
  buildDistillPrompt,
} from '../../../scripts/lib/capture-distill.mjs';

describe('capture-distill fail-closed', () => {
  it('caps L1 salience at 0.7', () => {
    const r = failClosedDistill(null, [{ title: 't', content: 'c', salience: 0.99 }]);
    expect(r.ok).toBe(true);
    expect(r.memories[0].salience).toBe(L1_SALIENCE_CAP);
    expect(r.memories[0].capture_layer).toBe('L1');
  });

  it('skips on error — empty memories', () => {
    const r = failClosedDistill(new Error('timeout'), [{ title: 't', content: 'c' }]);
    expect(r.ok).toBe(false);
    expect(r.memories).toEqual([]);
  });

  it('rejects invalid schema', () => {
    const r = failClosedDistill(null, null);
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('invalid-schema');
  });

  it('regex fallback only in explicit regex mode', () => {
    expect(allowRegexFallback('distill')).toBe(false);
    expect(allowRegexFallback('distill_required')).toBe(false);
    expect(allowRegexFallback('regex')).toBe(true);
  });

  it('defaults to distill when provider configured', () => {
    expect(resolveCaptureMode(undefined, { providerConfigured: true })).toBe('distill');
    expect(resolveCaptureMode(undefined, { providerConfigured: false })).toBe('regex');
  });

  it('normalizes unknown categories to note', () => {
    const r = failClosedDistill(null, [{ title: 't', content: 'c', category: 'WAT' }]);
    expect(r.memories[0].category).toBe('note');
  });
});

describe('capture-distill provider + parse', () => {
  it('resolveDistillProvider detects openai key from env', () => {
    const p = resolveDistillProvider({ OPENAI_API_KEY: 'sk-test' }, {});
    expect(p.configured).toBe(true);
    expect(p.source).toBe('openai-compatible');
    expect(p.apiKey).toBe('sk-test');
  });

  it('resolveDistillProvider detects anthropic key', () => {
    const p = resolveDistillProvider({ ANTHROPIC_API_KEY: 'sk-ant-test' }, {});
    expect(p.configured).toBe(true);
    expect(p.source).toBe('anthropic');
  });

  it('resolveDistillProvider unconfigured without keys or oauth', () => {
    const p = resolveDistillProvider(
      { SHIELDCORTEX_DISTILL_OAUTH: '0', HOME: '/tmp/no-hermes-home-sc-test' },
      {},
    );
    expect(p.configured).toBe(false);
  });

  it('resolveHermesOAuthProvider can be disabled', () => {
    const p = resolveHermesOAuthProvider({ SHIELDCORTEX_DISTILL_OAUTH: '0' }, {});
    expect(p.configured).toBe(false);
  });

  it('parseDistillResponseText accepts fenced json', () => {
    const text = '```json\n{"memories":[{"title":"A","content":"B","salience":0.9}]}\n```';
    const arr = parseDistillResponseText(text);
    expect(arr).toHaveLength(1);
    const closed = failClosedDistill(null, arr);
    expect(closed.memories[0].salience).toBe(L1_SALIENCE_CAP);
  });

  it('buildDistillPrompt clips long transcripts', () => {
    const long = 'x'.repeat(50_000);
    const { user } = buildDistillPrompt(long);
    expect(user.length).toBeLessThan(30_000);
  });
});

describe('extractCaptureMemories', () => {
  const transcript = 'A'.repeat(200) + '\nWe decided to use inject pack v2 with nativeContract sc_only on TARS.';

  it('uses regex path when mode=regex', async () => {
    const r = await extractCaptureMemories(transcript, {
      mode: 'regex',
      env: {},
      config: {},
      regexExtract: () => [{ title: 'regex-hit', content: 'from regex', category: 'note', salience: 0.5, tags: [] }],
      log: () => {},
    });
    expect(r.path).toBe('regex');
    expect(r.memories[0].title).toBe('regex-hit');
  });

  it('skips without regex fallback when distill fails', async () => {
    const fetchImpl = async () => {
      throw new Error('network-down');
    };
    const r = await extractCaptureMemories(transcript, {
      mode: 'distill',
      env: { OPENAI_API_KEY: 'sk-test', SHIELDCORTEX_DISTILL_OAUTH: '0' },
      config: {},
      fetchImpl,
      regexExtract: () => [{ title: 'should-not', content: 'nope', category: 'note', salience: 0.5 }],
      log: () => {},
    });
    expect(r.path).toBe('skip');
    expect(r.memories).toEqual([]);
  });

  it('distills via mock openai response', async () => {
    const fetchImpl = async () => ({
      ok: true,
      json: async () => ({
        choices: [{
          message: {
            content: JSON.stringify({
              memories: [
                { title: 'Inject contract', content: 'Use sc_only on TARS', category: 'decision', salience: 0.9 },
              ],
            }),
          },
        }],
      }),
    });
    const r = await extractCaptureMemories(transcript, {
      mode: 'distill',
      env: { OPENAI_API_KEY: 'sk-test', SHIELDCORTEX_DISTILL_OAUTH: '0' },
      config: {},
      fetchImpl,
      regexExtract: () => [],
      log: () => {},
    });
    expect(r.path).toBe('distill');
    expect(r.memories).toHaveLength(1);
    expect(r.memories[0].title).toBe('Inject contract');
    expect(r.memories[0].salience).toBe(L1_SALIENCE_CAP);
    expect(r.memories[0].capture_layer).toBe('L1');
  });

  it('distill_required without provider skips', async () => {
    const r = await extractCaptureMemories(transcript, {
      mode: 'distill_required',
      env: { SHIELDCORTEX_DISTILL_OAUTH: '0', HOME: '/tmp/no-hermes-home-sc-test' },
      config: {},
      regexExtract: () => [{ title: 'nope', content: 'x', category: 'note', salience: 0.4 }],
      log: () => {},
    });
    expect(r.path).toBe('skip');
    expect(r.memories).toEqual([]);
  });
});
