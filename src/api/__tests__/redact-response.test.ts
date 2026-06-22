import { describe, expect, it } from '@jest/globals';
import { redactRestrictedResponses } from '../redact-response.js';
import { RESTRICTED_CONTENT_PLACEHOLDER } from '../../defence/trust/read-guard.js';

/**
 * The HTTP response interceptor: every JSON response from the visualization API
 * must have RESTRICTED memory content redacted before it reaches the browser.
 */
function fakeRes() {
  const captured: { body: unknown } = { body: undefined };
  const res = {
    json(body: unknown) {
      // the "real" terminal json — records what would actually be serialized
      captured.body = body;
      return res;
    },
  } as unknown as import('express').Response;
  return { res, captured };
}

function run(payload: unknown) {
  const { res, captured } = fakeRes();
  let nextCalled = false;
  redactRestrictedResponses({} as import('express').Request, res, () => {
    nextCalled = true;
  });
  // After the middleware, res.json is the wrapped version.
  res.json(payload);
  return { captured, nextCalled };
}

describe('redactRestrictedResponses middleware', () => {
  it('calls next()', () => {
    const { nextCalled } = run({ ok: true });
    expect(nextCalled).toBe(true);
  });

  it('redacts RESTRICTED memory content in the response body', () => {
    const { captured } = run({
      memories: [
        { id: 1, sensitivityLevel: 'RESTRICTED', content: 'sk_live_secret', title: 'Stripe key' },
        { id: 2, sensitivityLevel: 'INTERNAL', content: 'ordinary note' },
      ],
    });
    const body = captured.body as { memories: { content: string }[] };
    expect(body.memories[0].content).toBe(RESTRICTED_CONTENT_PLACEHOLDER);
    expect(body.memories[1].content).toBe('ordinary note');
  });

  it('redacts deeply nested memories (recall results[].memory)', () => {
    const { captured } = run({ results: [{ memory: { id: 9, sensitivityLevel: 'RESTRICTED', content: 'token' } }] });
    const body = captured.body as { results: { memory: { content: string } }[] };
    expect(body.results[0].memory.content).toBe(RESTRICTED_CONTENT_PLACEHOLDER);
  });

  it('passes non-memory payloads through unchanged', () => {
    const payload = { status: 'ok', total: 3, items: ['a'] };
    const { captured } = run(payload);
    expect(captured.body).toEqual(payload);
  });
});
