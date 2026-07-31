/**
 * Failing-first spec for the OpenClaw judge transport (#143).
 *
 * The design is explicit that the broker brings no credentials of its own: on
 * the gateway it "rides the host's existing model pool". The gateway does not
 * currently expose a completion seam to plugins, so this defines the narrowest
 * one that could work — `context.invokeModel` — and, crucially, defines what
 * happens when it is absent, which today is *always*: no seam → no invoker →
 * no judge → the broker holds for a human. Nothing is invented, nothing fails
 * open.
 *
 * The other half of the contract is what the seam is NOT given. The judge must
 * never receive the agent's transcript; if it did, a poisoned session could
 * simply argue for its own approval. So these tests assert that the request
 * object carries NOTHING beyond a declared allowlist, rather than spot-checking
 * that the right fields are present.
 */
import { describe, it, expect, jest } from '@jest/globals';
import {
  createGatewayInvoker,
  coerceCompletion,
  GATEWAY_REQUEST_KEYS,
  type GatewayCompletionRequest,
} from '../broker-invoker.js';

type Invoke = (req: GatewayCompletionRequest) => Promise<unknown>;

function seam(reply: unknown | ((req: GatewayCompletionRequest) => unknown)): {
  invokeModel: Invoke;
  calls: GatewayCompletionRequest[];
} {
  const calls: GatewayCompletionRequest[] = [];
  const invokeModel: Invoke = async req => {
    calls.push(req);
    return typeof reply === 'function' ? (reply as (r: GatewayCompletionRequest) => unknown)(req) : reply;
  };
  return { invokeModel, calls };
}

const SYSTEM = 'you are a classifier';
const USER = 'judge this: sudo modprobe softdog';

// ── absence of a seam is the normal case, and it must fail closed ───────────

describe('no completion seam on the context', () => {
  it('returns null rather than inventing a transport', () => {
    expect(createGatewayInvoker({})).toBeNull();
    expect(createGatewayInvoker({ invokeModel: undefined })).toBeNull();
  });

  it('returns null for a context that is not a context at all', () => {
    for (const junk of [undefined, null, 'ctx', 42, []]) {
      expect(createGatewayInvoker(junk as never)).toBeNull();
    }
  });

  it('returns null when invokeModel is present but not callable', () => {
    for (const junk of ['yes', 1, {}, [], true]) {
      expect(createGatewayInvoker({ invokeModel: junk as never })).toBeNull();
    }
  });
});

// ── what the seam receives ──────────────────────────────────────────────────

describe('the request handed to the gateway', () => {
  it('carries the system prompt and the request, and passes the reply back', async () => {
    const { invokeModel, calls } = seam('{"assessment":"benign"}');
    const invoke = createGatewayInvoker({ invokeModel })!;
    await expect(invoke(SYSTEM, USER)).resolves.toBe('{"assessment":"benign"}');
    expect(calls[0].system).toBe(SYSTEM);
    expect(calls[0].prompt).toBe(USER);
  });

  it('NEVER carries the session, the transcript, or the agent history', async () => {
    const { invokeModel, calls } = seam('ok');
    const invoke = createGatewayInvoker({ invokeModel })!;
    await invoke(SYSTEM, USER);

    // Asserted against the allowlist, not spot-checked: a future field added
    // "just for context" is precisely how the judge would end up reading the
    // poisoned transcript it exists to be immune to.
    for (const key of Object.keys(calls[0])) {
      expect(GATEWAY_REQUEST_KEYS as readonly string[]).toContain(key);
    }
    for (const forbidden of ['messages', 'history', 'transcript', 'session', 'sessionId', 'context', 'tools']) {
      expect(Object.keys(calls[0])).not.toContain(forbidden);
    }
  });

  it('asks for a tool-less, single-shot completion', async () => {
    const { invokeModel, calls } = seam('ok');
    await createGatewayInvoker({ invokeModel })!(SYSTEM, USER);
    // The gateway must be told this is a classifier call, not an agent turn.
    expect(calls[0].toolless).toBe(true);
  });

  it('forwards the model override and the deadline', async () => {
    const { invokeModel, calls } = seam('ok');
    await createGatewayInvoker({ invokeModel }, { model: 'haiku', timeoutMs: 3_000 })!(SYSTEM, USER);
    expect(calls[0].model).toBe('haiku');
    expect(calls[0].timeoutMs).toBe(3_000);
  });

  it('omits a hostile model override rather than forwarding it', async () => {
    const { invokeModel, calls } = seam('ok');
    await createGatewayInvoker({ invokeModel }, { model: '--dangerously-skip-permissions' })!(SYSTEM, USER);
    expect(calls[0].model).toBeUndefined();
  });
});

// ── what comes back ─────────────────────────────────────────────────────────

describe('coerceCompletion', () => {
  it('accepts the shapes a completion API plausibly returns', () => {
    expect(coerceCompletion('plain')).toBe('plain');
    expect(coerceCompletion({ text: 'from text' })).toBe('from text');
    expect(coerceCompletion({ completion: 'from completion' })).toBe('from completion');
    expect(coerceCompletion({ content: 'from content' })).toBe('from content');
    expect(coerceCompletion({ content: [{ type: 'text', text: 'a' }, { type: 'text', text: 'b' }] })).toBe('ab');
    expect(coerceCompletion({ message: { content: 'nested' } })).toBe('nested');
  });

  it('refuses anything it cannot read as text', () => {
    for (const junk of [null, undefined, 42, true, [], {}, { text: 42 }, { content: [{ type: 'image' }] }]) {
      expect(coerceCompletion(junk)).toBeNull();
    }
  });

  it('bounds an absurdly long completion', () => {
    const out = coerceCompletion('x'.repeat(500_000));
    expect(out!.length).toBeLessThanOrEqual(65_536);
  });
});

describe('failure is always a rejection, never a verdict', () => {
  it('rejects when the gateway throws', async () => {
    const invoke = createGatewayInvoker({ invokeModel: async () => { throw new Error('pool exhausted'); } })!;
    await expect(invoke(SYSTEM, USER)).rejects.toThrow(/pool exhausted/);
  });

  it('rejects when the gateway returns something unreadable', async () => {
    for (const junk of [null, undefined, 42, {}, []]) {
      const invoke = createGatewayInvoker({ invokeModel: async () => junk })!;
      await expect(invoke(SYSTEM, USER)).rejects.toThrow(/unreadable|no text|completion/i);
    }
  });

  it('rejects an empty completion rather than handing the parser nothing', async () => {
    const invoke = createGatewayInvoker({ invokeModel: async () => '   ' })!;
    await expect(invoke(SYSTEM, USER)).rejects.toThrow();
  });

  it('does not call the gateway more than once per judgement', async () => {
    const invokeModel = jest.fn(async () => 'ok') as unknown as Invoke;
    await createGatewayInvoker({ invokeModel })!(SYSTEM, USER);
    expect(invokeModel).toHaveBeenCalledTimes(1);
  });
});
