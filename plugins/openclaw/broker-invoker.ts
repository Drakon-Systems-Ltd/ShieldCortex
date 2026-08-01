/**
 * ShieldCortex — the OpenClaw judge transport for the approval broker (#143).
 *
 * Design: docs/design/2026-07-31-ai-approval-broker.md
 *
 * The design decided (Michael, 31 Jul 2026) that the broker rides the host's
 * existing model pool: no API key of its own, no login, no second bill. On the
 * gateway that means "ask OpenClaw for one completion through the pool the
 * operator already pays for and already governs".
 *
 * The gateway does not expose a completion seam to plugins today. Rather than
 * inventing credentials or importing an SDK — either of which would make
 * ShieldCortex a second, unaudited path to a model using the operator's
 * money — this defines the narrowest seam that could satisfy the design and
 * fails closed when it is absent:
 *
 *   no `context.invokeModel` → no invoker → no judge → the broker HOLDS.
 *
 * Which is exactly today's behaviour: the operator gets asked. When a gateway
 * build starts offering `invokeModel`, the broker lights up with no change here.
 *
 * The second half of the contract is what the seam is NOT given. The request is
 * a system prompt and one block of text, and the exported key allowlist is
 * asserted by test — because the failure mode this guards against is somebody
 * later adding `messages` or `session` "for context" and quietly handing the
 * judge the poisoned transcript it exists to be immune to.
 *
 * Types are declared locally rather than imported from `shieldcortex/defence`:
 * this file is built by tsconfig.openclaw-plugin.json across the plugin
 * boundary, the same reason `ToolGuardVerdictLike` is structural in
 * interceptor.ts.
 */

/** The judge's view of a model. Mirrors `ModelInvoker` in approval-judge.ts. */
export type ModelInvokerLike = (system: string, user: string) => Promise<string>;

/**
 * The completion request. Every field is trusted-or-bounded; there is no field
 * for conversation state, and that omission is the security property.
 */
export interface GatewayCompletionRequest {
  /** ShieldCortex's own classifier prompt. Trusted, constant. */
  system: string;
  /** The delimited, neutralised request under review. Untrusted DATA. */
  prompt: string;
  /** Tell the host this is a classifier call: no tools, no agent loop. */
  toolless: true;
  /** Optional judge-model override, already validated as a model name. */
  model?: string;
  /** Advisory deadline; the caller enforces its own regardless. */
  timeoutMs?: number;
}

/** The exact key set of a request. Pinned by test — see the header. */
export const GATEWAY_REQUEST_KEYS = ['system', 'prompt', 'toolless', 'model', 'timeoutMs'] as const;

/** The optional seam. Structural, so any gateway shape that fits can supply it. */
export interface BrokerInvokerContext {
  invokeModel?: (req: GatewayCompletionRequest) => Promise<unknown>;
}

export interface GatewayInvokerOptions {
  model?: string;
  timeoutMs?: number;
}

/** A judge reply is one small JSON object; anything past this is noise. */
const MAX_COMPLETION_CHARS = 65_536;

/** Duplicated from broker-config.ts's MODEL_NAME — the plugin build cannot
 *  import across the package boundary, and a hostile model string must be
 *  refused on both sides of it. Kept in sync there. */
const MODEL_NAME = /^[A-Za-z0-9][A-Za-z0-9._:@/-]*$/;

function safeModel(model: unknown): string | undefined {
  if (typeof model !== 'string') return undefined;
  const trimmed = model.trim();
  if (!trimmed || trimmed.length > 64 || !MODEL_NAME.test(trimmed)) return undefined;
  return trimmed;
}

/**
 * Read text out of whatever the host's pool returned.
 *
 * Deliberately permissive about SHAPE (a gateway may hand back a string, an
 * Anthropic-style content array, or an OpenAI-style message) and deliberately
 * strict about SUBSTANCE: anything that is not readable text is null, and null
 * becomes a rejection, which becomes a hold. A response we cannot read is never
 * optimistically treated as approval.
 */
export function coerceCompletion(raw: unknown): string | null {
  const bound = (s: string): string | null => (s.length > MAX_COMPLETION_CHARS ? s.slice(0, MAX_COMPLETION_CHARS) : s);

  if (typeof raw === 'string') return bound(raw);
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;

  const o = raw as Record<string, unknown>;
  for (const key of ['text', 'completion', 'output'] as const) {
    if (typeof o[key] === 'string') return bound(o[key] as string);
  }
  if (typeof o.content === 'string') return bound(o.content);
  if (Array.isArray(o.content)) {
    const parts = o.content
      .filter((b): b is Record<string, unknown> => !!b && typeof b === 'object')
      .filter(b => b.type === 'text' && typeof b.text === 'string')
      .map(b => b.text as string);
    return parts.length ? bound(parts.join('')) : null;
  }
  if (o.message && typeof o.message === 'object') return coerceCompletion(o.message);
  return null;
}

/**
 * Build a judge transport from the gateway's completion seam, or null when the
 * gateway does not offer one.
 *
 * Null is not an error state — it is the honest answer on every gateway build
 * that ships today, and the broker's response to it (hold for the operator) is
 * the behaviour ShieldCortex already had.
 */
export function createGatewayInvoker(
  context: BrokerInvokerContext,
  opts: GatewayInvokerOptions = {},
): ModelInvokerLike | null {
  if (!context || typeof context !== 'object') return null;
  const invokeModel = context.invokeModel;
  if (typeof invokeModel !== 'function') return null;

  const model = safeModel(opts.model);

  return async (system: string, user: string): Promise<string> => {
    const req: GatewayCompletionRequest = {
      system,
      prompt: user,
      toolless: true,
    };
    if (model) req.model = model;
    if (typeof opts.timeoutMs === 'number' && Number.isFinite(opts.timeoutMs)) req.timeoutMs = opts.timeoutMs;

    // A throw here propagates: runJudge catches it and returns null, which the
    // broker reads as "hold". Swallowing it into a default would be the one
    // failure mode this whole layer exists to avoid.
    const raw = await invokeModel(req);

    const text = coerceCompletion(raw);
    if (text === null) throw new Error('gateway returned an unreadable completion');
    if (!text.trim()) throw new Error('gateway returned an empty completion');
    return text;
  };
}
