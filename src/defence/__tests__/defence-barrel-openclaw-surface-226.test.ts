import { describe, expect, it } from '@jest/globals';

// THE REAL BARREL. Not `../iron-dome/operator-notify.js`, not a hand-written
// mirror — the exact specifier the OpenClaw plugin resolves at runtime
// (`shieldcortex/defence` → dist/defence/index.js, whose source is this file).
import * as defence from '../index.js';

/**
 * #226 — the plugin's only door into this package, tested through the door.
 *
 * The OpenClaw plugin builds as a SEPARATE compilation unit. It cannot import
 * `shieldcortex/defence` at compile time (the package only exists at runtime on
 * an installed box), so it declares a hand-written `DefenceModule` type,
 * imports by a string-concatenated specifier, and looks every symbol up BY
 * NAME. Nothing in either build fails if a name is wrong: the plugin's
 * `typeof mod.X !== 'function'` guards simply degrade, quietly, to "this
 * shieldcortex build has no notify transport" — on a build that has one.
 *
 * That mirror has already been wrong once in this feature, in the way that
 * matters most: it named the webhook signing key `secret`, which
 * `normaliseNotifyConfig` does not return, so `createWebhookNotifyChannel` was
 * handed `undefined` and every POST would have gone out UNSIGNED while the
 * config said it was signed.
 *
 * Both suites either side of this one test the mirror against itself:
 * conversation-gate-226.test.ts stubs the defence module, and
 * conversation-threat-notify-226.test.ts imports the transport modules
 * directly. Neither would notice the barrel dropping an export — which is the
 * one failure that reaches a real box. This file asserts the CONTRACT AT THE
 * BOUNDARY: the four names the plugin reaches for exist on the real barrel, and
 * a config round-trips through them with the signing key intact.
 */

/** The exact names plugins/openclaw/index.ts looks up on the defence module. */
const PLUGIN_REQUIRED_EXPORTS = [
  'normaliseNotifyConfig',
  'buildConversationThreatNotification',
  'deliverOperatorNotification',
  'createWebhookNotifyChannel',
] as const;

describe('#226 the shieldcortex/defence barrel exports what the OpenClaw plugin resolves by name', () => {
  it.each(PLUGIN_REQUIRED_EXPORTS)('exports %s as a function', (name) => {
    expect(typeof (defence as Record<string, unknown>)[name]).toBe('function');
  });

  it('also exports the pieces the plugin uses for the tool-call path (#143/#189)', () => {
    // Same class of coupling, same failure mode: `resolveBrokerRuntime` needs
    // ALL FOUR of these or it silently disables the broker.
    for (const name of ['normaliseBrokerConfig', 'brokerDecision', 'runJudge', 'timeoutOutcome', 'scanToolResponse', 'runDefencePipeline']) {
      expect(typeof (defence as Record<string, unknown>)[name]).toBe('function');
    }
  });
});

describe('#226 webhookSecret survives normalisation under THAT NAME', () => {
  it('returns the signing key on `webhookSecret`, which is the field the plugin reads', () => {
    const cfg = defence.normaliseNotifyConfig({
      enabled: true,
      webhookUrl: 'https://hooks.example/shieldcortex',
      webhookSecret: 'placeholder-not-a-real-key',
      timeoutMs: 8_000,
      openclaw: false,
    });

    expect(cfg.enabled).toBe(true);
    expect(cfg.webhookUrl).toBe('https://hooks.example/shieldcortex');
    expect(cfg.webhookSecret).toBe('placeholder-not-a-real-key');
    expect(cfg.timeoutMs).toBe(8_000);
    // The bug, pinned by name: `secret` is not and has never been the field.
    // A mirror that reads it gets `undefined` and signs nothing.
    expect((cfg as Record<string, unknown>).secret).toBeUndefined();
  });

  it('a config that arms notify without a key is reported as keyless, not as signed', () => {
    const cfg = defence.normaliseNotifyConfig({ enabled: true, webhookUrl: 'https://hooks.example/x' });
    expect(cfg.enabled).toBe(true);
    expect(cfg.webhookSecret).toBeUndefined();
  });
});

describe('#226 an end-to-end round trip through the barrel, exactly as the plugin does it', () => {
  it('normalise → build → deliver, with the signing key reaching the channel factory', async () => {
    const raw = {
      enabled: true,
      webhookUrl: 'https://hooks.example/shieldcortex',
      webhookSecret: 'placeholder-not-a-real-key',
    };

    // 1. The plugin normalises the RAW config block it parsed out of openclaw.json.
    const notify = defence.normaliseNotifyConfig(raw);
    expect(notify.enabled).toBe(true);

    // 2. It builds the channel from the normalised fields. `fetchImpl` is the
    //    real channel's injectable transport, so this exercises the real
    //    factory rather than a stand-in for it.
    const posted: Array<{ url: string; headers: Record<string, string>; body: string }> = [];
    const channel = defence.createWebhookNotifyChannel({
      url: notify.webhookUrl!,
      secret: notify.webhookSecret,
      fetchImpl: (async (url: unknown, init: unknown) => {
        const req = init as { headers?: Record<string, string>; body?: string };
        posted.push({ url: String(url), headers: req.headers ?? {}, body: String(req.body ?? '') });
        return { ok: true, status: 204 } as Response;
      }) as unknown as typeof fetch,
    });

    // 3. It builds the notification through the BUILDER, never as a literal.
    const notification = defence.buildConversationThreatNotification({
      outcome: 'observed',
      posture: 'observe',
      summary: 'HIGH (2 detections)',
      reason: 'conversation threat: HIGH (2 detections)',
      sessionId: 'sess-barrel',
      model: 'claude-opus-5',
      host: 'test-host',
      detectedAt: '2026-08-10T12:00:00.000Z',
    });
    expect(defence.isConversationThreatNotification(notification)).toBe(true);

    // 4. And delivers through the SHARED core.
    const result = await defence.deliverOperatorNotification(notification, {
      channels: [channel],
      timeoutMs: 5_000,
    });

    expect(result.deliveredVia).toBe(channel.name);
    expect(posted).toHaveLength(1);
    // The key was actually used: a signature header exists. Its value is not
    // asserted here (webhook-notify-channel's own suite owns the HMAC); what
    // this pins is that the key SURVIVED the name it travels under.
    const signature = posted[0].headers['X-ShieldCortex-Signature'] ?? posted[0].headers['x-shieldcortex-signature'];
    expect(typeof signature).toBe('string');
    expect(signature).not.toContain('undefined');
    // And the alert carries the conversation discriminator, with no approval
    // affordance anywhere in the body.
    expect(posted[0].body).toContain('conversation_threat');
    expect(posted[0].body).not.toContain('[Approve]');
    // The signing key is never in the payload.
    expect(posted[0].body).not.toContain('placeholder-not-a-real-key');
  });
});
