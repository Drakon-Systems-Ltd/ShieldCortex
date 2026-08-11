import fs from 'node:fs';
import path from 'node:path';
import url from 'node:url';
import Ajv from 'ajv';
import { describe, expect, it } from '@jest/globals';

import plugin from '../index.js';

/**
 * #225/#226 — the posture and the notify transport must be accepted by the
 * schema the HOST validates against, not only by our runtime parser.
 *
 * `openclaw.plugin.json`'s `configSchema` declares `additionalProperties: false`
 * at every level. So a key that exists in the TypeScript normaliser but not in
 * that file does not merely go unvalidated — it makes the whole enclosing block
 * invalid on any host that validates plugin config against the manifest. An
 * operator following our own documentation writes
 * `interceptor.conversation.posture` and the gateway rejects their config.
 *
 * These tests validate REAL config shapes against the REAL manifest with a real
 * JSON Schema validator, and pin the two schemas against drift from each other.
 */

const here = path.dirname(url.fileURLToPath(import.meta.url));
const manifest = JSON.parse(fs.readFileSync(path.join(here, '..', 'openclaw.plugin.json'), 'utf-8'));

// The manifest uses plain JSON Schema draft-07-style keywords; `strict: false`
// keeps ajv from rejecting the `description`/`default` annotations the host UI
// reads.
const ajv = new Ajv({ strict: false, allErrors: true });
const validate = ajv.compile(manifest.configSchema);

describe('#226 manifest configSchema accepts the conversation posture', () => {
  it.each(['off', 'observe', 'enforce'])('accepts posture "%s"', (posture) => {
    const ok = validate({ interceptor: { conversation: { posture } } });
    expect(validate.errors ?? []).toEqual([]);
    expect(ok).toBe(true);
  });

  it('rejects a posture that is not one of the three', () => {
    expect(validate({ interceptor: { conversation: { posture: 'block-everything' } } })).toBe(false);
  });

  it('rejects an unknown key inside the conversation block rather than ignoring it', () => {
    expect(validate({ interceptor: { conversation: { postures: 'enforce' } } })).toBe(false);
  });
});

describe('#226 manifest configSchema accepts the operator-notify transport', () => {
  it('accepts a fully configured notify block', () => {
    const ok = validate({
      interceptor: {
        actionGuard: {
          enabled: true,
          enforce: true,
          notify: {
            enabled: true,
            webhookUrl: 'https://hook.example/shieldcortex',
            webhookSecret: 'placeholder-not-a-real-key',
            openclaw: true,
            timeoutMs: 8000,
          },
        },
      },
    });
    expect(validate.errors ?? []).toEqual([]);
    expect(ok).toBe(true);
  });

  it('rejects an out-of-range timeout and an unknown notify key', () => {
    expect(validate({ interceptor: { actionGuard: { notify: { timeoutMs: 10 } } } })).toBe(false);
    expect(validate({ interceptor: { actionGuard: { notify: { secret: 'x' } } } })).toBe(false);
  });

  it('accepts a realistic whole-plugin config as an operator would write it', () => {
    const ok = validate({
      binaryPath: '/usr/local/bin/shieldcortex',
      openclawAutoMemory: true,
      interceptor: {
        enabled: true,
        conversation: { posture: 'observe' },
        severityActions: { high: 'warn', critical: 'require_approval' },
        actionGuard: {
          enabled: true,
          enforce: true,
          auditAllows: true,
          notify: { enabled: true, webhookUrl: 'https://hook.example/sc' },
        },
      },
    });
    expect(validate.errors ?? []).toEqual([]);
    expect(ok).toBe(true);
  });
});

/**
 * The exact config path behind the original `parsedNotify: null` reproduction.
 *
 * `normaliseConfig` has read a TOP-LEVEL `actionGuard` block since #209 — that
 * is the canonical location and `interceptor.actionGuard` is the deprecated
 * alias. Both schemas declared only the alias, under `additionalProperties:
 * false`. So an operator writing the documented, canonical shape
 * (`actionGuard.notify` at the top level) had their config rejected as an
 * unknown key by any host that validates against the manifest — the parser
 * would have kept it, and the config never reached the parser.
 */
describe('#226 top-level actionGuard is canonical, and BOTH schemas accept it', () => {
  it('the manifest accepts a top-level actionGuard.notify block', () => {
    const ok = validate({
      actionGuard: {
        enabled: true,
        enforce: true,
        notify: {
          enabled: true,
          webhookUrl: 'https://hook.example/shieldcortex',
          webhookSecret: 'placeholder-not-a-real-key',
          openclaw: true,
          timeoutMs: 8000,
        },
      },
    });
    expect(validate.errors ?? []).toEqual([]);
    expect(ok).toBe(true);
  });

  it('the manifest accepts BOTH locations in one config (canonical + alias)', () => {
    const ok = validate({
      actionGuard: { enforce: true, notify: { enabled: true, webhookUrl: 'https://hook.example/sc' } },
      interceptor: { enabled: true, actionGuard: { auditAllows: false } },
    });
    expect(validate.errors ?? []).toEqual([]);
    expect(ok).toBe(true);
  });

  it('the manifest still rejects junk at the top level, exactly as it does nested', () => {
    expect(validate({ actionGuard: { notify: { timeoutMs: 10 } } })).toBe(false);
    expect(validate({ actionGuard: { notify: { secret: 'x' } } })).toBe(false);
    expect(validate({ actionGuard: { enfource: true } })).toBe(false);
  });

  it('the runtime parser KEEPS a top-level actionGuard.notify (the reproduction)', () => {
    const parsed = plugin.configSchema.parse({
      actionGuard: {
        enabled: true,
        notify: { enabled: true, webhookUrl: 'https://hook.example/sc', webhookSecret: 'placeholder' },
      },
    }) as any;
    // Folded to the single enforcement location, with nothing lost.
    expect(parsed.interceptor.actionGuard.notify).toEqual({
      enabled: true,
      webhookUrl: 'https://hook.example/sc',
      webhookSecret: 'placeholder',
    });
    expect(parsed.interceptor.actionGuard.enabled).toBe(true);
  });

  it('the runtime parser KEEPS a nested interceptor.actionGuard.notify too', () => {
    const parsed = plugin.configSchema.parse({
      interceptor: {
        actionGuard: { notify: { enabled: true, webhookUrl: 'https://alias.example/sc' } },
      },
    }) as any;
    expect(parsed.interceptor.actionGuard.notify).toEqual({
      enabled: true,
      webhookUrl: 'https://alias.example/sc',
    });
  });

  it('on a conflict the canonical top-level value wins, per-key', () => {
    const parsed = plugin.configSchema.parse({
      actionGuard: { enforce: true, notify: { enabled: true, webhookUrl: 'https://canonical.example/sc' } },
      interceptor: { actionGuard: { enforce: false, auditAllows: false } },
    }) as any;
    expect(parsed.interceptor.actionGuard.enforce).toBe(true);
    expect(parsed.interceptor.actionGuard.notify.webhookUrl).toBe('https://canonical.example/sc');
    // A key the canonical block does not mention survives from the alias.
    expect(parsed.interceptor.actionGuard.auditAllows).toBe(false);
  });

  it('every shape the schemas accept round-trips through the parser', () => {
    // Schema-accepts and parser-keeps must agree in BOTH directions, or a
    // config validates on the host and then does nothing.
    for (const cfg of [
      { actionGuard: { notify: { enabled: true, webhookUrl: 'https://a.example/x' } } },
      { interceptor: { actionGuard: { notify: { enabled: true, webhookUrl: 'https://a.example/x' } } } },
    ]) {
      expect(validate(cfg)).toBe(true);
      const parsed = plugin.configSchema.parse(cfg) as any;
      expect(parsed.interceptor.actionGuard.notify.enabled).toBe(true);
    }
  });
});

describe('#226 the manifest and the runtime schema do not drift apart', () => {
  const runtimeSchema = (plugin.configSchema as { jsonSchema: any }).jsonSchema;

  it('the canonical and alias Action Guard schemas are identical in BOTH files', () => {
    // One constant mounted twice on the runtime side; mirrored by hand into the
    // manifest. If the two ever diverge, a config that validates against one
    // location is rejected at the other for no reason an operator can see.
    expect(manifest.configSchema.properties.actionGuard).toEqual(
      manifest.configSchema.properties.interceptor.properties.actionGuard,
    );
    expect(runtimeSchema.properties.actionGuard).toEqual(
      runtimeSchema.properties.interceptor.properties.actionGuard,
    );
  });

  // BIDIRECTIONAL, deliberately (#226). The one-way check this replaces only
  // asserted that every MANIFEST key existed in the runtime schema, and
  // explicitly excused the reverse — which is the direction that actually
  // breaks an operator. `additionalProperties: false` means a key the manifest
  // omits is not merely undeclared: it makes the whole enclosing block INVALID
  // on any host that validates config against the manifest. `broker` and
  // `reviewedScripts` were in exactly that state, so a config the runtime
  // parser accepts and acts on was rejected before it ever reached the parser.
  // Omission is rejection, so parity has to be tested in both directions.
  it.each([
    ['top-level actionGuard', () => [
      manifest.configSchema.properties.actionGuard,
      runtimeSchema.properties.actionGuard,
    ]],
    ['interceptor.actionGuard (the deprecated alias)', () => [
      manifest.configSchema.properties.interceptor.properties.actionGuard,
      runtimeSchema.properties.interceptor.properties.actionGuard,
    ]],
  ])('%s declares exactly the same keys in both files', (_label, pick) => {
    const [manifestGuard, runtimeGuard] = (pick as () => any[])();
    expect(Object.keys(manifestGuard.properties).sort()).toEqual(
      Object.keys(runtimeGuard.properties).sort(),
    );
    // …and one level deeper, for every object-valued key. A `broker` block
    // declared in both files but missing `preClearConfidence` in one of them
    // fails the same way the whole block did.
    for (const key of ['broker', 'notify']) {
      expect(Object.keys(manifestGuard.properties[key].properties).sort()).toEqual(
        Object.keys(runtimeGuard.properties[key].properties).sort(),
      );
    }
    expect(Object.keys(manifestGuard.properties.reviewedScripts.items.properties).sort()).toEqual(
      Object.keys(runtimeGuard.properties.reviewedScripts.items.properties).sort(),
    );
    expect(manifestGuard.properties.reviewedScripts.items.required).toEqual(
      runtimeGuard.properties.reviewedScripts.items.required,
    );
  });

  it('conversationTrust is declared identically in both files, and is actually parsed', () => {
    // #235 landed `conversationTrust.trustOwnerInput` as a READ against a
    // config object that no schema declared and `normaliseConfig` did not
    // allowlist. Under `additionalProperties: false` an operator who sets it
    // has their whole plugin config rejected by the host; on a host that does
    // not validate, the key is dropped by the parser and reads as undefined.
    // Either way the documented opt-out could not be turned on by anyone —
    // which matters because it is the only way to ask for the owner's own
    // input to be policed like everything else.
    expect(manifest.configSchema.properties.conversationTrust).toEqual(
      runtimeSchema.properties.conversationTrust,
    );
    expect(validate({ conversationTrust: { trustOwnerInput: false } })).toBe(true);
    expect(validate({ conversationTrust: { trustOwnerInput: 'false' } })).toBe(false);
    expect(validate({ conversationTrust: { trustOwner: false } })).toBe(false);

    // …and the parser KEEPS what the schema accepts. A schema that validates a
    // key the parser drops is the same silent failure wearing the other hat.
    const parse = (v: unknown) => (plugin.configSchema as { parse(v: unknown): any }).parse(v);
    expect(parse({ conversationTrust: { trustOwnerInput: false } }).conversationTrust).toEqual({
      trustOwnerInput: false,
    });
    expect(parse({ conversationTrust: { trustOwnerInput: true } }).conversationTrust).toEqual({
      trustOwnerInput: true,
    });
    // A non-boolean is dropped rather than coerced — `"false"` is the #112 typo
    // shape, and reading it as the opt-out would be a guess.
    expect(parse({ conversationTrust: { trustOwnerInput: 'false' } }).conversationTrust).toBeUndefined();
  });

  it('the manifest accepts a broker and a reviewedScripts entry at BOTH locations', () => {
    // The reproduction, one layer out from notify: these are documented,
    // parsed, enforced keys, and `additionalProperties: false` made a config
    // carrying either of them invalid at the manifest boundary.
    const broker = { enabled: true, allowPreClear: true, preClearConfidence: 0.95, judgeTimeoutMs: 4000 };
    const reviewedScripts = [{ path: '/opt/ops/deploy.sh', sha256: 'a'.repeat(64), note: 'reviewed 2026-08' }];
    for (const cfg of [
      { actionGuard: { broker, reviewedScripts } },
      { interceptor: { actionGuard: { broker, reviewedScripts } } },
    ]) {
      expect(validate(cfg)).toBe(true);
      expect(validate.errors ?? []).toEqual([]);
    }
    // And the bounds still bite at both locations.
    expect(validate({ actionGuard: { broker: { preClearConfidence: 0.5 } } })).toBe(false);
    expect(validate({ interceptor: { actionGuard: { broker: { judgeTimeoutMs: 1 } } } })).toBe(false);
    // A reviewedScripts entry with no hash is not a pin.
    expect(validate({ actionGuard: { reviewedScripts: [{ path: '/opt/ops/deploy.sh' }] } })).toBe(false);
  });

  it('the runtime parser keeps broker and reviewedScripts from BOTH locations', () => {
    const broker = { enabled: true, allowPreClear: true };
    const reviewedScripts = [{ path: '/opt/ops/deploy.sh', sha256: 'b'.repeat(64) }];
    for (const cfg of [
      { actionGuard: { broker, reviewedScripts } },
      { interceptor: { actionGuard: { broker, reviewedScripts } } },
    ]) {
      const parsed = plugin.configSchema.parse(cfg) as any;
      expect(parsed.interceptor.actionGuard.broker).toEqual(broker);
      expect(parsed.interceptor.actionGuard.reviewedScripts).toEqual(reviewedScripts);
    }
  });

  it('top-level actionGuard.notify declares the same keys in both files', () => {
    expect(Object.keys(manifest.configSchema.properties.actionGuard.properties.notify.properties).sort()).toEqual(
      Object.keys(runtimeSchema.properties.actionGuard.properties.notify.properties).sort(),
    );
  });

  it('both declare interceptor.conversation.posture with the same three values', () => {
    const manifestPosture =
      manifest.configSchema.properties.interceptor.properties.conversation.properties.posture;
    const runtimePosture = runtimeSchema.properties.interceptor.properties.conversation.properties.posture;
    expect(manifestPosture.enum).toEqual(['off', 'observe', 'enforce']);
    expect(runtimePosture.enum).toEqual(manifestPosture.enum);
    expect(manifestPosture.default).toBe('observe');
  });

  it('both declare interceptor.actionGuard.notify with the same keys', () => {
    const manifestNotify = manifest.configSchema.properties.interceptor.properties.actionGuard.properties.notify;
    const runtimeNotify = runtimeSchema.properties.interceptor.properties.actionGuard.properties.notify;
    expect(Object.keys(manifestNotify.properties).sort()).toEqual(
      Object.keys(runtimeNotify.properties).sort(),
    );
    // The credential field is named as notify-config.ts returns it. The mirror
    // that called it `secret` shipped unsigned webhooks.
    expect(Object.keys(manifestNotify.properties)).toContain('webhookSecret');
  });

  it('names the conversation gate floor established from published OpenClaw artifacts', () => {
    // 2026.5.7 has no before_agent_run; 2026.5.9-beta.1 is the first build that
    // declares it; 2026.5.12 is the first stable one. The manifest records the
    // stable floor so an operator can tell whether enforcement is even possible
    // on their host.
    expect(manifest.engines.conversationGate).toBe('>=2026.5.12');
    expect(manifest.engines.conversationGateNote).toMatch(/2026\.5\.9-beta\.1/);
    // The base engine floor is unchanged: everything EXCEPT the conversation
    // gate still works below it.
    expect(manifest.engines.openclaw).toBe('>=2026.3.22');
  });

  it('surfaces the posture in the UI hints, not just the schema', () => {
    expect(manifest.uiHints['interceptor.conversation.posture']).toBeDefined();
    expect(manifest.uiHints['interceptor.conversation.posture'].description).toMatch(
      /allowConversationAccess/,
    );
    expect((plugin.configSchema as { uiHints: any }).uiHints['interceptor.conversation.posture']).toBeDefined();
  });

  it('the two files declare EXACTLY the same UI hint keys, in both directions', () => {
    // A hint on only one side is a setting one surface documents and the other
    // silently omits — the host renders its config UI from the manifest, and
    // `configSchema.uiHints` is what the plugin declares about itself. They
    // must describe the same set of knobs. (The two shapes differ — the
    // manifest uses `description`/`type`, the runtime uses `help` — so only
    // the KEYS are pinned here, which is the part that decides what an
    // operator can see and set.)
    const runtimeHints = (plugin.configSchema as { uiHints: Record<string, unknown> }).uiHints;
    expect(Object.keys(manifest.uiHints).sort()).toEqual(Object.keys(runtimeHints).sort());
  });

  it('every object-valued config key with a UI hint is actually declared in both schemas', () => {
    // The gap #226 is about, stated as a rule: a hint that points at a config
    // path no schema declares is a control that writes a config the host then
    // rejects. Checked for the guard sub-blocks, which is where it happened.
    for (const hintKey of ['interceptor.actionGuard.broker.enabled', 'interceptor.actionGuard.notify.enabled']) {
      const segments = hintKey.split('.');
      for (const root of [
        { manifestNode: manifest.configSchema, runtimeNode: runtimeSchema },
      ]) {
        let m = root.manifestNode;
        let r = root.runtimeNode;
        for (const segment of segments) {
          m = m.properties?.[segment];
          r = r.properties?.[segment];
          expect(m).toBeDefined();
          expect(r).toBeDefined();
        }
      }
    }
  });
});

describe('#226 the runtime parser preserves what the schema now accepts', () => {
  it('keeps the notify block instead of silently dropping it', () => {
    const parsed = plugin.configSchema.parse({
      interceptor: {
        actionGuard: {
          enabled: true,
          notify: { enabled: true, webhookUrl: 'https://hook.example/sc', webhookSecret: 'placeholder' },
        },
      },
    }) as any;
    // Before #226 this whole key vanished at the parse boundary, so the plugin
    // could not reach an operator even where the Claude Code hook could.
    expect(parsed.interceptor.actionGuard.notify).toEqual({
      enabled: true,
      webhookUrl: 'https://hook.example/sc',
      webhookSecret: 'placeholder',
    });
  });

  it('drops a non-object notify rather than passing junk to the transport', () => {
    const parsed = plugin.configSchema.parse({
      interceptor: { actionGuard: { enabled: true, notify: 'yes please' } },
    }) as any;
    expect(parsed.interceptor.actionGuard.notify).toBeUndefined();
    expect(parsed.interceptor.actionGuard.enabled).toBe(true);
  });

  it('copies the notify block rather than aliasing the caller’s object', () => {
    const hostConfig = {
      interceptor: { actionGuard: { notify: { enabled: true, webhookUrl: 'https://hook.example/sc' } } },
    };
    const parsed = plugin.configSchema.parse(hostConfig) as any;
    (hostConfig.interceptor.actionGuard.notify as any).enabled = false;
    expect(parsed.interceptor.actionGuard.notify.enabled).toBe(true);
  });

  it('keeps a valid posture and drops an invalid one (never coercing upward)', () => {
    expect(
      (plugin.configSchema.parse({ interceptor: { conversation: { posture: 'enforce' } } }) as any)
        .interceptor.conversation.posture,
    ).toBe('enforce');
    const junk = plugin.configSchema.parse({
      interceptor: { enabled: true, conversation: { posture: 'ENFORCE' } },
    }) as any;
    expect(junk.interceptor.conversation).toBeUndefined();
    expect(junk.interceptor.enabled).toBe(true);
  });
});
