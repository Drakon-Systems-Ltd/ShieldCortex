import fs from 'node:fs';
import path from 'node:path';
import url from 'node:url';
import { describe, expect, it } from '@jest/globals';

import { CONVERSATION_ENFORCEMENT_MIN_OPENCLAW } from '../integrations/openclaw-conversation-capability.js';
import {
  CONVERSATION_GATE_MIN_OPENCLAW,
  CONVERSATION_GATE_FIRST_PRERELEASE_OPENCLAW,
} from '../../plugins/openclaw/index.js';

/**
 * #226/#225 phase 2 — ONE conversation-enforcement floor, three files.
 *
 * The `before_agent_run` floor has to be stated three times because the three
 * consumers cannot import each other:
 *
 *   1. `src/integrations/openclaw-conversation-capability.ts` — the CLI/doctor
 *      side. Imports `semver`.
 *   2. `plugins/openclaw/index.ts` — the plugin, compiled to its OWN dist by
 *      `tsconfig.openclaw-plugin.json` with `rootDir: ./plugins/openclaw` and
 *      an explicit `include` list. A `src/` import does not merely cross a
 *      layer, it fails to emit; and the plugin bundle does not carry `semver`,
 *      which is why it hand-rolls `compareOpenClawVersions`.
 *   3. `plugins/openclaw/openclaw.plugin.json` — JSON the HOST reads to decide
 *      whether to accept the plugin. It imports nothing, by construction.
 *
 * So the build boundary is real and the constant cannot be shared by import.
 * This test is the substitute: it reads all three and fails on drift. Two
 * independently-invented floors is what the #226 review flagged, and the
 * failure mode is not cosmetic — the CLI and the plugin would give an operator
 * different answers to "can this host block a turn".
 *
 * The prerelease (2026.5.9-beta.1) is asserted SUBORDINATE: it appears in the
 * plugin as documentation and in the manifest note, and it is never the floor.
 */

const here = path.dirname(url.fileURLToPath(import.meta.url));
const manifest = JSON.parse(
  fs.readFileSync(path.join(here, '..', '..', 'plugins', 'openclaw', 'openclaw.plugin.json'), 'utf-8'),
) as { engines: Record<string, string> };

/** The single authoritative value. Changing it here is meant to be the loud way
 *  to change it — the assertions below then name every file that must follow. */
const STABLE_FLOOR = '2026.5.12';
const FIRST_PRERELEASE = '2026.5.9-beta.1';

describe('#226 the conversation-gate floor does not drift across the build boundary', () => {
  it('all three files state the same STABLE floor', () => {
    expect(CONVERSATION_ENFORCEMENT_MIN_OPENCLAW).toBe(STABLE_FLOOR);
    expect(CONVERSATION_GATE_MIN_OPENCLAW).toBe(STABLE_FLOOR);
    expect(manifest.engines.conversationGate).toBe(`>=${STABLE_FLOOR}`);
  });

  it('the src constant and the plugin constant are equal to each other, not merely to a literal', () => {
    // Stated separately from the test above so a future edit that changes the
    // literal in one place and this file's copy in the same commit still fails.
    expect(CONVERSATION_GATE_MIN_OPENCLAW).toBe(CONVERSATION_ENFORCEMENT_MIN_OPENCLAW);
    expect(manifest.engines.conversationGate).toBe(`>=${CONVERSATION_ENFORCEMENT_MIN_OPENCLAW}`);
  });

  it('the prerelease is documented but is never the floor', () => {
    expect(CONVERSATION_GATE_FIRST_PRERELEASE_OPENCLAW).toBe(FIRST_PRERELEASE);
    expect(CONVERSATION_GATE_FIRST_PRERELEASE_OPENCLAW).not.toBe(CONVERSATION_GATE_MIN_OPENCLAW);
    // The manifest records it in prose only — the machine-readable engines key
    // above is the stable floor.
    expect(manifest.engines.conversationGateNote).toContain(FIRST_PRERELEASE);
    expect(manifest.engines.conversationGateNote).toContain(STABLE_FLOOR);
  });

  it('the base engine floor is untouched — only the gate is version-gated', () => {
    // Raising engines.openclaw to the gate floor would block installation for
    // every operator on an older host, including for the Action Guard, which is
    // not a conversation hook and works far below it.
    expect(manifest.engines.openclaw).toBe('>=2026.3.22');
  });
});
