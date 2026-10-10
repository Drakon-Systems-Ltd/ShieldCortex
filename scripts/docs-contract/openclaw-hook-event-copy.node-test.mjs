/**
 * Docs/source contract: what the cortex-memory hook's copy says it does on
 * OpenClaw, checked against the events the two shipped manifests subscribe.
 *
 * The manifests (hooks/openclaw/cortex-memory/HOOK.md and the ClawHub-bundled
 * skills/shieldcortex/bundled/cortex-memory-hook/HOOK.md) declare
 * `metadata.openclaw.events`. That list is pinned here unchanged. The copy must
 * then:
 *   - describe session-end capture only for subscribed commands (`/new`,
 *     `/stop`), and say `/clear` and `/exit` are not core OpenClaw 2026.9.6
 *     hook events;
 *   - mark keyword triggers and per-message proactive recall as dormant /
 *     not registered (no `message` key), never as enabled by default.
 *
 * This is a docs/source contract, NOT host or runtime proof and NOT loader
 * equivalence. It reads text files and parses the manifest JSON. It does not
 * load OpenClaw, register or fire a hook, run the handler or touch the home
 * directory. Dependency-free (node:test) and NOT part of the Jest suite:
 *
 *   node --test scripts/docs-contract/openclaw-hook-event-copy.node-test.mjs
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const read = (...rel) => fs.readFileSync(path.join(REPO_ROOT, ...rel), 'utf8');

/** Text from `start` up to (not including) `end`. */
function between(src, start, end) {
  const a = src.indexOf(start);
  assert.ok(a > -1, `start not found: ${start}`);
  const b = src.indexOf(end, a + start.length);
  assert.ok(b > a, `end not found after start: ${end}`);
  return src.slice(a, b);
}

const oneLine = (s) => s.replace(/\s+/g, ' ');

const HOOK_DIRS = [
  ['hooks', 'openclaw', 'cortex-memory'],
  ['skills', 'shieldcortex', 'bundled', 'cortex-memory-hook'],
];

const EXPECTED_EVENTS = ['command:new', 'command:stop', 'agent:bootstrap'];
const EXPECTED_METADATA_LINE =
  '  { "openclaw": { "emoji": "🧠", "events": ["command:new", "command:stop", "agent:bootstrap"], ' +
  '"requires": { "bins": ["npx"] }, "install": [{ "id": "community", "kind": "community", "label": "ShieldCortex" }] } }';

/** Parse the `metadata:` JSON out of a HOOK.md YAML frontmatter block. */
function manifest(src) {
  const front = src.match(/^---\n([\s\S]*?)\n---\n/);
  assert.ok(front, 'HOOK.md has no frontmatter');
  const lines = front[1].split('\n');
  const at = lines.indexOf('metadata:');
  assert.ok(at > -1, 'frontmatter has no metadata: key');
  const line = lines[at + 1];
  return { line, metadata: JSON.parse(line) };
}

/** Text of the `### <heading>` section, up to the next `##`/`###` heading. */
function section(src, heading) {
  const m = src.match(new RegExp(`\\n### ${heading}[^\\n]*\\n[\\s\\S]*?(?=\\n## |\\n### )`));
  assert.ok(m, `section not found: ${heading}`);
  return m[0];
}

describe('manifest subscriptions (unchanged)', () => {
  for (const dir of HOOK_DIRS) {
    it(`${dir.join('/')}: metadata line is byte-identical and events are exactly new/stop/bootstrap`, () => {
      const { line, metadata } = manifest(read(...dir, 'HOOK.md'));
      assert.equal(line, EXPECTED_METADATA_LINE);
      assert.deepEqual(metadata.openclaw.events, EXPECTED_EVENTS);
      assert.ok(!metadata.openclaw.events.some((e) => e === 'message' || e.startsWith('message:')));
      assert.ok(!metadata.openclaw.events.includes('command'), 'bare command family must stay unsubscribed');
      for (const e of ['command:clear', 'command:exit']) assert.ok(!metadata.openclaw.events.includes(e));
    });
  }
});

describe('handler source facts the copy describes', () => {
  for (const dir of HOOK_DIRS) {
    it(`${dir.join('/')}: keyword and proactive recall live only behind the message / command-fallback branches`, () => {
      const h = read(...dir, 'handler.ts');
      const main = between(h, 'const cortexMemoryHandler = async (event) => {', 'export default cortexMemoryHandler;');
      assert.match(main, /event\.type === "message"\) \{\s*await proactiveRecall\(event\);\s*await onMessageKeywordTrigger\(event\);/);
      assert.match(main, /\} else if \(event\.type === "command"\) \{[\s\S]*?await onKeywordTrigger\(event\);/);
      assert.match(main, /event\.action === "stop"\) \{\s*await onSessionStop\(event\);/);
      assert.match(main, /event\.action === "new"\) \{\s*await onSessionEnd\(event\);/);
    });

    it(`${dir.join('/')}: message keyword path reads top-level event.role / event.content`, () => {
      const h = read(...dir, 'handler.ts');
      const fn = between(h, 'async function onMessageKeywordTrigger(event) {', 'await checkAndSaveKeywordTrigger(messageText, event);');
      assert.match(fn, /if \(event\.role !== "user"\) return;/);
      assert.match(fn, /let messageText = event\.content;/);
    });
  }
});

describe('HOOK.md copy (both copies)', () => {
  for (const dir of HOOK_DIRS) {
    const md = read(...dir, 'HOOK.md');
    const { metadata } = manifest(md);

    it(`${dir.join('/')}: every "### On \`/cmd\`" heading names a subscribed command`, () => {
      const headings = [...md.matchAll(/^### On (.+)$/gm)].map((m) => m[1]);
      const commands = headings.flatMap((h) => [...h.matchAll(/`\/([a-z-]+)`/g)].map((m) => m[1]));
      assert.deepEqual(commands, ['new', 'stop']);
      for (const c of commands) assert.ok(metadata.openclaw.events.includes(`command:${c}`), c);
    });

    it(`${dir.join('/')}: /stop section is qualified and makes no save guarantee`, () => {
      const stop = oneLine(section(md, 'On `/stop`'));
      assert.match(stop, /When `openclawAutoMemory` is enabled/);
      assert.doesNotMatch(stop, /Ensures work is saved/);
      assert.match(stop, /does not show the hook's "Saved N memories" note for `\/stop`/);
      assert.match(stop, /does not read the hook's `event\.messages`/);
      assert.match(stop, /`\/clear` and `\/exit` are not core OpenClaw 2026\.9\.6 hook events/);
      assert.match(stop, /this hook does not capture on them/);
    });

    it(`${dir.join('/')}: keyword triggers and per-message recall are marked dormant, not enabled`, () => {
      const kw = oneLine(section(md, 'Keyword Triggers'));
      assert.match(kw, /### Keyword Triggers \(dormant, not registered\)/);
      assert.match(kw, /\*\*not registered\*\* on core OpenClaw 2026\.9\.6/);
      assert.match(kw, /not enabled by default/);
      assert.match(kw, /does \*\*not\*\* save anything through this hook/);
      assert.match(kw, /per-message proactive recall in the same `message` branch is dormant/);
      assert.doesNotMatch(kw, /Say any of these phrases to trigger/);
      assert.doesNotMatch(md, /Content after the trigger phrase is extracted and saved/);
    });

    it(`${dir.join('/')}: keyword copy does not promise that registration alone would make saves work`, () => {
      const kw = oneLine(section(md, 'Keyword Triggers'));
      assert.doesNotMatch(md, /If that path were registered, it would save/);
      assert.doesNotMatch(kw, /if (that path|it) (were|was) registered/i);
      assert.match(kw, /Subscribing a `message` event would not be enough on its own/);
      assert.match(kw, /returns unless `event\.role` is `"user"` and reads the text from `event\.content`/);
      assert.match(kw, /no top-level `role` or `content` field \(a received message's text is in `event\.context\.content`\)/);
      assert.match(kw, /stops at the role check and never reaches the keyword check/);
    });
  }
});

describe('docs/openclaw-integration.md copy', () => {
  const doc = read('docs', 'openclaw-integration.md');

  it('"Enabled by default" no longer lists keyword triggers', () => {
    const enabled = between(doc, 'Enabled by default:', 'Off unless `actionGuard.enabled`');
    assert.doesNotMatch(enabled, /[Kk]eyword/);
  });

  it('auto-extract lists /new and /stop only; /clear and /exit are named unsupported', () => {
    const autoMem = oneLine(between(doc, 'Off unless `openclawAutoMemory` is `true`:', '- `llm_output`'));
    assert.match(autoMem, /Auto-extract on `\/new` and `\/stop`\./);
    assert.doesNotMatch(autoMem, /`\/stop`, `\/clear`/);
    assert.match(autoMem, /`\/clear` and `\/exit` are not core OpenClaw 2026\.9\.6 hook events/);
    assert.match(autoMem, /does not show the hook's "Saved N memories" note/);
  });

  it('install summary drops "explicit keyword saves" and marks keyword + per-message recall dormant', () => {
    const install = oneLine(between(doc, '1. `cortex-memory` hook', '2. `shieldcortex-realtime` plugin'));
    assert.doesNotMatch(install, /\+ explicit keyword saves/);
    assert.match(install, /session-end capture on `\/new` and `\/stop`/);
    assert.match(install, /keyword-trigger saves and per-message proactive recall are dormant/);
  });

  it('framed-recall list marks the OpenClaw hook message surface dormant', () => {
    const line = doc.split('\n').find((l) => l.startsWith('- proactive recall on a `message` event'));
    assert.ok(line);
    assert.match(line, /dormant: the hook does not subscribe `message` events/);
  });
});

describe('skills/shieldcortex/SKILL.md copy', () => {
  const skill = oneLine(read('skills', 'shieldcortex', 'SKILL.md'));

  it('OpenClaw extraction is scoped to /new and /stop; keyword triggers are qualified dormant', () => {
    assert.doesNotMatch(skill, /extracts from assistant output and explicit keyword triggers/);
    assert.match(skill, /does this on `\/new` and `\/stop` when `openclawAutoMemory` is `true`/);
    assert.match(skill, /\*\*Keyword triggers are dormant on OpenClaw\.\*\*/);
    assert.match(skill, /not registered on core OpenClaw 2026\.9\.6/);
    assert.doesNotMatch(skill, /\*\*Triggers capture surrounding context\.\*\* Keyword auto-save triggers/);
  });
});
