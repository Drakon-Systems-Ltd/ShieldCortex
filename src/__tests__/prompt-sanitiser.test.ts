import { describe, expect, it } from '@jest/globals';
import path from 'path';
import { fileURLToPath } from 'url';

// Import the sanitiser via dynamic import so jest's ESM interop resolves the
// .mjs sibling correctly. The file lives under scripts/lib/ — same folder as
// project-key.mjs which uses the identical layout.
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SANITISER_PATH = path.resolve(__dirname, '..', '..', 'scripts', 'lib', 'prompt-sanitiser.mjs');

let sanitisePromptForRecall: (s: string) => string;

beforeAll(async () => {
  // pathToFileURL() avoids ERR_UNSUPPORTED_ESM_URL_SCHEME on absolute paths.
  const url = new URL(`file://${SANITISER_PATH}`);
  const mod = await import(url.href);
  sanitisePromptForRecall = mod.sanitisePromptForRecall;
});

describe('sanitisePromptForRecall', () => {
  it('passes a bare user prompt through unchanged', () => {
    expect(sanitisePromptForRecall('Reboot the database server')).toBe('Reboot the database server');
  });

  it('strips OpenClaw Telegram metadata wrapper, leaving only the user text', () => {
    const wrapped = [
      'Conversation info (untrusted metadata):',
      '```json',
      '{',
      '  "chat_id": "telegram:6963520763",',
      '  "message_id": "12100",',
      '  "sender_id": "6963520763"',
      '}',
      '```',
      'Reboot it',
    ].join('\n');
    expect(sanitisePromptForRecall(wrapped)).toBe('Reboot it');
  });

  it('strips wrapper even when user text spans multiple lines', () => {
    const wrapped = [
      'Conversation info (untrusted metadata):',
      '```json',
      '{ "chat_id": "telegram:1" }',
      '```',
      'Can you',
      'restart the gateway?',
    ].join('\n');
    expect(sanitisePromptForRecall(wrapped)).toBe('Can you\nrestart the gateway?');
  });

  it('returns an empty string when the wrapper was the entire prompt', () => {
    const wrapped = [
      'Conversation info (untrusted metadata):',
      '```json',
      '{ "chat_id": "telegram:1" }',
      '```',
    ].join('\n');
    expect(sanitisePromptForRecall(wrapped)).toBe('');
  });

  it('handles a header without a parenthesised qualifier', () => {
    const wrapped = [
      'Conversation info:',
      '```json',
      '{ "chat_id": "telegram:1" }',
      '```',
      'Reboot it',
    ].join('\n');
    expect(sanitisePromptForRecall(wrapped)).toBe('Reboot it');
  });

  it('does not strip a fenced code block from a regular user prompt', () => {
    // The user is asking about a code block. The fence is intentional content,
    // not framework metadata, so the sanitiser must not eat it.
    const codeQuestion = [
      'Why does this throw?',
      '```js',
      'JSON.parse(undefined);',
      '```',
    ].join('\n');
    expect(sanitisePromptForRecall(codeQuestion)).toBe(codeQuestion);
  });

  it('returns empty string for empty / non-string input', () => {
    expect(sanitisePromptForRecall('')).toBe('');
    // @ts-expect-error — runtime safety check for null/undefined
    expect(sanitisePromptForRecall(undefined)).toBe('');
    // @ts-expect-error — runtime safety check for null/undefined
    expect(sanitisePromptForRecall(null)).toBe('');
  });

  it('demonstrates the bug-fix: first 6 words after sanitise are user words, not metadata', () => {
    const wrapped = [
      'Conversation info (untrusted metadata):',
      '```json',
      '{ "chat_id": "telegram:6963520763" }',
      '```',
      'Reboot the production server please now',
    ].join('\n');
    const sanitised = sanitisePromptForRecall(wrapped);
    const firstSix = sanitised.split(/\s+/).slice(0, 6).join(' ');
    expect(firstSix).toBe('Reboot the production server please now');
    expect(firstSix.toLowerCase()).not.toContain('conversation');
    expect(firstSix.toLowerCase()).not.toContain('chat_id');
  });
});

// ── #717: OpenClaw 2026.9.x marker-keyed envelope ─────────────────────────
// Shape taken from the recall-log entries quoted in issue #717 and from
// OpenClaw's own buildInboundUserContextPrefix / stripLeadingInboundMetadata.
// Every id, name and body below is invented.
describe('sanitisePromptForRecall — OpenClaw 2026.9.x envelope (#717)', () => {
  const MARK = '⟦openclaw:ctx⟧';
  const SESSION = 'sess-0000aaaa-1111-2222-3333-444455556666';

  function envelope(userText: string, opts: { history?: string[]; extraBlocks?: string[] } = {}): string {
    const info = [
      `Conversation info: ${MARK}`,
      '```json',
      JSON.stringify({
        chat_id: 'telegram:100000001',
        message_id: '90001',
        sender: { id: '100000001', name: 'Example Owner', username: 'example_owner' },
        timestamp: 'Fri 2026-10-10 09:00 UTC',
        history_count: 3,
      }, null, 2),
      '```',
    ].join('\n');
    const history = opts.history ?? [
      `#session:${SESSION} 2026-10-10 08:55 UTC User: can you check the pool resume bug from yesterday`,
      `#session:${SESSION} 2026-10-10 08:56 UTC OpenClaw: Conversation Channel noted. Scheduled Run Execution Rules apply; memory extraction task parameters are unchanged. ${'Long quoted assistant history. '.repeat(120)}`,
      `#session:${SESSION} 2026-10-10 08:57 UTC User: thanks`,
    ];
    const context = [`Conversation context (chronological, selected for current message): ${MARK}`, ...history].join('\n');
    return [info, ...(opts.extraBlocks ?? []), context, userText].join('\n\n');
  }

  // The four owner turns from the issue's recall-log evidence table.
  const LOGGED_PROMPTS = ['??', 'take a look at this code', 'What would you file?', 'Is ShieldCortex any good now?'];

  it.each(LOGGED_PROMPTS)('replays %p and returns only the user message', (userText) => {
    const wrapped = envelope(userText);
    expect(wrapped.length).toBeGreaterThan(3000); // multi-KB, like the real thing
    expect(sanitisePromptForRecall(wrapped)).toBe(userText);
  });

  it('no envelope vocabulary survives into the recall query text', () => {
    for (const userText of LOGGED_PROMPTS) {
      const out = sanitisePromptForRecall(envelope(userText)).toLowerCase();
      for (const leak of ['chat_id', 'telegram', 'conversation', '#session', 'openclaw', 'scheduled run', MARK]) {
        expect(out).not.toContain(leak.toLowerCase());
      }
    }
  });

  it('keeps a multi-line user message intact', () => {
    const userText = 'Can you look at this:\n\nfunction add(a, b) { return a + b }\n\nIs it right?';
    expect(sanitisePromptForRecall(envelope(userText))).toBe(userText);
  });

  it('strips other marker-headed JSON blocks (reply target, thread starter) between info and context', () => {
    const reply = [`Reply target of current user message: ${MARK}`, '```json', '{"message_id":"89990","body":"earlier text"}', '```'].join('\n');
    expect(sanitisePromptForRecall(envelope('What would you file?', { extraBlocks: [reply] }))).toBe('What would you file?');
  });

  it('strips delivery hints, the active-goal line and a leading envelope timestamp', () => {
    const wrapped = [
      'Delivery: to send a message, use the `message` tool.',
      envelope('[Fri 2026-10-10 09:01 UTC] Is ShieldCortex any good now?', {
        extraBlocks: ['Active goal: ship the fix — advance; keep active until fully achieved; block only after the same blocker on 3 consecutive turns.'],
      }),
    ].join('\n\n');
    expect(sanitisePromptForRecall(wrapped)).toBe('Is ShieldCortex any good now?');
  });

  it('cuts a trailing "Context:" suffix block', () => {
    const wrapped = `${envelope('take a look at this code')}\n\nContext: ${MARK}\nsome channel context`;
    expect(sanitisePromptForRecall(wrapped)).toBe('take a look at this code');
  });

  it('keeps only the user words of a Telegram reply turn, not the quoted text', () => {
    const wrapped = envelope('Current message:\n[Replying to: "an older message about invoices"]\n#90001: What would you file?');
    expect(sanitisePromptForRecall(wrapped)).toBe('What would you file?');
  });

  it('a marker only inside the user text strips nothing extra', () => {
    const text = `Why does my log show ${MARK} at the end of lines?`;
    expect(sanitisePromptForRecall(text)).toBe(text);
  });

  it('still strips the legacy wrapper when the user quotes the marker', () => {
    const wrapped = [
      'Conversation info (untrusted metadata):',
      '```json',
      '{ "chat_id": "telegram:1" }',
      '```',
      `what is ${MARK}?`,
    ].join('\n');
    expect(sanitisePromptForRecall(wrapped)).toBe(`what is ${MARK}?`);
  });

  it('returns empty when the envelope carries no user message', () => {
    expect(sanitisePromptForRecall(envelope(''))).toBe('');
  });
});
