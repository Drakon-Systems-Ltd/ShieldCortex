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

// ── #720 review (Tars, blocker 2): owner text must survive byte-for-byte ──
// The envelope is stripped only when its boundaries are complete and verified:
// a label header carrying the marker, a ```json fence that closes and parses,
// and every other marker block terminated by a blank line. Anything ambiguous
// or unclosed is the owner's own words and is returned untouched.
describe('sanitisePromptForRecall — owner text that mentions the envelope (#720)', () => {
  const MARK = '⟦openclaw:ctx⟧';
  const INFO = [
    `Conversation info: ${MARK}`,
    '```json',
    '{ "chat_id": "telegram:100000001", "message_id": "90002" }',
    '```',
  ].join('\n');

  const OWNER_FIXTURES: Array<[string, string]> = [
    ['first line ends with the marker but is prose', [
      `Why does every prompt start with Conversation info: ${MARK}`,
      'I want to know what that marker is for.',
    ].join('\n')],
    ['label-shaped first line ending in the marker, then a blank line and a question', [
      `Conversation context: ${MARK}`,
      'is what I see at the top of every turn.',
      '',
      'What would you file about it?',
    ].join('\n')],
    ['marker header followed by an unclosed ```json fence', [
      `Conversation info: ${MARK}`,
      '```json',
      '{ "chat_id": "telegram:1"',
      'Why does this fence never close? What should I do about it?',
    ].join('\n')],
    ['marker header followed by a ```json fence whose body is not JSON', [
      `Conversation info: ${MARK}`,
      '```json',
      'this is just me pasting prose into a json fence',
      '```',
      'Is that a problem?',
    ].join('\n')],
    ['owner code fence containing the trailing Context header', [
      'Here is the raw prompt I captured:',
      '```',
      `Context: ${MARK}`,
      'channel: telegram',
      '```',
      'Why is the Context block there?',
    ].join('\n')],
  ];

  it.each(OWNER_FIXTURES)('%s — survives byte-for-byte', (_label, text) => {
    expect(sanitisePromptForRecall(text)).toBe(text);
  });

  it('an envelope whose second marker block is unclosed is left untouched', () => {
    const text = [INFO, '', `Conversation context (chronological, selected for current message): ${MARK}`, '#session:x 2026-10-10 User: hi'].join('\n');
    expect(sanitisePromptForRecall(text)).toBe(text);
  });

  it('a verified envelope keeps an owner code fence that contains the Context header', () => {
    const userText = [
      'Here is the raw prompt I captured:',
      '```',
      `Context: ${MARK}`,
      'channel: telegram',
      '```',
      'Why is the Context block there?',
    ].join('\n');
    const wrapped = `${INFO}\n\n${userText}\n\nContext: ${MARK}\nreal channel context`;
    expect(sanitisePromptForRecall(wrapped)).toBe(userText);
  });

  it('a verified envelope with no user text and a trailing Context block yields empty', () => {
    expect(sanitisePromptForRecall(`${INFO}\n\nContext: ${MARK}\nreal channel context`)).toBe('');
  });

  it('a verified envelope keeps an owner question that explains the marker', () => {
    const userText = `What does ${MARK} mean at the end of "Conversation info:"?`;
    expect(sanitisePromptForRecall(`${INFO}\n\n${userText}`)).toBe(userText);
  });
});

// ── #720 review round 2 (Tars): verified labels and matched fences ─────────
// R2 finding 1: the envelope detector accepted ANY capitalised, colon-ended
// label as a framework header. After a valid JSON envelope the loop could then
// consume an owner's own marker-ended paragraph as "another metadata block",
// and a bare owner label + complete JSON object collapsed to an EMPTY recall
// prompt. Only OpenClaw's verified labels (buildInboundUserContextPrefix /
// selectInboundHistoryContext) with their exact block grammar are consumed now.
// R2 finding 2: the suffix scanner toggled a boolean on any ``` prefix, so a
// ~~~ fence was invisible and a ```` outer fence holding a ``` example flipped
// state early — a quoted "Context:" header then truncated owner text.
describe('sanitisePromptForRecall — verified labels and matched fences (#720 R2)', () => {
  const MARK = '⟦openclaw:ctx⟧';
  const INFO = [
    `Conversation info: ${MARK}`,
    '```json',
    '{ "chat_id": "telegram:100000001", "message_id": "90003" }',
    '```',
  ].join('\n');
  const SUFFIX = `Context: ${MARK}\nreal channel context`;

  describe('(a) a bare owner label plus a complete JSON object is not an envelope', () => {
    const ownerBlock = [
      `My config: ${MARK}`,
      '```json',
      '{ "retries": 3, "backend": "claw2" }',
      '```',
    ].join('\n');

    it('standalone — survives byte-for-byte, never an empty prompt', () => {
      const out = sanitisePromptForRecall(ownerBlock);
      expect(out).toBe(ownerBlock);
      expect(out).not.toBe('');
    });

    it('after a verified envelope — the owner block is the recall prompt, not metadata', () => {
      const out = sanitisePromptForRecall(`${INFO}\n\n${ownerBlock}`);
      expect(out).toBe(ownerBlock);
      expect(out).not.toBe('');
    });

    it('after a verified envelope with a trailing Context suffix — still the owner block', () => {
      expect(sanitisePromptForRecall(`${INFO}\n\n${ownerBlock}\n\n${SUFFIX}`)).toBe(ownerBlock);
    });
  });

  describe('(b) an owner marker-ended paragraph is never consumed as a history block', () => {
    const ownerParagraph = [
      `Notes for you: ${MARK}`,
      'line two of my own notes, pasted from the log',
      'line three of my own notes',
      '',
      'What do you make of that marker?',
    ].join('\n');

    it('standalone — survives byte-for-byte', () => {
      expect(sanitisePromptForRecall(ownerParagraph)).toBe(ownerParagraph);
    });

    it('immediately after a verified envelope — preserved, not consumed as metadata', () => {
      expect(sanitisePromptForRecall(`${INFO}\n\n${ownerParagraph}`)).toBe(ownerParagraph);
    });

    it('after the full envelope (info + history) — the paragraph is the whole recall prompt', () => {
      const history = [
        `Conversation context (chronological, selected for current message): ${MARK}`,
        '#session:sess-1 2026-10-10 08:55 UTC User: earlier turn',
      ].join('\n');
      expect(sanitisePromptForRecall(`${INFO}\n\n${history}\n\n${ownerParagraph}`)).toBe(ownerParagraph);
    });

    it('a verified JSON label that is not followed by a ```json fence is owner text', () => {
      const ownerText = [
        `Conversation info: ${MARK}`,
        'is the first line of every prompt I see.',
        '',
        'Why is it there?',
      ].join('\n');
      expect(sanitisePromptForRecall(`${INFO}\n\n${ownerText}`)).toBe(ownerText);
    });
  });

  describe('(c) the trailing-suffix scanner matches fence character and length', () => {
    // Each owner capture carries a blank line before the quoted "Context:"
    // header — exactly as a real captured prompt would — so the only thing
    // keeping the header from being mistaken for the live suffix is the fence.
    const TILDE_CAPTURE = [
      'Here is the raw prompt I captured:',
      '~~~',
      'hello',
      '',
      `Context: ${MARK}`,
      'channel: telegram',
      '~~~',
      'Why is the Context block there?',
    ].join('\n');
    const NESTED_CAPTURE = [
      'Here is the raw prompt I captured, with a fenced example inside it:',
      '````',
      'look:',
      '```',
      'hello',
      '',
      `Context: ${MARK}`,
      'channel: telegram',
      '```',
      '````',
      'Why is the Context block there?',
    ].join('\n');
    const TILDE_INFO_CAPTURE = [
      'And here is the same thing in a tilde fence with a json tag:',
      '~~~json',
      '{ "note": "```" }',
      '',
      `Context: ${MARK}`,
      '~~~',
      'Does the inner backtick run confuse you?',
    ].join('\n');

    it.each([
      ['tilde fence', TILDE_CAPTURE],
      ['four-backtick outer fence holding a three-backtick example', NESTED_CAPTURE],
      ['tilde fence whose body contains a backtick run', TILDE_INFO_CAPTURE],
    ])('%s — standalone survives byte-for-byte', (_label, text) => {
      expect(sanitisePromptForRecall(text)).toBe(text);
    });

    it.each([
      ['tilde fence', TILDE_CAPTURE],
      ['four-backtick outer fence holding a three-backtick example', NESTED_CAPTURE],
      ['tilde fence whose body contains a backtick run', TILDE_INFO_CAPTURE],
    ])('%s — after a verified envelope the owner capture is kept whole', (_label, text) => {
      expect(sanitisePromptForRecall(`${INFO}\n\n${text}`)).toBe(text);
    });

    it.each([
      ['tilde fence', TILDE_CAPTURE],
      ['four-backtick outer fence holding a three-backtick example', NESTED_CAPTURE],
      ['tilde fence whose body contains a backtick run', TILDE_INFO_CAPTURE],
    ])('%s — the real trailing suffix is still cut, the quoted one is not', (_label, text) => {
      expect(sanitisePromptForRecall(`${INFO}\n\n${text}\n\n${SUFFIX}`)).toBe(text);
    });

    it('an unclosed owner fence declines suffix removal rather than guessing', () => {
      const text = [
        'I pasted this and forgot to close the fence:',
        '```',
        'hello',
        '',
        `Context: ${MARK}`,
        'channel: telegram',
      ].join('\n');
      expect(sanitisePromptForRecall(`${INFO}\n\n${text}`)).toBe(text);
    });
  });

  it('retains the verified envelope stripping for every supported OpenClaw label', () => {
    const json = (label: string, payload: unknown) => [`${label} ${MARK}`, '```json', JSON.stringify(payload), '```'].join('\n');
    const wrapped = [
      json('Conversation info:', { chat_id: 'telegram:100000001', message_id: '90004' }),
      json('Thread starter:', { body: 'thread root text' }),
      json('Reply chain of current user message (nearest first):', [{ message_id: '90000', body: 'older' }]),
      json('Forwarded message context:', { from: 'Example Forwarder' }),
      json('Location:', { lat: 0, lon: 0 }),
      [`Recent chat history: ${MARK}`, '#session:sess-1 2026-10-10 08:55 UTC User: earlier turn'].join('\n'),
      [`Chat window (newest last): ${MARK}`, 'Example Owner: an older line'].join('\n'),
      [`Conversation context (chronological, selected for current message): ${MARK}`, '#session:sess-1 2026-10-10 08:56 UTC User: another'].join('\n'),
      'Is ShieldCortex any good now?',
      SUFFIX,
    ].join('\n\n');
    expect(sanitisePromptForRecall(wrapped)).toBe('Is ShieldCortex any good now?');
  });
});
