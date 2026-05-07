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
