import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const READER_PATH = path.resolve(
  __dirname,
  '..',
  '..',
  'scripts',
  'lib',
  'transcript-reader.mjs',
);

type ReaderModule = {
  readTranscriptText: (
    transcriptPath: string | null | undefined,
    opts?: {
      maxBytes?: number;
      maxLines?: number;
      keepSlashCommandProse?: boolean;
    },
  ) => { text: string; messageCount: number; bytesRead: number; rawLineCount: number };
};

async function loadReader(): Promise<ReaderModule> {
  return (await import(READER_PATH)) as ReaderModule;
}

function jsonl(lines: object[]): string {
  return lines.map((l) => JSON.stringify(l)).join('\n');
}

function userMsg(text: string) {
  return { type: 'user', message: { role: 'user', content: text } };
}

function asstMsg(text: string) {
  return { type: 'assistant', message: { role: 'assistant', content: [{ type: 'text', text }] } };
}

describe('readTranscriptText', () => {
  let tmpDir: string;
  let transcriptPath: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-transcript-reader-'));
    transcriptPath = path.join(tmpDir, 'session.jsonl');
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('returns empty for missing transcriptPath', async () => {
    const { readTranscriptText } = await loadReader();
    const out = readTranscriptText(undefined);
    expect(out.text).toBe('');
    expect(out.messageCount).toBe(0);
  });

  it('returns empty when file does not exist', async () => {
    const { readTranscriptText } = await loadReader();
    const out = readTranscriptText('/nonexistent/path/foo.jsonl');
    expect(out.text).toBe('');
    expect(out.messageCount).toBe(0);
  });

  it('expands ~ to homedir', async () => {
    const { readTranscriptText } = await loadReader();
    const out = readTranscriptText('~/__definitely_does_not_exist__.jsonl');
    expect(out.text).toBe('');
  });

  it('reads user and assistant messages, skips other roles', async () => {
    fs.writeFileSync(
      transcriptPath,
      jsonl([
        userMsg('first user message about decisions'),
        { type: 'system', message: { role: 'system', content: 'system prompt here' } },
        asstMsg('assistant reply about the architecture'),
        { type: 'tool_result', message: { role: 'tool', content: 'tool result' } },
      ]),
    );
    const { readTranscriptText } = await loadReader();
    const out = readTranscriptText(transcriptPath);
    expect(out.messageCount).toBe(2);
    expect(out.text).toContain('first user message');
    expect(out.text).toContain('architecture');
    expect(out.text).not.toContain('system prompt here');
    expect(out.text).not.toContain('tool result');
  });

  it('reads ALL turns when transcript fits within maxBytes (no slice(-50) ceiling)', async () => {
    // 200 turns — old slice(-50) would have lost 150 of these
    const turns: object[] = [];
    for (let i = 0; i < 200; i++) {
      turns.push(userMsg(`user turn ${i} talking about feature X`));
      turns.push(asstMsg(`assistant turn ${i} responding`));
    }
    fs.writeFileSync(transcriptPath, jsonl(turns));

    const { readTranscriptText } = await loadReader();
    const out = readTranscriptText(transcriptPath);
    // 400 messages total
    expect(out.messageCount).toBe(400);
    expect(out.text).toContain('user turn 0 talking');
    expect(out.text).toContain('user turn 199 talking');
  });

  it('caps reads at maxBytes from the end of large transcripts', async () => {
    // ~3 MB transcript
    const turns: object[] = [];
    for (let i = 0; i < 3000; i++) {
      turns.push(userMsg(`turn ${i} ` + 'x'.repeat(500)));
    }
    fs.writeFileSync(transcriptPath, jsonl(turns));
    const stat = fs.statSync(transcriptPath);
    expect(stat.size).toBeGreaterThan(1_500_000);

    const { readTranscriptText } = await loadReader();
    const out = readTranscriptText(transcriptPath, { maxBytes: 64 * 1024 });
    expect(out.bytesRead).toBeLessThanOrEqual(64 * 1024);
    // Final turn must be included
    expect(out.text).toContain('turn 2999');
    // Earliest turn must be excluded — well outside the byte window
    expect(out.text).not.toContain('turn 0 ');
  });

  it('discards a partial first line after byte slicing', async () => {
    // Construct a transcript where the byte-slice cuts mid-line. The reader
    // must drop that mangled prefix, not return it as a JSON parse error.
    const turns = [
      userMsg('aaaa ' + 'A'.repeat(200)),
      userMsg('bbbb ' + 'B'.repeat(200)),
      userMsg('cccc ' + 'C'.repeat(200)),
    ];
    fs.writeFileSync(transcriptPath, jsonl(turns));
    const stat = fs.statSync(transcriptPath);

    const { readTranscriptText } = await loadReader();
    // Slice that cuts inside the second line
    const out = readTranscriptText(transcriptPath, { maxBytes: stat.size - 250 });
    expect(out.text).not.toContain('aaaa');
    expect(out.text).toContain('cccc');
  });

  it('drops single-line slash-command-only messages under 200 chars', async () => {
    fs.writeFileSync(
      transcriptPath,
      jsonl([
        userMsg('/loop 5m /foo'),
        userMsg('/help'),
        asstMsg('assistant reply about the bug fix'),
      ]),
    );
    const { readTranscriptText } = await loadReader();
    const out = readTranscriptText(transcriptPath);
    expect(out.text).not.toContain('/loop 5m /foo');
    expect(out.text).not.toContain('/help');
    expect(out.text).toContain('bug fix');
  });

  it('keeps multi-line slash messages (the prose part is signal)', async () => {
    const multiLine = '/skill brainstorming\n\nWe need to decide between Postgres and SQLite for this feature';
    fs.writeFileSync(
      transcriptPath,
      jsonl([userMsg(multiLine), asstMsg('reply')]),
    );
    const { readTranscriptText } = await loadReader();
    const out = readTranscriptText(transcriptPath);
    expect(out.text).toContain('Postgres and SQLite');
  });

  it('keeps long single-line slash messages (>= 200 chars)', async () => {
    const longSlash = '/loop ' + 'context-rich content '.repeat(15);
    expect(longSlash.length).toBeGreaterThanOrEqual(200);
    fs.writeFileSync(
      transcriptPath,
      jsonl([userMsg(longSlash)]),
    );
    const { readTranscriptText } = await loadReader();
    const out = readTranscriptText(transcriptPath);
    expect(out.text).toContain('context-rich content');
  });

  it('honours keepSlashCommandProse=false (strict mode drops all slash prefixes)', async () => {
    const multiLine = '/skill x\n\nimportant decision content here';
    fs.writeFileSync(transcriptPath, jsonl([userMsg(multiLine)]));
    const { readTranscriptText } = await loadReader();
    const out = readTranscriptText(transcriptPath, { keepSlashCommandProse: false });
    expect(out.text).toBe('');
  });

  it('caps at maxLines as a safety belt', async () => {
    const turns: object[] = [];
    for (let i = 0; i < 500; i++) turns.push(userMsg(`turn ${i}`));
    fs.writeFileSync(transcriptPath, jsonl(turns));

    const { readTranscriptText } = await loadReader();
    const out = readTranscriptText(transcriptPath, { maxLines: 50 });
    expect(out.rawLineCount).toBeLessThanOrEqual(50);
  });

  it('handles array content with multiple text parts', async () => {
    fs.writeFileSync(
      transcriptPath,
      jsonl([
        {
          type: 'assistant',
          message: {
            role: 'assistant',
            content: [
              { type: 'text', text: 'part one of reply' },
              { type: 'tool_use', input: { foo: 'bar' } },
              { type: 'text', text: 'part two of reply' },
            ],
          },
        },
      ]),
    );
    const { readTranscriptText } = await loadReader();
    const out = readTranscriptText(transcriptPath);
    expect(out.text).toContain('part one');
    expect(out.text).toContain('part two');
  });

  it('skips invalid JSON lines silently', async () => {
    fs.writeFileSync(
      transcriptPath,
      [
        JSON.stringify(userMsg('valid before')),
        'NOT VALID JSON',
        JSON.stringify(asstMsg('valid after')),
      ].join('\n'),
    );
    const { readTranscriptText } = await loadReader();
    const out = readTranscriptText(transcriptPath);
    expect(out.messageCount).toBe(2);
    expect(out.text).toContain('valid before');
    expect(out.text).toContain('valid after');
  });
});
