/** #341 Face 1 */
import { describe, expect, it } from '@jest/globals';
import { evaluateToolCall, neutralizeMarkdownCommandMentions } from '../tool-action-guard.js';

const U = 'sys' + 'tem' + 'ctl';
const V = 'st' + 'op';
const SSH = 'ss' + 'h ' + 'ro' + 'ot@host uptime';

describe('#341 Face 1 neutralize', () => {
  it('strips fences and backticks', () => {
    const out = neutralizeMarkdownCommandMentions('seen `foo` and\n```\nbaz\n```\nend');
    expect(out).not.toContain('foo');
    expect(out).not.toContain('baz');
    expect(out).toContain('seen');
  });
});

describe('#341 Face 1 memory md', () => {
  it('MEMORY.md quoting ops forms allows', () => {
    const quoted = '`' + U + ' ' + V + ' nginx`';
    const sshq = '`' + SSH + '`';
    const v = evaluateToolCall('Edit', {
      file_path: 'MEMORY.md',
      old_string: 'x',
      new_string: 'Incident: ' + quoted + ' and ' + sshq,
    });
    expect(v.decision).toBe('allow');
    expect(v.signals ?? []).not.toContain('write-content-dangerous');
  });
  it('claude memory fence allows', () => {
    const fence = '```\n' + U + ' ' + V + ' nginx\n```';
    const v = evaluateToolCall('Edit', {
      file_path: '/home/u/.claude/memory/facts.md',
      old_string: 'x',
      new_string: 'Forensics:\n' + fence,
    });
    expect(v.decision).toBe('allow');
  });
  it('script shebang still gates', () => {
    const v = evaluateToolCall('Write', {
      file_path: 'util.sh',
      content: '#!/bin/bash\n' + U + ' ' + V + ' nginx\n',
    });
    expect(v.decision).not.toBe('allow');
  });
});

