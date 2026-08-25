/**
 * #412 follow-up cases (Grok holes)
 */
import { describe, expect, it } from '@jest/globals';
import { enforceToolInput, validateToolInput } from '../tool-input-schema.js';
import { evaluateToolCall } from '../tool-action-guard.js';

describe('#412 follow-up family alignment', () => {
  it('run_command is exec family — unknown keys blocked', () => {
    const r = enforceToolInput('run_command', {
      command: 'echo safe',
      hidden_script: 'not-allowed-key',
    });
    expect(r.ok).toBe(false);
  });

  it('web_fetch allows url; rejects unknown keys', () => {
    expect(enforceToolInput('web_fetch', { url: 'https://example.com/path' }).ok).toBe(true);
    expect(enforceToolInput('web_fetch', { url: 'https://example.com', evil: 1 }).ok).toBe(false);
  });

  it('nested env may only be string map — no nested objects', () => {
    expect(enforceToolInput('Bash', { command: 'true', env: { PATH: '/bin' } }).ok).toBe(true);
    expect(enforceToolInput('Bash', { command: 'true', env: { nested: { x: 1 } } }).ok).toBe(false);
  });

  it('stdin is an allowed exec surface', () => {
    const r = enforceToolInput('Bash', { command: 'cat', stdin: 'hello' });
    expect(r.ok).toBe(true);
  });

  it('evaluateToolCall still allows clean Bash', () => {
    const v = evaluateToolCall('Bash', { command: 'git status' });
    expect(v.decision).toBe('allow');
  });
});

/**
 * CI regression: annotate mode used to strip the very keys the extractors read,
 * so `Workflow.script` carrying a force-push scanned clean and returned `allow`.
 * The guard was blind, not lenient. Fixtures reuse the same paraphrased
 * force-push the notify-143 suite drives the real hook with.
 */
describe('#412 annotate must not blind the extractors', () => {
  const FORCE_PUSH = 'git push --force origin main';

  it('Workflow.script reaches the guard (not allow-by-blindness)', () => {
    const v = evaluateToolCall('Workflow', { script: FORCE_PUSH, description: 'Publish the release branch' });
    expect(v.decision).not.toBe('allow');
    expect(['ask', 'require_approval', 'block']).toContain(v.decision);
    expect(v.signals).toContain('git-force-push');
  });

  it('create_issue.code is annotated, not enforced away, and still scans', () => {
    const v = evaluateToolCall('create_issue', { code: FORCE_PUSH, description: 'Create a tracking issue' });
    expect(v.decision).not.toBe('allow');
    expect(v.signals).toContain('git-force-push');
  });

  it('create_issue.script is annotated, not enforced away, and still scans', () => {
    const v = evaluateToolCall('create_issue', { script: FORCE_PUSH, description: 'Create a tracking issue' });
    expect(v.decision).not.toBe('allow');
    expect(v.signals).toContain('git-force-push');
  });

  it('GitHub-shaped create_issue payloads are not false-blocked by enforce', () => {
    // `create_issue` matches WRITE_TOOLS; enforcing a closed key set here would
    // reject every real issue payload. Annotate strips, it does not block.
    const v = evaluateToolCall('create_issue', {
      title: 'Track the flaky gate',
      body: 'The notify suite is red on main.',
      labels: 'bug',
      assignees: 'tars',
    });
    expect(v.decision).toBe('allow');
  });

  it('annotate keeps extractor keys on an unknown family', () => {
    const r = validateToolInput('Workflow', { script: FORCE_PUSH, junk: 'strip-me' }, 'annotate');
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.args.script).toBe(FORCE_PUSH);
      expect(r.strippedKeys).toContain('junk');
    }
  });

  it('enforce still rejects unknown Bash keys, including empty ones', () => {
    expect(enforceToolInput('Bash', { command: 'git status', evil_payload: 'x' }).ok).toBe(false);
    // An empty value must not buy an unknown key a free pass on the enforce path.
    const empty = enforceToolInput('Bash', { command: 'git status', evil_payload: '' });
    expect(empty.ok).toBe(false);
    if (!empty.ok) {
      expect(empty.code).toBe('UNKNOWN_KEYS');
      expect(empty.unknownKeys).toContain('evil_payload');
    }
  });

  it('empty values on ALLOWED keys are absent, not invalid', () => {
    // Hosts routinely send `command: ''` alongside the field they actually used.
    const r = enforceToolInput('web_fetch', { url: 'https://example.com/path', query: '' });
    expect(r.ok).toBe(true);
    if (r.ok) expect(Object.prototype.hasOwnProperty.call(r.args, 'query')).toBe(false);
  });

  it('an object or array on an extractor key fails closed', () => {
    const obj = enforceToolInput('Bash', { command: { toString: 'evil' } });
    expect(obj.ok).toBe(false);
    if (!obj.ok) expect(['NESTED_INVALID', 'TYPE_COERCION']).toContain(obj.code);

    const arr = enforceToolInput('Bash', { command: ['git', 'push', '--force'] });
    expect(arr.ok).toBe(false);

    // Same discipline in annotate mode — a retained extractor key must be scannable.
    const annotated = validateToolInput('Workflow', { script: { nested: FORCE_PUSH } }, 'annotate');
    expect(annotated.ok).toBe(false);
  });

  it('structured messaging content is not treated as a command string', () => {
    const r = validateToolInput('notify', { content: { text: 'hello' }, channel: 'ops-channel' }, 'annotate');
    expect(r.ok).toBe(true);
    if (r.ok) expect((r.args.content as { text: string }).text).toBe('hello');
  });

  it('github-named tools are not git-enforce (title/body stay allowed)', () => {
    expect(evaluateToolCall('github_create_issue', {
      title: 'Track the flaky gate',
      body: 'The notify suite is red on main.',
      labels: 'bug',
    }).decision).toBe('allow');
    expect(evaluateToolCall('list_github_repos', { owner: 'Drakon-Systems-Ltd' }).decision).toBe('allow');
  });

  it('non-string command/path primitives fail closed', () => {
    const n = enforceToolInput('Bash', { command: 1 });
    expect(n.ok).toBe(false);
    if (!n.ok) expect(n.code).toBe('TYPE_COERCION');
    expect(enforceToolInput('Bash', { command: true }).ok).toBe(false);
    expect(enforceToolInput('Bash', { path: 0 }).ok).toBe(false);
  });
});
