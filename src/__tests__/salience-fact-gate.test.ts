import { describe, expect, it } from '@jest/globals';
import { isDurableFact, classifyCategory, suggestCategory } from '../memory/salience.js';
import type { MemoryCategory } from '../memory/types.js';

/**
 * Issue #49 (task 3): a fact gate must run BEFORE keyword classification in
 * salience.ts. A candidate that is not a declarative durable statement
 * (interrogative, conjunction-led fragment, or a sub-clause below the
 * meaningful-token floor) is dropped — `classifyCategory` returns null rather
 * than forcing a (usually wrong) category. `suggestCategory` keeps its non-null
 * contract by falling back to 'note' for non-facts, so the manual MCP path
 * never mislabels a question as a `preference`.
 *
 * Acceptance: 20-sample category precision >= 18/20 correct-or-correctly-rejected.
 */

describe('isDurableFact', () => {
  it('accepts a declarative durable statement', () => {
    expect(isDurableFact({ title: '', content: 'We migrated the billing service onto Postgres for consistency' })).toBe(true);
  });

  it('rejects an interrogative', () => {
    expect(isDurableFact({ title: '', content: 'should we just buy a new computer?' })).toBe(false);
  });

  it('rejects a conjunction-led fragment', () => {
    expect(isDurableFact({ title: '', content: 'and so they sit at project null for now' })).toBe(false);
    expect(isDurableFact({ title: '', content: "you're going to need a bigger machine" })).toBe(false);
  });

  it('rejects a sub-clause below the meaningful-token floor', () => {
    expect(isDurableFact({ title: '', content: 'new box' })).toBe(false);
  });
});

describe('classifyCategory — fact gate before classification', () => {
  it('returns null for a non-fact instead of forcing a category', () => {
    // The OLD keyword scan filed this question under `preference` (it contains
    // "should"). The gate must drop it to null.
    expect(classifyCategory({ title: '', content: 'should we always rebuild the cache?' })).toBeNull();
  });

  it('classifies a real preference', () => {
    expect(classifyCategory({ title: '', content: 'the team prefers TypeScript strict mode on every package' })).toBe('preference');
  });

  it('classifies a real error resolution', () => {
    expect(classifyCategory({ title: '', content: 'the crash was caused by a null pointer in the date parser' })).toBe('error');
  });
});

describe('suggestCategory — non-destructive fallback', () => {
  it('falls back to note for a non-fact (never a confidently-wrong label)', () => {
    expect(suggestCategory({ title: '', content: 'should we always rebuild the cache?' })).toBe('note');
  });

  it('still classifies a genuine architecture fact', () => {
    expect(suggestCategory({ title: 'System Design', content: 'Using microservices architecture with an API gateway' })).toBe('architecture');
  });
});

describe('issue #49 — 20-sample category precision >= 18/20', () => {
  interface Sample {
    content: string;
    expected: MemoryCategory | null; // null == should be correctly rejected as a non-fact
  }

  const SAMPLES: Sample[] = [
    // --- valid declarative facts (expected category) ---
    { content: 'the system uses a microservices architecture behind an API gateway', expected: 'architecture' },
    { content: 'the database schema models each tenant as a separate row-level scope', expected: 'architecture' },
    { content: 'the crash was caused by a null pointer exception in the date parser', expected: 'error' },
    { content: 'the bug was fixed by adding a busy_timeout and enabling WAL mode', expected: 'error' },
    { content: 'the team prefers TypeScript strict mode on every package in the repo', expected: 'preference' },
    { content: 'we should always run the build before pushing changes to the main branch', expected: 'preference' },
    { content: 'the recommended approach uses a retry strategy with exponential backoff', expected: 'pattern' },
    { content: 'the default workflow runs the linter then the unit test suite in order', expected: 'pattern' },
    { content: 'todo: rotate the deploy key every ninety days before the certificate expires', expected: 'todo' },
    { content: 'the parser depends on the shared tokenizer module for its input stage', expected: 'relationship' },
    // --- non-facts that must be correctly REJECTED (null) ---
    { content: 'should we just buy a brand new development computer for the team?', expected: null },
    { content: 'is the apostrophe really splitting into two separate sub-tokens?', expected: null },
    { content: 'do you want me to flip the primary back to opus permanently now?', expected: null },
    { content: 'and so they sit at project null until the next reconciliation pass', expected: null },
    { content: "you're going to want a bigger instance before that backlog replay", expected: null },
    { content: "it's stored under the wrong project key across every single row", expected: null },
    { content: "that's the third night the heartbeat job has silently skipped", expected: null },
    { content: 'because the migration ran twice against the same shard last night', expected: null },
    { content: 'new box', expected: null },
    { content: 'plus a couple of stray edge cases slipped through the net last week', expected: null },
  ];

  it('scores at least 18/20 correct-or-correctly-rejected', () => {
    expect(SAMPLES).toHaveLength(20);
    let correct = 0;
    const misses: Array<{ content: string; expected: MemoryCategory | null; got: MemoryCategory | null }> = [];
    for (const s of SAMPLES) {
      const got = classifyCategory({ title: '', content: s.content });
      if (got === s.expected) correct++;
      else misses.push({ content: s.content, expected: s.expected, got });
    }
    if (correct < 18) {
      // Surface the misclassifications for a fast diagnosis if this regresses.
      // eslint-disable-next-line no-console
      console.error('category misses:', JSON.stringify(misses, null, 2));
    }
    expect(correct).toBeGreaterThanOrEqual(18);
  });
});
