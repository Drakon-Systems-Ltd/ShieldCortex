import { describe, expect, it } from '@jest/globals';

/**
 * Issue #49: the OpenClaw auto-capture pipeline was storing sentence FRAGMENTS
 * (mid-clause slices that begin on a leading conjunction / pronoun-tail, or end
 * on a trailing `?`) instead of self-contained durable facts.
 *
 * This suite pins the HARDENED rejection corpus in the shared chunker
 * (scripts/lib/extract-memorable-segments.mjs):
 *
 *   (a) leading conjunction / sentence-continuation token  → reject
 *       (and|so|but|yet|or|because|also|then|plus|have|has|
 *        he's|she's|you're|it's|that's|there's|we're|they're|i'm)
 *   (b) trailing `?` (interrogative)                        → reject
 *   (c) bare clause / no subject+verb                       → reject
 *   (d) below the minimum meaningful-token count            → reject
 *
 * Acceptance (from the issue):
 *   - new auto-capture fragment rate < 5% over a 50-candidate sample.
 */

type Reject = (
  segment: { title: string; content: string; extractorType?: string },
  conversationText?: string,
) => { rejected: boolean; reason: string };

async function loadChunker() {
  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-expect-error -- importing a .mjs hook util (no type decls)
  return import('../../scripts/lib/extract-memorable-segments.mjs');
}

describe('issue #49 — leading conjunction / continuation rejection', () => {
  // The full closed list from the issue brief, case-insensitive.
  const CONTINUATION_TOKENS = [
    'and', 'so', 'but', 'yet', 'or', 'because', 'also', 'then', 'plus',
    'have', 'has', "he's", "she's", "you're", "it's", "that's", "there's",
    "we're", "they're", "i'm",
  ];

  it.each(CONTINUATION_TOKENS)('rejects a capture that begins with "%s"', async (tok) => {
    const { shouldRejectCandidate } = (await loadChunker()) as { shouldRejectCandidate: Reject };
    const content = `${tok} the rest of the thought trails on for a while here`;
    const verdict = shouldRejectCandidate({ title: '', content });
    expect(verdict.rejected).toBe(true);
    expect(verdict.reason).toBeTruthy();
  });

  it('is case-insensitive (capitalised conjunction still rejected)', async () => {
    const { shouldRejectCandidate } = (await loadChunker()) as { shouldRejectCandidate: Reject };
    expect(shouldRejectCandidate({ title: '', content: 'And then we shipped the broken build to prod' }).rejected).toBe(true);
    expect(shouldRejectCandidate({ title: '', content: "You're going to need a bigger machine for this job" }).rejected).toBe(true);
  });

  it('normalises a curly apostrophe in a pronoun-tail', async () => {
    const { shouldRejectCandidate } = (await loadChunker()) as { shouldRejectCandidate: Reject };
    expect(shouldRejectCandidate({ title: '', content: 'it’s stored under the wrong project key entirely here' }).rejected).toBe(true);
  });

  it('does NOT reject a legitimate verb-led capture that merely contains a conjunction', async () => {
    const { shouldRejectCandidate } = (await loadChunker()) as { shouldRejectCandidate: Reject };
    // "and" appears mid-sentence, not as the opener — must survive.
    const verdict = shouldRejectCandidate({
      title: '',
      content: 'rotating session tokens replace long-lived keys and expire after one hour',
    });
    expect(verdict.rejected).toBe(false);
  });
});

describe('issue #49 — trailing interrogative rejection', () => {
  it('rejects a capture ending in a question mark', async () => {
    const { shouldRejectCandidate } = (await loadChunker()) as { shouldRejectCandidate: Reject };
    expect(shouldRejectCandidate({ title: '', content: 'should we just buy a new computer?' }).rejected).toBe(true);
  });

  it('rejects a trailing `?` even with a closing quote/paren after it', async () => {
    const { shouldRejectCandidate } = (await loadChunker()) as { shouldRejectCandidate: Reject };
    expect(shouldRejectCandidate({ title: '', content: 'is this really the right approach here?)' }).rejected).toBe(true);
  });

  it('does not reject a declarative that merely contains a `?` mid-string', async () => {
    const { shouldRejectCandidate } = (await loadChunker()) as { shouldRejectCandidate: Reject };
    const verdict = shouldRejectCandidate({
      title: '',
      content: 'the parser handles the "what now?" prompt by falling back to the default route',
    });
    expect(verdict.rejected).toBe(false);
  });
});

describe('issue #49 — bare clause / minimum token rejection', () => {
  it('rejects a too-short candidate (below the meaningful-token floor)', async () => {
    const { shouldRejectCandidate } = (await loadChunker()) as { shouldRejectCandidate: Reject };
    expect(shouldRejectCandidate({ title: '', content: 'new box' }).rejected).toBe(true);
  });

  it('rejects a bare noun-phrase clause with no verb', async () => {
    const { shouldRejectCandidate } = (await loadChunker()) as { shouldRejectCandidate: Reject };
    expect(shouldRejectCandidate({ title: '', content: 'the brand new build machine' }).rejected).toBe(true);
  });

  it('keeps a complete clause that has a verb', async () => {
    const { shouldRejectCandidate } = (await loadChunker()) as { shouldRejectCandidate: Reject };
    expect(shouldRejectCandidate({ title: '', content: 'the staging rack hosts the nightly build agents' }).rejected).toBe(false);
  });
});

describe('issue #49 — sentence-start enforcement in the segmenter', () => {
  it('extractMemorableSegments never emits a capture that opens on a continuation token', async () => {
    const { extractMemorableSegments } = (await loadChunker()) as {
      extractMemorableSegments: (t: string) => Array<{ content: string }>;
    };
    // The decision regex `decided\s+(?:to\s+)?(...)` would otherwise capture
    // "and then ship it" out of "...we decided and then ship it tomorrow".
    const text = 'Honestly we decided and then ship it tomorrow to the whole fleet at once.';
    const segments = extractMemorableSegments(text);
    for (const s of segments) {
      expect(/^(and|so|but|yet|or|because|also|then|plus|have|has)\b/i.test(s.content.trim())).toBe(false);
    }
  });

  it('extractMemorableSegments never emits an interrogative capture', async () => {
    const { extractMemorableSegments } = (await loadChunker()) as {
      extractMemorableSegments: (t: string) => Array<{ content: string }>;
    };
    const text = 'So the bug is in the date parser, is it not really clear at all?';
    const segments = extractMemorableSegments(text);
    for (const s of segments) {
      expect(/\?["')\]]?\s*$/.test(s.content.trim())).toBe(false);
    }
  });
});

describe('issue #49 — fragment rate < 5% over a 50-candidate sample', () => {
  // A representative mix mirroring the live store: 25 genuine fragments
  // (must be rejected) + 25 self-contained facts (must survive).
  const FRAGMENTS: string[] = [
    'and so the whole pipeline stalled until the gateway came back online',
    'so they sit at project equals null until the next reconciliation pass',
    'but that means the cache never warms before the first real request',
    'yet nobody noticed the regression until the weekly report went out',
    'or maybe we should just roll the change back before friday afternoon',
    'because the migration ran twice against the same shard last night',
    'also the dashboard kept rendering the stale figure for ten minutes',
    'then the worker exited zero without flushing the pending batch first',
    'plus the retries stacked up behind the lock and timed the request out',
    'have you actually confirmed the backup restored cleanly this morning',
    'has the new key already been rotated into the production secret store',
    "he's still waiting on the review before he can merge the hotfix branch",
    "she's convinced the flake is in the date parser not the network layer",
    "you're going to want a bigger instance before you replay that backlog",
    "it's stored under the wrong project key across every one of the rows",
    "that's the third time the heartbeat job has silently skipped a night",
    "there's no index on the created_at column so the scan goes full table",
    "we're capping salience at zero point six for all auto extracted rows",
    "they're filed as preference even though the line is plainly a question",
    "i'm fairly sure the regex grabbed the tail of the previous sentence",
    'should we just buy a brand new development computer for the team?',
    'is the apostrophe really splitting into two separate sub tokens?',
    'do you want me to flip the primary back to opus permanently now?',
    'and nobody re-ran the verification after the gateway finally recovered',
    'is the heartbeat marker even being written on a successful nightly run?',
  ];

  const FACTS: string[] = [
    'the deploy key rotates every ninety days and must be rotated by an admin',
    'we migrated the billing service onto Postgres for stronger write consistency',
    'the salience cap holds at zero point six for every auto-extracted memory row',
    'rotating session tokens replace the long-lived keys and expire after one hour',
    'the defence pipeline applies sanitisation before trust scoring on every write',
    'the FTS5 tokenizer splits apostrophes into separate sub-tokens during indexing',
    'the worker flushes the pending batch before it exits to avoid losing events',
    'the heartbeat job writes a marker row to the audit table on every successful run',
    'the dashboard caches the figure for ten seconds to smooth the websocket updates',
    'the migration adds a composite index on the project and created_at columns',
    'the gateway restarts gracefully and drains in-flight requests before exiting',
    'the backup script verifies the restore against a checksum before rotating files',
    'the recall ranker blends vector similarity with recency using a weighted sum',
    'the quarantine queue holds blocked content until an operator approves the row',
    'the sync queue retries failed uploads with exponential backoff up to five times',
    'the chunker pins category from the extractor type rather than rescanning text',
    'the prune job excludes pinned and suppressed rows from the deletion candidate set',
    'the installer rebuilds the native module whenever the node runtime version changes',
    'the api server holds an open connection in WAL mode for the dashboard reads',
    'the trust score reflects the human approval once the operator clears the item',
    'the novelty gate deduplicates a candidate against the most recent captured rows',
    'the embedding cache reuses a vector when the content hash already exists in store',
    'the firewall fails closed on a non-allow verdict during the update content path',
    'the session hook extracts at most five memories from one conversation transcript',
    'the cloud sync excludes any row that carries the cloud-excluded flag on upload',
  ];

  it('rejects every genuine fragment and keeps the facts (< 5% accepted-fragment rate)', async () => {
    const { shouldRejectCandidate } = (await loadChunker()) as { shouldRejectCandidate: Reject };

    const candidates = [
      ...FRAGMENTS.map((content) => ({ content, isFragment: true })),
      ...FACTS.map((content) => ({ content, isFragment: false })),
    ];
    expect(candidates).toHaveLength(50);

    const accepted = candidates.filter((c) => !shouldRejectCandidate({ title: '', content: c.content }).rejected);
    const acceptedFragments = accepted.filter((c) => c.isFragment);

    // No fragment should survive — fragment rate among accepted captures < 5%.
    const fragmentRate = accepted.length === 0 ? 0 : acceptedFragments.length / accepted.length;
    expect(fragmentRate).toBeLessThan(0.05);

    // Sanity: the gate must not be nuking everything — most real facts survive.
    const acceptedFacts = accepted.filter((c) => !c.isFragment);
    expect(acceptedFacts.length).toBeGreaterThanOrEqual(23); // >= 23/25 facts kept
  });
});
