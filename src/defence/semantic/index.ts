/**
 * Semantic Analysis defence layer.
 *
 * Embeds incoming content and compares it (cosine similarity) against a curated
 * corpus of attack phrasings. This catches PARAPHRASED injection / jailbreak /
 * exfiltration attempts that the literal regex layer misses.
 *
 * This is a LOCAL layer that runs on the ASYNC / deep-scan path only — never on
 * the synchronous hot path (regex stays the only thing on `runDefencePipeline`).
 * It degrades gracefully: if the embedding model is unavailable (transformers is
 * optional, and the suite/CI sets `SHIELDCORTEX_SKIP_EMBEDDINGS=1`), it returns
 * `available:false, flagged:false` and the caller does nothing.
 *
 * The corpus is embedded at RUNTIME and cached at module scope, so corpus
 * vectors always use the same model as the content being scanned.
 */

import { cosineSimilarity } from '../../embeddings/index.js';
import { forEachWindow } from '../scan-windows.js';
import { ATTACK_CORPUS } from './attack-corpus.js';

/**
 * Cosine-similarity threshold above which content is considered a semantic
 * match for a known attack phrasing.
 *
 * CONSERVATIVE BY DESIGN, AND TUNABLE. Precision is the priority: it is far
 * worse to flag a benign developer note than to miss one paraphrase (the regex
 * + other layers are the primary net; this is an additive backstop).
 *
 * Tuned against the REAL all-MiniLM-L6-v2 model on a small held-out set of
 * paraphrased attacks vs. realistic benign developer notes (see the smoke test
 * in src/__tests__/semantic-layer.test.ts). Observed distributions:
 *   - benign dev notes:        0.14 – 0.41, with one outlier at 0.51
 *     ("Update the system prompt template in the docs…" — lexical "system prompt")
 *   - paraphrased attacks:     0.49 – 0.88 (median ~0.63)
 * The clusters OVERLAP at the low end, so no threshold catches every attack
 * with zero false positives. We choose 0.58 — just above the benign ceiling —
 * to keep FALSE POSITIVES AT ZERO on that set (the precision gate) while still
 * catching the clear paraphrases (~75% recall). The weakest/most-ambiguous
 * paraphrases, which sit in benign territory in embedding space, are
 * deliberately left to the regex + behavioural layers.
 *
 * NOTE: this was tuned on a SMALL set. Run a proper eval pass (broader corpus,
 * more benign categories incl. security-domain notes) before treating this as a
 * primary control rather than an additive backstop.
 */
export const SEMANTIC_SIMILARITY_THRESHOLD = 0.58;

/**
 * An embedder returns an embedding vector for `text`, or `null` when the model
 * is unavailable. Injected for testing so the threshold logic can be asserted
 * with controlled vectors, without loading the ~349MB model.
 */
export type Embedder = (text: string) => Promise<Float32Array | null>;

export interface SemanticAnalysisResult {
  /** False when the embedding model is unavailable (graceful degrade). */
  available: boolean;
  /** Max cosine similarity between content and any corpus phrase (0 when unavailable). */
  maxSimilarity: number;
  /** The corpus phrase that produced `maxSimilarity` (when available). */
  matchedPhrase?: string;
  /** True when `maxSimilarity >= SEMANTIC_SIMILARITY_THRESHOLD`. */
  flagged: boolean;
}

/** Module-level cache of corpus embeddings, keyed by the embedder identity. */
let cachedCorpus: { embedder: Embedder; vectors: Float32Array[] } | null = null;

const UNAVAILABLE: SemanticAnalysisResult = { available: false, maxSimilarity: 0, flagged: false };

/**
 * The default embedder: wraps `generateEmbedding`, lazily imported so the sync
 * pipeline never pulls in the embedding worker, and catches any failure (model
 * absent, worker missing, SKIP flag, timeout) into a `null` graceful degrade.
 */
const defaultEmbedder: Embedder = async (text: string) => {
  try {
    const { generateEmbedding } = await import('../../embeddings/index.js');
    return await generateEmbedding(text);
  } catch {
    return null;
  }
};

/**
 * Embed the attack corpus once per embedder and cache it. Returns `null` if the
 * embedder is unavailable (first corpus embed returns null) so callers degrade.
 */
async function getCorpusVectors(embedder: Embedder): Promise<Float32Array[] | null> {
  if (cachedCorpus && cachedCorpus.embedder === embedder) {
    return cachedCorpus.vectors;
  }

  const vectors: Float32Array[] = [];
  for (const phrase of ATTACK_CORPUS) {
    const vec = await embedder(phrase);
    if (!vec) {
      // Model unavailable — do not cache a partial corpus; degrade.
      return null;
    }
    vectors.push(vec);
  }

  cachedCorpus = { embedder, vectors };
  return vectors;
}

/** Test-only: drop the cached corpus so a different injected embedder is used. */
export function _resetCorpusCache(): void {
  cachedCorpus = null;
}

/**
 * Analyse `content` for semantic similarity to the attack corpus.
 *
 * @param content The text to analyse.
 * @param embedder Optional injected embedder (for tests). Defaults to the real model.
 */
export async function analyzeSemanticSimilarity(
  content: string,
  embedder: Embedder = defaultEmbedder,
): Promise<SemanticAnalysisResult> {
  if (!content || content.trim().length === 0) {
    return UNAVAILABLE;
  }

  const corpusVectors = await getCorpusVectors(embedder);
  if (!corpusVectors) {
    return UNAVAILABLE;
  }

  // Chunk long content with the shared window helper; embed each chunk and keep
  // the strongest match across chunks (a payload buried in filler still scores).
  const chunks: string[] = [];
  forEachWindow(content, (window) => {
    chunks.push(window);
  });

  let maxSimilarity = 0;
  let matchedPhrase: string | undefined;
  let sawAnyVector = false;

  for (const chunk of chunks) {
    const contentVec = await embedder(chunk);
    if (!contentVec) {
      // The model became unavailable mid-scan — degrade rather than report a
      // partial (and therefore misleadingly low) similarity.
      return UNAVAILABLE;
    }
    sawAnyVector = true;

    for (let i = 0; i < corpusVectors.length; i++) {
      const corpusVec = corpusVectors[i];
      if (corpusVec.length !== contentVec.length) continue; // dimension guard
      const sim = cosineSimilarity(contentVec, corpusVec);
      if (sim > maxSimilarity) {
        maxSimilarity = sim;
        matchedPhrase = ATTACK_CORPUS[i];
      }
    }
  }

  if (!sawAnyVector) {
    return UNAVAILABLE;
  }

  return {
    available: true,
    maxSimilarity,
    matchedPhrase,
    flagged: maxSimilarity >= SEMANTIC_SIMILARITY_THRESHOLD,
  };
}
