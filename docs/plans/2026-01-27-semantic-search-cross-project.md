# Semantic Search + Cross-Project Knowledge Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add meaning-based search via vector embeddings and enable cross-project knowledge sharing.

**Architecture:** Hybrid search combining FTS5 keyword matching with vector similarity using local embeddings (@xenova/transformers). Memories gain `scope` (project/global) and `transferable` flags to enable cross-project pattern sharing.

**Tech Stack:** @xenova/transformers (all-MiniLM-L6-v2), SQLite BLOB storage, TypeScript

---

## Task 1: Add Embedding Dependencies

**Files:**
- Modify: `package.json`

**Step 1: Install @xenova/transformers**

Run:
```bash
npm install @xenova/transformers
```

**Step 2: Verify installation**

Run:
```bash
npm ls @xenova/transformers
```
Expected: Shows version ~2.x installed

**Step 3: Commit**

```bash
git add package.json package-lock.json
git commit -m "deps: add @xenova/transformers for local embeddings"
```

---

## Task 2: Create Embedding Generator

**Files:**
- Create: `src/embeddings/generator.ts`
- Create: `src/embeddings/index.ts`

**Step 1: Create the generator module**

Create `src/embeddings/generator.ts`:
```typescript
import { pipeline, env } from '@xenova/transformers';

// Configure for local-only operation
env.allowRemoteModels = true;
env.allowLocalModels = true;

let embeddingPipeline: any = null;
let isLoading = false;
let loadPromise: Promise<any> | null = null;

/**
 * Lazy-load the embedding model
 * Model: all-MiniLM-L6-v2 (22MB, 384 dimensions)
 */
async function getEmbeddingPipeline() {
  if (embeddingPipeline) return embeddingPipeline;

  if (isLoading && loadPromise) {
    return loadPromise;
  }

  isLoading = true;
  loadPromise = pipeline('feature-extraction', 'Xenova/all-MiniLM-L6-v2');

  try {
    embeddingPipeline = await loadPromise;
    return embeddingPipeline;
  } finally {
    isLoading = false;
    loadPromise = null;
  }
}

/**
 * Generate embedding vector for text
 * @param text - Text to embed (title + content recommended)
 * @returns Float32Array of 384 dimensions
 */
export async function generateEmbedding(text: string): Promise<Float32Array> {
  const extractor = await getEmbeddingPipeline();

  // Truncate to ~512 tokens worth (~2000 chars) for model limits
  const truncated = text.slice(0, 2000);

  const output = await extractor(truncated, {
    pooling: 'mean',
    normalize: true,
  });

  return new Float32Array(output.data);
}

/**
 * Calculate cosine similarity between two embeddings
 * @returns Similarity score 0-1 (1 = identical)
 */
export function cosineSimilarity(a: Float32Array, b: Float32Array): number {
  if (a.length !== b.length) {
    throw new Error(`Embedding dimension mismatch: ${a.length} vs ${b.length}`);
  }

  let dotProduct = 0;
  let normA = 0;
  let normB = 0;

  for (let i = 0; i < a.length; i++) {
    dotProduct += a[i] * b[i];
    normA += a[i] * a[i];
    normB += b[i] * b[i];
  }

  const magnitude = Math.sqrt(normA) * Math.sqrt(normB);
  if (magnitude === 0) return 0;

  return dotProduct / magnitude;
}

/**
 * Check if embedding model is loaded
 */
export function isModelLoaded(): boolean {
  return embeddingPipeline !== null;
}

/**
 * Preload the model (call during startup if desired)
 */
export async function preloadModel(): Promise<void> {
  await getEmbeddingPipeline();
}
```

**Step 2: Create index export**

Create `src/embeddings/index.ts`:
```typescript
export { generateEmbedding, cosineSimilarity, isModelLoaded, preloadModel } from './generator.js';
```

**Step 3: Test embedding generation manually**

Run:
```bash
npx tsx -e "
import { generateEmbedding, cosineSimilarity } from './src/embeddings/generator.js';

async function test() {
  console.log('Generating embedding 1...');
  const e1 = await generateEmbedding('JWT authentication middleware');
  console.log('Embedding 1 dims:', e1.length);

  console.log('Generating embedding 2...');
  const e2 = await generateEmbedding('Login security token validation');
  console.log('Embedding 2 dims:', e2.length);

  const similarity = cosineSimilarity(e1, e2);
  console.log('Similarity (should be >0.5):', similarity.toFixed(4));

  const e3 = await generateEmbedding('SQLite database schema');
  const dissimilar = cosineSimilarity(e1, e3);
  console.log('Dissimilar (should be <0.3):', dissimilar.toFixed(4));
}

test().catch(console.error);
"
```
Expected:
- Embedding dims: 384
- Similar texts: >0.5
- Dissimilar texts: <0.3

**Step 4: Commit**

```bash
git add src/embeddings/
git commit -m "feat: add embedding generator with MiniLM-L6-v2"
```

---

## Task 3: Update Database Schema

**Files:**
- Modify: `src/database/init.ts`
- Modify: `src/memory/types.ts`

**Step 1: Add columns to schema**

In `src/database/init.ts`, find the CREATE TABLE memories statement and add after the `metadata` column:

```typescript
// Find this line (approximately):
//   metadata TEXT,
// Add these columns after it:

      embedding BLOB,
      scope TEXT DEFAULT 'project',
      transferable INTEGER DEFAULT 0,
```

**Step 2: Update Memory type**

In `src/memory/types.ts`, add to the Memory interface:

```typescript
// Find the Memory interface and add:
  embedding?: Buffer;
  scope: 'project' | 'global';
  transferable: boolean;
```

**Step 3: Update RememberOptions type**

In `src/memory/types.ts`, add to RememberOptions interface:

```typescript
// Add to RememberOptions:
  scope?: 'project' | 'global';
  transferable?: boolean;
```

**Step 4: Build to verify types**

Run:
```bash
npm run build
```
Expected: Build succeeds with no type errors

**Step 5: Commit**

```bash
git add src/database/init.ts src/memory/types.ts
git commit -m "feat: add embedding, scope, transferable columns to schema"
```

---

## Task 4: Modify addMemory for Embeddings

**Files:**
- Modify: `src/memory/store.ts`

**Step 1: Import embedding functions**

At top of `src/memory/store.ts`, add:

```typescript
import { generateEmbedding } from '../embeddings/index.js';
```

**Step 2: Add detectGlobalPattern function**

Add this function before `addMemory`:

```typescript
/**
 * Detect if memory content suggests global applicability
 */
function detectGlobalPattern(content: string, category: string, tags: string[]): boolean {
  const globalCategories = ['pattern', 'preference', 'learning'];
  const globalKeywords = ['always', 'never', 'best practice', 'general rule', 'universal'];
  const globalTags = ['universal', 'global', 'general', 'cross-project'];

  if (globalCategories.includes(category)) return true;
  if (globalKeywords.some(k => content.toLowerCase().includes(k))) return true;
  if (tags.some(t => globalTags.includes(t.toLowerCase()))) return true;

  return false;
}
```

**Step 3: Modify addMemory to generate embeddings and set scope**

Find the INSERT statement in `addMemory` and modify to include new columns. After the INSERT succeeds, add embedding generation:

```typescript
// After successful INSERT, generate embedding async (don't block)
const memoryId = result.lastInsertRowid as number;

// Generate embedding in background
generateEmbedding(title + ' ' + content)
  .then(embedding => {
    try {
      db.prepare('UPDATE memories SET embedding = ? WHERE id = ?')
        .run(Buffer.from(embedding.buffer), memoryId);
    } catch (e) {
      console.error('[claude-memory] Failed to store embedding:', e);
    }
  })
  .catch(e => {
    console.error('[claude-memory] Failed to generate embedding:', e);
  });
```

**Step 4: Update INSERT to include scope/transferable**

Modify the INSERT statement to include:

```typescript
const scope = options.scope ??
  (detectGlobalPattern(content, category, tags) ? 'global' : 'project');
const transferable = options.transferable ?? (scope === 'global' ? 1 : 0);

// Add to INSERT columns: scope, transferable
// Add to VALUES: scope, transferable
```

**Step 5: Build and test**

Run:
```bash
npm run build
```
Expected: Build succeeds

**Step 6: Commit**

```bash
git add src/memory/store.ts
git commit -m "feat: generate embeddings on memory creation, auto-detect global scope"
```

---

## Task 5: Add Vector Search Function

**Files:**
- Modify: `src/memory/store.ts`

**Step 1: Add vectorSearch function**

Add this function in `store.ts`:

```typescript
import { cosineSimilarity } from '../embeddings/index.js';

/**
 * Search memories by vector similarity
 */
function vectorSearch(
  queryEmbedding: Float32Array,
  limit: number,
  project?: string,
  includeGlobal: boolean = true
): Array<{ memory: Memory; similarity: number }> {
  const db = getDatabase();

  // Get memories with embeddings
  let query = `
    SELECT * FROM memories
    WHERE embedding IS NOT NULL
  `;
  const params: any[] = [];

  if (project && includeGlobal) {
    query += ` AND (project = ? OR scope = 'global')`;
    params.push(project);
  } else if (project) {
    query += ` AND project = ?`;
    params.push(project);
  }

  const rows = db.prepare(query).all(...params) as any[];

  // Calculate similarities
  const results = rows
    .map(row => {
      const embedding = new Float32Array(row.embedding.buffer);
      const similarity = cosineSimilarity(queryEmbedding, embedding);
      return {
        memory: rowToMemory(row),
        similarity,
      };
    })
    .filter(r => r.similarity > 0.3) // Threshold for relevance
    .sort((a, b) => b.similarity - a.similarity)
    .slice(0, limit);

  return results;
}
```

**Step 2: Build to verify**

Run:
```bash
npm run build
```
Expected: Build succeeds

**Step 3: Commit**

```bash
git add src/memory/store.ts
git commit -m "feat: add vector search function with cosine similarity"
```

---

## Task 6: Integrate Hybrid Search

**Files:**
- Modify: `src/memory/store.ts`

**Step 1: Modify searchMemories for hybrid scoring**

Find `searchMemories` function and modify to include vector search. Add at the beginning of the function:

```typescript
// Generate query embedding (async, may fail on first call while model loads)
let queryEmbedding: Float32Array | null = null;
try {
  queryEmbedding = await generateEmbedding(query);
} catch (e) {
  console.log('[claude-memory] Vector search unavailable, using FTS only');
}
```

Then in the scoring section, add vector similarity to the weights:

```typescript
// If we have vector results, add similarity boost
let vectorBoost = 0;
if (queryEmbedding) {
  const vectorResults = vectorSearch(queryEmbedding, limit * 2, project, options.includeGlobal ?? true);
  const vectorMatch = vectorResults.find(v => v.memory.id === memory.id);
  if (vectorMatch) {
    vectorBoost = vectorMatch.similarity * 0.3; // 30% weight for vector similarity
  }
}

// Update final score calculation to include vectorBoost
const finalScore =
  ftsScore * 0.3 +      // Reduced from 0.35
  vectorBoost +          // New: 0-0.3 from vector similarity
  decayedScore * 0.25 +  // Reduced from 0.35
  priorityScore * 0.1 +  // Reduced from 0.15
  activationBoost +
  linkBoost +
  categoryBoost +
  tagBoost +
  recencyBoost;
```

**Step 2: Make searchMemories async**

Change function signature from:
```typescript
export function searchMemories(options: SearchOptions): Memory[]
```
To:
```typescript
export async function searchMemories(options: SearchOptions): Promise<Memory[]>
```

**Step 3: Update all callers to await searchMemories**

Check files that call searchMemories and add await:
- `src/tools/recall.ts`
- `src/api/visualization-server.ts`

**Step 4: Build to verify**

Run:
```bash
npm run build
```
Expected: Build succeeds

**Step 5: Commit**

```bash
git add src/memory/store.ts src/tools/recall.ts src/api/visualization-server.ts
git commit -m "feat: integrate hybrid search with FTS5 + vector similarity"
```

---

## Task 7: Update MCP Tools for Scope

**Files:**
- Modify: `src/server.ts`
- Modify: `src/tools/recall.ts`

**Step 1: Update remember tool schema**

In `src/server.ts`, find the remember tool definition and add parameters:

```typescript
// Add to inputSchema.properties:
scope: {
  type: 'string',
  enum: ['project', 'global'],
  description: 'Memory scope: project (default) or global (cross-project)',
},
transferable: {
  type: 'boolean',
  description: 'Whether this memory can be transferred to other projects',
},
```

**Step 2: Update recall tool schema**

In `src/server.ts`, find the recall tool definition and add:

```typescript
// Add to inputSchema.properties:
includeGlobal: {
  type: 'boolean',
  description: 'Include global memories in search results (default: true)',
},
```

**Step 3: Update recall tool handler**

In `src/tools/recall.ts`, pass includeGlobal to searchMemories:

```typescript
const results = await searchMemories({
  ...options,
  includeGlobal: args.includeGlobal ?? true,
});
```

**Step 4: Build to verify**

Run:
```bash
npm run build
```
Expected: Build succeeds

**Step 5: Commit**

```bash
git add src/server.ts src/tools/recall.ts
git commit -m "feat: add scope and includeGlobal parameters to MCP tools"
```

---

## Task 8: Integration Testing

**Files:**
- None (manual testing)

**Step 1: Restart Claude Code to reload MCP server**

Close and reopen Claude Code, or run `/mcp` to check server status.

**Step 2: Test semantic search**

```
remember "Fixed authentication by validating JWT tokens in the middleware layer"
```

Then search with no keyword overlap:
```
recall "login security"
```
Expected: Should find the JWT memory (semantic similarity)

**Step 3: Test global scope**

```
remember "Best practice: always sanitize user input before database queries" category: pattern
```

Check that scope was auto-detected as global:
```
recall "sanitize"
```
Expected: Memory has scope: global

**Step 4: Test cross-project**

In a different project:
```
recall "sanitize"
```
Expected: Global memory from other project appears

**Step 5: Test isolation**

```
remember "This project uses PostgreSQL for the database"
```

In a different project:
```
recall "PostgreSQL"
```
Expected: Should NOT find it (project-scoped)

**Step 6: Final commit**

```bash
git add -A
git commit -m "test: verify semantic search and cross-project features"
```

---

## Summary

| Task | Description | Time |
|------|-------------|------|
| 1 | Add dependencies | 5m |
| 2 | Create embedding generator | 20m |
| 3 | Update database schema | 15m |
| 4 | Modify addMemory | 20m |
| 5 | Add vector search | 15m |
| 6 | Integrate hybrid search | 25m |
| 7 | Update MCP tools | 15m |
| 8 | Integration testing | 20m |

**Total: ~2.5 hours**

---

## Rollback Plan

If issues arise:
1. Remove embedding column: `ALTER TABLE memories DROP COLUMN embedding`
2. Revert to FTS-only search in searchMemories
3. Remove @xenova/transformers from package.json

The system will continue working with FTS5 search only.
