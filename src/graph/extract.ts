/**
 * Pattern-based entity and triple extraction engine.
 * Extracts entities (files, languages, tools, people, concepts) and
 * relationship triples from memory title + content using pure regex matching.
 */

export type EntityType = 'person' | 'tool' | 'concept' | 'file' | 'language' | 'service' | 'pattern';

export interface ExtractedEntity {
  name: string;
  type: EntityType;
}

export interface ExtractedTriple {
  subject: string;
  predicate: string;
  object: string;
}

export interface ExtractionResult {
  entities: ExtractedEntity[];
  triples: ExtractedTriple[];
}

const LANGUAGES = new Set([
  'TypeScript', 'JavaScript', 'Python', 'Rust', 'Go', 'SQL', 'HTML', 'CSS',
  'Ruby', 'Java', 'C++', 'C#', 'Swift', 'Kotlin', 'Scala', 'Elixir',
  'Haskell', 'Lua', 'PHP', 'Perl', 'Shell', 'Bash', 'Zsh',
]);

const TOOLS_AND_SERVICES = new Set([
  'PostgreSQL', 'Redis', 'Docker', 'SQLite', 'Express', 'React', 'Next.js',
  'Node.js', 'npm', 'pnpm', 'yarn', 'git', 'GitHub', 'GitLab', 'Vercel',
  'AWS', 'Azure', 'GCP', 'MongoDB', 'MySQL', 'Prisma', 'Drizzle',
  'Webpack', 'Vite', 'ESLint', 'Prettier', 'Jest', 'Vitest', 'Playwright',
  'Cypress', 'Tailwind', 'MCP',
]);

// Lowercase lookup for case-insensitive matching
const TOOLS_LOWER = new Map<string, string>();
for (const t of TOOLS_AND_SERVICES) {
  TOOLS_LOWER.set(t.toLowerCase(), t);
}

const LANGUAGES_LOWER = new Map<string, string>();
for (const l of LANGUAGES) {
  LANGUAGES_LOWER.set(l.toLowerCase(), l);
}

const PASCAL_CASE_FALSE_POSITIVES = new Set([
  'README', 'TODO', 'IMPORTANT', 'NOTE', 'CREATE', 'INSERT', 'SELECT',
  'UPDATE', 'DELETE', 'WHERE', 'FROM', 'NULL', 'TRUE', 'FALSE', 'THEN',
  'ELSE', 'WHEN', 'CASE', 'INTO', 'TABLE', 'INDEX', 'ALTER', 'DROP',
  'BEGIN', 'COMMIT', 'ROLLBACK',
]);

// Generic words that should never become entities
const STOPWORDS = new Set([
  'project', 'the', 'a', 'an', 'this', 'that', 'these', 'those',
  'is', 'are', 'was', 'were', 'be', 'been', 'being', 'have', 'has', 'had',
  'do', 'does', 'did', 'will', 'would', 'could', 'should', 'may', 'might',
  'shall', 'can', 'need', 'must', 'it', 'its', 'we', 'our', 'my', 'your',
  'not', 'no', 'yes', 'all', 'any', 'some', 'each', 'every', 'both',
  'new', 'old', 'first', 'last', 'next', 'now', 'then', 'here', 'there',
  'up', 'down', 'out', 'in', 'on', 'off', 'over', 'under', 'more', 'less',
  'also', 'just', 'only', 'very', 'still', 'already', 'always', 'never',
  'added', 'built', 'made', 'set', 'got', 'put', 'run', 'let', 'get',
  'use', 'used', 'using', 'make', 'take', 'keep', 'work', 'call',
  'issue', 'issues', 'fix', 'fixed', 'bug', 'error', 'change', 'changes',
  'feature', 'step', 'phase', 'task', 'item', 'thing', 'things',
  'way', 'part', 'type', 'kind', 'form', 'case', 'point', 'end', 'start',
  'data', 'code', 'file', 'function', 'class', 'method', 'system', 'test',
  'cross', 'visual', 'auto', 'default', 'custom', 'main', 'base',
  'uses', 'with', 'for', 'from', 'after', 'before', 'same', 'key',
  'other', 'into', 'about', 'when', 'where', 'how', 'what', 'which',
  'notes', 'note', 'decisions', 'decision', 'discoveries', 'editing',
  'making', 'matching', 'update', 'updates', 'network', 'design',
  'pattern', 'approach', 'strategy', 'architecture', 'principle',
  'extraction', 'implementation', 'configuration', 'optimization',
]);

const FILE_EXT_RE = /\b[\w./-]+\.(ts|py|js|sql|json|md|tsx|jsx|rs|go|css|html)\b/g;
const DIR_PATH_RE = /\b(src|lib|dist|tests?|scripts?|dashboard)\/[\w./-]+\b/g;
const USERNAME_RE = /@(\w+)/g;
const NAME_SAID_RE = /\b([A-Z][a-z]+)\s+(?:said|mentioned|suggested|noted|asked|proposed)\b/g;
const PASCAL_CASE_RE = /\b([A-Z][a-z]+(?:[A-Z][a-z]+)+)\b/g;
const BEFORE_KEYWORD_RE = /\b(\w+)\s+(?:database|server|API|framework|library|plugin|extension)\b/g;
const CONCEPT_RE = /\b(?:architecture|pattern|approach|strategy|design)\s+(?:is\s+)?(\w[\w\s-]{0,30}?\w)\b/gi;
const CONCEPT_BEFORE_RE = /\b([\w-]+)\s+(?:architecture|pattern|approach|strategy|design)\b/gi;

export function extractFromMemory(title: string, content: string, category: string): ExtractionResult {
  const text = (title || '') + '\n' + (content || '');
  if (text.trim().length < 2) {
    return { entities: [], triples: [] };
  }

  const entityMap = new Map<string, ExtractedEntity>();

  function addEntity(name: string, type: EntityType): void {
    if (STOPWORDS.has(name.toLowerCase())) return;
    if (name.length < 2) return;
    const key = `${name}::${type}`;
    if (!entityMap.has(key)) {
      entityMap.set(key, { name, type });
    }
  }

  // --- Entity extraction ---

  // Files
  for (const m of text.matchAll(FILE_EXT_RE)) {
    addEntity(m[0], 'file');
  }
  for (const m of text.matchAll(DIR_PATH_RE)) {
    // Skip if already captured as a file with extension
    const val = m[0];
    if (!entityMap.has(`${val}::file`)) {
      addEntity(val, 'file');
    }
  }

  // Languages
  for (const lang of LANGUAGES) {
    // Build a regex that handles special chars like C++ and C#
    const escaped = lang.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const re = new RegExp(`\\b${escaped}\\b`, 'g');
    if (re.test(text)) {
      addEntity(lang, 'language');
    }
  }

  // Tools/services — exact match
  for (const [lower, canonical] of TOOLS_LOWER) {
    const escaped = canonical.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const re = new RegExp(`\\b${escaped}\\b`, 'gi');
    if (re.test(text)) {
      addEntity(canonical, 'tool');
    }
  }

  // PascalCase words (tools)
  for (const m of text.matchAll(PASCAL_CASE_RE)) {
    const word = m[1];
    if (!PASCAL_CASE_FALSE_POSITIVES.has(word.toUpperCase()) &&
        !LANGUAGES.has(word) &&
        !TOOLS_AND_SERVICES.has(word)) {
      addEntity(word, 'tool');
    }
  }

  // Words before "database", "server", etc.
  for (const m of text.matchAll(BEFORE_KEYWORD_RE)) {
    const word = m[1];
    if (word.length > 1 &&
        !PASCAL_CASE_FALSE_POSITIVES.has(word.toUpperCase()) &&
        !['the', 'a', 'an', 'this', 'that', 'my', 'our', 'its'].includes(word.toLowerCase())) {
      const canonical = TOOLS_LOWER.get(word.toLowerCase());
      addEntity(canonical || word, 'tool');
    }
  }

  // People
  for (const m of text.matchAll(USERNAME_RE)) {
    addEntity(m[1], 'person');
  }
  for (const m of text.matchAll(NAME_SAID_RE)) {
    addEntity(m[1], 'person');
  }

  // Concepts — only hyphenated or multi-word terms (e.g., "microservices architecture")
  for (const m of text.matchAll(CONCEPT_BEFORE_RE)) {
    const concept = m[1].toLowerCase();
    if (concept.length > 4) {
      addEntity(concept, 'concept');
    }
  }
  for (const m of text.matchAll(CONCEPT_RE)) {
    const concept = m[1].trim().toLowerCase();
    if (concept.length > 4) {
      addEntity(concept, 'concept');
    }
  }

  // --- Triple extraction ---

  const triples: ExtractedTriple[] = [];
  const tripleSet = new Set<string>();

  // Build a set of known entity names for resolving regex captures
  const knownNames = new Set<string>();
  const nameLookup = new Map<string, string>(); // lowercase → canonical name
  for (const [key] of entityMap) {
    const name = key.split('::')[0];
    knownNames.add(name);
    nameLookup.set(name.toLowerCase(), name);
  }
  for (const [lower, canonical] of TOOLS_LOWER) {
    nameLookup.set(lower, canonical);
  }
  for (const [lower, canonical] of LANGUAGES_LOWER) {
    nameLookup.set(lower, canonical);
  }

  // Resolve a raw capture to a known entity name
  function resolveEntityName(raw: string): string | null {
    if (!raw || STOPWORDS.has(raw.toLowerCase())) return null;
    // Exact match
    if (knownNames.has(raw)) return raw;
    // Case-insensitive match
    const canonical = nameLookup.get(raw.toLowerCase());
    if (canonical) return canonical;
    return null;
  }

  function addTriple(subject: string, predicate: string, object: string): void {
    if (subject === object) return;
    const key = `${subject}|${predicate}|${object}`;
    if (!tripleSet.has(key)) {
      tripleSet.add(key);
      triples.push({ subject, predicate, object });
      // Ensure referenced entities exist in entityMap
      ensureEntity(subject);
      ensureEntity(object);
    }
  }

  function ensureEntity(name: string): void {
    if (STOPWORDS.has(name.toLowerCase())) return;
    for (const [key] of entityMap) {
      if (key.startsWith(name + '::')) return;
    }
    if (TOOLS_LOWER.has(name.toLowerCase())) {
      addEntity(TOOLS_LOWER.get(name.toLowerCase())!, 'tool');
    } else if (LANGUAGES_LOWER.has(name.toLowerCase())) {
      addEntity(LANGUAGES_LOWER.get(name.toLowerCase())!, 'language');
    }
  }

  // Entity name pattern for regexes — captures dotted names like Next.js, Node.js
  const ENT = `(\\w+(?:[.-]\\w+)*)`;

  // "using X for Y" → X uses Y
  for (const m of text.matchAll(new RegExp(`\\busing\\s+${ENT}\\s+for\\s+${ENT}`, 'gi'))) {
    const subj = resolveEntityName(m[1]);
    const obj = resolveEntityName(m[2]);
    if (subj && obj) addTriple(subj, 'uses', obj);
  }

  // "replaced X with Y" → Y replaces X
  for (const m of text.matchAll(new RegExp(`\\breplaced\\s+${ENT}\\s+with\\s+${ENT}`, 'gi'))) {
    const old = resolveEntityName(m[1]);
    const nw = resolveEntityName(m[2]);
    if (old && nw) addTriple(nw, 'replaces', old);
  }

  // "X depends on Y"
  for (const m of text.matchAll(new RegExp(`${ENT}\\s+depends\\s+on\\s+${ENT}`, 'gi'))) {
    const subj = resolveEntityName(m[1]);
    const obj = resolveEntityName(m[2]);
    if (subj && obj) addTriple(subj, 'depends_on', obj);
  }

  // "X uses Y" / "X built with Y" / "X powered by Y"
  for (const m of text.matchAll(new RegExp(`${ENT}\\s+(?:uses|built\\s+with|powered\\s+by)\\s+${ENT}`, 'gi'))) {
    const subj = resolveEntityName(m[1]);
    const obj = resolveEntityName(m[2]);
    if (subj && obj) addTriple(subj, 'uses', obj);
  }

  // "fixed X by Y" — only if both resolve
  for (const m of text.matchAll(new RegExp(`\\bfixed\\s+${ENT}\\s+by\\s+${ENT}`, 'gi'))) {
    const what = resolveEntityName(m[1]);
    const how = resolveEntityName(m[2]);
    if (what && how) addTriple(how, 'fixes', what);
  }

  // "chose X over Y"
  for (const m of text.matchAll(new RegExp(`\\bchose\\s+${ENT}\\s+over\\s+${ENT}`, 'gi'))) {
    const pref = resolveEntityName(m[1]);
    const avoid = resolveEntityName(m[2]);
    if (pref) addTriple('project', 'prefers', pref);
    if (avoid) addTriple('project', 'avoids', avoid);
  }

  // "X configured with Y"
  for (const m of text.matchAll(new RegExp(`${ENT}\\s+configured\\s+with\\s+${ENT}`, 'gi'))) {
    const subj = resolveEntityName(m[1]);
    const obj = resolveEntityName(m[2]);
    if (subj && obj) addTriple(subj, 'configures', obj);
  }

  // "implemented X" — only if X resolves
  for (const m of text.matchAll(new RegExp(`\\bimplemented\\s+${ENT}`, 'gi'))) {
    const what = resolveEntityName(m[1]);
    if (what) addTriple('project', 'implements', what);
  }

  // "X extends Y"
  for (const m of text.matchAll(new RegExp(`${ENT}\\s+extends\\s+${ENT}`, 'gi'))) {
    const subj = resolveEntityName(m[1]);
    const obj = resolveEntityName(m[2]);
    if (subj && obj) addTriple(subj, 'extends', obj);
  }

  // --- Co-occurrence triples ---
  // Entities appearing in the same memory are related.
  // Generate "co_occurs_with" triples for entities in the same text.
  const entityNames = Array.from(entityMap.values())
    .filter(e => !STOPWORDS.has(e.name.toLowerCase()))
    .map(e => e.name);
  // Only generate co-occurrence for manageable counts (avoid O(n^2) explosion)
  if (entityNames.length >= 2 && entityNames.length <= 20) {
    for (let i = 0; i < entityNames.length; i++) {
      for (let j = i + 1; j < entityNames.length; j++) {
        addTriple(entityNames[i], 'related_to', entityNames[j]);
      }
    }
  } else if (entityNames.length > 20) {
    // For large entity sets, only link the first 10 most important (first found = in title/early content)
    const top = entityNames.slice(0, 10);
    for (let i = 0; i < top.length; i++) {
      for (let j = i + 1; j < top.length; j++) {
        addTriple(top[i], 'related_to', top[j]);
      }
    }
  }

  return {
    entities: Array.from(entityMap.values()),
    triples,
  };
}
