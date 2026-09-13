#!/usr/bin/env node
/**
 * Dashboard v2 synthetic fixture generator.
 *
 * Creates two fully synthetic ShieldCortex databases for dashboard visual /
 * perf verification (docs/design/2026-09-13-dashboard-v2-ux.md §11, §13.7):
 *
 *   <out>/fixture-seeded.db   ~2000 memories, ~600 entities, ~2600 triples,
 *                             memory links of all four relationships, two
 *                             named projects + unscoped memories, plus the
 *                             mandated edge cases: a suspended triple
 *                             (valid_to set), a `conflicts` link, archived /
 *                             suppressed / pinned memories, one RESTRICTED
 *                             memory, disputed triples, and an entity with
 *                             zero memories.
 *   <out>/fixture-empty.db    schema only.
 *
 * Deterministic: seeded PRNG, no Date.now() in row data. NO real user data —
 * every string is generated from the word lists below.
 *
 * Usage: node scripts/dashboard-v2/make-fixture.mjs [outDir]   (default .dashv2)
 */

import Database from 'better-sqlite3';
import { readFileSync, mkdirSync, rmSync, existsSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join, resolve } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = resolve(__dirname, '..', '..');
const outDir = resolve(process.argv[2] || join(root, '.dashv2'));
mkdirSync(outDir, { recursive: true });

// ── Deterministic PRNG (mulberry32) ─────────────────────────
function mulberry32(seed) {
  let a = seed >>> 0;
  return function () {
    a |= 0; a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const rand = mulberry32(20260913);
const pick = (arr) => arr[Math.floor(rand() * arr.length)];
const between = (a, b) => a + rand() * (b - a);

// ── Synthetic vocabulary (no real data) ─────────────────────
const ENTITY_TYPES = ['tool', 'concept', 'project', 'file', 'service', 'person', 'language', 'pattern'];
const WORDS_A = ['quartz', 'ember', 'cobalt', 'lattice', 'onyx', 'saffron', 'delta', 'harbor', 'nimbus', 'cedar', 'raven', 'sable', 'tundra', 'vertex', 'willow', 'zenith', 'aurora', 'basalt', 'cinder', 'drift'];
const WORDS_B = ['parser', 'cache', 'router', 'ledger', 'beacon', 'index', 'daemon', 'schema', 'bridge', 'buffer', 'kernel', 'probe', 'relay', 'scheduler', 'vault', 'worker', 'monitor', 'queue', 'shard', 'gateway'];
const PREDICATES = ['uses', 'depends_on', 'part_of', 'configures', 'implements', 'monitors', 'stores_data_in', 'related_to'];
const CATEGORIES = ['architecture', 'pattern', 'preference', 'error', 'context', 'learning', 'todo', 'note', 'relationship'];
const MEM_TYPES = ['short_term', 'long_term', 'episodic'];
const PROJECTS = ['project-atlas', 'project-zephyr', null]; // null = unscoped
const LINK_RELS = ['related', 'supersedes', 'conflicts', 'supports'];

const N_ENTITIES = 600;
const N_MEMORIES = 2000;
const N_TRIPLES = 2600;
const N_LINKS = 400;

function build(dbPath, seeded) {
  rmSync(dbPath, { force: true });
  rmSync(dbPath + '-wal', { force: true });
  rmSync(dbPath + '-shm', { force: true });
  const db = new Database(dbPath);
  db.pragma('journal_mode = WAL');
  const schema = readFileSync(join(root, 'src', 'database', 'schema.sql'), 'utf8');
  db.exec(schema);
  if (!seeded) { db.close(); return { entities: 0, memories: 0, triples: 0, links: 0 }; }

  const day = 86400000;
  const t0 = Date.parse('2026-06-01T00:00:00Z');
  const iso = (ms) => new Date(ms).toISOString().replace('T', ' ').slice(0, 19);

  // Entities. names unique per (name,type); index 0 is the zero-memory entity.
  const insEntity = db.prepare(
    'INSERT INTO entities (name, type, aliases, first_seen, memory_count) VALUES (?, ?, ?, ?, 0)');
  const entityIds = [];
  const seen = new Set();
  db.transaction(() => {
    let made = 0;
    while (made < N_ENTITIES) {
      const type = made === 0 ? 'concept' : pick(ENTITY_TYPES);
      const name = made === 0
        ? 'orphan-holotype' // mandated: entity with zero memories
        : `${pick(WORDS_A)}-${pick(WORDS_B)}${made % 7 === 0 ? '-' + made : ''}`;
      const key = `${name}|${type}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const info = insEntity.run(name, type, '[]', iso(t0 + Math.floor(rand() * 90) * day));
      entityIds.push(Number(info.lastInsertRowid));
      made++;
    }
  })();

  // Memories.
  const insMem = db.prepare(`INSERT INTO memories
    (uuid, type, category, title, content, project, tags, salience, created_at, updated_at,
     last_accessed, trust_score, sensitivity_level, source, status, pinned, source_kind,
     capture_method, defence_verdict)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
  const memoryIds = [];
  db.transaction(() => {
    for (let i = 0; i < N_MEMORIES; i++) {
      const created = t0 + Math.floor(rand() * 100 * day);
      const category = pick(CATEGORIES);
      const project = PROJECTS[i % PROJECTS.length];
      let status = 'active';
      if (i === 5) status = 'archived';
      else if (i === 6) status = 'suppressed';
      else if (rand() < 0.02) status = 'archived';
      const pinned = i === 7 || rand() < 0.01 ? 1 : 0;
      const restricted = i === 8; // mandated: one RESTRICTED memory
      const title = restricted
        ? 'Synthetic credential holotype'
        : `${pick(WORDS_A)} ${pick(WORDS_B)} ${category} #${i}`;
      const content = restricted
        ? 'api_key=sk_synth_0000000000000000 (synthetic fixture value, never real)'
        : `Synthetic ${category} note ${i}: the ${pick(WORDS_A)} ${pick(WORDS_B)} interacts with the ${pick(WORDS_A)} ${pick(WORDS_B)} under condition ${Math.floor(rand() * 100)}.`;
      const info = insMem.run(
        `00000000-0000-4000-8000-${String(i).padStart(12, '0')}`,
        MEM_TYPES[i % 3], category, title, content, project,
        JSON.stringify([pick(WORDS_A), pick(WORDS_B)]),
        Number(between(0.05, 1).toFixed(3)), iso(created), iso(created),
        iso(created + Math.floor(rand() * 20) * day),
        Number(between(0.3, 1).toFixed(2)),
        restricted ? 'RESTRICTED' : 'INTERNAL',
        'user:direct', status, pinned, 'user', 'manual', 'unverified');
      memoryIds.push(Number(info.lastInsertRowid));
    }
  })();

  // memory_entities: 1–4 entities per memory (skip entity 0 = orphan).
  const insME = db.prepare(
    'INSERT OR IGNORE INTO memory_entities (memory_id, entity_id, role) VALUES (?, ?, ?)');
  const roles = ['mention', 'subject', 'object'];
  const mentionCounts = new Map();
  db.transaction(() => {
    for (const mid of memoryIds) {
      const n = 1 + Math.floor(rand() * 4);
      for (let k = 0; k < n; k++) {
        const eid = entityIds[1 + Math.floor(rand() * (entityIds.length - 1))];
        insME.run(mid, eid, pick(roles));
        mentionCounts.set(eid, (mentionCounts.get(eid) || 0) + 1);
      }
    }
  })();
  const updCount = db.prepare('UPDATE entities SET memory_count = ? WHERE id = ?');
  db.transaction(() => {
    for (const [eid, c] of mentionCounts) updCount.run(c, eid);
  })();

  // Triples. Mandated: ≥1 suspended (valid_to set), some disputed.
  const insTriple = db.prepare(`INSERT OR IGNORE INTO triples
    (subject_id, predicate, object_id, source_memory_id, confidence, created_at, valid_from, valid_to, disputed)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`);
  let triplesMade = 0;
  db.transaction(() => {
    let attempts = 0;
    while (triplesMade < N_TRIPLES && attempts < N_TRIPLES * 4) {
      attempts++;
      const s = entityIds[1 + Math.floor(rand() * (entityIds.length - 1))];
      const o = entityIds[1 + Math.floor(rand() * (entityIds.length - 1))];
      if (s === o) continue;
      const created = iso(t0 + Math.floor(rand() * 100 * day));
      const suspended = triplesMade < 5; // first five are suspended — must never render
      const info = insTriple.run(
        s, suspended ? 'previously_used' : pick(PREDICATES), o,
        memoryIds[Math.floor(rand() * memoryIds.length)],
        Number(between(0.4, 1).toFixed(2)), created, created,
        suspended ? iso(t0 + 60 * day) : null,
        rand() < 0.03 ? 1 : 0);
      if (info.changes > 0) triplesMade++;
    }
  })();

  // Memory links — all four relationships incl. a guaranteed `conflicts`.
  const insLink = db.prepare(
    'INSERT OR IGNORE INTO memory_links (source_id, target_id, relationship, strength, created_at) VALUES (?, ?, ?, ?, ?)');
  let linksMade = 0;
  db.transaction(() => {
    insLink.run(memoryIds[10], memoryIds[11], 'conflicts', 0.9, iso(t0 + 70 * day));
    insLink.run(memoryIds[12], memoryIds[5], 'supersedes', 0.95, iso(t0 + 71 * day));
    linksMade = 2;
    let attempts = 0;
    while (linksMade < N_LINKS && attempts < N_LINKS * 4) {
      attempts++;
      const a = memoryIds[Math.floor(rand() * memoryIds.length)];
      const b = memoryIds[Math.floor(rand() * memoryIds.length)];
      if (a === b) continue;
      const info = insLink.run(a, b, pick(LINK_RELS), Number(between(0.2, 1).toFixed(2)), iso(t0 + Math.floor(rand() * 100) * day));
      if (info.changes > 0) linksMade++;
    }
  })();

  const counts = {
    entities: db.prepare('SELECT COUNT(*) c FROM entities').get().c,
    memories: db.prepare('SELECT COUNT(*) c FROM memories').get().c,
    triples: db.prepare('SELECT COUNT(*) c FROM triples').get().c,
    suspendedTriples: db.prepare('SELECT COUNT(*) c FROM triples WHERE valid_to IS NOT NULL').get().c,
    disputedTriples: db.prepare('SELECT COUNT(*) c FROM triples WHERE disputed = 1').get().c,
    links: db.prepare('SELECT COUNT(*) c FROM memory_links').get().c,
    restricted: db.prepare("SELECT COUNT(*) c FROM memories WHERE sensitivity_level='RESTRICTED'").get().c,
    pinned: db.prepare('SELECT COUNT(*) c FROM memories WHERE pinned=1').get().c,
    archived: db.prepare("SELECT COUNT(*) c FROM memories WHERE status='archived'").get().c,
    zeroMemoryEntities: db.prepare('SELECT COUNT(*) c FROM entities WHERE memory_count=0').get().c,
    projects: db.prepare('SELECT COUNT(DISTINCT project) c FROM memories WHERE project IS NOT NULL').get().c,
  };
  db.close();
  return counts;
}

const seededPath = join(outDir, 'fixture-seeded.db');
const emptyPath = join(outDir, 'fixture-empty.db');
console.log('[fixture] building', seededPath);
const counts = build(seededPath, true);
console.log('[fixture] counts:', JSON.stringify(counts, null, 2));
console.log('[fixture] building', emptyPath);
build(emptyPath, false);
console.log('[fixture] done');
