/**
 * `shieldcortex memory <subcommand>` (v4.25.0)
 *
 * Local-only operator commands that read and adjust a single memory row.
 * The plural `memories` namespace at src/index.ts:700 is for the legacy
 * migrate flow — `memory` (singular) is the new operator surface.
 *
 * Subcommands:
 *   shieldcortex memory show <id>
 *   shieldcortex memory downvote <id> [--reason <text>]
 *   shieldcortex memory list [--purpose <X>] [--category <X>] [--limit N]
 *
 * Effective salience is computed via scripts/lib/salience.mjs so this CLI
 * shows the same numbers the recall hook actually ranks by.
 */

import path from 'path';
import os from 'os';
import { initDatabase, getDatabase } from '../database/init.js';

// ANSI colours — match doctor.ts conventions.
const bold = '\x1b[1m';
const reset = '\x1b[0m';
const green = '\x1b[32m';
const yellow = '\x1b[33m';
const red = '\x1b[31m';
const cyan = '\x1b[36m';
const dim = '\x1b[2m';

interface MemoryRow {
  id: number;
  uuid: string;
  title: string;
  content: string;
  category: string;
  salience: number;
  access_count: number | null;
  last_accessed: string | null;
  pinned: number | null;
  downvote_count: number | null;
  last_downvoted_at: string | null;
  memory_purpose: string | null;
  source: string | null;
  source_kind: string | null;
  created_at: string;
}

function defaultDbPath(): string {
  return process.env.CLAUDE_MEMORY_DB || path.join(os.homedir(), '.shieldcortex', 'memories.db');
}

function openDb() {
  initDatabase(defaultDbPath());
  return getDatabase();
}

async function effectiveSalienceFor(row: MemoryRow): Promise<number> {
  // @ts-expect-error — importing a .mjs hook util that has no .d.ts
  const { computeEffectiveSalience } = await import('../../scripts/lib/salience.mjs');
  return computeEffectiveSalience({
    salience: row.salience,
    access_count: row.access_count ?? 0,
    last_accessed: row.last_accessed,
    pinned: row.pinned ?? 0,
    downvote_count: row.downvote_count ?? 0,
  });
}

function parseFlag(args: string[], name: string): string | undefined {
  const idx = args.indexOf(name);
  if (idx === -1 || idx === args.length - 1) return undefined;
  return args[idx + 1];
}

function parseIntArg(value: string | undefined, fallback: number): number {
  if (value === undefined) return fallback;
  const n = parseInt(value, 10);
  return Number.isFinite(n) ? n : fallback;
}

function printMemory(row: MemoryRow, effective: number) {
  console.log(`${bold}Memory #${row.id}${reset}  ${dim}(${row.uuid})${reset}`);
  console.log(`  ${cyan}Title:${reset}      ${row.title}`);
  console.log(`  ${cyan}Category:${reset}   ${row.category}`);
  console.log(`  ${cyan}Purpose:${reset}    ${row.memory_purpose ?? 'project'}`);
  console.log(`  ${cyan}Source:${reset}     ${row.source ?? 'user:direct'} ${dim}(${row.source_kind ?? 'user'})${reset}`);
  console.log(`  ${cyan}Created:${reset}    ${row.created_at}`);
  console.log(`  ${cyan}Last seen:${reset}  ${row.last_accessed ?? '—'}`);
  console.log(`  ${cyan}Access #:${reset}   ${row.access_count ?? 0}`);
  console.log(`  ${cyan}Pinned:${reset}     ${row.pinned ? 'yes' : 'no'}`);
  console.log(`  ${cyan}Downvotes:${reset}  ${row.downvote_count ?? 0}${row.last_downvoted_at ? ` ${dim}(last ${row.last_downvoted_at})${reset}` : ''}`);
  console.log(`  ${cyan}Salience:${reset}   ${row.salience.toFixed(3)} ${dim}(base)${reset}`);
  const effColour = effective >= row.salience ? green : effective >= row.salience * 0.5 ? yellow : red;
  console.log(`  ${cyan}Effective:${reset}  ${effColour}${effective.toFixed(3)}${reset} ${dim}(after recency × access × pin × downvote)${reset}`);
  if (row.content) {
    console.log(`  ${cyan}Content:${reset}`);
    const lines = row.content.split('\n');
    for (const line of lines.slice(0, 8)) {
      console.log(`    ${dim}${line}${reset}`);
    }
    if (lines.length > 8) console.log(`    ${dim}… (+${lines.length - 8} more lines)${reset}`);
  }
}

async function cmdShow(args: string[]): Promise<number> {
  const idArg = args[0];
  if (!idArg) {
    console.error('Usage: shieldcortex memory show <id>');
    return 2;
  }
  const id = parseInt(idArg, 10);
  if (!Number.isFinite(id)) {
    console.error(`Invalid memory id: ${idArg}`);
    return 2;
  }
  const db = openDb();
  const row = db.prepare(`
    SELECT id, uuid, title, content, category, salience,
           access_count, last_accessed, pinned,
           COALESCE(downvote_count, 0) AS downvote_count,
           last_downvoted_at,
           memory_purpose, source, source_kind, created_at
    FROM memories WHERE id = ?
  `).get(id) as MemoryRow | undefined;
  if (!row) {
    console.error(`No memory found with id ${id}.`);
    return 1;
  }
  const effective = await effectiveSalienceFor(row);
  printMemory(row, effective);
  return 0;
}

async function cmdDownvote(args: string[]): Promise<number> {
  const idArg = args[0];
  if (!idArg) {
    console.error('Usage: shieldcortex memory downvote <id> [--reason <text>]');
    return 2;
  }
  const id = parseInt(idArg, 10);
  if (!Number.isFinite(id)) {
    console.error(`Invalid memory id: ${idArg}`);
    return 2;
  }
  const reason = parseFlag(args, '--reason');

  const db = openDb();
  const before = db.prepare(`
    SELECT id, uuid, title, content, category, salience,
           access_count, last_accessed, pinned,
           COALESCE(downvote_count, 0) AS downvote_count,
           last_downvoted_at, memory_purpose, source, source_kind, created_at
    FROM memories WHERE id = ?
  `).get(id) as MemoryRow | undefined;
  if (!before) {
    console.error(`No memory found with id ${id}.`);
    return 1;
  }
  const effBefore = await effectiveSalienceFor(before);

  const now = new Date().toISOString();
  db.prepare(`
    UPDATE memories
    SET downvote_count = COALESCE(downvote_count, 0) + 1,
        last_downvoted_at = ?
    WHERE id = ?
  `).run(now, id);

  const after = db.prepare(`
    SELECT id, uuid, title, content, category, salience,
           access_count, last_accessed, pinned,
           COALESCE(downvote_count, 0) AS downvote_count,
           last_downvoted_at, memory_purpose, source, source_kind, created_at
    FROM memories WHERE id = ?
  `).get(id) as MemoryRow;
  const effAfter = await effectiveSalienceFor(after);

  console.log(`${green}Downvoted${reset} memory #${id}: ${before.title}`);
  console.log(`  Downvote count: ${before.downvote_count ?? 0} → ${after.downvote_count}`);
  console.log(`  Effective salience: ${effBefore.toFixed(3)} → ${effAfter.toFixed(3)} ${dim}(${((effAfter / Math.max(effBefore, 1e-9) - 1) * 100).toFixed(1)}%)${reset}`);
  if (reason) {
    console.log(`  Reason: ${dim}${reason}${reset}`);
  }
  return 0;
}

async function cmdList(args: string[]): Promise<number> {
  const purpose = parseFlag(args, '--purpose');
  const category = parseFlag(args, '--category');
  const limit = parseIntArg(parseFlag(args, '--limit'), 20);

  const where: string[] = [];
  const params: unknown[] = [];
  if (purpose) {
    where.push('memory_purpose = ?');
    params.push(purpose);
  }
  if (category) {
    where.push('category = ?');
    params.push(category);
  }
  const whereClause = where.length ? `WHERE ${where.join(' AND ')}` : '';

  const db = openDb();
  const rows = db.prepare(`
    SELECT id, title, category, salience,
           COALESCE(downvote_count, 0) AS downvote_count,
           pinned, memory_purpose, source_kind
    FROM memories
    ${whereClause}
    ORDER BY salience DESC, last_accessed DESC
    LIMIT ?
  `).all(...params, limit) as Array<Pick<MemoryRow, 'id' | 'title' | 'category' | 'salience' | 'downvote_count' | 'pinned' | 'memory_purpose' | 'source_kind'>>;

  if (rows.length === 0) {
    console.log(`${dim}No memories match the given filters.${reset}`);
    return 0;
  }

  console.log(`${bold}id      sal    dv  pin  purpose    category       source    title${reset}`);
  for (const r of rows) {
    const dv = (r.downvote_count ?? 0) > 0 ? `${yellow}${r.downvote_count}${reset}` : ' 0';
    const pin = r.pinned ? `${green}★${reset}` : ' ';
    const title = (r.title ?? '').slice(0, 70);
    console.log(
      `${String(r.id).padEnd(7)} ${r.salience.toFixed(2)}  ${dv}  ${pin}   ${(r.memory_purpose ?? 'project').padEnd(10)} ${(r.category ?? '').padEnd(14)} ${(r.source_kind ?? 'user').padEnd(8)}  ${title}`,
    );
  }
  return 0;
}

function printHelp() {
  console.log('Usage: shieldcortex memory <subcommand> [args]');
  console.log('');
  console.log('Subcommands:');
  console.log('  show <id>                          Show a single memory with effective-salience breakdown');
  console.log('  downvote <id> [--reason <text>]    Mark a memory unhelpful (reduces effective salience at recall)');
  console.log('  list [--purpose X] [--category X] [--limit N]   Table view (default 20 rows)');
}

export async function handleMemoryCommand(args: string[]): Promise<void> {
  const sub = args[0];
  let code = 0;
  switch (sub) {
    case 'show':
      code = await cmdShow(args.slice(1));
      break;
    case 'downvote':
      code = await cmdDownvote(args.slice(1));
      break;
    case 'list':
      code = await cmdList(args.slice(1));
      break;
    case undefined:
    case '--help':
    case '-h':
    case 'help':
      printHelp();
      break;
    default:
      console.error(`Unknown subcommand: memory ${sub}`);
      printHelp();
      code = 2;
  }
  process.exit(code);
}
