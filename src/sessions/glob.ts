/**
 * Minimal portable glob expansion for the session-capture import flow.
 *
 * Node 22 added `fs.promises.glob`, but ShieldCortex's `engines.node`
 * still declares `>=18.0.0` — using fs/promises.glob would break the
 * CI matrix (Node 20) and any production deployment running an LTS
 * earlier than 22. This module implements the narrow subset of glob
 * semantics the importer actually needs:
 *
 *   - Literal paths (no wildcards) — return as-is, caller checks existence.
 *   - Shell wildcards `*` `?` `[]` within a single directory segment.
 *   - `**` for any-depth recursion (only between `/`-separated segments;
 *     `**` inside a filename is treated as a regular `*` `*`).
 *
 * No braces, no extglob, no negation. The JSONL importer doesn't need
 * those and pulling in a full glob package would inflate the install
 * footprint for a single feature.
 */

import { readdirSync, statSync, type Dirent } from 'fs';
import { join, sep, isAbsolute } from 'path';
import { homedir } from 'os';

export interface ExpandGlobOptions {
  /**
   * Cap on the number of returned matches. Stops walking once hit so
   * pathological globs against `/` don't lock up the API process.
   */
  maxMatches?: number;
}

const DEFAULT_MAX_MATCHES = 10_000;

/**
 * Returns `true` when the pattern contains any glob metacharacter the
 * walker treats specially. Used by callers to short-circuit literal
 * paths and skip the walker entirely.
 */
export function isGlobPattern(pattern: string): boolean {
  return /[*?[\]]/.test(pattern);
}

/**
 * Expand a glob pattern to absolute file paths. Synchronous because
 * the importer's callsites are already synchronous and the result is
 * always small enough that I/O is not the bottleneck (sessions live
 * on local disk under `~/.claude/projects/`).
 */
export function expandGlob(pattern: string, options: ExpandGlobOptions = {}): string[] {
  const max = options.maxMatches ?? DEFAULT_MAX_MATCHES;
  const expanded = expandHome(pattern);

  if (!isGlobPattern(expanded)) {
    return [expanded];
  }

  const segments = expanded.split(/[\\/]+/);
  // Determine the literal prefix — everything up to the first segment
  // that has a wildcard. Walking starts from there.
  let prefix = isAbsolute(expanded) ? sep : '';
  let i = 0;
  for (; i < segments.length; i++) {
    if (isGlobPattern(segments[i])) break;
    prefix = prefix === sep ? sep + segments[i] : prefix ? join(prefix, segments[i]) : segments[i];
  }
  if (prefix === '') prefix = '.';

  const remaining = segments.slice(i);
  const matches: string[] = [];
  walk(prefix, remaining, matches, max);
  return matches.sort();
}

/** Recursive matcher. */
function walk(currentDir: string, segments: string[], out: string[], max: number): void {
  if (out.length >= max) return;
  if (segments.length === 0) return;

  const [head, ...rest] = segments;

  // `**` — match any number of directory levels (including zero).
  if (head === '**') {
    // Zero levels: continue at currentDir with `rest`.
    walk(currentDir, rest, out, max);
    // One-or-more: recurse into every subdirectory with the same `**`.
    let entries: Dirent[] = [];
    try {
      entries = readdirSync(currentDir, { withFileTypes: true }) as unknown as Dirent[];
    } catch {
      return;
    }
    for (const entry of entries) {
      if (out.length >= max) return;
      if (entry.isDirectory()) {
        walk(join(currentDir, String(entry.name)), segments, out, max);
      }
    }
    return;
  }

  const regex = segmentToRegex(head);
  const isLastSegment = rest.length === 0;

  let entries: Dirent[] = [];
  try {
    entries = readdirSync(currentDir, { withFileTypes: true }) as unknown as Dirent[];
  } catch {
    return;
  }

  for (const entry of entries) {
    if (out.length >= max) return;
    const name = String(entry.name);
    if (!regex.test(name)) continue;
    const full = join(currentDir, name);
    if (isLastSegment) {
      // Only files match a leaf glob — directories aren't useful for the importer.
      if (entry.isFile()) out.push(full);
      else if (entry.isSymbolicLink()) {
        // Resolve symlinks lazily — a broken link just gets skipped.
        try {
          if (statSync(full).isFile()) out.push(full);
        } catch {
          // ignore
        }
      }
    } else if (entry.isDirectory() || entry.isSymbolicLink()) {
      walk(full, rest, out, max);
    }
  }
}

/** Convert a single shell-glob path segment to a regex. */
function segmentToRegex(segment: string): RegExp {
  let pattern = '^';
  let inCharClass = false;
  for (let i = 0; i < segment.length; i++) {
    const c = segment[i];
    if (inCharClass) {
      if (c === ']') {
        inCharClass = false;
        pattern += ']';
      } else if (c === '\\') {
        pattern += '\\\\';
      } else {
        pattern += escapeForRegex(c);
      }
      continue;
    }
    switch (c) {
      case '*':
        pattern += '[^/\\\\]*';
        break;
      case '?':
        pattern += '[^/\\\\]';
        break;
      case '[':
        inCharClass = true;
        pattern += '[';
        break;
      case '.':
      case '+':
      case '(':
      case ')':
      case '{':
      case '}':
      case '|':
      case '^':
      case '$':
        pattern += '\\' + c;
        break;
      default:
        pattern += c;
    }
  }
  pattern += '$';
  return new RegExp(pattern);
}

function escapeForRegex(c: string): string {
  return /[.*+?^${}()|[\]\\]/.test(c) ? '\\' + c : c;
}

/** Expand a leading `~` to the user's home directory. */
function expandHome(p: string): string {
  if (p === '~') return homedir();
  if (p.startsWith('~/') || p.startsWith('~\\')) {
    return join(homedir(), p.slice(2));
  }
  return p;
}
