/**
 * Owner-authored memory and the `stealth_instruction` marker rule (issue #514).
 *
 * Claude Code memory files open with YAML frontmatter and their bodies are
 * standing guidance ("always ...", "never ..."). The skill scanner's marker
 * pattern reads the line that CLOSES that frontmatter as a hidden
 * end-of-document marker, so every such file was reported: 288 hits over 147
 * owner files in the 15 Sep 2026 run, 38 of 57 on a second box, none real.
 *
 * The detector is NOT changed for this. An earlier revision taught the pattern
 * itself to skip a frontmatter closer, and that was a bypass: it accepted any
 * text between two `---` lines, for every caller, so a skill file could put a
 * fake block on top and hide what followed. The rule stays at full strength
 * for skills, tool output, `scan` and the hooks. What changes is how the AUDIT
 * grades one narrow case, and it is a downgrade to INFO, never a suppression:
 * the finding still exists and `--json` still carries it.
 *
 * All of these must hold:
 *   1. the file was discovered under the owner's HOME Claude memory roots -- not
 *      the working directory, which may be a repository someone else wrote;
 *   2. stealth_instruction is the ONLY reason the pipeline flagged the file;
 *   3. the file opens with frontmatter in which every line is YAML (a `key:`,
 *      an indented child or list item, or a comment) -- free prose is not;
 *   4. with that one closer blanked, the rule no longer fires. A later `---`,
 *      an HTML comment or a bidi override is still a hit, and still HIGH.
 */

import { detectSkillThreats } from '../defence/skill-scanner/patterns.js';

/** Discovery labels for memory under the owner's home. See discoverMemoryFiles. */
const OWNER_HOME_MEMORY_SOURCES: ReadonlySet<string> = new Set([
  'Claude project memory',
  'Claude global memory',
]);

const MAX_FRONTMATTER_LINES = 64;

const YAML_KEY_LINE = /^[A-Za-z_][\w.-]*:(?:[ \t].*)?$/;
const YAML_CHILD_LINE = /^[ \t]+(?:-[ \t]+\S.*|[A-Za-z_][\w.-]*:(?:[ \t].*)?)$/;
const YAML_COMMENT_LINE = /^[ \t]*#.*$/;

/**
 * Offset of the `---` that closes strict leading YAML frontmatter, or -1.
 *
 * Strict on purpose. The opener must be the first line (a BOM is allowed), the
 * first inner line must be a top-level key, every inner line must be YAML, and
 * a blank line or a second `---` inside ends the attempt.
 */
export function strictFrontmatterCloserOffset(content: string): number {
  const text = content.charCodeAt(0) === 0xfeff ? content.slice(1) : content;
  const shift = content.length - text.length;
  const lines = text.split('\n');
  if (lines.length < 3 || lines[0].replace(/\r$/, '').trimEnd() !== '---') return -1;

  let offset = lines[0].length + 1;
  for (let i = 1; i < lines.length && i <= MAX_FRONTMATTER_LINES + 1; i++) {
    const line = lines[i].replace(/\r$/, '');
    if (line.trimEnd() === '---') return i === 1 ? -1 : shift + offset;
    const yaml = i === 1
      ? YAML_KEY_LINE.test(line)
      : YAML_KEY_LINE.test(line) || YAML_CHILD_LINE.test(line) || YAML_COMMENT_LINE.test(line);
    if (!yaml) return -1;
    offset += lines[i].length + 1;
  }
  return -1;
}

export interface StealthVerdictInput {
  /** Discovery label of the file, from discoverMemoryFiles. */
  discoverySource: string;
  /** `firewall.reason` for the file. */
  reason: string;
  /** `firewall.blockedPatterns` for the file. */
  blockedPatterns: string[];
}

// Balanced mode names the skill threats; strict mode lists every indicator. In
// both, stealth_instruction has to be the whole list, not a member of it.
const STEALTH_ONLY_REASON =
  /Skill-level threat detected: stealth_instruction \(|Strict mode: detected stealth_instruction$/;

/**
 * True when the ONLY thing wrong with an owner memory file is that its
 * frontmatter closer tripped the marker rule.
 */
export function isFrontmatterOnlyStealthHit(content: string, verdict: StealthVerdictInput): boolean {
  if (!OWNER_HOME_MEMORY_SOURCES.has(verdict.discoverySource)) return false;
  if (!STEALTH_ONLY_REASON.test(verdict.reason)) return false;
  if (verdict.blockedPatterns.length !== 1 || verdict.blockedPatterns[0] !== 'skill:stealth_instruction') return false;

  const closer = strictFrontmatterCloserOffset(content);
  if (closer === -1) return false;
  const withoutCloser = `${content.slice(0, closer)}   ${content.slice(closer + 3)}`;
  return !detectSkillThreats(withoutCloser).threats.includes('stealth_instruction');
}
