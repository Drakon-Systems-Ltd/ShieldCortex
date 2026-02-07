/**
 * Skill File Parser
 *
 * Parses agent instruction files from 8 different AI frameworks into a common
 * format for scanning. Supports SKILL.md, HOOK.md, handler.js, .cursorrules,
 * .windsurfrules, .clinerules, CLAUDE.md, copilot-instructions.md,
 * .aider.conf.yml, and .continue/config.json.
 *
 * The parser never throws — malformed input produces sensible defaults.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';

// ── Types ──

export type SkillFormat =
  | 'skill-md'
  | 'hook-md'
  | 'hook-js'
  | 'rules'
  | 'claude-md'
  | 'copilot-md'
  | 'aider-yml'
  | 'continue-json'
  | 'unknown';

export interface ParsedSkill {
  /** Extracted from metadata or filename */
  name: string;
  /** Auto-detected format */
  format: SkillFormat;
  /** The text content to scan (body only, no frontmatter) */
  content: string;
  /** YAML/JSON frontmatter if present */
  metadata?: Record<string, unknown>;
  /** Original file contents */
  raw: string;
  /** Source path if read from disc */
  filePath?: string;
}

// ── Format Detection ──

/**
 * Auto-detect the skill format based on the file path.
 * Uses basename for filename matching; case-insensitive for .md files.
 */
export function detectFormat(filePath: string): SkillFormat {
  const basename = path.basename(filePath);
  const lower = basename.toLowerCase();

  // Exact filename matches (case-insensitive for .md)
  if (lower === 'skill.md') return 'skill-md';
  if (lower === 'hook.md') return 'hook-md';
  if (basename === 'handler.js') return 'hook-js';
  if (lower === 'claude.md') return 'claude-md';
  if (lower === 'copilot-instructions.md') return 'copilot-md';
  if (basename === '.aider.conf.yml') return 'aider-yml';

  // Rules files (exact basename match, case-sensitive — these are dotfiles)
  if (basename === '.cursorrules' || basename === '.windsurfrules' || basename === '.clinerules') {
    return 'rules';
  }

  // Path-based matches
  const normalised = filePath.replace(/\\/g, '/');

  if (normalised.includes('.claude/commands/')) return 'claude-md';

  if (basename === 'config.json' && normalised.includes('.continue/')) {
    return 'continue-json';
  }

  return 'unknown';
}

// ── Simple YAML Parser ──

/**
 * Parse simple YAML key-value pairs, supporting one level of nesting.
 *
 * This does NOT handle the full YAML specification — only the straightforward
 * frontmatter structures used by skill and hook files:
 *   key: value
 *   key: "quoted value"
 *   parent:
 *     child: value
 */
function parseSimpleYaml(yamlText: string): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  const lines = yamlText.split('\n');

  let currentParent: string | null = null;
  let nestedObj: Record<string, unknown> | null = null;

  for (const line of lines) {
    // Skip empty lines and comments
    const trimmed = line.trimEnd();
    if (trimmed === '' || trimmed.startsWith('#')) {
      continue;
    }

    // Determine indentation level
    const indent = line.length - line.trimStart().length;
    const content = trimmed.trim();

    // Match key: value pattern
    const kvMatch = content.match(/^([A-Za-z_][\w.-]*)\s*:\s*(.*)/);
    if (!kvMatch) continue;

    const key = kvMatch[1];
    let value: string = kvMatch[2].trim();

    if (indent >= 2 && currentParent && nestedObj) {
      // This is a nested key under the current parent
      nestedObj[key] = unquoteValue(value);
    } else {
      // Top-level key — flush any previous nested object
      if (currentParent && nestedObj) {
        result[currentParent] = nestedObj;
        currentParent = null;
        nestedObj = null;
      }

      if (value === '' || value === '') {
        // This key has no inline value — it introduces a nested block
        currentParent = key;
        nestedObj = {};
      } else {
        result[key] = unquoteValue(value);
      }
    }
  }

  // Flush trailing nested object
  if (currentParent && nestedObj) {
    result[currentParent] = nestedObj;
  }

  return result;
}

/**
 * Remove surrounding quotes from a YAML value string and coerce simple types.
 */
function unquoteValue(raw: string): unknown {
  if (raw === '') return '';

  // Remove surrounding quotes (single or double)
  if (
    (raw.startsWith('"') && raw.endsWith('"')) ||
    (raw.startsWith("'") && raw.endsWith("'"))
  ) {
    return raw.slice(1, -1);
  }

  // Boolean coercion
  if (raw === 'true') return true;
  if (raw === 'false') return false;

  // Numeric coercion
  if (/^-?\d+(\.\d+)?$/.test(raw)) {
    return Number(raw);
  }

  return raw;
}

// ── Frontmatter Extraction ──

/**
 * Split YAML frontmatter (between --- markers at the start of a file)
 * from the markdown body. Returns [frontmatter, body].
 */
function splitFrontmatter(content: string): [string | null, string] {
  // Frontmatter must start at the very beginning of the file
  if (!content.startsWith('---')) {
    return [null, content];
  }

  // Find the closing --- marker (must be on its own line)
  const closingIndex = content.indexOf('\n---', 3);
  if (closingIndex === -1) {
    // No closing marker — treat the entire file as body
    return [null, content];
  }

  const frontmatter = content.slice(3, closingIndex).trim();
  const body = content.slice(closingIndex + 4).trim();

  return [frontmatter, body];
}

// ── Name Extraction Helpers ──

/**
 * Try to extract a name from the first line comment in a JS file,
 * For example: "// my-hook" or block comments like "Hook Name".
 */
function extractJsName(source: string): string | null {
  const firstLine = source.split('\n')[0]?.trim() ?? '';

  // Single-line comment: // name
  const singleComment = firstLine.match(/^\/\/\s*(.+)/);
  if (singleComment) {
    return singleComment[1].trim();
  }

  // Block comment: /* name */
  const blockComment = firstLine.match(/^\/\*\s*(.+?)\s*\*\//);
  if (blockComment) {
    return blockComment[1].trim();
  }

  // module.exports name — look for module.exports.name = "..."
  const exportsName = source.match(/module\.exports\.name\s*=\s*["']([^"']+)["']/);
  if (exportsName) {
    return exportsName[1];
  }

  // module.exports = { name: "..." }
  const objName = source.match(/module\.exports\s*=\s*\{[^}]*name\s*:\s*["']([^"']+)["']/);
  if (objName) {
    return objName[1];
  }

  return null;
}

/**
 * Derive a name from a filename, stripping the extension and leading dot.
 */
function nameFromFilename(filename: string): string {
  const basename = path.basename(filename);
  const ext = path.extname(basename);
  let name = ext ? basename.slice(0, -ext.length) : basename;

  // Strip leading dot for dotfiles (e.g. .cursorrules -> cursorrules)
  if (name.startsWith('.')) {
    name = name.slice(1);
  }

  return name || 'unknown';
}

// ── Core Parser ──

/**
 * Parse file content into a ParsedSkill structure.
 *
 * @param content  Raw file content
 * @param format   Detected format (defaults to 'unknown')
 */
export function parseSkillFile(content: string, format?: SkillFormat): ParsedSkill {
  const effectiveFormat = format ?? 'unknown';
  const raw = content;

  // Guard against empty or binary-looking content
  if (!content || content.length === 0) {
    return {
      name: 'unknown',
      format: effectiveFormat,
      content: '',
      raw,
    };
  }

  // Detect likely binary content (high ratio of non-printable characters)
  const nonPrintable = content.slice(0, 1024).replace(/[\x20-\x7E\t\n\r]/g, '').length;
  if (nonPrintable > 128) {
    return {
      name: 'unknown',
      format: effectiveFormat,
      content: '',
      raw,
    };
  }

  switch (effectiveFormat) {
    case 'skill-md':
    case 'hook-md':
      return parseMarkdownWithFrontmatter(content, effectiveFormat, raw);

    case 'rules':
    case 'claude-md':
    case 'copilot-md':
      return parseRawContent(content, effectiveFormat, raw);

    case 'hook-js':
      return parseJavaScript(content, raw);

    case 'aider-yml':
      return parseAiderYaml(content, raw);

    case 'continue-json':
      return parseContinueJson(content, raw);

    case 'unknown':
    default:
      return {
        name: 'unknown',
        format: 'unknown',
        content,
        raw,
      };
  }
}

/**
 * Parse a markdown file that may contain YAML frontmatter (skill-md, hook-md).
 */
function parseMarkdownWithFrontmatter(
  content: string,
  format: 'skill-md' | 'hook-md',
  raw: string,
): ParsedSkill {
  const [frontmatter, body] = splitFrontmatter(content);

  let metadata: Record<string, unknown> | undefined;
  let name = 'unknown';

  if (frontmatter) {
    try {
      metadata = parseSimpleYaml(frontmatter);
    } catch {
      // Malformed YAML — continue without metadata
      metadata = undefined;
    }

    if (metadata && typeof metadata.name === 'string' && metadata.name.length > 0) {
      name = metadata.name;
    }
  }

  return {
    name,
    format,
    content: body,
    metadata,
    raw,
  };
}

/**
 * Parse a raw content file with no frontmatter (rules, claude-md, copilot-md).
 * The name is derived from the filename if available, otherwise defaults.
 */
function parseRawContent(
  content: string,
  format: 'rules' | 'claude-md' | 'copilot-md',
  raw: string,
): ParsedSkill {
  // Name will be overridden by readSkillFile when filePath is available
  return {
    name: 'unknown',
    format,
    content,
    raw,
  };
}

/**
 * Parse a JavaScript hook file.
 */
function parseJavaScript(content: string, raw: string): ParsedSkill {
  const extracted = extractJsName(content);

  return {
    name: extracted ?? 'handler',
    format: 'hook-js',
    content,
    raw,
  };
}

/**
 * Parse an Aider YAML configuration file.
 */
function parseAiderYaml(content: string, raw: string): ParsedSkill {
  let metadata: Record<string, unknown> | undefined;

  try {
    metadata = parseSimpleYaml(content);
  } catch {
    // Malformed YAML — continue without metadata
    metadata = undefined;
  }

  return {
    name: 'aider',
    format: 'aider-yml',
    content,
    metadata,
    raw,
  };
}

/**
 * Parse a Continue JSON configuration file.
 */
function parseContinueJson(content: string, raw: string): ParsedSkill {
  let metadata: Record<string, unknown> | undefined;
  let parsedContent = content;
  let name = 'continue';

  try {
    const parsed = JSON.parse(content) as Record<string, unknown>;
    metadata = parsed;
    parsedContent = JSON.stringify(parsed);

    if (typeof parsed.name === 'string' && parsed.name.length > 0) {
      name = parsed.name;
    }
  } catch {
    // Malformed JSON — use raw content as-is
    metadata = undefined;
    parsedContent = content;
  }

  return {
    name,
    format: 'continue-json',
    content: parsedContent,
    metadata,
    raw,
  };
}

// ── File Reader ──

/**
 * Read a skill file from disc, auto-detect its format, and parse it.
 *
 * Returns a ParsedSkill with the filePath field populated.
 * If the file cannot be read, returns a minimal ParsedSkill with empty content.
 */
export function readSkillFile(filePath: string): ParsedSkill {
  let content: string;

  try {
    content = fs.readFileSync(filePath, 'utf-8');
  } catch {
    // File unreadable — return a safe default
    return {
      name: nameFromFilename(filePath),
      format: detectFormat(filePath),
      content: '',
      raw: '',
      filePath,
    };
  }

  const format = detectFormat(filePath);
  const result = parseSkillFile(content, format);

  result.filePath = filePath;

  // For formats that derive their name from the filename, apply it now
  if (result.name === 'unknown' || result.name === '') {
    result.name = nameFromFilename(filePath);
  }

  return result;
}
