/**
 * X-Ray File Scanner
 *
 * Scans individual files for hidden risk patterns.
 * Handles code files (.js/.ts), JSON, and binary/image files.
 * Uses only Node.js built-ins — no new dependencies.
 */

import fs from 'fs';
import path from 'path';

import type { XRayFinding } from './types.js';
import { detectPatterns, detectFilenameDirectives } from './patterns.js';

// ── Constants ───────────────────────────────────────────────

/** Extensions treated as code files. */
const CODE_EXTENSIONS = new Set(['.js', '.ts', '.mjs', '.cjs', '.mts', '.cts', '.jsx', '.tsx']);

/** Extensions treated as JSON. */
const JSON_EXTENSIONS = new Set(['.json']);

/** Extensions treated as images. */
const IMAGE_EXTENSIONS = new Set(['.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp']);

/** Maximum file size to scan (10 MB). */
const MAX_FILE_SIZE = 10 * 1024 * 1024;

// ── Image EOI markers ───────────────────────────────────────

/** JPEG End-of-Image marker. */
const JPEG_EOI = Buffer.from([0xff, 0xd9]);

/** PNG IEND chunk signature. */
const PNG_IEND = Buffer.from([0x49, 0x45, 0x4e, 0x44]);

/** GIF trailer byte. */
const GIF_TRAILER = 0x3b;

// ── Helpers ─────────────────────────────────────────────────

function hasZeroWidthUnicode(content: string): XRayFinding | null {
  const zwMatch = content.match(/[\u200b\u200c\u200d\ufeff\u2060]{2,}/);
  if (!zwMatch) return null;

  const before = content.slice(0, zwMatch.index);
  const line = (before.match(/\n/g) || []).length + 1;

  return {
    severity: 'medium',
    category: 'unicode-trick',
    title: 'Zero-width Unicode characters detected',
    description: 'File contains clusters of zero-width characters that may hide invisible content.',
    line,
    evidence: `${zwMatch[0].length} zero-width chars at line ${line}`,
  };
}

function checkPolyglot(buf: Buffer): XRayFinding | null {
  // Check for multiple magic byte signatures in a single file
  const signatures: Array<{ name: string; magic: Buffer }> = [
    { name: 'PDF', magic: Buffer.from('%PDF') },
    { name: 'ZIP/JAR', magic: Buffer.from([0x50, 0x4b, 0x03, 0x04]) },
    { name: 'ELF', magic: Buffer.from([0x7f, 0x45, 0x4c, 0x46]) },
    { name: 'PE/EXE', magic: Buffer.from([0x4d, 0x5a]) },
    { name: 'GZIP', magic: Buffer.from([0x1f, 0x8b]) },
  ];

  const matched: string[] = [];
  for (const sig of signatures) {
    // Check at start and also embedded
    if (buf.includes(sig.magic)) {
      matched.push(sig.name);
    }
  }

  if (matched.length >= 2) {
    return {
      severity: 'high',
      category: 'steganography',
      title: 'Polyglot file detected',
      description: `File contains multiple format signatures (${matched.join(', ')}), indicating a polyglot that may hide payloads.`,
      evidence: matched.join(', '),
    };
  }

  return null;
}

// ── Image scanner ───────────────────────────────────────────

function scanImage(filePath: string, buf: Buffer): XRayFinding[] {
  const findings: XRayFinding[] = [];
  const ext = path.extname(filePath).toLowerCase();

  // Check for appended data after EOI marker
  if (ext === '.jpg' || ext === '.jpeg') {
    const eoiIndex = buf.lastIndexOf(JPEG_EOI);
    if (eoiIndex >= 0 && eoiIndex < buf.length - 2) {
      const trailing = buf.length - eoiIndex - 2;
      if (trailing > 16) {
        findings.push({
          severity: 'high',
          category: 'steganography',
          title: 'Data appended after JPEG EOI marker',
          description: `${trailing} bytes found after the JPEG End-of-Image marker — may contain hidden payloads.`,
          file: filePath,
          evidence: `${trailing} trailing bytes after EOI at offset ${eoiIndex}`,
        });
      }
    }
  }

  if (ext === '.png') {
    const iendIndex = buf.lastIndexOf(PNG_IEND);
    if (iendIndex >= 0) {
      // IEND chunk: 4-byte length + 4-byte type + 4-byte CRC = the IEND text is at +4 from chunk start
      // After IEND chunk: iendIndex + 4 (IEND) + 4 (CRC) = iendIndex + 8
      const afterIend = iendIndex + 8;
      if (afterIend < buf.length) {
        const trailing = buf.length - afterIend;
        if (trailing > 16) {
          findings.push({
            severity: 'high',
            category: 'steganography',
            title: 'Data appended after PNG IEND chunk',
            description: `${trailing} bytes found after the PNG IEND marker — may contain hidden payloads.`,
            file: filePath,
            evidence: `${trailing} trailing bytes after IEND at offset ${iendIndex}`,
          });
        }
      }
    }
  }

  if (ext === '.gif') {
    const lastByte = buf[buf.length - 1];
    if (lastByte !== GIF_TRAILER) {
      // Find the trailer
      const trailerIndex = buf.lastIndexOf(GIF_TRAILER);
      if (trailerIndex >= 0 && trailerIndex < buf.length - 1) {
        const trailing = buf.length - trailerIndex - 1;
        if (trailing > 16) {
          findings.push({
            severity: 'high',
            category: 'steganography',
            title: 'Data appended after GIF trailer',
            description: `${trailing} bytes found after the GIF trailer byte — may contain hidden payloads.`,
            file: filePath,
            evidence: `${trailing} trailing bytes after GIF trailer`,
          });
        }
      }
    }
  }

  // Check EXIF/metadata chunks for text with AI directives
  // Look for readable text in the binary that matches AI directive patterns
  const textChunks = extractTextFromBinary(buf);
  if (textChunks) {
    const metaFindings = detectPatterns(textChunks, filePath);
    for (const f of metaFindings) {
      if (f.category === 'ai-directive' || f.category === 'metadata-exploit') {
        f.description = `Image metadata contains: ${f.description}`;
        findings.push(f);
      }
    }
  }

  return findings;
}

/**
 * Extract readable ASCII/UTF-8 text sequences from a binary buffer.
 * Returns concatenated text chunks >= 8 chars for pattern scanning.
 */
function extractTextFromBinary(buf: Buffer): string | null {
  const chunks: string[] = [];
  let current = '';

  for (let i = 0; i < buf.length && i < 1024 * 1024; i++) {
    const byte = buf[i];
    // Printable ASCII range
    if (byte >= 0x20 && byte <= 0x7e) {
      current += String.fromCharCode(byte);
    } else {
      if (current.length >= 8) {
        chunks.push(current);
      }
      current = '';
    }
  }
  if (current.length >= 8) {
    chunks.push(current);
  }

  return chunks.length > 0 ? chunks.join('\n') : null;
}

// ── JSON scanner ────────────────────────────────────────────

function scanJson(filePath: string, content: string): XRayFinding[] {
  const findings: XRayFinding[] = [];

  // Run pattern detection for metadata injection, postinstall hooks, etc.
  findings.push(...detectPatterns(content, filePath));

  // Check for suspicious scripts in package.json
  const basename = path.basename(filePath);
  if (basename === 'package.json') {
    try {
      const pkg = JSON.parse(content);
      const scripts = pkg.scripts || {};

      for (const hook of ['preinstall', 'install', 'postinstall', 'preuninstall', 'postuninstall']) {
        if (scripts[hook]) {
          const val = scripts[hook];
          if (/curl|wget|node\s+-e|bash\s+-c|powershell|https?:\/\/|eval|exec/i.test(val)) {
            findings.push({
              severity: 'high',
              category: 'persistence-hook',
              title: `Suspicious ${hook} script`,
              description: `package.json "${hook}" script executes potentially dangerous commands.`,
              file: filePath,
              evidence: val.slice(0, 120),
            });
          }
        }
      }
    } catch {
      // Not valid JSON — just rely on pattern detection
    }
  }

  return findings;
}

// ── Public API ──────────────────────────────────────────────

/**
 * Scan a single file for X-Ray findings.
 *
 * @param filePath - Absolute or relative path to the file
 * @param deep - If true, performs deeper analysis (Pro feature)
 */
export async function scanFile(filePath: string, deep: boolean): Promise<XRayFinding[]> {
  const findings: XRayFinding[] = [];
  const ext = path.extname(filePath).toLowerCase();
  const basename = path.basename(filePath);

  // Check filename for AI directives
  findings.push(...detectFilenameDirectives(basename));

  // Check file exists and size
  let stat: fs.Stats;
  try {
    stat = fs.statSync(filePath);
  } catch {
    return findings;
  }

  if (!stat.isFile() || stat.size > MAX_FILE_SIZE) {
    return findings;
  }

  // Route by extension
  if (IMAGE_EXTENSIONS.has(ext)) {
    const buf = fs.readFileSync(filePath);
    findings.push(...scanImage(filePath, buf));

    // Polyglot check
    const polyglot = checkPolyglot(buf);
    if (polyglot) {
      polyglot.file = filePath;
      findings.push(polyglot);
    }
  } else if (JSON_EXTENSIONS.has(ext)) {
    const content = fs.readFileSync(filePath, 'utf-8');
    findings.push(...scanJson(filePath, content));

    // Zero-width unicode check
    const zw = hasZeroWidthUnicode(content);
    if (zw) {
      zw.file = filePath;
      findings.push(zw);
    }
  } else if (CODE_EXTENSIONS.has(ext)) {
    const content = fs.readFileSync(filePath, 'utf-8');
    findings.push(...detectPatterns(content, filePath));

    // Zero-width unicode check
    const zw = hasZeroWidthUnicode(content);
    if (zw) {
      zw.file = filePath;
      findings.push(zw);
    }
  } else {
    // For any other text-like file, try reading as text
    try {
      const buf = fs.readFileSync(filePath);

      // Check if it's mostly text
      let nonPrintable = 0;
      const sampleSize = Math.min(buf.length, 8192);
      for (let i = 0; i < sampleSize; i++) {
        const b = buf[i];
        if (b < 0x09 || (b > 0x0d && b < 0x20 && b !== 0x1b)) {
          nonPrintable++;
        }
      }

      if (nonPrintable / sampleSize < 0.1) {
        // Treat as text
        const content = buf.toString('utf-8');
        findings.push(...detectPatterns(content, filePath));

        const zw = hasZeroWidthUnicode(content);
        if (zw) {
          zw.file = filePath;
          findings.push(zw);
        }
      } else {
        // Binary file — polyglot check
        const polyglot = checkPolyglot(buf);
        if (polyglot) {
          polyglot.file = filePath;
          findings.push(polyglot);
        }
      }
    } catch {
      // Can't read — skip
    }
  }

  // Deep mode: additional analysis (Pro feature)
  if (deep && stat.size > 0) {
    try {
      const content = fs.readFileSync(filePath, 'utf-8');

      // Entropy analysis — detect packed/obfuscated code
      if (CODE_EXTENSIONS.has(ext) || ext === '.js' || ext === '.mjs') {
        const entropy = shannonEntropy(content);
        if (entropy > 5.5) {
          findings.push({
            category: 'obfuscation',
            title: `High entropy code (${entropy.toFixed(2)} bits/char)`,
            description: 'File may contain obfuscated or packed code',
            severity: 'medium',
            file: filePath,
          });
        }
      }

      // Long single-line detection — common in minified/obfuscated code
      const lines = content.split('\n');
      const longLines = lines.filter(l => l.length > 2000);
      if (longLines.length > 0 && lines.length < 10) {
        findings.push({
          category: 'obfuscation',
          title: `Minified/packed code (${longLines.length} lines over 2000 chars)`,
          description: 'File appears to contain minified or packed code which may hide malicious content',
          severity: 'low',
          file: filePath,
        });
      }
    } catch {
      // Can't read as text for deep analysis — skip
    }
  }

  return findings;
}

/** Shannon entropy of a string (bits per character). Higher = more random/compressed. */
function shannonEntropy(str: string): number {
  if (str.length === 0) return 0;
  const freq = new Map<number, number>();
  for (let i = 0; i < str.length; i++) {
    const c = str.charCodeAt(i);
    freq.set(c, (freq.get(c) ?? 0) + 1);
  }
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / str.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}
