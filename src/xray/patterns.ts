/**
 * X-Ray Pattern Detection
 *
 * Comprehensive pattern groups for detecting hidden risk in packages, files,
 * and metadata. Follows the same conventions as skill-scanner/patterns.ts:
 *   - safeRegexTest wrapper for every test
 *   - MAX_SCAN_LENGTH truncation to prevent ReDOS
 *   - PatternGroup style with weighted confidence
 *   - One match per group is enough (break after first)
 */

import type { XRayCategory, XRayFinding } from './types.js';

// ── Types ───────────────────────────────────────────────────────────────────

interface PatternGroup {
  name: string;
  category: XRayCategory;
  severity: XRayFinding['severity'];
  patterns: RegExp[];
  title: string;
  description: string;
}

// ── Constants ───────────────────────────────────────────────────────────────

/** Maximum content length to analyse (prevents ReDOS on very long inputs). */
const MAX_SCAN_LENGTH = 50000;

// ── Helpers ─────────────────────────────────────────────────────────────────

/**
 * Safely test a regex against content with a length limit.
 */
function safeRegexTest(pattern: RegExp, text: string): boolean {
  const truncated = text.length > MAX_SCAN_LENGTH ? text.slice(0, MAX_SCAN_LENGTH) : text;
  return pattern.test(truncated);
}

// ── Pattern Groups ──────────────────────────────────────────────────────────

const XRAY_PATTERN_GROUPS: PatternGroup[] = [
  // 1. eval/exec with dynamic input
  {
    name: 'eval_exec',
    category: 'eval-exec',
    severity: 'critical',
    title: 'Dynamic code execution detected',
    description: 'Code uses eval(), new Function(), or vm.runIn* which can execute arbitrary code.',
    patterns: [
      /\beval\s*\(\s*[^)'"]/,
      /\beval\s*\(\s*['"`]\s*\+/,
      /\bnew\s+Function\s*\(/,
      /\bvm\.runIn(ThisContext|NewContext|Context)\s*\(/,
      /\bvm\.compileFunction\s*\(/,
      /\bvm\.Script\s*\(/,
    ],
  },

  // 2. Shell execution
  {
    name: 'shell_execution',
    category: 'shell-execution',
    severity: 'critical',
    title: 'Shell command execution detected',
    description: 'Code executes shell commands via child_process or similar APIs.',
    patterns: [
      /child_process\.(exec|execSync|spawn|spawnSync|fork)\s*\(/,
      /require\s*\(\s*['"]child_process['"]\s*\)/,
      /import\s+.*from\s+['"]child_process['"]/,
      /\bexecSync\s*\(\s*[`'"]/,
      /\bspawn\s*\([^)]*shell\s*:\s*true/,
      /\bexec\s*\(\s*['"`](?:bash|sh|cmd|powershell)/i,
    ],
  },

  // 3. Suspicious postinstall hooks
  {
    name: 'postinstall_hook',
    category: 'persistence-hook',
    severity: 'high',
    title: 'Suspicious lifecycle script detected',
    description: 'Package.json contains postinstall/preinstall/install scripts that may execute arbitrary code.',
    patterns: [
      /"(?:post|pre)?install"\s*:\s*"[^"]*(?:curl|wget|node\s+-e|bash|sh\s+-c|powershell)/i,
      /"(?:post|pre)?install"\s*:\s*"[^"]*(?:https?:\/\/|eval|exec)/i,
      /"(?:post|pre)?install"\s*:\s*"[^"]*\|\s*(?:bash|sh|node)/i,
    ],
  },

  // 4. Network beacons on import
  {
    name: 'network_beacon',
    category: 'network-beacon',
    severity: 'high',
    title: 'Network beacon on load detected',
    description: 'Code makes network requests at the top level (on import/require), potentially phoning home.',
    patterns: [
      /^(?:const|let|var|import)[\s\S]{0,200}(?:fetch|http\.get|https\.get|http\.request|https\.request)\s*\(/m,
      /^(?:const|let|var)[\s\S]{0,50}require\s*\(\s*['"](?:http|https|node-fetch|axios)['"]\s*\)[\s\S]{0,200}\.(?:get|post|request)\s*\(/m,
      /\bnew\s+WebSocket\s*\(\s*['"`]/,
      /\bdns\.(?:lookup|resolve|resolve4|resolve6)\s*\(/,
      /\bnet\.connect\s*\(/,
      /\bdgram\.createSocket\s*\(/,
    ],
  },

  // 5. Obfuscation techniques
  {
    name: 'obfuscation',
    category: 'obfuscation',
    severity: 'high',
    title: 'Code obfuscation detected',
    description: 'Code uses obfuscation techniques such as hex-encoded strings, fromCharCode arrays, or atob/btoa chains.',
    patterns: [
      // Hex-encoded strings > 50 chars
      /['"]\\x[0-9a-f]{2}(?:\\x[0-9a-f]{2}){24,}['"]/i,
      // Long hex literal strings
      /['"][0-9a-f]{50,}['"]/i,
      // atob/btoa chains
      /\batob\s*\(\s*(?:atob|btoa)\s*\(/,
      /\batob\s*\(\s*['"][A-Za-z0-9+/=]{20,}['"]\s*\)/,
      // String.fromCharCode arrays
      /String\.fromCharCode\s*\(\s*(?:\d+\s*,\s*){10,}/,
      // Buffer.from with hex/base64 for code execution
      /Buffer\.from\s*\(\s*['"][A-Za-z0-9+/=]{40,}['"]\s*,\s*['"](?:base64|hex)['"]\s*\)[\s\S]{0,50}\.toString\s*\(/,
      // _0x variable naming pattern (common obfuscator output)
      /\b_0x[0-9a-f]{4,}\b/i,
    ],
  },

  // 6. AI directive patterns (modelled on ST3GG INJECTION_TEMPLATES)
  {
    name: 'ai_directive',
    category: 'ai-directive',
    severity: 'critical',
    title: 'AI directive injection detected',
    description: 'Content contains patterns designed to manipulate AI model behaviour — prompt injection, jailbreak, or hidden instructions.',
    patterns: [
      // Direct AI instruction patterns
      /ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)/i,
      /disregard\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?)/i,
      /override\s+(previous|prior|all)\s+(instructions?|rules?|constraints?)/i,
      /you\s+are\s+now\s+(?:in\s+)?(?:developer|god|admin|root|unrestricted)\s+mode/i,
      /enter\s+(?:developer|god|admin|DAN|jailbreak)\s+mode/i,
      /(?:system|hidden|secret)\s*(?:prompt|instruction|directive)\s*:/i,
      // Instruction boundary attacks
      /\[SYSTEM\]\s*:/i,
      /\[INST\]/i,
      /<\|(?:system|user|assistant|im_start|im_end)\|>/i,
      // Encoded/hidden instruction markers
      /(?:decode|execute|follow)\s+(?:the\s+)?hidden\s+(?:instructions?|payload|message)/i,
      /(?:hidden|embedded|encoded)\s+(?:instructions?|directive|command)\s+(?:in|within|inside)/i,
      // LSB steganography references
      /(?:LSB|least\s+significant\s+bit)\s+(?:encoding|steganography|injection|extraction)/i,
      /extract\s+(?:the\s+)?(?:hidden|embedded)\s+(?:data|message|payload)\s+from\s+(?:the\s+)?image/i,
      // Filename-based directive patterns
      /ignore_previous/i,
      /decode_hidden/i,
      /execute_instructions/i,
      /override_previous/i,
      /developer_mode/i,
    ],
  },

  // 7. Unicode tricks
  {
    name: 'unicode_trick',
    category: 'unicode-trick',
    severity: 'medium',
    title: 'Suspicious Unicode characters detected',
    description: 'Content contains zero-width characters, homoglyphs, or bidirectional overrides that may hide malicious content.',
    patterns: [
      // Zero-width characters (multiple in sequence suggest intentional hiding)
      /[\u200b\u200c\u200d\ufeff\u2060]{2,}/,
      // RTL/LTR override characters
      /[\u202a-\u202e\u2066-\u2069]/,
      // Tag characters (U+E0001-U+E007F) — used for invisible text
      /[\u{E0001}-\u{E007F}]/u,
      // Combining characters abuse (>3 combining marks in a row)
      /[\u0300-\u036f]{4,}/,
    ],
  },

  // 8. Prompt injection in metadata
  {
    name: 'metadata_injection',
    category: 'metadata-exploit',
    severity: 'high',
    title: 'Prompt injection in metadata',
    description: 'Package metadata (description, keywords, author) contains AI instruction fragments designed to manipulate model behaviour.',
    patterns: [
      /"description"\s*:\s*"[^"]*(?:ignore\s+previous|you\s+are\s+now|system\s+prompt|execute\s+the\s+following|run\s+this\s+command)[^"]*"/i,
      /"keywords"\s*:\s*\[[^\]]*"(?:ignore|override|execute|system.?prompt|jailbreak|DAN)[^"]*"[^\]]*\]/i,
      /"author"\s*:\s*"[^"]*(?:ignore\s+previous|execute|system\s+prompt)[^"]*"/i,
    ],
  },

  // 9. Covert channels
  {
    name: 'covert_channel',
    category: 'covert-channel',
    severity: 'high',
    title: 'Potential covert communication channel',
    description: 'Code establishes hidden communication channels using DNS, WebSocket, or encoded data exfiltration.',
    patterns: [
      // DNS-based exfiltration
      /dns\.resolve[\s\S]{0,50}\.(?:concat|join)\s*\(/,
      /\.replace\s*\([^)]+\)[\s\S]{0,50}dns\.(?:lookup|resolve)/,
      // Steganographic data hiding
      /\.(?:getImageData|putImageData)\s*\([\s\S]{0,200}(?:charCodeAt|fromCharCode)/,
      // Data encoded in HTTP headers
      /headers\s*[\[.]\s*['"](?:X-|Cookie)[\s\S]{0,100}(?:encode|btoa|Buffer\.from)/i,
    ],
  },

  // 10. Dependency risk signals
  {
    name: 'dependency_risk',
    category: 'dependency-risk',
    severity: 'medium',
    title: 'Dependency risk indicator',
    description: 'Package exhibits characteristics associated with supply-chain attacks: wildcard versions, git dependencies, or excessive install scripts.',
    patterns: [
      // Wildcard or latest version
      /"dependencies"\s*:\s*\{[^}]*"[^"]+"\s*:\s*"(?:\*|latest|>=)"/,
      // Git URL dependencies
      /"dependencies"\s*:\s*\{[^}]*"[^"]+"\s*:\s*"(?:git\+|github:|https:\/\/github\.com)/,
      // Multiple lifecycle scripts
      /"(?:preinstall|postinstall|preuninstall|postuninstall)"\s*:\s*"[^"]+"/,
    ],
  },
];

// ── Public API ──────────────────────────────────────────────────────────────

/**
 * Run all X-Ray pattern groups against content and return matched findings.
 * Optionally tag findings with a file path and compute line numbers.
 */
export function detectPatterns(content: string, filePath?: string): XRayFinding[] {
  const findings: XRayFinding[] = [];
  const truncated = content.length > MAX_SCAN_LENGTH ? content.slice(0, MAX_SCAN_LENGTH) : content;

  for (const group of XRAY_PATTERN_GROUPS) {
    for (const pattern of group.patterns) {
      if (safeRegexTest(pattern, truncated)) {
        const match = pattern.exec(truncated);
        let line: number | undefined;
        let evidence: string | undefined;

        if (match) {
          // Calculate line number from match index
          const before = truncated.slice(0, match.index);
          line = (before.match(/\n/g) || []).length + 1;
          evidence = match[0].slice(0, 120);
        }

        findings.push({
          severity: group.severity,
          category: group.category,
          title: group.title,
          description: group.description,
          file: filePath,
          line,
          evidence,
        });
        break; // one match per group is enough
      }
    }
  }

  return findings;
}

/**
 * Check if a filename itself contains AI directive patterns.
 */
export function detectFilenameDirectives(filename: string): XRayFinding[] {
  const findings: XRayFinding[] = [];
  const suspiciousPatterns = [
    /ignore_previous/i,
    /decode_hidden/i,
    /execute_instructions/i,
    /override_previous/i,
    /developer_mode/i,
    /system_prompt/i,
    /jailbreak/i,
    /\[SYSTEM\]/i,
    /\[INST\]/i,
  ];

  for (const pattern of suspiciousPatterns) {
    if (pattern.test(filename)) {
      findings.push({
        severity: 'critical',
        category: 'ai-directive',
        title: 'AI directive in filename',
        description: `Filename "${filename}" contains an AI directive pattern designed to manipulate model behaviour.`,
        file: filename,
        evidence: filename,
      });
      break; // one finding per filename is enough
    }
  }

  return findings;
}
