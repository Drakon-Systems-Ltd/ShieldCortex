/**
 * Memory Save Filter — v4.0.0
 *
 * Prevents saving derivable information that can be found in
 * code, git history, or file system.
 */

export interface SaveFilterConfig {
  filterDerivable: boolean;
}

export const DEFAULT_SAVE_FILTER_CONFIG: SaveFilterConfig = {
  filterDerivable: true,
};

export interface SaveFilterResult {
  allowed: boolean;
  reason?: string;
  warning?: string;
}

// Patterns that suggest derivable content
const DERIVABLE_PATTERNS = [
  // File paths that can be found with grep/find
  { pattern: /^(?:the )?file (?:is )?(?:at |located at )?[\/~][\w\/.@-]+$/i, reason: 'File paths are discoverable via file system' },
  // Git commit references
  { pattern: /^(?:commit |git )(?:hash |sha )?[0-9a-f]{7,40}/i, reason: 'Git history is queryable with git log' },
  // Simple grep-able patterns
  { pattern: /^(?:the )?(?:function|class|method|variable|const|let|var) ['"`]?\w+['"`]? (?:is |exists )?(?:in|at) /i, reason: 'Code symbols are discoverable via grep/search' },
  // Package version info
  { pattern: /^(?:the )?(?:version|pkg) (?:of |is )?\w+(?:@| is )[\d.]+/i, reason: 'Package versions are in package.json/lock files' },
  // Environment variable values
  { pattern: /^(?:the )?(?:env(?:ironment)? )?(?:var(?:iable)? )?[A-Z_]{3,}(?:\s*=\s*|\s+is\s+)/i, reason: 'Environment variables should not be stored in memory (security risk)' },
];

// Content characteristics that suggest derivable info
const DERIVABLE_SIGNALS = [
  { test: (c: string) => /^(?:import|require|from)\s/m.test(c), reason: 'Import statements are visible in source code' },
  { test: (c: string) => c.split('\n').length <= 2 && /^\s*(?:cd |ls |cat |grep |find |git )\s/m.test(c), reason: 'Shell commands are not valuable to memorize' },
];

/**
 * Check whether a memory should be filtered (not saved).
 */
export function shouldFilterMemory(
  title: string,
  content: string,
  config: SaveFilterConfig = DEFAULT_SAVE_FILTER_CONFIG,
): SaveFilterResult {
  if (!config.filterDerivable) {
    return { allowed: true };
  }

  const combined = `${title}\n${content}`.trim();

  // Check against derivable patterns
  for (const { pattern, reason } of DERIVABLE_PATTERNS) {
    if (pattern.test(title) || pattern.test(content)) {
      return { allowed: false, reason };
    }
  }

  // Check content signals
  for (const { test, reason } of DERIVABLE_SIGNALS) {
    if (test(combined)) {
      return { allowed: false, reason, warning: `Filtered: ${reason}` };
    }
  }

  // Heuristic: very short content with file path patterns = likely derivable
  if (combined.length < 100) {
    const pathCount = (combined.match(/[\/~][\w\/.@-]{5,}/g) || []).length;
    if (pathCount > 0 && combined.replace(/[\/~][\w\/.@-]+/g, '').trim().length < 30) {
      return {
        allowed: false,
        reason: 'Content appears to be primarily file paths (discoverable via file system)',
        warning: 'Memory content is mostly file paths — these are discoverable without memory',
      };
    }
  }

  return { allowed: true };
}
