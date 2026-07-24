/**
 * Skill Scanner
 *
 * Framework-agnostic scanner for AI agent instruction files.
 * Detects prompt injection, data exfiltration, tool abuse, and other
 * threats hidden in skill definitions, hook files, and agent rules.
 *
 * Supports: Claude Code (SKILL.md, CLAUDE.md), OpenClaw (HOOK.md, handler.js),
 * Cursor (.cursorrules), Windsurf (.windsurfrules), Cline (.clinerules),
 * GitHub Copilot (copilot-instructions.md), Aider (.aider.conf.yml),
 * Continue (.continue/config.json).
 */

export { scanSkill, scanSkillContent } from './scan-skill.js';
export type {
  SkillScanResult,
  SkillScanOptions,
  SkillThreatFinding,
} from './scan-skill.js';

export { detectSkillThreats, detectCodeThreats } from './patterns.js';
export type { SkillThreatResult } from './patterns.js';

export { parseSkillFile, readSkillFile, detectFormat, detectFormatFromContent } from './parser.js';
export type { ParsedSkill, SkillFormat } from './parser.js';

export { discoverSkillFiles } from './discover.js';

export {
  applyDensityCap,
  hasHardSignal,
  isInstructionDensityFormat,
  HARD_SIGNAL_PATTERNS,
} from './scan-profile.js';

export {
  contentHash,
  loadVerdicts,
  getVerdict,
  recordVerdict,
  removeVerdict,
  getFileVerdict,
} from './verdict-store.js';
export type { ScanVerdict } from './verdict-store.js';

export {
  generateWarningsMarkdown,
  writeWarningsFile,
  WARNINGS_FILENAME,
} from './report.js';
export type { FlaggedSkill } from './report.js';
