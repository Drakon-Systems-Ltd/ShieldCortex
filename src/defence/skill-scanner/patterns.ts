/**
 * Skill-Specific Threat Patterns
 *
 * Detects malicious patterns in agent instruction files (skill files, tool
 * definitions, .mdc rules, etc.) and in code files (JS/TS/JSON) that may
 * accompany them.
 *
 * Two entry points:
 *  - detectSkillThreats()  — natural-language instruction scanning
 *  - detectCodeThreats()   — JavaScript / JSON code scanning
 *
 * Follows the same conventions as instruction-detector.ts:
 *  - One match per group is enough (break after first)
 *  - Overlapping windowed scanning to bound per-regex work (ReDOS guard)
 *  - safeRegexTest wrapper for every test
 *  - Length caps on unbounded quantifiers ([\s\S]{0,N})
 */

import { someWindow } from '../scan-windows.js';

// ── Types ────────────────────────────────────────────────────────────────────

export interface SkillThreatResult {
  detected: boolean;
  threats: string[];    // matched group names
  confidence: number;   // 0–1
}

interface PatternGroup {
  name: string;
  patterns: RegExp[];
  weight: number;
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Safely test a regex against content.
 *
 * Scans the WHOLE input as overlapping windows (<= SCAN_WINDOW_SIZE chars each)
 * instead of truncating to the first 50KB, so a payload padded past the cap is
 * still tested. Each window bounds the per-regex work (ReDOS guard).
 */
function safeRegexTest(pattern: RegExp, text: string): boolean {
  return someWindow(text, (window) => pattern.test(window));
}

/**
 * Run a set of pattern groups against content and return a SkillThreatResult.
 *
 * Confidence = max matched group weight + 0.1 bonus per additional group,
 * capped at 1.0.
 */
function runPatternGroups(content: string, groups: PatternGroup[]): SkillThreatResult {
  const matchedThreats: string[] = [];
  let maxWeight = 0;

  for (const group of groups) {
    for (const pattern of group.patterns) {
      if (safeRegexTest(pattern, content)) {
        matchedThreats.push(group.name);
        if (group.weight > maxWeight) {
          maxWeight = group.weight;
        }
        break; // one match per group is enough
      }
    }
  }

  const groupBonus = Math.min((matchedThreats.length - 1) * 0.1, 0.3);
  const confidence =
    matchedThreats.length > 0 ? Math.min(maxWeight + groupBonus, 1.0) : 0;

  return {
    detected: matchedThreats.length > 0,
    threats: [...new Set(matchedThreats)],
    confidence: Math.round(confidence * 100) / 100,
  };
}

// ── Skill Instruction Patterns ───────────────────────────────────────────────

// Agent configuration files an instruction file may try to rewrite, and the
// verbs that make such a mention an instruction (shared by the one-line and
// the Markdown two-line rows of `agent_config_tamper`).
const AGENT_CONFIG_FILE =
  String.raw`(?:\.claude\/settings[\w.-]*\.json|\.claude\/hooks|\.codex\/config\.toml|\.cursor\/mcp\.json|\.gemini\/settings\.json|\.windsurf\/mcp[\w.-]*\.json|(?<![\w-])mcp\.json\b)`;
const CONFIG_WRITE_VERB =
  String.raw`\b(?:write|add|append|put|insert|create|edit|modify|update|change|set|merge|patch|overwrite|replace|configure|save|store)\b`;

const SKILL_PATTERN_GROUPS: PatternGroup[] = [
  // 1. Tool injection — instructions to run shell commands or write files
  {
    name: 'tool_injection',
    weight: 0.9,
    patterns: [
      /always run\s*:?\s*[`'"]/i,
      /execute\s+(this\s+)?(bash|shell|command|script)/i,
      /run\s+the\s+following\s+(command|script)/i,
      /write\s+(this|the\s+following)\s+to\s+\//i,
      /use\s+the\s+Bash\s+tool\s+to/i,
      /pipe[\s\S]{0,50}\|\s*(bash|sh|zsh)/i,
      // echo <data> > /abs/path  — a real file write to an absolute path.
      // Negative lookbehind (?<![\d&]) excludes fd/device redirects like
      // `2>/dev/null` or `&>/log`; (?!dev\/) excludes /dev/* device targets.
      // (issue #68: benign `echo ...; cmd 2>/dev/null` used to trip this at 0.9)
      /echo\s+[\s\S]{0,100}(?<![\d&])>\s*\/(?!dev\/)/i,
    ],
  },

  // 2. Scope escalation — access to files / data outside the project
  {
    name: 'scope_escalation',
    weight: 0.85,
    patterns: [
      /read\s+[\s\S]{0,50}~\/\.ssh/i,
      /read\s+[\s\S]{0,50}~\/\.aws/i,
      /read\s+[\s\S]{0,50}~\/\.env/i,
      /read\s+[\s\S]{0,50}\/etc\/(passwd|shadow|hosts)/i,
      /access\s+[\s\S]{0,50}environment\s+var/i,
      /process\.env\[/i,
      /cat\s+~\//i,
      /cat\s+\/etc\//i,
      /~\/\.gnupg/i,
      /~\/\.config\/(gcloud|gh|hub)/i,
      /read[\s\S]{0,50}(private\.key|id_rsa|id_ed25519)/i,
    ],
  },

  // 3. Data exfiltration — extract and send data externally
  {
    name: 'data_exfiltration',
    weight: 0.9,
    patterns: [
      /include\s+(the\s+)?(contents?|data|output|result)\s+(in|with)\s+(your\s+)?response/i,
      /send\s+(to|via)\s+https?:/i,
      /post\s+(to|data)[\s\S]{0,50}https?:/i,
      /curl\s+[\s\S]{0,100}-d\s+[\s\S]{0,100}https?:/i,
      /upload\s+[\s\S]{0,50}to\s+https?:/i,
      /webhook\s*[=:]\s*https?:/i,
      /fetch\s*\(\s*['"]https?:/i,
      /encode\s+[\s\S]{0,50}base64[\s\S]{0,50}send/i,
    ],
  },

  // 4. Persistence — modify agent configuration files
  {
    name: 'persistence',
    weight: 0.85,
    patterns: [
      /modify\s+[\s\S]{0,50}\.claude\/settings/i,
      /edit\s+[\s\S]{0,50}CLAUDE\.md/i,
      /write\s+[\s\S]{0,50}\.cursorrules/i,
      /write\s+[\s\S]{0,50}\.windsurfrules/i,
      /write\s+[\s\S]{0,50}\.clinerules/i,
      /modify\s+[\s\S]{0,50}\.claude\/commands/i,
      // add/install/register a hook — tight adjacency only. The old
      // /add[\s\S]{0,50}hook/ bridged up to 50 chars of unrelated markdown
      // (issue #121: cortex-memory's "…skills install shieldcortex ``` … "hooks"
      // config block" matched across a code fence → spurious `persistence`).
      // Require the hook to be the direct object of the verb, allowing only
      // short benign qualifiers (a / the / new / git / pre-commit / shell …).
      /\b(add|install|register)\s+(a\s+|an\s+|the\s+|new\s+|custom\s+|git\s+|pre-commit\s+|post-commit\s+|shell\s+)*hooks?\b/i,
      /modify\s+[\s\S]{0,50}\.claude\/plugins/i,
      /\bcrontab\b/i,
      /\blaunchd\b/i,
      /systemctl\s+enable/i,
      /write\s+[\s\S]{0,50}\.(bashrc|zshrc|profile)/i,
    ],
  },

  // 5. Supply chain — install packages or modify dependencies
  {
    name: 'supply_chain',
    weight: 0.8,
    patterns: [
      /npm\s+install\s+/i,
      /pip\s+install\s+/i,
      /add\s+[\s\S]{0,50}to\s+(package\.json|requirements\.txt|Gemfile|go\.mod)/i,
      /install\s+(this\s+)?package/i,
      /add\s+(this\s+)?dependency/i,
      /cargo\s+add\s+/i,
      /brew\s+install/i,
    ],
  },

  // 6. Agent manipulation — override agent safety or behaviour
  {
    name: 'agent_manipulation',
    weight: 0.9,
    patterns: [
      /ignore\s+(all\s+)?(safety|security|permission|restriction)/i,
      /bypass\s+(the\s+)?(sandbox|permission|safety|check)/i,
      /disable\s+(the\s+)?(firewall|security|protection|hook|guard)/i,
      /never\s+(ask|check|verify|confirm|prompt)\s+(for\s+)?permission/i,
      /auto-?approve\s+all/i,
      /skip\s+(verification|validation|check)/i,
      /override\s+(the\s+)?(safety|security)/i,
      /dangerouslyDisableSandbox/i,
      /--no-verify|--force|--yes/i,
    ],
  },

  // 7. Agent config tamper — instructions to redirect model/API traffic or
  //    rewrite the agent's own configuration. Every pattern needs an
  //    imperative verb, a literal assignment with a URL value, or a literal
  //    config block / dangerous setting, so a prose mention such as
  //    "ANTHROPIC_BASE_URL is supported for proxies" does not match. Every
  //    quantifier is length-capped; the only row that crosses a line break
  //    (verb line ending in a colon, path on one of the next three lines) is
  //    capped per line and never uses `^` with the `m` flag or a `\s*` run,
  //    which the 5.4.1 newline-run gate (newline-run-redos-541.test.ts)
  //    showed rescans a 100 KB blank run from every newline.
  {
    name: 'agent_config_tamper',
    weight: 0.9,
    patterns: [
      // Set/override an API endpoint or proxy variable (imperative verb on
      // the same line as the variable name).
      /\b(?:[Ss]et|[Ee]xport|[Oo]verride|[Cc]hange|[Pp]oint|[Rr]edirect|[Rr]oute|[Cc]onfigure|[Dd]efine|[Aa]dd)\b[^\n]{0,60}\b(?:[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*_(?:BASE_URL|API_BASE|API_BASE_URL)|AZURE_OPENAI_ENDPOINT)\b/,
      /\b(?:[Ss]et|[Ee]xport|[Oo]verride|[Cc]hange|[Pp]oint|[Rr]edirect|[Rr]oute|[Cc]onfigure|[Dd]efine|[Aa]dd)\b[^\n]{0,60}\b(?:HTTPS?_PROXY|ALL_PROXY|https?_proxy|all_proxy)\b/,
      // Literal assignment of an endpoint or proxy variable to a URL, in the
      // shapes an instruction file uses: `VAR=https://…`, `export VAR=…`,
      // `"VAR": "https://…"`, `VAR: https://…`, including the lowercase
      // proxy names. The value must carry a scheme, so a bare mention
      // ("HTTPS_PROXY is honoured") or a placeholder (`HTTPS_PROXY=<url>`)
      // does not match. Horizontal whitespace only around the separator.
      /(?<![\w.$-])["']?(?:[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*_(?:BASE_URL|API_BASE|API_BASE_URL)|AZURE_OPENAI_ENDPOINT|HTTPS?_PROXY|ALL_PROXY|https?_proxy|all_proxy)["']?[ \t]*[=:][ \t]*["']?(?:https?|socks[45]?h?):\/\//,
      // Write/modify an agent config file, verb and path on one line.
      new RegExp(`${CONFIG_WRITE_VERB}[^\\n]{0,80}${AGENT_CONFIG_FILE}`, 'i'),
      // The same instruction in ordinary Markdown: the verb line ends with a
      // colon and the path sits on one of the next three lines, on its own
      // (optionally as a list item, in backticks/bold, or inside a code fence
      // opened on the line between). At most two blank/fence lines may sit in
      // between and every line segment is capped, so this never bridges
      // unrelated paragraphs or a whole code block (#121).
      new RegExp(
        `${CONFIG_WRITE_VERB}[^\\n]{0,80}:(?:\\*{1,2}|_{1,2})?[ \\t]*\\r?\\n` +
          `(?:[ \\t]*\\r?\\n|[ \\t]*\`\`\`[^\\n]{0,20}\\r?\\n){0,2}` +
          `[ \\t]*(?:[-*+]|\\d+[.)])?[ \\t]*[\`"'*_]{0,2}[\\w~$./\\\\-]{0,60}?${AGENT_CONFIG_FILE}`,
        'i',
      ),
      /(?:>>?|\btee\b(?:\s+-a)?)\s*\S*(?:\.claude\/settings[\w.-]*\.json|\.codex\/config\.toml|\.cursor\/mcp\.json|\.gemini\/settings\.json)/i,
      // Add MCP servers or hooks.
      /\b(add|register|install|configure|append|insert|enable)\b[^\n]{0,40}\b(?:mcp\s+servers?|mcpServers|mcp_servers)\b/i,
      /\[mcp_servers\.[\w-]+\]/,
      /["']mcpServers["']\s*:\s*\{/,
      // A Claude-style hooks block keyed by event name (a bare "hooks": {…}
      // also appears in benign enable/disable docs, so require an event).
      /["']hooks["']\s*:\s*\{\s*["'](?:PreToolUse|PostToolUse|SessionStart|SessionEnd|UserPromptSubmit|Stop|SubagentStop|Notification|PreCompact)["']/,
      // Turn off sandbox / approval settings.
      /(?<!(?:never|not|avoid|n't|without)\s+(?:\w+\s+){0,2})--dangerously-(?:skip-permissions|bypass-approvals-and-sandbox)\b/i,
      /(?<!(?:never|not|avoid|n't|without)\s+(?:\w+\s+){0,2})\bapproval[_-]policy\s*[=:]\s*["']?never\b/i,
      /(?<!(?:never|not|avoid|n't|without)\s+(?:\w+\s+){0,2})\bsandbox[_-]mode\s*[=:]\s*["']?danger-full-access\b/i,
      /["']?defaultMode["']?\s*[=:]\s*["']?bypassPermissions\b/,
      /\bskipDangerousModePermissionPrompt\b|\benableAllProjectMcpServers\b/,
      /\b(?:turn|switch|set)\s+(?:off|the)\s+(?:the\s+)?(?:sandbox|approval)/i,
      /\bsandbox\s*[=:]\s*["']?(?:false|off|disabled)\b/i,
    ],
  },

  // 8. Stealth instruction — hidden instructions using formatting tricks
  {
    name: 'stealth_instruction',
    weight: 0.85,
    patterns: [
      // HTML comments containing actionable words (length-capped)
      /<!--[\s\S]{0,500}?(always|never|must|ignore|execute|run|send|read)[\s\S]{0,500}?-->/i,
      // Buried after excessive whitespace (length-capped). The newline run is
      // anchored at both ends so a long run is matched once, not retried at
      // every newline (catastrophic on large inputs). Same matches as before.
      /(?<!\n)\n{10,}(?!\n)[\s\S]{0,200}(always|never|must|ignore|execute|run|send|read)/i,
      // Content after --- end-of-document marker with actionable words
      /\n---\s*\n[\s\S]{0,500}?(always|never|must|ignore|execute|run|send|read)/i,
      // Unicode direction overrides in instruction context
      /[\u200E\u200F\u202A-\u202E\u2066-\u2069]/,
    ],
  },
];

// ── Code Threat Patterns (JS / JSON) ─────────────────────────────────────────

const CODE_PATTERN_GROUPS: PatternGroup[] = [
  // 1. Dangerous require / import
  {
    name: 'dangerous_require',
    weight: 0.9,
    patterns: [
      /require\s*\(\s*['"]child_process['"]\s*\)/,
      /require\s*\(\s*['"]net['"]\s*\)/,
      /require\s*\(\s*['"]http['"]\s*\)/,
      /require\s*\(\s*['"]https['"]\s*\)/,
      /require\s*\(\s*['"]dgram['"]\s*\)/,
      /import\s+.*from\s+['"]child_process['"]/,
    ],
  },

  // 2. Dangerous function calls
  {
    name: 'dangerous_calls',
    weight: 0.9,
    patterns: [
      /\beval\s*\(/,
      /\bFunction\s*\(/,
      /child_process\.(exec|spawn|execSync|fork)/,
      /\.exec\s*\(\s*[`'"]/,
      /process\.exit/,
    ],
  },

  // 3. Filesystem access to sensitive paths
  {
    name: 'filesystem_access',
    weight: 0.7,
    patterns: [
      /fs\.readFileSync\s*\(\s*['"][\s\S]{0,100}\.(env|key|pem|ssh)/,
      /readFile[\s\S]{0,50}\/etc\/(passwd|shadow)/,
      /writeFile[\s\S]{0,50}\.(bashrc|zshrc|profile|claude)/,
    ],
  },

  // 4. Network access
  {
    name: 'network_access',
    weight: 0.8,
    patterns: [
      /http\.request|https\.request/,
      /fetch\s*\(\s*['"]https?:/,
      /new\s+WebSocket/,
      /\.listen\s*\(\s*\d+\s*\)/,
    ],
  },
];

// ── Public API ───────────────────────────────────────────────────────────────

/**
 * Analyse natural-language skill / instruction content for threat patterns.
 *
 * Designed for scanning .mdc files, skill definitions, tool descriptions,
 * and similar agent instruction documents.
 */
export function detectSkillThreats(content: string): SkillThreatResult {
  return runPatternGroups(content, SKILL_PATTERN_GROUPS);
}

/**
 * Analyse JavaScript / JSON code content for threat patterns.
 *
 * Designed for scanning code files that accompany skill definitions —
 * tool implementations, config files, etc.
 */
export function detectCodeThreats(content: string): SkillThreatResult {
  return runPatternGroups(content, CODE_PATTERN_GROUPS);
}
