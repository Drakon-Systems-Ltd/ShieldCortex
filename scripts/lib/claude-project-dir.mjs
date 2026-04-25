/**
 * Encode a working directory the same way Claude Code does when picking
 * the `~/.claude/projects/<slug>/` folder for that session.
 *
 * Claude Code replaces BOTH `/` (and `\` on Windows) AND `.` with `-`,
 * with a leading `-` separator before the first path component.
 *
 * Earlier versions of pre-compact-hook only replaced slashes, so any
 * session under a dotfile-prefixed dir (e.g. `~/.openclaw/workspace`)
 * silently extracted zero memories: the lookup path
 * `-home-u-.openclaw-workspace` never matched the folder Claude Code
 * actually wrote (`-home-u--openclaw-workspace`).
 */
export function encodeClaudeProjectDir(cwd) {
  // Match Claude Code: replace `/`, `\`, `.`, and `:` with `-`. The `:`
  // matters on Windows so `C:\Users\u\.openclaw\workspace` becomes
  // `-C--Users-u--openclaw-workspace` (drive-letter colon → dash).
  const slug = String(cwd).replace(/[\\/.:]/g, '-');
  return slug.startsWith('-') ? slug : `-${slug}`;
}
