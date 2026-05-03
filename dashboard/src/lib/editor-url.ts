/**
 * Build a `vscode://file/...` URL that opens a file (and optional line) in
 * the user's editor. The vscode:// scheme is honoured by VSCode, Cursor, and
 * Windsurf — anything else falls through to the OS default handler.
 */
export function buildEditorUrl(file: string, line?: number): string {
  const trimmed = file.trim();
  if (!trimmed) return '';
  // Strip a leading file:// if present so the scheme prefix below is unique.
  const withoutScheme = trimmed.replace(/^file:\/+/, '');
  // Ensure a single leading slash so vscode:// can stitch it back together.
  const absolute = withoutScheme.startsWith('/') ? withoutScheme : `/${withoutScheme}`;
  const suffix = typeof line === 'number' && Number.isFinite(line) && line > 0 ? `:${line}` : '';
  return `vscode://file${absolute}${suffix}`;
}
