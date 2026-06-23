/**
 * CIC command-line parser.
 *
 * Tokenises a command string into `{ name, args, flags }`, honouring double-quoted
 * phrases (so `recall "auth bug fix"` is one arg) and `--key value` / `--bool`
 * flags. The command name is lowercased; arg/flag-value case is preserved.
 */
export interface ParsedCommand {
  name: string;
  args: string[];
  flags: Record<string, string | true>;
}

/** Split into tokens, keeping double-quoted spans as single tokens (quotes stripped). */
function tokenise(input: string): string[] {
  const tokens: string[] = [];
  const re = /"([^"]*)"|(\S+)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(input)) !== null) {
    tokens.push(m[1] !== undefined ? m[1] : m[2]);
  }
  return tokens;
}

export function parseCommand(input: string): ParsedCommand | null {
  const trimmed = input.trim();
  if (!trimmed) return null;

  const tokens = tokenise(trimmed);
  const name = tokens[0].toLowerCase();
  const args: string[] = [];
  const flags: Record<string, string | true> = {};

  for (let i = 1; i < tokens.length; i += 1) {
    const tok = tokens[i];
    if (tok.startsWith('--')) {
      const key = tok.slice(2);
      const next = tokens[i + 1];
      if (next !== undefined && !next.startsWith('--')) {
        flags[key] = next;
        i += 1;
      } else {
        flags[key] = true;
      }
    } else {
      args.push(tok);
    }
  }

  return { name, args, flags };
}
