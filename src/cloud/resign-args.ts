/**
 * The argument grammar of `shieldcortex config --resign [--confirm <sha256>]`
 * (#647), on its own so the global help gate (src/cli/dispatch-help.ts) can ask
 * the same question as the handler without importing it.
 *
 * Accepted, exactly:
 *   --resign                          preview
 *   --resign --confirm <sha256>       confirmed re-sign
 *   --confirm <sha256> --resign       the same, in the other order
 *   any of the above plus ONE --help or -h, and nothing else: usage
 *
 * Everything else that LOOKS like a recovery request — `--resign` or
 * `--confirm` in any position, or a `--resign=…` / `--confirm=…` spelling — is
 * a recovery request that is rejected, as is a repeated flag (`--help` and
 * `-h` count as one flag). It must never fall through to the
 * ordinary setters, and a `--help` beside an unsupported token must not turn
 * the rejection into a usage print. Messages name flags, never values: a value
 * beside a flag can be a credential.
 */

export type ResignArgs =
  | { kind: 'not-resign' }
  | { kind: 'help' }
  | { kind: 'preview' }
  | { kind: 'confirm'; sha256: string }
  | { kind: 'reject'; message: string };

const isHelp = (a: string): boolean => a === '--help' || a === '-h';

/** True for any token that makes `config …` a recovery request. */
export function isResignToken(a: string): boolean {
  return a === '--resign' || a === '--confirm' || a.startsWith('--resign=') || a.startsWith('--confirm=');
}

export function isResignInvocation(args: readonly string[]): boolean {
  return args.some(isResignToken);
}

const reject = (detail: string): ResignArgs => ({
  kind: 'reject',
  message: `\`config --resign\` takes only \`--confirm <sha256>\`${detail}. Run setting changes as their own command. Nothing was written.`,
});

/** Flag NAME of a token (`--resign=x` → `--resign`), or null for a non-flag. */
function flagName(a: string): string | null {
  if (!a.startsWith('-')) return null;
  const eq = a.indexOf('=');
  return eq === -1 ? a : a.slice(0, eq);
}

export function parseResignArgs(args: readonly string[]): ResignArgs {
  if (!isResignInvocation(args)) return { kind: 'not-resign' };

  const spelled = args.filter((a) => a.startsWith('--resign=') || a.startsWith('--confirm='));
  if (spelled.length > 0) {
    const names = [...new Set(spelled.map((a) => `${flagName(a)}=…`))];
    return reject(`, as separate words — not ${names.join(', ')}`);
  }
  const resigns = args.filter((a) => a === '--resign').length;
  if (resigns === 0) {
    return { kind: 'reject', message: '`--confirm` is only for `shieldcortex config --resign --confirm <sha256>`. Nothing was written.' };
  }
  const confirms = args.reduce<number[]>((at, a, i) => (a === '--confirm' ? [...at, i] : at), []);
  if (resigns > 1 || confirms.length > 1) return reject(', once');
  // `--help` and `-h` are one option: a second occurrence, in any spelling, is
  // a repeated flag like any other.
  if (args.filter(isHelp).length > 1) {
    return { kind: 'reject', message: '`config --resign` takes `--help` / `-h` once. Nothing was written.' };
  }

  let value: string | undefined;
  if (confirms.length === 1) {
    value = args[confirms[0] + 1];
    if (value === undefined || value.startsWith('-')) {
      return {
        kind: 'reject',
        message: 'Missing value for --confirm. Run `shieldcortex config --resign` first and pass the full sha256 it prints. Nothing was written.',
      };
    }
  }

  const extra = args.filter((a, i) =>
    a !== '--resign' && a !== '--confirm' && !isHelp(a) && !(confirms.length === 1 && i === confirms[0] + 1));
  if (extra.length > 0) {
    const named = [...new Set(extra.map(flagName).filter((n): n is string => n !== null))];
    return reject(named.length > 0 ? `, not ${named.join(', ')}` : ', no other arguments');
  }

  if (args.some(isHelp)) return { kind: 'help' };
  return value === undefined ? { kind: 'preview' } : { kind: 'confirm', sha256: value };
}
