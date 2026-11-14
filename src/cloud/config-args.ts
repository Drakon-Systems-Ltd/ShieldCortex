/**
 * Unknown-option check for `shieldcortex config` (#1038).
 *
 * A typo such as `--action-guard-enabled` used to match nothing, print the
 * full help wall and exit 0. The operator reasonably concluded the command
 * had run. This check runs before any read or write. It names flags only:
 * a value after `=` can be a credential and is never echoed.
 */

/** Next token is the value even when it looks like a flag (`--mode --help`). */
export const CONFIG_VALUE_FLAGS_ALWAYS = [
  '--mode',
  '--cloud-api-key',
  '--cloud-url',
  '--verify-mode',
  '--verify-timeout',
  '--openclaw-auto-memory',
  '--ranker',
  '--proactive-recall',
  '--self-heal',
  '--dashboard-update-check',
] as const;

/** Next token is the value only when it does not start with `--`. */
export const CONFIG_VALUE_FLAGS_UNLESS_DASH = [
  '--action-guard-notify-webhook',
  '--memory-inject-contract',
  '--memory-plane',
  '--memory-host-posture',
  '--memory-host-runtime',
  '--auto-memory-sampling',
] as const;

export const CONFIG_BOOLEAN_FLAGS = [
  '--cloud-status',
  '--cloud-enable',
  '--cloud-disable',
  '--cloud-include-sensitive',
  '--cloud-exclude-sensitive',
  '--verify-enable',
  '--verify-disable',
  '--restore-4.10-defaults',
  '--tool-firewall-enforce',
  '--tool-firewall-advisory',
  '--tool-firewall-off',
  '--tool-firewall-on',
  '--policy-status',
  '--action-guard-enable',
  '--action-guard-disable',
  '--action-guard-enforce',
  '--action-guard-enforce-when-ready',
  '--action-guard-advisory',
  '--action-guard-notify-openclaw',
  '--action-guard-notify-disable',
  '--allow-revoke-by-source',
  '--disallow-revoke-by-source',
  '--upsell-mute',
  '--upsell-unmute',
] as const;

const VALUE_ALWAYS = new Set<string>(CONFIG_VALUE_FLAGS_ALWAYS);
const VALUE_UNLESS_DASH = new Set<string>(CONFIG_VALUE_FLAGS_UNLESS_DASH);
const BOOLEANS = new Set<string>(CONFIG_BOOLEAN_FLAGS);
const HELP = new Set(['--help', '-h']);

export const CONFIG_KNOWN_OPTIONS: readonly string[] = [
  ...CONFIG_BOOLEAN_FLAGS,
  ...CONFIG_VALUE_FLAGS_ALWAYS,
  ...CONFIG_VALUE_FLAGS_UNLESS_DASH,
];

/** Flag name of a token. `--mode=strict` → `--mode`. Never returns the value. */
export function configOptionName(token: string): string {
  const eq = token.indexOf('=');
  return eq === -1 ? token : token.slice(0, eq);
}

function editDistance(a: string, b: string): number {
  if (Math.abs(a.length - b.length) > 2) return 3;
  const rows = Array.from({ length: a.length + 1 }, () => new Array<number>(b.length + 1));
  for (let i = 0; i <= a.length; i++) rows[i][0] = i;
  for (let j = 0; j <= b.length; j++) rows[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      rows[i][j] = Math.min(rows[i - 1][j] + 1, rows[i][j - 1] + 1, rows[i - 1][j - 1] + cost);
    }
  }
  return rows[a.length][b.length];
}

/** Unique nearest known flag within two edits, or null. Never guesses on a tie. */
export function suggestConfigOption(name: string, known: readonly string[] = CONFIG_KNOWN_OPTIONS): string | null {
  let best: string | null = null;
  let bestD = 3;
  let ties = 0;
  for (const flag of known) {
    if (flag === name) continue;
    const d = editDistance(name, flag);
    if (d <= 2 && d < bestD) {
      best = flag;
      bestD = d;
      ties = 1;
    } else if (d === bestD && d <= 2) {
      ties++;
    }
  }
  return ties === 1 ? best : null;
}

function shownOption(token: string): string {
  const eq = token.indexOf('=');
  return eq === -1 ? token : `${token.slice(0, eq)}=…`;
}

export function unknownConfigOptionLine(token: string, known: readonly string[] = CONFIG_KNOWN_OPTIONS): string {
  const name = configOptionName(token);
  const suggestion = suggestConfigOption(name, known);
  const did = suggestion ? ` Did you mean ${suggestion}?` : '';
  const equalsHint = token.includes('=') && known.includes(name)
    ? ' Pass the value as a separate word.'
    : '';
  return `Unknown option "${shownOption(token)}".${did}${equalsHint}`;
}

/**
 * Tokens that are not a known option and not a value consumed by one.
 * Help flags and a bare invocation are not unknown. Equals spellings are
 * unknown: the handler only accepts a separate word.
 */
export function unknownConfigOptions(args: readonly string[]): string[] {
  const unknown: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const token = args[i];
    const name = configOptionName(token);
    if (VALUE_ALWAYS.has(name) && !token.includes('=')) {
      if (i + 1 < args.length) i++;
      continue;
    }
    if (VALUE_UNLESS_DASH.has(name) && !token.includes('=')) {
      const next = args[i + 1];
      if (next && !next.startsWith('--')) i++;
      continue;
    }
    if (BOOLEANS.has(token) || HELP.has(token)) continue;
    if (token.startsWith('-')) unknown.push(token);
  }
  return unknown;
}

/** Lines for stderr, or null when the handler may proceed. */
export function formatUnknownConfigOptions(args: readonly string[]): string[] | null {
  const unknown = unknownConfigOptions(args);
  if (unknown.length === 0) return null;
  const line = unknown.length === 1
    ? unknownConfigOptionLine(unknown[0])
    : `Unknown options: ${unknown.map(shownOption).join(', ')}.`;
  return [line, 'See `shieldcortex config --help`.'];
}
