/**
 * Operator + agent UX: when a denial matches a known reviewed work pattern,
 * suggest the pinned lane instead of freehand retry thrash.
 *
 * Hints are advisory copy only — they do not approve anything.
 * Never invent an unreviewed host path: only suggest paths present in
 * reviewedScriptPaths (or omit the lane entirely).
 */

/** Lane ids shipped in work-lane pack v1 (#401) — the denial→door matrix
 *  test asserts each has a working hint path. */
export const WORK_LANE_PACK_V1 = ['vita-ci', 'jotform', 'lan-diag'] as const;

export interface WorkLaneHintInput {
  signals?: string[];
  cwd?: string | null;
  tool?: string | null;
  /** Absolute paths of reviewed/pinned scripts on this host (optional). */
  reviewedScriptPaths?: string[];
}

export interface WorkLaneHint {
  /** One-line command the agent/operator should run instead. */
  command: string;
  /** Short why (no raw secrets, no full command that was blocked). */
  reason: string;
}

function norm(s: unknown): string {
  return String(s ?? '').trim().toLowerCase();
}

function findPin(paths: string[], frag: string): string | undefined {
  return paths.find((p) => {
    // Exact basename match ("lan-diag.sh") or a full directory segment
    // ("/lan-diag/"). Substring inclusion would let "not-lan-diag.sh.backup"
    // masquerade as the lane (SOL review).
    const norm = p.replace(/\\/g, '/');
    if (frag.startsWith('/') && frag.endsWith('/')) {
      return norm.includes(frag);
    }
    const base = norm.slice(norm.lastIndexOf('/') + 1);
    return base === frag;
  });
}

/** cwd tokens that read as LAN/connectivity work (lowercased input).
 *  Bounded so `plan` / `finland` / `planner` do not match `lan`. */
const LAN_DIAG_CWD_WORDS = ['lan', 'diag', 'diagnostics', 'network', 'connectivity', 'wifi'];

function cwdHasWord(cwd: string, word: string): boolean {
  return new RegExp(`(^|[^a-z0-9])${word}([^a-z0-9]|$)`).test(cwd);
}

/** Network diagnostic programs whose denial should point at the lane. */
const LAN_DIAG_TOOLS = new Set([
  'ping', 'traceroute', 'tracepath', 'mtr', 'ip', 'ss', 'dig', 'nslookup',
  'nmcli', 'iw', 'iwconfig', 'arp',
]);

/**
 * Suggest a reviewed work lane for a denial, or null if unknown.
 * Requires an actual pin path — no hardcoded host fallbacks.
 */
export function suggestWorkLane(input: WorkLaneHintInput): WorkLaneHint | null {
  const cwd = norm(input.cwd);
  const signals = (input.signals ?? []).map(norm);
  const paths = (input.reviewedScriptPaths ?? []).map(String).filter(Boolean);

  // Only exact external-egress (not secret-egress / other *egress* substrings)
  const hasExternalEgress = signals.includes('external-egress');
  if (!hasExternalEgress || paths.length === 0) return null;

  // Vita website CI / ship — cwd must look like vita work AND pin must exist
  const vitaPin = findPin(paths, 'vita-site/gh-ci.sh') ?? findPin(paths, 'gh-ci.sh');
  if (
    vitaPin
    && (cwd.includes('vita') || cwd.includes('vitaetpax') || cwd.includes('vita-mobile'))
  ) {
    return {
      command: `${vitaPin} status staging`,
      reason: 'Vita site CI — use the pinned ship script, not freehand gh/curl',
    };
  }

  // Jotform toolkit — pin required
  if (cwd.includes('jotform') || signals.some((s) => s.includes('jotform'))) {
    const pin = findPin(paths, 'jotform.py')
      ?? findPin(paths, 'jotform_builder.py')
      ?? findPin(paths, 'club_form_payment_upgrade.py');
    if (pin) {
      return {
        command: `python3 ${pin} --help`,
        reason: 'Jotform — use the pinned toolkit path, not freehand API/curl',
      };
    }
  }

  // LAN diagnostics (#401 — the Edith gap). Checked AFTER vita/jotform so it
  // never steals their lanes. Pin required, plus a lan-shaped cwd or a network
  // tool name — external-egress alone must not fire this on unrelated work.
  const lanPin = findPin(paths, 'lan-diag.sh') ?? findPin(paths, '/lan-diag/');
  if (lanPin) {
    const cwdLooksLan = LAN_DIAG_CWD_WORDS.some((w) => cwdHasWord(cwd, w));
    const toolIsLan = LAN_DIAG_TOOLS.has(norm(input.tool));
    if (cwdLooksLan || toolIsLan) {
      return {
        command: `${lanPin} status`,
        reason: 'LAN diagnostics — use the pinned script, not freehand curl/nmap',
      };
    }
  }

  return null;
}

/** Compact lines for digest / card footers. */
export function formatWorkLaneHintLines(hint: WorkLaneHint | null): string[] {
  if (!hint) return [];
  return [
    `Lane:  ${hint.command}`,
    `       ${hint.reason}`,
  ];
}
