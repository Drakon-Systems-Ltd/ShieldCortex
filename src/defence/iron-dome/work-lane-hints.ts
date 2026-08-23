/**
 * Operator + agent UX: when a denial matches a known reviewed work pattern,
 * suggest the pinned lane instead of freehand retry thrash.
 *
 * Hints are advisory copy only — they do not approve anything.
 * Never invent an unreviewed host path: only suggest paths present in
 * reviewedScriptPaths (or omit the lane entirely).
 */

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
  return paths.find((p) => p.includes(frag));
}

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
