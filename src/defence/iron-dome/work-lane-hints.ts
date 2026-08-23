/**
 * Operator + agent UX: when a denial matches a known reviewed work pattern,
 * suggest the pinned lane instead of freehand retry thrash.
 *
 * Hints are advisory copy only — they do not approve anything.
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

/**
 * Suggest a reviewed work lane for a denial, or null if unknown.
 */
export function suggestWorkLane(input: WorkLaneHintInput): WorkLaneHint | null {
  const cwd = norm(input.cwd);
  const signals = (input.signals ?? []).map(norm);
  const paths = (input.reviewedScriptPaths ?? []).map(String);
  const hasEgress = signals.some((s) =>
    s.includes('external-egress') || s.includes('network') || s.includes('egress'),
  );
  const hasJotform = signals.some((s) => s.includes('jotform'))
    || cwd.includes('jotform');

  const findPin = (frag: string): string | undefined =>
    paths.find((p) => p.includes(frag));

  // Vita website CI / ship
  if (
    hasEgress
    && (cwd.includes('vita') || cwd.includes('vitaetpax') || cwd.includes('vita-mobile')
      || findPin('vita-site/gh-ci.sh'))
  ) {
    const pin = findPin('vita-site/gh-ci.sh') ?? '/home/edith/scripts/vita-site/gh-ci.sh';
    return {
      command: `${pin} status staging`,
      reason: 'Vita site CI — use the pinned ship script, not freehand gh/curl',
    };
  }

  // Jotform toolkit
  if (hasJotform || (hasEgress && cwd.includes('jotform'))) {
    const pin = findPin('jotform.py')
      ?? findPin('jotform_builder.py')
      ?? findPin('club_form_payment_upgrade.py');
    if (pin) {
      return {
        command: `python3 ${pin} --help`,
        reason: 'Jotform — use the pinned toolkit path, not freehand API/curl',
      };
    }
  }

  // Generic: pinned gh-ci exists and egress denied from a workspace
  if (hasEgress) {
    const pin = findPin('vita-site/gh-ci.sh') ?? findPin('gh-ci.sh');
    if (pin && (cwd.includes('workspace') || cwd.includes('openclaw') || cwd.includes('.git'))) {
      return {
        command: `${pin} status staging`,
        reason: 'Network was held — if this is site CI, use the pinned gh-ci lane',
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
