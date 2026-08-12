import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from '@jest/globals';

/**
 * #221 — a SOURCE-level rail, because the runtime gate can only act on results
 * that were tagged, and the tagging is the part a future edit will forget.
 *
 * The behavioural tests in doctor-openclaw-cli-gate.test.ts prove the gate
 * withdraws a tagged remedy. Nothing there notices when someone adds a
 * seventeenth `fix: 'Run \`openclaw plugins …\`'` without the tag — the gate
 * would silently sail past it and the operator would be back to following a
 * command that cannot run. That is the same shape as the defect this issue
 * reports, so it is worth a rail of its own.
 *
 * Deliberately NOT matched: a bare `shieldcortex repair`. It appears on both
 * sides of the line — blocked when it routes to `plugins install --force`, and
 * genuinely working when it routes to restore-registration (a pure JSON write,
 * and the only remedy for an UNPROTECTED host). No text test can separate
 * those, which is exactly why the tag is declared per site.
 */

const DOCTOR = resolve(dirname(fileURLToPath(import.meta.url)), '..', 'cli', 'doctor.ts');

/** Commands OpenClaw refuses outright while its config is invalid. */
const BLOCKED_COMMAND =
  /(openclaw plugins |openclaw skills |openclaw config patch|shieldcortex openclaw (skill install|repair|install))/;

/** How far after a remediation line the tag may sit before we call it absent. */
const TAG_WINDOW = 14;

describe('#221 — every blocked remediation in doctor.ts carries the tag', () => {
  it('finds no untagged remediation that needs an OpenClaw subcommand', () => {
    const lines = readFileSync(DOCTOR, 'utf-8').split('\n');
    const untagged: string[] = [];

    lines.forEach((line, i) => {
      const trimmed = line.trim();
      // Remediation only: a `fix:` value, or the one site that carries its
      // advice in `message:`. Comments and prose are not instructions.
      if (trimmed.startsWith('*') || trimmed.startsWith('//')) return;
      if (!/^(fix:|message:)/.test(trimmed) && !/^\s*fix:/.test(line)) return;
      if (!BLOCKED_COMMAND.test(line)) return;

      const window = lines.slice(i, i + TAG_WINDOW).join('\n');
      // Stop at the end of this result object so a NEIGHBOUR's tag cannot
      // vouch for an untagged site.
      const objectEnd = window.indexOf('\n      };');
      const scope = objectEnd === -1 ? window : window.slice(0, objectEnd);
      if (!scope.includes('needsOpenClawCli')) {
        untagged.push(`doctor.ts:${i + 1}  ${trimmed.slice(0, 110)}`);
      }
    });

    expect(untagged).toEqual([]);
  });

  it('the tag is only ever spelled in ways the gate understands', () => {
    const source = readFileSync(DOCTOR, 'utf-8');
    const tags = source.match(/needsOpenClawCli: \{[^}]*\}/g) ?? [];

    expect(tags.length).toBeGreaterThanOrEqual(18);
    for (const tag of tags) {
      expect(tag).toMatch(/subcommand: '(plugins|skills|config)'/);
    }
  });
});
