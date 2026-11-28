/**
 * ADR-002 frozen corpus (#1065, Phase 0): the index.
 *
 * `EPIC_LINES` is the list of issue lines that were unchecked on the epic when
 * the corpus was frozen (12 Nov 2026). Every one of them must end up with at
 * least one named fixture. `FROZEN_CORPUS` is what has been authored so far.
 *
 * STATE AT THIS COMMIT: the Phase 1 line (#519), one Phase 3 line (#1005:
 * the reverse-shell shapes, the exfil labels and the memory-directive label,
 * with their controls) and the Phase 4 line (#556, one note) have fixtures.
 * The other Phase 2 and 3 fixtures are not in the tree yet; see
 * `docs/architecture/ADR-002-frozen-corpus.md` for why and for what each
 * missing line needs. The test holds that gap as a known-gap, so CI goes red
 * when the last line is covered and the marker has not been removed.
 * 3 of 20 epic lines have a fixture. #519's is a cost fixture, whose growth
 * measurement is an opt-in report; #1005's are verdict fixtures; #556's is a
 * note, never executed. The reverse-shell fixtures are `settled` since #1088
 * and the two credential-store exfil fixtures since #1104. #1005's epic line
 * stays unchecked: the credential-named-variable exfil fixture is still
 * `known-gap` (#1065 Phase 2), the memory-directive fixture is `known-gap`
 * on the Action Guard plane until the Guard change that screens memory writes
 * lands (the memory pipeline already quarantines it on MCP `remember`), its
 * other labels
 * have no fixture yet, and the Read-tool credential control is
 * `pending-decision`.
 */
import type { FrozenFixture } from './types.js';
import { PHASE1_FIXTURES } from './phase1.js';
import { PHASE3_FIXTURES } from './phase3.js';
import { PHASE4_FIXTURES } from './phase4.js';

export interface EpicLine {
  issue: number;
  phase: 1 | 2 | 3 | 4;
  /** The epic's own one-line description. */
  line: string;
}

export const EPIC_LINES: EpicLine[] = [
  { issue: 519, phase: 1, line: 'tokeniser cost grows with the square of token count' },
  { issue: 629, phase: 2, line: 'substring matching flags read-only commands and prose' },
  { issue: 927, phase: 2, line: 'quoted prose, lease script, config reads, loopback' },
  { issue: 512, phase: 2, line: 'false-positive batch from the 15 Sep test' },
  { issue: 551, phase: 2, line: 'comment marker visible to text rules after file substitution (also covers #549)' },
  { issue: 738, phase: 2, line: 'shell comment stripping applied inside interpreter heredoc bodies' },
  { issue: 958, phase: 2, line: 'test fixtures that name watched config keys' },
  { issue: 634, phase: 2, line: 'hook and interceptor disagree on the same call' },
  { issue: 874, phase: 2, line: 'remaining misread routine commands (closes on live-host note)' },
  { issue: 504, phase: 3, line: 'normalisation before block-list matching' },
  { issue: 703, phase: 3, line: 'inline program output routed into a shell' },
  { issue: 662, phase: 3, line: 'sends to a bare host carry no egress signal' },
  { issue: 995, phase: 3, line: 'home-wide search for secret material' },
  { issue: 755, phase: 3, line: 'write-content rows slow on long blank-line runs' },
  { issue: 929, phase: 3, line: 'over-cap identifier and grep-pattern relief' },
  { issue: 1049, phase: 3, line: 'issuer door follow-ups' },
  { issue: 588, phase: 3, line: 'startup-file writes inside written script content' },
  { issue: 1005, phase: 3, line: 'nightly red-team shapes: class each as guard-detectable, posture or out of scope' },
  { issue: 885, phase: 3, line: 'fixture note: no interpreter trust when the same command writes the interpreter path' },
  { issue: 556, phase: 4, line: 'ADR-002 tracker; closes with a one-page go-live decision for the owner' },
];

export const FROZEN_CORPUS: FrozenFixture[] = [
  ...PHASE1_FIXTURES,
  ...PHASE3_FIXTURES,
  ...PHASE4_FIXTURES,
];

export type { FrozenFixture } from './types.js';
