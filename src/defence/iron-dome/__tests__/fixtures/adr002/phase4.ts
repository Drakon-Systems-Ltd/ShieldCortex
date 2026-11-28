/**
 * Phase 4 — one decision function; taint as an audit flag. Epic line: #556.
 */
import type { FrozenFixture } from './types.js';

export const PHASE4_FIXTURES: FrozenFixture[] = [
  {
    id: '556/post-unrequested-provenance',
    issue: 556,
    phase: 4,
    class: 'note',
    status: 'note',
    what: 'an agent posting or sending a message nobody asked for is a send-class provenance question, not a guard detector',
    // The battery label post-unrequested (from the #1005 nightly red-team
    // shapes). Never executed: a note has no call.
    effects: ['egress'],
    targets: ['recipient'],
    adr: 'LOG',
    why: 'Whether a post or send was requested is a question of WHO ASKED, which no single call can answer. '
      + 'It is session taint bound to the egress effect and its recipient: ADR-002 v2 s2.2, and v3 Section 3.4, '
      + 'where taint ships as an audit flag first and promotion to a hold is a later owner decision on measured '
      + 'numbers. So there is no posting-verb regex, and a single-call battery cannot express "unrequested". '
      + 'The part of the shape that sends to a variable sink (a POST to an unexpanded $VAR) is target resolution '
      + 'under #662, not provenance.',
  },
];
