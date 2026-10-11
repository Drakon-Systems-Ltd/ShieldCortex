/**
 * #729 (follow-up to #722): the README said private-life notes (PERSONAL)
 * "never reach" cron jobs, subagents and liveness probes. Lanes only scope
 * prompt-time recall in the UserPromptSubmit hook, for turns it detects from a
 * marker or a valid pin, and the stored label decides: a private note the
 * classifier missed and labelled PUBLIC is not withheld. SessionStart, MCP
 * tool reads and dashboard previews are not lane-scoped. These strings are the contract; text only,
 * nothing here runs a hook or reads config.
 */
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

function read(rel: string): string {
  return fs.readFileSync(path.join(ROOT, rel), 'utf8');
}

/** Text from `start` up to (not including) `end`. */
function between(src: string, start: string, end: string): string {
  const a = src.indexOf(start);
  expect(a).toBeGreaterThan(-1);
  const b = src.indexOf(end, a + start.length);
  expect(b).toBeGreaterThan(a);
  return src.slice(a, b);
}

describe('recall lane docs — bounded claims (#729)', () => {
  it('README no longer claims PERSONAL notes never reach automated lanes', () => {
    const readme = read('README.md');
    expect(readme).not.toMatch(/never reach them/);
    const line = readme.split('\n').find((l) => l.includes('docs/UPDATING.md#recall-lanes'));
    expect(line).toBeDefined();
    expect(line).toContain('`UserPromptSubmit` hook');
    expect(line).toMatch(/detected as a cron job, subagent or liveness probe, or pinned/);
    expect(line).toContain('rows labelled PERSONAL');
    expect(line).toContain('not universal isolation');
    expect(line).toMatch(/labelled `PUBLIC` can still reach/);
    expect(line).toMatch(/SessionStart context, MCP tool reads and dashboard previews are not lane-scoped/);
  });

  it('UPDATING recall-lanes guide carries the SessionStart / MCP / dashboard exclusions', () => {
    const guide = read('docs/UPDATING.md');
    const section = between(guide, '### Recall lanes and the PERSONAL tier', '#### Backfilling labels');
    expect(section).toContain('**What lanes do not cover.**');
    expect(section).toMatch(/only to prompt-time recall in the `UserPromptSubmit` hook/);
    expect(section).toMatch(/an unmarked, unpinned turn from another scheduler is `interactive`/);
    expect(section).toMatch(/labelled `PUBLIC` can still reach a non-interactive lane/);
    expect(section).toMatch(/SessionStart context, MCP tool reads .* and dashboard previews are not lane-scoped/);
  });

  it('UPDATING keeps the existing defaults, pin and PUBLIC-only rules', () => {
    const section = between(read('docs/UPDATING.md'), '### Recall lanes and the PERSONAL tier', '#### Backfilling labels');
    expect(section).toContain('| `interactive` | everything (unchanged) |');
    expect(section).toContain('| `automation` | none |');
    expect(section).toContain('a lane other than `interactive` only ever receives rows labelled `PUBLIC`');
    expect(section).toContain('SHIELDCORTEX_RECALL_LANE=cron');
    expect(section).toContain('(no recall unless you opted `automation` in, and then PUBLIC rows only)');
  });
});
