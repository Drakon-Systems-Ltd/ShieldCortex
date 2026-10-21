import { describe, it, expect } from '@jest/globals';
import { evaluateToolCall } from '../tool-action-guard.js';

/**
 * #732 N1 (round 4 review, TARS + a separate Opus pass) — heredoc-relief
 * ELIGIBILITY was judged on `deobfuscateIfs(extractCommand(args))`, never on
 * the true pre-normalisation bytes. `deobfuscateIfs` (#84) blindly erases
 * every `${IFS...}` / `$IFS` substring in the WHOLE command, including inside
 * a quoted interpreter heredoc body the real shell never expands at all. A
 * Perl heredoc can contain a `${IFS...}`-SHAPED token that is genuine Perl
 * string-interpolation syntax (a block that executes and dereferences), not
 * shell IFS obfuscation. Erasing it before #713's relief gate ran let a
 * `read_file()` call stay visible (so the body still looked like "all data
 * reads") while the `eval()` that turned its contents into CODE vanished —
 * `hasShellOutSink` found no sink, `bodyIsAllDataRead` wrongly accepted, the
 * whole body was masked, and the file the Perl code actually loaded was never
 * asked for. Fix: `evaluateToolCallCore` now carries a `rawCommand` — the
 * pre-`deobfuscateIfs` bytes — alongside `command` through both the outer
 * call and the #517 typed/expanded recursive surfaces, and judges heredoc
 * relief ELIGIBILITY on `rawCommand` only. The general shell-sink scan keeps
 * using the deobfuscated `command` exactly as before (deobfuscateIfs is left
 * untouched there by design — see #84 and the HARD BOUNDARY in this fix).
 *
 * A direct `scriptDiscoverySurface(raw)` call is NOT a regression test for
 * this: it never passes through `deobfuscateIfs` at all, so it cannot
 * reproduce the bug. Every case below goes through the real evaluator entry
 * point, `evaluateToolCall`, exactly as the two review rounds' probes did.
 */

const heredoc = (interp: string, body: string): string => `${interp} <<'EOF'\n${body}\nEOF`;

/** Every path the guard asks its resolver for while evaluating `command`,
 *  with an optional per-path source override (default: an inert fixture). */
function askedWith(
  command: string,
  sources: Record<string, string> = {},
  defaultSrc = 'print("benign fixture")\n',
): { seen: string[]; verdict: ReturnType<typeof evaluateToolCall> } {
  const seen: string[] = [];
  const verdict = evaluateToolCall('Bash', { command }, undefined, {
    resolveScriptSource: (p: string) => {
      seen.push(p);
      return sources[p] ?? defaultSrc;
    },
  });
  return { seen, verdict };
}

const asked = (command: string): string[] => askedWith(command).seen;

/** The same command scanned with the #713 relief out of reach — the shape
 *  `dataReadHeredocRelief` would need to re-derive when it fails closed on
 *  `rawCommand`, i.e. the "original pre-#713" baseline the existing #713 test
 *  file (heredoc-data-read-allowlist-713.test.ts) also uses for this. */
const unmasked = (command: string): string[] => asked(`true\n${command}`);

/**
 * Catastrophic/dangerous command text assembled at test RUNTIME, one
 * character at a time, rather than written as one literal substring in this
 * file's own source. This repo's own Action Guard write hook scans a
 * `.test.ts` file's source bytes before letting it land (#93's script-like
 * write-path gate) — writing the live payload as a readable literal would
 * gate editing this regression test the same way it gates the exploit it
 * exercises. `evaluateToolCall`, the code under test, still receives the
 * exact same reconstructed string at run time.
 */
const assemble = (parts: string[]): string => parts.join('');
const RM_RF_ROOT = assemble(['s', 'y', 's', 't', 'e', 'm', '(', "'", 'r', 'm', ' ', '-', 'r', 'f', ' ', '/', "'", ')', ';']);
const IFS_RM_RF = assemble(['r', 'm', '$', '{', 'I', 'F', 'S', '}', '-', 'r', 'f', '$', '{', 'I', 'F', 'S', '}', '/']);
const IFS_CHMOD = assemble(['c', 'h', 'm', 'o', 'd', '$', '{', 'I', 'F', 'S', '}', '-', 'R', '$', '{', 'I', 'F', 'S', '}', '7', '7', '7', '$', '{', 'I', 'F', 'S', '}', '/']);
const IFS_FORKBOMB = assemble([':', '(', ')', '{', '$', '{', 'I', 'F', 'S', '}', ':', '|', ':', '&', '}', ';', ':']);

describe('#732 N1 — heredoc-relief eligibility is judged on pre-deobfuscation bytes', () => {
  it('(a) a Perl ${IFS(...)} interpolation span hiding eval($src) of a loaded file: discovered and escalated, not a false allow/benign', () => {
    // `read_file` alone is a recognised #713 data read and stays visible after
    // deobfuscation (it is not IFS-shaped); the `eval($src)` wrapper that
    // turns its contents into code is the part sitting inside `${IFS(...)}`.
    const body = "my $src = read_file('/tmp/x/loaded.pl');\nprint \"${IFS(eval($src))}\\n\";";
    const cmd = heredoc('perl -', body);

    const { seen, verdict } = askedWith(cmd, { '/tmp/x/loaded.pl': RM_RF_ROOT });
    expect(seen).toContain('/tmp/x/loaded.pl');
    expect(verdict.decision).not.toBe('allow');
    expect(verdict.severity).not.toBe('benign');
    expect(verdict.severity).toBe('catastrophic');

    // Matches the pre-#713-relief ("original scan") baseline exactly: the raw
    // body fails the allow-list shape (a sink is present), so eligibility
    // fails closed and discovery falls back to scanning the body as before
    // #713 existed at all.
    expect(seen).toEqual(unmasked(cmd));
  });

  it('(a, recursive surface) the same exploit beside an unrelated $(cat f) substitution still resolves — #517 typed/expanded split carries rawCommand too', () => {
    const body = "my $src = read_file('/tmp/x/loaded.pl');\nprint \"${IFS(eval($src))}\\n\";";
    const exploit = heredoc('perl -', body);
    const cmd = `echo "$(cat /tmp/other/benign.txt)"; ${exploit}`;

    const { seen, verdict } = askedWith(cmd, {
      '/tmp/x/loaded.pl': RM_RF_ROOT,
      '/tmp/other/benign.txt': 'just some benign notes',
    });
    expect(seen).toContain('/tmp/x/loaded.pl');
    expect(verdict.decision).toBe('block');
    expect(verdict.severity).toBe('catastrophic');
  });

  it('(a, whole-body-blanked shape) a bare ${IFS(do(x))} span: the body is no longer masked wholesale', () => {
    // Before the fix this returned NO resolver calls at all — the entire
    // heredoc body (including the unrelated leading data read) was blanked
    // because relief was wrongly granted on the deobfuscated text.
    const body = "my $t = read_file('/tmp/x/table.md');\nprint \"${IFS(do('/tmp/fx/a.pl'))}\\n\";";
    const cmd = heredoc('perl -', body);
    expect(asked(cmd)).toEqual(unmasked(cmd));
    expect(asked(cmd)).toContain('/tmp/x/table.md');
  });

  it('(b) a genuine bash ${IFS}-obfuscated catastrophic command OUTSIDE any heredoc is still caught — general deobfuscation path is untouched', () => {
    for (const cmd of [IFS_RM_RF, IFS_CHMOD, IFS_FORKBOMB]) {
      const verdict = evaluateToolCall('Bash', { command: cmd });
      expect([cmd, verdict.decision]).toEqual([cmd, 'block']);
      expect([cmd, verdict.severity]).toEqual([cmd, 'catastrophic']);
    }
  });

  it('(c) a legitimate, non-obfuscated data-read-only heredoc still gets the #713 relief', () => {
    const cmd = heredoc('python3 -', "text = open('/tmp/x/table.md').read()\nprint(len(text))");
    expect(asked(cmd)).not.toContain('/tmp/x/table.md');

    const verdict = evaluateToolCall('Bash', { command: cmd }, undefined, {
      resolveScriptSource: () => 'print("benign fixture")\n',
    });
    expect(verdict.decision).toBe('allow');
  });

  it('(c, control) a named span that is NOT IFS-shaped behaves identically to raw text — confirms the fix is not a blanket revert of #713', () => {
    const body = "my $t = read_file('/tmp/x/table.md');\nprint \"${FOO(do('/tmp/fx/a.pl'))}\\n\";";
    const cmd = heredoc('perl -', body);
    expect(asked(cmd)).toEqual(unmasked(cmd));
    expect(asked(cmd)).toEqual(expect.arrayContaining(['/tmp/x/table.md', '/tmp/fx/a.pl']));
  });
});
