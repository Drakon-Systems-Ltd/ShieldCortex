/**
 * Iron Dome — Tool Action Guard
 *
 * Recognition layer that turns a live agent tool call (`toolName` + `arguments`)
 * into an Iron Dome action verdict. This is the piece that makes the headline
 * claim — "Iron Dome protects what the agent DOES" — true at runtime.
 *
 * Before this, the OpenClaw `before_tool_call` interceptor only inspected the
 * two memory-write tools (`WATCHED_TOOLS`), so an agent told to `rm -rf`,
 * `curl | sh`, or exfiltrate secrets passed completely ungated. This module
 * recognises destructive shell / file / network / git calls, hard-BLOCKs the
 * unambiguously catastrophic ones, and routes the rest through the existing
 * RED/AMBER/GREEN confirmation vocabulary.
 *
 * Design principle: POSITIVE RECOGNITION, not deny-all.
 *  - Unrecognised or read-only tools → `allow` (the guard never nags on benign
 *    work — generic `ls`, `git status`, `npm test`, web search all pass).
 *  - Recognised-dangerous (plain `rm <path>`, `sudo`, force-push, external
 *    egress) → `require_approval`.
 *  - Catastrophic (`rm -rf /`, fork bomb, `mkfs`, `dd of=/dev/sd*`, `curl | sh`,
 *    secret exfil) → `block`, and this can NEVER fail open, regardless of config.
 *
 * The danger detection is self-contained so the guard works out-of-the-box
 * (security on by default); an optional `IronDomeConfig` only relaxes via the
 * user's `autoApprove` list.
 */

import { lstatSync, realpathSync } from 'node:fs';
import type { IronDomeConfig } from './config.js';
import { validateToolInput, schemaFamilyForTool } from './tool-input-schema.js';
import { forEachWindow } from '../scan-windows.js';

export type ToolGuardDecision = 'allow' | 'require_approval' | 'block';
export type ToolGuardSeverity = 'benign' | 'sensitive' | 'dangerous' | 'catastrophic';
export type ToolFamily =
  | 'read'
  | 'write'
  | 'delete'
  | 'exec'
  | 'network'
  | 'git'
  | 'memory'
  | 'unknown';

export interface ToolGuardVerdict {
  decision: ToolGuardDecision;
  severity: ToolGuardSeverity;
  family: ToolFamily;
  /** Canonical Iron Dome action string (e.g. `execute_command`, `delete_file`). */
  action: string;
  reason: string;
  /** Matched indicators, e.g. `['recursive-force-delete', 'root-path']`. */
  signals: string[];
  /**
   * The evidence behind `signals` (issue #192): each rule that fired, with the
   * `fmtSpan`-bounded text it matched, so the durable audit record can explain
   * a denial without re-running the command on the reporter's box. Absent on
   * clean allows. `secret-egress` deliberately never contributes a span — the
   * span would be the secret, and the audit log must not store credentials.
   *
   * #184: when the match came from folded script source (not the command the
   * operator typed), `source` / `line` / `chain` name the file and invocation
   * path so the operator is not left reading a parent script that does not
   * contain the matched pattern.
   */
  matches?: Array<{
    signal: string;
    span: string;
    /** Absolute or as-invoked path of the folded file that produced the match. */
    source?: string;
    /** 1-based line within that source file (best-effort). */
    line?: number;
    /** Invocation chain, e.g. `scripts/github-backup.sh → resilience/sync-code-backup.sh`. */
    chain?: string;
  }>;
  /**
   * Scripts whose source was exempted from folding by the reviewed-script
   * allowlist (#189). Present only when an exemption actually fired, so its
   * absence means "nothing was exempted", never "nobody looked". Both audit
   * writers persist it: a verdict that leaned on review must say so.
   */
  reviewedScripts?: string[];
}

// ── Tool-name recognition ───────────────────────────────────────────────────

/** Strip MCP / namespace prefixes and lowercase: `mcp__memory__remember` → `remember`. */
export function normaliseToolName(name: string): string {
  const raw = String(name || '').toLowerCase().trim();
  // Keep the most specific segment after mcp/namespace separators.
  const seg = raw.split(/__|\.|:|\//).filter(Boolean).pop() ?? raw;
  return seg;
}

const MEMORY_TOOLS = /^(remember|recall|forget|memory|get_context|graph)$/;
const READ_TOOLS = /^(read|read_file|cat|less|more|head|tail|view|open|get|glob|grep|search|find|ls|list|list_files|stat|pwd|which|web_search|websearch)$/;
const NETWORK_TOOLS = /(fetch|curl|wget|http|https|request|download|upload|web_fetch|webfetch|post|put|api_call|apicall|send|email|webhook)/;
const DELETE_TOOLS = /(delete|remove|rm|trash|unlink|destroy|drop|purge|rmdir)/;
const WRITE_TOOLS = /(write|edit|create|update|patch|append|save|mkdir|move|copy|cp|mv|rename|chmod|chown)/;
const EXEC_TOOLS = /(bash|shell|exec|run|run_command|runcommand|command|terminal|system|sh|zsh|powershell|cmd|spawn|process|eval|script)/;
const GIT_TOOLS = /(^git$|git_|_git|github)/;

export function classifyFamily(toolName: string): ToolFamily {
  const n = normaliseToolName(toolName);
  if (MEMORY_TOOLS.test(n)) return 'memory';
  // Exec is checked early: a "Bash" tool can do anything, so its args drive risk.
  if (EXEC_TOOLS.test(n)) return 'exec';
  if (GIT_TOOLS.test(n)) return 'git';
  if (READ_TOOLS.test(n)) return 'read';
  if (DELETE_TOOLS.test(n)) return 'delete';
  if (NETWORK_TOOLS.test(n)) return 'network';
  if (WRITE_TOOLS.test(n)) return 'write';
  return 'unknown';
}

// ── Argument extraction ──────────────────────────────────────────────────────

function pickString(args: Record<string, unknown>, keys: string[]): string {
  for (const k of keys) {
    const v = args?.[k];
    if (typeof v === 'string' && v.length > 0) return v;
  }
  return '';
}

export function extractCommand(args: Record<string, unknown>): string {
  return pickString(args, ['command', 'cmd', 'script', 'code', 'input', 'shell', 'run']);
}

// `${IFS}`, `${IFS:0:1}`, `$IFS` all expand to whitespace at runtime and are used
// purely to strip the literal spaces that several danger patterns anchor on
// (`\s/` in recursive-perms, the fork-bomb shape). Normalise them to a space
// before scanning so those patterns see the real command shape. Fail-closed:
// this can only ever REVEAL a danger the raw string hid, never mask one.
const IFS_OBFUSCATION = /\$\{IFS[^}]*\}|\$IFS\b/gi;
export function deobfuscateIfs(s: string): string { return s.replace(IFS_OBFUSCATION, ' '); }
export function extractPath(args: Record<string, unknown>): string {
  return pickString(args, ['path', 'file_path', 'filePath', 'file', 'target', 'destination', 'dir', 'directory']);
}
export function extractUrl(args: Record<string, unknown>): string {
  return pickString(args, ['url', 'uri', 'endpoint', 'href', 'host', 'to']);
}

// ── Write-content extraction + target recognition (issue #93) ────────────────
//
// Production bypass: a Bash heredoc writing a dangerous payload was DENIED
// (the command surface is scanned), while the byte-identical payload delivered
// via Edit/Write passed silently — the write tools were path-only by design.
// The predicates below decide WHICH write targets get their content scanned:
// a script-like path, a memory ledger, or a shebang-carrying body. Ordinary
// docs/data files keep the field discipline — content there is prose.

/** The content-bearing string of a write-family tool call, first present key wins. */
export function extractWriteContent(args: Record<string, unknown>): string {
  return pickString(args, ['new_string', 'content', 'contents', 'file_text', 'body', 'text']);
}

const SCRIPT_WRITE_EXT_RE = /\.(?:sh|bash|zsh|py|pyw|js|mjs|cjs|ts|tsx|rb|pl|php|ps1|bat|cmd|fish)$/i;
const SHELL_RC_BASENAME_RE = /^\.(?:bashrc|zshrc|zprofile|zshenv|zlogin|zlogout|profile|bash_profile|bash_login|bash_logout)$/i;

/** A write target whose contents an interpreter (or a sourcing shell) will run. */
export function isScriptLikeWritePath(path: string): boolean {
  const base = String(path || '').trim().split(/[\\/]/).pop() ?? '';
  return SCRIPT_WRITE_EXT_RE.test(base) || SHELL_RC_BASENAME_RE.test(base);
}

const MEMORY_BASENAME_RE = /^(?:MEMORY|CORTEX_MEMORY|CLAUDE)\.md$/i;

/**
 * A memory ledger / agent-instruction file. Content written here is re-read as
 * INSTRUCTIONS on later turns, so a command payload in it is an injection, not
 * prose — the same reason the memory-write tools get their own defence pipeline.
 */
export function isMemoryWritePath(path: string): boolean {
  const norm = String(path || '').trim().replace(/\\/g, '/');
  if (!norm) return false;
  const base = norm.split('/').pop() ?? '';
  if (MEMORY_BASENAME_RE.test(base)) return true;
  return /\.md$/i.test(base)
    && (/\/\.claude\/memory(?:\/|$)/i.test(norm) || /(?:^|\/)memory\//i.test(norm));
}

/**
 * A body that is a PROGRAM by its own first bytes: a shebang prologue. Kept
 * deliberately this narrow — a runbook that embeds a full script listing in a
 * fenced code block contains `#!` at some line start, and gating on that would
 * reopen the docs-prose FP class the field discipline exists to prevent. The
 * kernel only honours a shebang at byte 0; the leading `\s*` tolerance is for
 * Edit fragments that carry the prologue after a blank line.
 */
export function writeContentLooksExecutable(content: string): boolean {
  return /^\uFEFF?\s*#!/.test(String(content || ''));
}

/**
 * #341 Face 1 — memory/markdown writes re-read as prose. Quoted forensic
 * evidence (inline backticks, fenced blocks) is a mention, not a command to
 * run. Strip those spans before the write-content danger scan so incident
 * notes can cite shell/ops forms without a promptless deny.
 * Script-like targets never use this — their bytes are programs.
 */
export function neutralizeMarkdownCommandMentions(content: string): string {
  let s = String(content || '');
  s = s.replace(/```[\s\S]*?```/g, ' ');
  s = s.replace(/`[^`\n]+`/g, ' ');
  return s;
}

// ── Danger detection ─────────────────────────────────────────────────────────

interface Pattern { re: RegExp; signal: string; }

/**
 * Unambiguously catastrophic, irreversible operations. Matching ANY of these is
 * a hard BLOCK that cannot be relaxed by config — there is no legitimate agent
 * reason to wipe a disk or fork-bomb a host mid-task.
 */
const CATASTROPHIC: Pattern[] = [
  // rm with both -r and -f (any flag order/cluster), e.g. rm -rf, rm -fr, rm -Rf, rm --recursive --force
  // The `-rf`/`-fr` short-flag cluster must begin at an argv boundary — the
  // `(?<![\w.\/-])` before the leading `-` rejects a hyphen embedded in a
  // FILENAME token (`.write-verify-test`, `my-perf-report`), which otherwise
  // matched `-\w*r\w*f\w*` as if `-verify`/`-perf` were an `-rf` flag and
  // hard-blocked a plain single-file `rm` as catastrophic (field FP report).
  { re: /\brm\b[^|;&\n]*?(?:(?<![\w.\/-])-\w*r\w*f\w*|(?<![\w.\/-])-\w*f\w*r\w*|(?=[^|;&\n]*--recursive)(?=[^|;&\n]*--force))/i, signal: 'recursive-force-delete' },
  // rm targeting a root-ish / home / wildcard path — or the WHOLE current
  // directory. `.` and `./` wipe every entry in cwd (`.git`, source, uncommitted
  // work) — the same blast radius as `./*` / `*`, which already block here — so
  // they gate at the same tier. The trailing `(?:\s|$)` keeps this to the BARE
  // whole-cwd target: a NAMED confined subdir (`.next`, `./build`, `.DS_Store`)
  // has a non-space char after the dot and stays allowed via the confined-delete
  // exemption. `..`/`../` climb out and are already caught by that exemption.
  { re: /\brm\b[^|;&\n]*\s(?:-\w+\s+)*(?:\/|~|\$HOME|\/\*|\*|\.\/\*|\.\/|\.)(?:\s|$)/i, signal: 'delete-root-or-home' },
  // fork bomb  :(){ :|:& };:
  { re: /:\s*\(\s*\)\s*\{\s*:\s*\|\s*:?\s*&?\s*\}\s*;\s*:/, signal: 'fork-bomb' },
  // filesystem creation / raw disk writes
  { re: /\bmkfs(\.\w+)?\b/i, signal: 'format-filesystem' },
  { re: /\bdd\b[^|;&\n]*\bof=\/dev\/(sd|nvme|hd|disk|mmcblk|vd)/i, signal: 'raw-disk-write' },
  { re: /[>|]\s*\/dev\/(sd|nvme|hd|disk|mmcblk|vd)\w/i, signal: 'redirect-to-block-device' },
  { re: /\b(fdisk|parted|sgdisk|wipefs|blkdiscard)\b/i, signal: 'disk-partition-tool' },
  // pipe a download straight into an interpreter (remote code execution).
  // The danger is a BARE interpreter reading the fetched bytes as its PROGRAM
  // (`curl … | sh`, `curl … | python3`, `curl … | sh -s`). When the interpreter
  // is given its own program via an inline-script flag (`-c`/`-e`/`-m`), the
  // piped bytes are stdin DATA, not code — e.g. `curl … | python3 -c '<parse>'`
  // parses JSON and is not RCE (issue #73.6). The negative lookahead exempts an
  // interpreter whose next flag (allowing intervening short flags) is -c/-e/-m.
  // The interpreter no longer needs to sit immediately after the FIRST pipe —
  // an env-assignment prefix (`LC_ALL=C bash`) or an intermediate pipe stage
  // (`curl … | tee /tmp/x | bash`) must not exempt the terminal interpreter
  // that actually executes the fetched bytes (issue #4475.2). `[^\n]*` (not
  // `[^|\n]*`) lets the bridge cross earlier pipe stages; the `(?:sudo\s+)?`
  // exemption becomes a general env-assignment prefix, same technique as
  // modify-scheduler below.
  // Leading span is `[^\n|]*` (NOT `[^\n]*`) — issue #92 must-fix 1: a leading
  // class that can also swallow `|` overlaps the following `(?:[^\n|]*\|)*`
  // bridge group, so the engine can choose ANY pipe in the string as "the
  // first one" and re-tries the whole group per choice — quadratic on a long,
  // pipe-dense string (measured 20k→5.3s, 30k→12s). Excluding `|` from the
  // leading class makes "the first pipe" unambiguous — one deterministic
  // scan, no backtracking blowup — while the explicit `(?:[^\n|]*\|)*` group
  // still crosses every later pipe stage exactly as before.
  // Also widened (issue #92 must-fix 3): `env <assign>… <interpreter>` (e.g.
  // `curl … | env LC_ALL=C bash`) evaded the env-assignment-prefix exemption
  // because `env` itself isn't a `word=value` token — `(?:env\s+)?` admits the
  // `env` command itself, and a second `(?:\w+=\S*\s+)*` after it still
  // consumes any assignments `env` is given before the real interpreter.
  { re: /\b(?:curl|wget|fetch)\b[^\n|]*\|(?:[^\n|]*\|)*\s*(?:\w+=\S*\s+)*(?:sudo\s+)?(?:env\s+)?(?:\w+=\S*\s+)*(?:bash|sh|zsh|ksh|python\d?|perl|ruby|node)\b(?!(?:\s+-[a-z]+)*\s+-[cem]\b)/i, signal: 'pipe-download-to-shell' },
  // ANTI-BYPASS for the exemption above: an inline `-c`/`-e` program that itself
  // EXECUTES its stdin (`python3 -c "exec(sys.stdin.read())"`, `node -e
  // "eval(...readFileSync(0)...)"`, `bash -c 'source /dev/stdin'`) re-opens the
  // fetched bytes as code — still RCE, not data consumption. Single-line bounded;
  // `\b(exec|eval)\b` deliberately does not match `literal_eval` or
  // `json.load(sys.stdin)`, so the #73.6 data-parsing exemption stands.
  { re: /\b(?:curl|wget|fetch)\b[^|\n]*\|[^\n]*\b(?:bash|sh|zsh|ksh|python\d?|perl|ruby|node)\b[^\n]*(?:\b(?:exec|eval)\b|(?:\bsource\b|(?<![\w./])\.)\s+\/dev\/stdin\b)/i, signal: 'pipe-download-stdin-exec' },
  // ANTI-BYPASS (issue #86.1): the `-m` inline-program exemption also covers a
  // deny-list of stdlib MODULES that execute their stdin — `python -m code` drops
  // into the interactive interpreter and runs the piped bytes as code, `pty`
  // spawns a shell, `pdb` reads debugger commands — none carry an exec/eval token
  // on the line. `-m json.tool`/`-m pip` (stdin as DATA, or no stdin) do NOT match,
  // so the #73.6 data-parsing exemption stands. `(?![\w.])` keeps `codecs` ≠ `code`.
  { re: /\b(?:curl|wget|fetch)\b[^|\n]*\|[^\n]*\bpython\d?\b[^\n]*\s-m\s*(?:code|pty|pdb)(?![\w.])/i, signal: 'pipe-download-module-exec' },
  // recursive permission/ownership change at the root (bare `/`, `/ `, or
  // trailing-slash `/ ` variants — the system-dir sibling below handles
  // /etc, /var, /home, etc. with the SAME trailing-slash discipline).
  { re: /\bch(?:mod|own)\b[^|;&\n]*(?:-\w*R\w*|--recursive)\b[^|;&\n]*\s\/(?:\s|$)/i, signal: 'recursive-perms-on-root' },
  // overwrite the whole disk with zeros/urandom. The [^|;&\n]* bridge keeps the
  // verb and the /dev/ target in ONE statement — mirroring recursive-force-delete
  // above — so `export PATH=/opt/wipe/bin; echo /dev/null` no longer collides two
  // unrelated statements into a false catastrophic block (issue #89).
  { re: /\b(?:shred|wipe)\b[^|;&\n]*\/dev\/(?!null\b|stdout\b|stderr\b|fd\/\d)/i, signal: 'shred-device' },

  // #342 — interpreter recursive delete of a root-ish path. Shell-verb-only
  // detection missed python/node one-liners that perform the same effect with
  // empty signals while a markdown note quoting the shell form was denied.
  // These match CALLS with a path arg — not a dict of pattern strings (issue
  // #89 mention class stays a mention).
  { re: /\b(?:shutil\s*\.\s*rmtree|os\s*\.\s*removedirs)\s*\(\s*(['"])(?:\/|~|\$HOME|\.|\.\.\/)\1/i, signal: 'recursive-force-delete' },
  { re: /\b(?:shutil\s*\.\s*rmtree)\s*\(\s*(['"])[^'"]+\1[^)]*\b(?:ignore_errors\s*=\s*True|onerror\s*=)/i, signal: 'recursive-force-delete' },
  // Node fs.rmSync / fs.rm with recursive:true against root/home/cwd.
  { re: /\b(?:fs\s*\.\s*)?(?:promises\s*\.\s*)?rm(?:Sync)?\s*\(\s*(['"])(?:\/[^'\"]*|~|\$HOME|\.|\.\.\/)\1[^)]*\brecursive\s*:\s*true/i, signal: 'recursive-force-delete' },
  { re: /\b(?:fs\s*\.\s*)?(?:promises\s*\.\s*)?rm(?:Sync)?\s*\(\s*(['"])[^'"]+\1[^)]*\brecursive\s*:\s*true[^)]*\bforce\s*:\s*true/i, signal: 'recursive-force-delete' },
  // Ruby FileUtils recursive remove of root-ish paths.
  { re: /\bFileUtils\s*\.\s*rm_rf\s*\(\s*(['"])(?:\/|~|\.|\.\.\/)/i, signal: 'recursive-force-delete' },
  { re: /\brm_rf\s*\(\s*(['"])(?:\/|~|\.|\.\.\/)/i, signal: 'recursive-force-delete' },
];

/**
 * Recognised-dangerous operations: effectful and worth a human nod, but not
 * automatically catastrophic. These map to an Iron Dome action and escalate to
 * `require_approval`.
 */
// The system package managers whose installs mutate the HOST. Named so the
// container-confinement check (#128) tests the identical shape rather than a
// drifting second copy.
const SYSTEM_INSTALL_RE = /\b(?:apt|apt-get|yum|dnf|brew|gem|cargo)\b[^|;&\n]*\b(?:install|add)\b/i;

const DANGEROUS: Pattern[] = [
  // `shred` is anchored to command position (issue #89 remainder): start of
  // statement, after a separator/subshell, after sudo/env-assignment prefixes,
  // or as the command run by `xargs` / `find -exec`. A grep whose *search
  // pattern* mentions the word (`grep -rn "shred" src/`) is a mention, not an
  // intent, and no longer gates. `rm`/`unlink`/`rmdir` stay unanchored — their
  // mention-FP class is the #84 span-classifier's scope, and anchoring the
  // highest-traffic delete verb needs that design, not a drive-by.
  // The delete verbs are preceded by a not-a-dash-flag guard (issue #128): a
  // token that begins with `-` is an OPTION, never the command. `docker run
  // --rm` asks the container runtime to clean up the CONTAINER on exit and
  // touches nothing on the host, yet it was hard-matching the highest-traffic
  // delete rule — hit live while setting up a clean-box install test for our
  // own product. This narrows only the flag form; `rm x`, `sudo rm x`,
  // `; rm x`, `xargs rm` and every inner `rm` inside a container command are
  // unchanged, and `rm -rf` remains catastrophic wherever it appears.
  { re: /(?<![-\w])rm\b|(?<![-\w])unlink\b|(?<![-\w])rmdir\b|(?:(?:^|[;&|(\n]|\$\()\s*(?:\w+=\S*\s+)*(?:sudo\s+)?|\bxargs\s+(?:-{1,2}\S+\s+)*|-exec\s+)shred\b/i, signal: 'file-delete' },
  { re: /\bsudo\b|\bdoas\b|\bsu\s/i, signal: 'privilege-escalation' },
  // Force-push, bounded to ONE statement and to real force TOKENS (issue #191).
  // Two independent widenings stacked here. The bridge was `[^|\n]*`, which
  // crossed `;` and `&&` exactly like the package-manager rule did before #89 —
  // so a plain `git push` in one statement paired with any later `-f`/`+` in an
  // unrelated one (`git push origin main && rsync -f rules dst`, `… && trash
  // old-f.tar.gz`, `… && echo "done+ok"`) gated as a force-push. And the force
  // alternatives were unanchored: a bare `\+` matched a plus ANYWHERE, and
  // `-f\b` matched the tail of any hyphenated word ending in `-f`. Both are now
  // token-anchored — a force flag or a `+refspec` starts a shell word.
  // Hit live on Friday-Mac's backup cron, whose entire chain was denied with the
  // whole 80-char span echoed back as the "matched" text (fmtSpan truncation of
  // a span that had swallowed four statements), which is why the error looked
  // like it was quoting a force-push that was never there.
  // `-[A-Za-z]*f[A-Za-z]*` rather than `-f\b`: git accepts clustered short
  // options, and `git push -fq` slipped the word-boundary form entirely
  // (issue #195). The leading `(?:^|\s)` still requires a real shell word, so
  // #191's `trash old-f.tar.gz` stays clean.
  // Proposer only — `gitForcePushInvoked` disposes (tokenised, quotes stripped,
  // command-position anchored). Deliberately LOOSE: it fires on any `git push`
  // carrying a flag/quote/refspec-plus, and the argv parser makes the real
  // decision. A precise quote-tolerant proposer kept missing interior-quote
  // shapes (`git push -"f"`); a loose one cannot miss, and over-proposing only
  // costs one disposer call that returns false. `git push origin main` (no
  // flag) does not propose.
  { re: /\bgit\b[^|;&\n]*\bpush\b[^|;&\n]*[-+'"]/i, signal: 'git-force-push' },
  // git branch-delete gates on force INTENT, not letter case. Force-deleting an
  // UNMERGED branch (real data loss) has many spellings, ALL verified in real
  // git: canonical `-D`, and any lowercase delete flag (`-d`/`--delete`) paired
  // with a force flag (`-f`/`--force`) — separated (`-d -f`, `-d --force`,
  // `--delete --force`) OR clustered into one token (`-df`, `-fd`). A BARE
  // `-d`/`--delete` (no force) deletes only a MERGED branch — git refuses it
  // otherwise — so it stays allowed (the #182 FP that started this).
  // Case-SENSITIVE (no `/i`) so canonical `-D` and safe `-d` are distinguishable;
  // the delete+force arm then re-catches the lowercase force combos that the old
  // `/i` rule only ever caught by accident (folding `-D`→`-d`), and as a bonus
  // closes the long-form `--delete --force` / clustered `-fd` gaps the accident
  // never covered. Flag tokens are `\s-…\b` (a filename arg never starts `-`),
  // and the delete/force lookaheads are single-pass over one statement — no
  // nested quantifier, no backtracking blowup.
  // Proposer only — `gitDeleteBranchInvoked` disposes. Deliberately LOOSE, same
  // reasoning as the force-push proposer above: it fires on `git branch` with
  // any flag/quote, or `git push` with any flag/quote/`:`-refspec, and the argv
  // parser (which tokenises and strips ALL quoting) decides. So every quoting
  // shape is PROPOSED — wrapped (`"-d"`), interior (`-"d"`), clustered — and a
  // quoted `-m "…git branch --delete --force…"` message is disposed as prose.
  // `git branch` with no flag (a plain listing/create) does not propose.
  { re: /\bgit\b[^|;&\n]*\b(?:branch\b[^|;&\n]*[-'"]|push\b[^|;&\n]*[-'":])/i, signal: 'git-delete-branch' },
  // Verb-hiding shape: git whose SUBCOMMAND is a substitution/expansion
  // (`git $(getcmd) origin --delete`, `git $VERB -D x`, `git `cmd` --force`) —
  // no literal `branch`/`push` fires the proposer above, but a destructive flag
  // is present. Propose here; gitDeleteBranchInvoked fails closed (its
  // GIT_SUBCOMMAND_SUBSTITUTION / `$`-subcommand checks). A destructive flag is
  // required so a benign `git $(echo status)` / `git $CMD log` is untouched.
  { re: /(?:^|[;&|(\n`]|\$\()\s*(?:sudo\s+)?git\s+(?:-\S+\s+)*(?:\$[({]|`|\$\w)[^;&|\n]*(?:--force\b|--delete\b|[\s'"]-[A-Za-z]*[DFf][A-Za-z]*\b|\s[+:]\S)/i, signal: 'git-delete-branch' },
  // The process verbs here are the SHELL commands, not a language's process API
  // (issue #165). `process.kill(process.pid, sig)` in a build script forwards a
  // signal to ITSELF, and `child.kill()` is a method call — neither stops
  // somebody else's service. #160 wired script-source folding into the Claude
  // Code hook, which made every such build script newly scannable on the
  // busiest surface, and this fired on `npm test` in this very repo. A guard
  // that blocks `npm test` is a guard people turn off.
  //
  // The lookbehind rejects only the member-access form. Every shell shape —
  // bare, sudo-prefixed, after a separator, via xargs — is untouched.
  // `kill -l` is carved out (same read-only exemption as `crontab -l`/`at -l`):
  // it prints the signal-name table and kills NOTHING (#182 corpus FP). Only
  // `kill` takes `-l`; `pkill`/`killall` have no such option and stay
  // unconditional. Name/pattern kill (`pkill -f`, `killall`) and every other
  // `kill` shape (`kill <pid>`, `kill -9 <pid>`) remain gated — that is the
  // attacker-weaponisable form and is intentionally NOT relaxed here.
  // A targeted `kill <pid>` of literal POSITIVE numeric PIDs (optionally after a
  // signal flag) is also carved out: an injection cannot weaponise a PID it does
  // not know, and killing a process the agent itself started by PID is the
  // single most common legitimate case. Only positive integers ≥2 to end-of-
  // statement qualify (`(?!0*[01]\b)[0-9]+` — a single quantifier that rejects a
  // 0 or 1 token in any zero-padded spelling; the earlier `[0-9]*[1-9][0-9]*`
  // form was correct but its
  // ambiguous overlap backtracked QUADRATICALLY on a long crafted digit run and
  // hung this synchronous guard, a DoS vector — see the ReDoS note below).
  // `kill $(pgrep x)`, `kill $PID`, `kill %1`, `kill 4021 -1` (broadcast),
  // name/pattern kill (`pkill`, `killall`) and any dynamic/compound form stay
  // gated (their own rule re-catches a lethal follow-on). Crucially PID `0` and
  // `-9 0` stay gated: `kill 0` signals the WHOLE process group (the agent's own
  // shell, sibling sessions, ShieldCortex itself) and needs no privilege — it is
  // the defence-disruption shape this rule exists for, not a targeted kill.
  // PID `1` stays gated too: init is UNIVERSALLY known, so it breaks the carve's
  // "an injection cannot know the PID" premise, and in a container the agent may
  // own PID 1 — killing it takes down the container/supervisor. A negative target
  // (`kill -1`) never matches the digit class either. `(?!0*[01]\b)` excludes
  // 0 and 1 AND their leading-zero spellings (`01`, `001`, `00`) — the shell
  // resolves `kill 01` to PID 1, so padding a zero must not defeat the gate.
  // ReDoS: `(?!0*[01]\b)[0-9]+` is a single greedy quantifier separated from its
  // repeats by required whitespace, so a long digit run is linear, not quadratic.
  { re: /\b(systemctl|service)\b[^|\n]*\b(stop|disable|mask)\b|(?<![.\w])(?:(?:pkill|killall)\b|kill\b(?!\s+-l\b)(?!\s+(?:-[A-Za-z0-9]+\s+)?(?!0*[01]\b)[0-9]+(?:\s+(?!0*[01]\b)[0-9]+)*\s*(?=$|[;&|\n])))/i, signal: 'stop-process-or-service' },
  { re: /\b(iptables|ufw|nft|netplan|firewall-cmd)\b/i, signal: 'modify-network-firewall' },
  // Package installs split by blast radius (issue #73.3). System package managers
  // and language *global* installs mutate the host → approval. A workspace-local
  // `npm/yarn/pnpm/bun install` (no -g/--global) is routine operator-directed dev
  // work and is handled as a sensitive-but-allowed op (SENSITIVE.local-package-install
  // below) so it is never a hard gate.
  // Bridge tightened from `[^|\n]*` to `[^|;&\n]*` (issue #89): the old span
  // crossed `;` and `&&`, so a package manager in one statement paired with an
  // `install` word in an unrelated later one (`pip --version && echo install
  // done`). Every other rule in this file already scopes to one statement.
  //
  // `pip`/`pip3` moved out to `hasUnscopedPipInstall` below — a pip install has
  // to be read as argv to tell a host mutation from a venv-scoped one.
  { re: SYSTEM_INSTALL_RE, signal: 'install-package' },
  // A GLOBAL install mutates the host → approval. It must carry BOTH an install
  // verb AND a global flag in the SAME statement. The verb is `install`/`add`,
  // or npm's own `i`/`in`/`ins`/`inst`/`insta`/`instal`/`install`/`isnt`/`isntall`
  // abbreviation family (npm's alias resolver accepts all of these as `install` —
  // the old regex only caught the bare `i` shorthand, so `npm inst -g x` etc.
  // bypassed the gate entirely; issue #90). `ci` is excluded — there is no global
  // `npm ci`. The verb must land as its own whitespace-delimited argv token, not
  // a `\b`-only substring, so a package name that merely contains the word —
  // `npm ls -g social-add-on`, `npm outdated -g @scope/add` — does not over-gate
  // (issue #90). A read-only global QUERY — `npm ls -g`, `npm root -g`,
  // `npm outdated -g`, `npm list --global` — mutates nothing and is not gated
  // (issue #88). Order-independent (`npm install -g` and `npm -g install` both hit).
  // Quote-tolerant on the global flag (issue #91.2): `npm install "-g" foo` is the
  // same host mutation — argv quoting is stripped by the shell — so an optional
  // quote is admitted on either side of `-g`. `--global` gets a `(?![\w-])` tail
  // so npm's real `--global-style` layout flag (workspace-local install) does not
  // over-gate.
  // The abbreviated-verb alternative accepts `--location=global` as well (#387):
  // it is npm's own long spelling of `-g`, the first alternative and the argv
  // disposer's GLOBAL_FLAG both already treat the three as one, and omitting it
  // here meant `npm i --location=global pkg` was never even PROPOSED.
  { re: /\b(?:npm|yarn|pnpm|bun)\b(?=[^|;&\n]*(?:\s['"]?-g\b['"]?|--global(?![\w-])|--location=global(?![\w-])|\bglobal\s+add\b))(?=[^|;&\n]*\s(?:install|add)(?=\s|$|[|;&\n]))|\b(?:npm|pnpm|bun)\s+(?:i(?:n(?:s(?:t(?:a(?:ll?)?)?)?)?)?|isnt(?:all)?)\b[^|;&\n]*(?:\s['"]?-g\b['"]?|--global(?![\w-])|--location=global(?![\w-]))/i, signal: 'install-package-global' },
  // Scheduler MUTATION only: `crontab` in command position that edits/installs
  // (`-e`, `-r`, a file, or stdin `-`) — never the read-only `crontab -l`, and
  // never the bare word mentioned inside an echo/string (issue #89). Env-var and
  // sudo prefixes allowed. `/etc/cron*` writes still gate. Extended (issue
  // #4475.7c) to cover `at <time-spec>` generally — not just the literal phrase
  // "at now" — and `systemd-run --on-calendar=…` (systemd's cron-equivalent
  // one-shot/timer scheduling). `at -l` (list pending jobs, the crontab -l
  // equivalent) stays read-only/allowed, same discipline as crontab.
  // Wrapper commands admitted at command position (issue #91.1): `env`, `nohup`,
  // `time`, `stdbuf`, `nice` are transparent process wrappers — `nohup crontab -e`
  // is the same mutation. Each wrapper may carry dash-flags, assignments, or a
  // bare numeric arg (`nice -n 10`); the loop is deterministic because every
  // token class is disjoint by first character from the scheduler verbs, so a
  // non-matching tail exits without re-partitioning (same ReDoS discipline as
  // issue #92 must-fix 1). The read-only `-l` exemption applies unchanged
  // through wrappers (`time crontab -l` stays allowed).
  // Wrapper set extended (issue #89) with `timeout`, `setsid`, `ionice`,
  // `command` and `exec` — the same transparent wrappers `EXEC_WRAPPER` already
  // steps over for script detection. `timeout` alone was a live false NEGATIVE:
  // `timeout 60 crontab -e` was not gated at all. `timeout` must precede `time`
  // in the alternation, or `time` matches its prefix and the `\b` fails.
  // `at` additionally excludes a following `=` (#135): the newline in the
  // command-position anchor makes every line start a command, so a variable
  // named `at` (common in embedded script bodies the guard also scans) matched
  // the scheduler verb. `at(1)` takes `at [options] TIME` — its grammar has no
  // `=` in that slot, so the carve-out removes the FP without losing a verb.
  { re: /(?:^|[;&|(\n]|\$\()\s*(?:\w+=\S*\s+)*(?:sudo\s+)?(?:(?:env|nohup|timeout|time|stdbuf|nice|ionice|setsid|command|exec)\b(?:\s+(?:-{1,2}\S+|\w+=\S*|\d+[smhd]?))*\s+)*(?:sudo\s+)?(?:crontab\b(?!\s+-l\b)|at\b(?!\s+-l\b)(?!\s*=)(?!\s*$))|\/etc\/cron|\bsystemd-run\b[^|;&\n]*--on-(?:calendar|active|boot|startup|unit-active|unit-inactive)\b/i, signal: 'modify-scheduler' },
  // Zero out a file's contents (issue #4475.7a): the pre-existing rule below
  // only caught a `.log` target; `-s 0` / `--size 0` is data-destructive
  // regardless of the target file, so it is gated on its own.
  { re: /\btruncate\b[^|;&\n]*(?:-s\s*0\b|--size(?:=|\s+)0\b)/i, signal: 'truncate-to-zero' },
  { re: /\bhistory\s+-c\b|\.bash_history|truncate\b[^|\n]*\.log/i, signal: 'wipe-history-or-logs' },
  // The dotfile here means the FILE, never a property access (issue #165).
  // `process.env`, `import.meta.env` and `env.FOO` are lookups — reading them
  // touches nothing on disk, yet they matched and helped block this repo's own
  // test runner once #160 made folded script source scannable on the Claude
  // Code surface. The lookbehind rejects an identifier immediately before the
  // dot; a leading `./`, `/app/`, a bare one, and `.env.local` all still match.
  { re: /\/etc\/(passwd|shadow|sudoers)|~\/\.ssh|id_rsa|\.aws\/credentials|(?<![A-Za-z0-9_])\.env\b/i, signal: 'touch-sensitive-path' },
  // The guard's own one-shot approval store (#118). The TTY gate stops the
  // agent using the CLI; without this rule the agent could instead just edit
  // approvals.json (a plain 0600 file owned by the same user) and mint its own
  // approval. MUTATING access still goes to the operator. Pure read-only
  // Pure shell inspection (ls/cat/grep/…) is carved out below (issue #89 live
  // FP 2026-08-14). Interpreters stay gated — fail closed. Gating a pure ls of
  // the store that remediation tells you to reconcile against is a
  // self-referential deadlock on enforced hosts with no broker.
  { re: /\.shieldcortex[\\/]+approvals\b/i, signal: 'touch-approval-store' },
  // The session-lease ledger + lease store (#227). A freeze an agent can edit
  // or delete is not a freeze: DECISIONS.md is lifted by the OPERATOR (TTY-
  // gated `shieldcortex unfreeze`), never by the agent it binds. Same
  // reasoning — and the same rule shape — as the approvals store above. This
  // is tamper RESISTANCE on the tool-call surface plus tamper EVIDENCE in the
  // lease layer (ledger hash audit), not proof: a same-uid write outside tool
  // calls cannot be prevented from userspace, and claiming otherwise would be
  // the over-claiming this feature was review-blocked for.
  { re: /\.shieldcortex[\\/]+(?:DECISIONS\.md|leases)\b/i, signal: 'touch-decisions-ledger' },
  // `dd of=` to ANY target (issue #4475.7b): a raw block device is already
  // CATASTROPHIC above (raw-disk-write, checked first); a regular-file target
  // is one tier down — it can silently overwrite/zero arbitrary file content.
  { re: /\bdd\b[^|;&\n]*\bof=/i, signal: 'dd-overwrite' },
  // Recursive chmod/chown on a top-level system dir (issue #4475.6): bare `/`
  // is already CATASTROPHIC above (recursive-perms-on-root); /etc /usr /var
  // /home /bin /sbin /boot /lib /opt /root are one tier down. Bare-dir-or-
  // wildcard only (mirrors isCriticalPath) so `chown -R user /home/ubuntu/proj`
  // — an operator fixing permissions on their OWN tree — is not caught.
  // `(?:\/\*?)?` (not `(?:\/\*)?`, issue #92 must-fix 2): a BARE trailing
  // slash (`/etc/`, `/var/`, `/home/`) is the same directory as `/etc` and
  // must gate too — the old suffix only admitted nothing or the literal `/*`
  // wildcard, so `chmod -R 777 /etc/` slipped through as allow.
  { re: /\bch(?:mod|own)\b[^|;&\n]*(?:-\w*R\w*|--recursive)\b[^|;&\n]*\s\/(?:etc|usr|var|home|bin|sbin|boot|lib|lib64|opt|root)(?:\/\*?)?(?:\s|$)/i, signal: 'recursive-perms-system-dir' },
  // Registry fetch-and-execute (issue #4475.4): uvx always creates a fresh
  // ephemeral env (no local-bin reuse), and `pnpm dlx` / `yarn dlx` are an
  // explicit fetch-and-run subcommand — both stay gated unconditionally.
  // Anchored to COMMAND POSITION (same technique as modify-scheduler above)
  // so a package merely NAMED "uvx" in an unrelated read-only query
  // (`npm ls uvx`) is not mistaken for invoking it.
  //
  // npx/bunx are handled separately (isGatedNpxBunx, below isCriticalPath) —
  // issue #92 must-fix (ALSO item): they resolve node_modules/.bin locally
  // FIRST, so gating every bare invocation (`npx tsc`, `npx jest`, `npx
  // eslint`, `npx prettier`) was pure approval-noise. Only an explicit
  // remote-fetch shape (auto-confirm flag, version/tag pin, URL/git/path ref)
  // is gated for those two.
  { re: /(?:^|[;&|(\n]|\$\()\s*(?:\w+=\S*\s+)*(?:sudo\s+)?uvx\b/i, signal: 'registry-code-exec' },
  { re: /(?:^|[;&|(\n]|\$\()\s*(?:\w+=\S*\s+)*(?:sudo\s+)?(?:pnpm|yarn)\b[^|;&\n]*\bdlx\b/i, signal: 'registry-code-exec' },
  // A non-curl fetch/decode (base64/openssl/xxd/cat/http) piped into a BARE
  // interpreter is the same RCE shape as curl|bash (CATASTROPHIC above), one
  // tier down (issue #4475.3): the interpreter must be reading the piped bytes
  // AS ITS PROGRAM, which only happens with no trailing script-file argument
  // (or the explicit stdin marker `-`). `cat data.json | python3 analyze.py`
  // keeps a script argument — stdin is DATA for that script, not the program —
  // so it must stay allowed; only a bare/`-`-terminated interpreter is gated.
  // Leading span is `[^\n|]*` (NOT `[^\n]*`) — same quadratic-ReDoS fix as
  // pipe-download-to-shell above (issue #92 must-fix 1): excluding `|` from
  // the leading class makes "the first pipe" unambiguous, so the engine can't
  // re-try the whole `(?:[^\n|]*\|)*` bridge once per candidate pipe position.
  { re: /\b(?:base64|openssl|xxd|cat|http)\b[^\n|]*\|(?:[^\n|]*\|)*\s*(?:\w+=\S*\s+)*(?:sudo\s+)?(?:bash|sh|zsh|ksh|python\d?|perl|ruby|node)\b(?:\s+-)?\s*(?:[;&|\n]|$)/i, signal: 'decode-pipe-to-shell' },
];

/** Sensitive-but-routine writes/edits: announced, default-allow (interceptor may warn). */
const SENSITIVE: Pattern[] = [
  { re: /\bchmod\b|\bchown\b/i, signal: 'change-permissions' },
  { re: /\b(mv|move|rename|cp|copy)\b/i, signal: 'move-or-copy' },
  { re: /\bgit\b[^|\n]*\b(push|commit|reset|rebase|merge|checkout)\b/i, signal: 'git-mutate' },
  // Workspace-local package install (issue #73.3): operator-directed, into the
  // project (node_modules / vendor). Global installs matched install-package-global
  // in DANGEROUS above and are checked first, so this only tags the local case.
  { re: /\b(?:npm|yarn|pnpm|bun)\b[^|\n]*\b(?:install|add|ci|i)\b/i, signal: 'local-package-install' },
  // A venv-scoped / explicitly-target-prefixed pip install (issue #89 class 4).
  // The host-mutating shapes matched `install-package` in DANGEROUS above via
  // hasUnscopedPipInstall and are checked first, so this only tags the scoped case.
  { re: /\bpip\d?\b[^|;&\n]*\binstall\b/i, signal: 'local-package-install' },
];

// ── pip: host mutation vs venv-scoped install (issue #89 class 4) ────────────
//
// `python3 -m venv .venv && .venv/bin/pip install -r requirements.txt` mutates
// that venv and nothing else, but gated as `install-package` — the top install
// FP in the live corpus, and the 26 Jul field note says the same. A pip install
// is SCOPED, and falls through to the sensitive tier, when the target prefix is
// explicit and is not the host:
//
//   - `--target/-t`, `--prefix`, `--root <dir>`;
//   - `uv pip install --python <path>` (installs into that interpreter's env);
//   - a path-qualified pip whose prefix is a venv this command creates, or whose
//     directory name carries a venv marker.
//
// Everything else stays gated, deliberately: a BARE `pip install` gives no
// evidence of where it lands (an activated venv is indistinguishable from the
// system interpreter at this layer), `--user` mutates `~/.local`, and
// `/usr/bin/pip` mutates the host. Fail-closed by construction — the scoped set
// is an allowlist of proofs, not a denylist of dangers.
const PIP_TOKEN_RE = /^(?:(.*)\/)?(?:pip\d?(?:\.\d+)?)$/i;
const PIP_SCOPE_FLAG_RE = /^(?:--target|-t|--prefix|--root|--python)(?:=|$)/i;
const VENV_DIR_MARKER = /(?:^|\/)[^/]*(?:venv|virtualenv)[^/]*$/i;

function venvPrefixesCreatedIn(text: string): string[] {
  const out: string[] = [];
  for (const re of [/\bpython[\d.]*\s+-m\s+venv\s+(\S+)/gi, /\bvirtualenv\s+(\S+)/gi, /\buv\s+venv\s+(\S+)/gi]) {
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) out.push(m[1].replace(/^['"]|['"]$/g, ''));
  }
  return out;
}

// ── Force-push must be an INVOCATION, not vocabulary (issue #195) ────────────
//
// #191 bounded the git-force-push rule to one statement and to real force
// tokens, which killed the statement-bridging half. It left the other half
// untouched: the rule never required `git` to be a command at all. So any text
// that mentions git, then push, then a `+` or `-f` armed it — inside a quoted
// argument, a commit message, a log-capture CLI's prose:
//
//   python3 cortex.py capture --what "git-force-push misfire … the + in +03-00"
//   git commit -m "fix the git push +1 bug"
//
// `\bgit\b` even matched inside the hyphenated rule NAME. Reported by Friday,
// who hit it while logging the lesson from the previous bug: writing up a
// denial got denied. That is the failure mode worth killing on its own — it
// suppresses exactly the record-keeping the fleet is asked for.
//
// Tokenising is what makes this precise: `tokeniseStatement` keeps a quoted
// span whole, so `--what "… git push +1 …"` is ONE token that is not `git`,
// while a real `git push -f` is three. Same principle as #188 and #193 — match
// the invocation, never the vocabulary.
const GIT_FORCE_FLAG = /^--force(?:-with-lease|-if-includes)?(?:=|$)|^-[A-Za-z]*f[A-Za-z]*$/;
/** Wrappers that still leave the next word a real command. */
const COMMAND_WRAPPER = /^(?:sudo|doas|env|nohup|time|timeout|xargs|nice|ionice|stdbuf|command|builtin|exec|setsid)$/;

// Shell keywords that can precede a command WITHOUT a statement separator, so a
// `git` right after one is still at command position (`if git branch -D; then …`,
// `while …`, `! git push --delete`). `{` opens a brace group. (Distinct from the
// block-terminator SHELL_KEYWORD elsewhere — these are the command-PREFIX ones.)
const CMD_PREFIX_KEYWORD = /^(?:if|then|elif|else|while|until|do|!|\{|\()$/;
// bash options that CONSUME the next token as a value — the inline-program scan
// must step over the value to reach `-c` (`bash -O extglob -c '…'`, #codex-P1).
const BASH_VALUE_OPTION = /^(?:-O|\+O|--rcfile|--init-file)$/;
// git GLOBAL options (before the subcommand) that consume the next token, so the
// real subcommand is found past them (`git -c k=v -C dir branch -D`).
const GIT_GLOBAL_VALUE_OPT = /^(?:-c|-C|--git-dir|--work-tree|--namespace|--exec-path|--super-prefix)$/;
// A command substitution AT THE SUBCOMMAND position — `git $(printf push) …`,
// `git `printf branch` …` — assembles the git verb at runtime. Detect it on
// the raw surface and fail closed (the argv walk cannot name a literal
// subcommand). Command-position anchored, so a substitution in an ARGUMENT
// (`git commit -m "$(date)"`, `git branch --list $(echo x)`) — where the real
// subcommand is a literal — does not match.
const GIT_SUBCOMMAND_SUBSTITUTION = /(?:^|[;&|(\n`]|\$\()\s*(?:sudo\s+)?git\s+(?:-\S+\s+)*(?:\$\(|`)/i;

/**
 * Is the `git` token at index `i` in COMMAND position? Every token before it
 * must be a shell keyword, a transparent wrapper, a wrapper flag/value, or a
 * `VAR=x` assignment — never a bare command word. This admits `if git …` /
 * `sudo git …` while rejecting `echo if git branch -D` (where `echo` is the
 * command and `git` is a printed argument).
 */
function gitAtCommandPosition(tokens: readonly string[], i: number): boolean {
  let sawWrapper = false;
  let prevWasFlag = false;   // a wrapper flag can take the next bare token as its value
  for (let k = 0; k < i; k++) {
    const t = tokens[k];
    const base = commandBaseName(t);
    if (COMMAND_WRAPPER.test(base)) { sawWrapper = true; prevWasFlag = false; continue; }
    if (CMD_PREFIX_KEYWORD.test(base)) { prevWasFlag = false; continue; }
    if (/^\w+=/.test(t)) { prevWasFlag = false; continue; }   // VAR=value assignment
    if (t.startsWith('-')) { prevWasFlag = true; continue; }  // a flag (which MAY take a value)
    // A wrapper's bare VALUE argument: the value of a preceding wrapper flag
    // (`env -u FOO git …`, `nice -n 10 git …`) or a bare numeric/duration
    // positional (`timeout 5 git …`, `timeout 1.5 git …` — timeout takes a
    // FRACTIONAL duration). Scoped to a wrapper context, so `sudo echo git
    // branch -D` (echo is the command, git a printed arg) and a bare `5 git …`
    // (no wrapper) are still rejected.
    if (sawWrapper && (prevWasFlag || /^\d+(?:\.\d+)?[smhd]?$/.test(t))) { prevWasFlag = false; continue; }
    return false;                                          // a bare word → git is an argument
  }
  return true;
}

/**
 * git's actual SUBCOMMAND and the args that follow it, or null. The subcommand
 * is the first token that is not a global option (or a global option's value),
 * so a revision/branch-name argument (`git diff branch -- -D`) is NOT mistaken
 * for the `branch` subcommand (#codex-P2).
 */
function gitSubcommandArgs(args: readonly string[]): { sub: string; rest: string[] } | null {
  for (let k = 0; k < args.length; k++) {
    const a = args[k];
    if (!a.startsWith('-')) return { sub: a.toLowerCase(), rest: args.slice(k + 1) };
    if (GIT_GLOBAL_VALUE_OPT.test(a)) k++;                 // step over the option's value
  }
  return null;
}

/**
 * Statement split for the git disposers. Splits on `;`/`&`/`|`/newlines only
 * OUTSIDE quotes — a separator inside a quoted argument is literal text, so
 * quoting/echoing a command no longer over-splits into fake `git …` statements
 * (#182 residual). Substitutions and subshells stay INSIDE the outer statement
 * so `git -C "$(pwd)" branch -D` is still one invocation; their bodies are
 * walked separately by `collectExecutableBodies`.
 */
function disposerStatements(text: string): string[] {
  const out: string[] = [];
  let cur = '';
  let quote: string | null = null;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '\\' && quote !== "'" && i + 1 < text.length) { cur += c + text[++i]; continue; }
    if (quote) { cur += c; if (c === quote) quote = null; continue; }
    if (c === '"' || c === "'") { quote = c; cur += c; continue; }
    if (c === ';' || c === '&' || c === '|' || c === '\n' || c === '\r') {
      if (cur) out.push(cur);
      cur = '';
      continue;
    }
    cur += c;
  }
  if (cur) out.push(cur);
  return out;
}

/** Scan a `$()` / backtick / `(...)` body. `end` is the closing delimiter index. */
function takeParenBody(text: string, open: number, start: number): { body: string; end: number } {
  let depth = 1;
  let j = start;
  while (j < text.length && depth > 0) {
    const c = text[j];
    if (c === '\\' && j + 1 < text.length) { j += 2; continue; }
    if (c === '"' || c === "'") {
      const q = c;
      j++;
      while (j < text.length && text[j] !== q) {
        if (text[j] === '\\' && q !== "'" && j + 1 < text.length) { j += 2; continue; }
        j++;
      }
      j++;
      continue;
    }
    if (c === '(') depth++;
    else if (c === ')') depth--;
    if (depth > 0) j++;
  }
  return { body: text.slice(open, depth === 0 ? j : text.length), end: j };
}

/**
 * Bodies that the shell actually executes: `$(...)` and backticks (including
 * inside double quotes) and unquoted `(...)` subshells. Single-quoted text is
 * literal and is skipped. Recursing these keeps `echo $(git branch -D x)` and
 * a zx `$`git push --force`` template gated without tearing the OUTER git
 * argv apart.
 */
function collectExecutableBodies(text: string): string[] {
  const out: string[] = [];
  let quote: string | null = null;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '\\' && quote !== "'" && i + 1 < text.length) { i++; continue; }
    if (quote === "'") { if (c === "'") quote = null; continue; }
    if (quote === '"') {
      if (c === '"') { quote = null; continue; }
    } else if (c === "'" || c === '"') {
      quote = c;
      continue;
    }
    // $() / backticks execute in unquoted and double-quoted text.
    if (c === '`') {
      let j = i + 1;
      while (j < text.length && text[j] !== '`') {
        if (text[j] === '\\' && j + 1 < text.length) { j += 2; continue; }
        j++;
      }
      out.push(text.slice(i + 1, j));
      i = j;
      continue;
    }
    if (c === '$' && text[i + 1] === '(') {
      const taken = takeParenBody(text, i + 2, i + 2);
      out.push(taken.body);
      i = taken.end;
      continue;
    }
    // Bare subshells do not run inside quotes.
    if (!quote && c === '(') {
      const taken = takeParenBody(text, i + 1, i + 1);
      out.push(taken.body);
      i = taken.end;
    }
  }
  return out;
}

/**
 * Shared invocation walker for the git disposers (#195, #182). Both the
 * force-push rule and the branch/ref-delete rule PROPOSE on vocabulary; this
 * confirms a genuine `git <subcommand>` INVOCATION and hands (subcommand, args)
 * to `matcher`. One home for the command-position, subcommand-identification and
 * inline-shell recursion logic, so a fix lands for both rules at once.
 *
 * Tokenised (a quoted arg is one token, never a subcommand — kills the prose FP);
 * command-position aware via gitAtCommandPosition (keywords + wrappers, not
 * `echo … git …`); recurses into `bash -c '…'` stepping over value-taking options;
 * fails closed on `eval` and a `$`-hidden verb (returns true — keep the gate).
 */
function gitInvocationDisposer(
  text: string,
  matcher: (sub: string, args: readonly string[]) => boolean,
  depth = 0,
): boolean {
  // A substitution occupying the SUBCOMMAND slot hides the verb the way `$GIT`
  // does — fail closed before the splitter breaks it apart (#codex-P1).
  if (GIT_SUBCOMMAND_SUBSTITUTION.test(text)) return true;
  // Recurse into bodies the shell will execute, then walk the OUTER statement
  // intact. Tearing `$(…)` out of `git -C "$(pwd)" branch -D` used to leave a
  // verb-less fragment; the disposer returned false and the signal was stripped.
  if (depth < MAX_INLINE_RECURSION) {
    for (const body of collectExecutableBodies(text)) {
      if (body && gitInvocationDisposer(body, matcher, depth + 1)) return true;
    }
  }
  // disposerStatements, NOT the blunt splitCommandStatements: a `;`/`&`/`|`
  // inside a quoted argument is literal text, so echoing/quoting a command
  // (`echo "git branch -D && git push -f"`, a PR-comment body) no longer
  // over-splits into fake `git …` statements the disposer would confirm (#182
  // residual).
  //
  // KNOWN RESIDUAL — a `$`-hidden force/delete FLAG is not gated, whether it
  // stands alone (`git push $FORCE` — the proposer never fires, no literal dash)
  // or rides beside a benign literal flag (`git push -v $FORCE` — the proposer
  // fires but the argv parser cannot read the variable's contents). This is not
  // closable without gating the ubiquitous `git push origin $BRANCH` /
  // `git branch -d "$stale"` (indistinguishable after quote-stripping), and it
  // adds no attacker capability: the no-dash form was never gated in any version,
  // so anyone who controls the variable already has that bypass. A `$`-hidden
  // VERB or SUBCOMMAND (`$GIT push -f`, `git $SUB`) IS caught below, and a
  // dangerous `git push $(rm -rf /)` is caught by the rm detector.
  for (const stmt of disposerStatements(text)) {
    if (!/\bgit\b/i.test(stmt)) continue;
    if (/\beval\b/.test(stmt)) return true;                         // reconstitutes a command → keep the gate
    const tokens = tokeniseStatement(stmt);
    // Recurse into an inline shell program (`bash -c '…'`), stepping over any
    // value-taking option so the `-c` is still reached (`bash -O extglob -c …`).
    if (depth < MAX_INLINE_RECURSION) {
      for (let i = 0; i < tokens.length; i++) {
        const b = commandBaseName(tokens[i]);
        if (!/^(?:bash|sh|zsh|ksh|dash|ash)$/.test(b)) continue;
        for (let j = i + 1; j < tokens.length; j++) {
          if (isInlineProgramFlag(b, tokens[j])) {
            if (gitInvocationDisposer(tokens[j + 1] ?? '', matcher, depth + 1)) return true;
            break;
          }
          if (BASH_VALUE_OPTION.test(tokens[j])) { j++; continue; }  // step over its value
          if (!tokens[j].startsWith('-')) break;                    // the script FILE, not inline
        }
      }
    }
    for (let i = 0; i < tokens.length; i++) {
      // A command-position token that is itself an expansion (`$GIT push -f`,
      // `sudo $GIT …`) hides the verb — fail closed (#195 "a variable hides the
      // verb"). A `$` in an ARGUMENT position (`git push origin $BRANCH`) does
      // not reach this and is not gated.
      if (tokens[i].startsWith('$') && gitAtCommandPosition(tokens, i)) return true;
      if (commandBaseName(tokens[i]).toLowerCase() !== 'git') continue;
      if (!gitAtCommandPosition(tokens, i)) continue;
      const sc = gitSubcommandArgs(tokens.slice(i + 1));
      // `git --version` (flags, no subcommand) is not a delete/force — keep
      // scanning. A command-position `git` we cannot parse that still carries a
      // substitution is the torn-argv shape: fail closed rather than strip.
      if (!sc) {
        if (stmt.includes('$') || stmt.includes('`')) return true;
        continue;
      }
      if (sc.sub.includes('$')) return true;   // `git $SUB …` — the subcommand itself is an expansion
      if (matcher(sc.sub, sc.rest)) return true;
    }
  }
  return false;
}

/**
 * True when a statement genuinely invokes `git push` with a force token.
 * Fail-closed on `eval`/`$` (see gitInvocationDisposer).
 */
function gitForcePushInvoked(text: string, depth = 0): boolean {
  return gitInvocationDisposer(
    text,
    (sub, args) => sub === 'push'
      && args.some(a => GIT_FORCE_FLAG.test(a) || (a.startsWith('+') && a.length > 1)),
    depth,
  );
}

const PACKAGE_INSTALLERS = /^(?:npm|yarn|pnpm|bun|pip\d?|pipx|gem|cargo|apt|apt-get|yum|dnf|brew)$/i;
const NPM_FAMILY = /^(?:npm|yarn|pnpm|bun)$/i;
const INSTALL_VERB = /^(?:install|add|i|isntall|isnt|in|ins|inst|insta|instal)$/i;
const GLOBAL_FLAG = /^(?:\-g|--global|--location=global)$/i;

/**
 * Explicit interpreter / process APIs that RUN a string or an argv: python
 * os/subprocess, node child_process, and the bare `exec`/`spawn` family (incl.
 * `.execSync` on a `require('child_process')` result).
 *
 * One home, shared by the global (#386) and system (#387) install disposers, so
 * the two families fail closed on the IDENTICAL sink set rather than drifting
 * apart — which is exactly how #387 happened: the npm rule grew this sink list
 * and the pip/apt rule kept a narrower same-parens regex.
 */
const INTERPRETER_EXEC_SINK = /(?:os\.(?:system|popen)|subprocess\.(?:run|call|Popen|check_call|check_output)|child_process\.(?:exec|execSync|spawn|spawnSync)|\.exec(?:Sync|File|FileSync)?|\.spawn(?:Sync)?|(?:^|[^\w.])(?:exec(?:Sync|File|FileSync)?|spawn(?:Sync)?)\s*\()/i;

/**
 * #386 — install-package-global must be an INVOCATION, not vocabulary.
 * Write-content and shell DATA args often quote package installs in logs
 * (Friday: forensic note after a real deny). Same discipline as
 * gitForcePushInvoked: tokenise, command-position only, recurse into
 * bash -c / os.system string programs; fail closed on eval/$.
 */
function packageInstallGlobalInvoked(text: string, depth = 0): boolean {
  if (depth > MAX_INLINE_RECURSION + 2) return true;
  // Explicit interpreter / process APIs that run a string or argv containing a
  // global install. Order of install vs global flag does not matter.
  // Fail-closed on these sinks: write-time authoring of "run this install" is intent.
  // Sinks: python os/subprocess, node child_process, bare exec/spawn (incl. .execSync after require()).
  if (INTERPRETER_EXEC_SINK.test(text)
      && /\b(?:npm|yarn|pnpm|bun|npx|corepack)\b/i.test(text)
      && /\b(?:install|add|i|isntall|in|ins|inst|insta|instal)\b/i.test(text)
      && /(?:\s-g\b|\s--global\b|--location=global|\bglobal\s+add\b)/i.test(text)) {
    return true;
  }
  // cmd = "…install -g…"; os.system(cmd)  — variable indirection
  if (/(?:os\.system|os\.popen|subprocess\.(?:run|call|Popen|check_call|check_output))\s*\(\s*[A-Za-z_]\w*\s*\)/.test(text)
      && /(?:npm|yarn|pnpm|bun)[^;\n]{0,80}(?:install|add)[^;\n]{0,40}(?:-g|--global|--location=global)/i.test(text)) {
    return true;
  }
  if (depth < MAX_INLINE_RECURSION) {
    for (const body of collectExecutableBodies(text)) {
      if (body && packageInstallGlobalInvoked(body, depth + 1)) return true;
    }
  }
  for (const stmt of disposerStatements(text)) {
    if (!/\b(?:npm|yarn|pnpm|bun|npx|corepack)\b/i.test(stmt)) continue;
    if (/\beval\b/.test(stmt)) return true;
    const tokens = tokeniseStatement(stmt).map(tok => {
      if ((tok.startsWith('"') && tok.endsWith('"')) || (tok.startsWith("'") && tok.endsWith("'"))) {
        return tok.slice(1, -1);
      }
      return tok;
    });
    if (depth < MAX_INLINE_RECURSION) {
      for (let i = 0; i < tokens.length; i++) {
        const b = commandBaseName(tokens[i]);
        if (!/^(?:bash|sh|zsh|ksh|dash|ash)$/.test(b)) continue;
        for (let j = i + 1; j < tokens.length; j++) {
          if (isInlineProgramFlag(b, tokens[j])) {
            if (packageInstallGlobalInvoked(tokens[j + 1] ?? '', depth + 1)) return true;
            break;
          }
          if (BASH_VALUE_OPTION.test(tokens[j])) { j++; continue; }
          if (!tokens[j].startsWith('-')) break;
        }
      }
    }
    for (let i = 0; i < tokens.length; i++) {
      if (tokens[i].startsWith('$') && gitAtCommandPosition(tokens, i)) return true;
      const base = commandBaseName(tokens[i]);
      // npx/corepack often wrap package managers — treat as installer family.
      const isNpmFamily = NPM_FAMILY.test(base) || /^(?:npx|corepack)$/i.test(base);
      if (!isNpmFamily) continue;
      if (!gitAtCommandPosition(tokens, i)) continue;
      const rest = tokens.slice(i + 1);
      const hasInstall = rest.some(a => INSTALL_VERB.test(a));
      const hasGlobal = rest.some((a, idx) =>
        GLOBAL_FLAG.test(a)
        || a === 'global'
        || (a === '--location' && String(rest[idx + 1] ?? '').replace(/^=/, '') === 'global')
      );
      const yarnGlobalAdd = base.toLowerCase() === 'yarn'
        && rest.some((a, idx) => a === 'global' && INSTALL_VERB.test(rest[idx + 1] ?? ''));
      if ((hasInstall && hasGlobal) || yarnGlobalAdd) return true;
    }
  }
  return false;
}

// ── #387: the SYSTEM installer family must fail closed like the npm one ──────
//
// #386 gave `install-package-global` an invocation disposer with an interpreter
// sink (os.system / subprocess / child_process) so a written script that RUNS a
// global install is still gated. `install-package` got the disposer but not the
// sink: it only matched installer+install INSIDE ONE set of parens, so
// `cmd = "apt-get install -y curl"` + `os.system(cmd)` — and every argv-list or
// os.popen spelling — dropped the signal at write time and re-opened the
// write-then-exec lane for apt/brew/gem/cargo/pip. Same shape as the npm side
// here, deliberately: one sink set (INTERPRETER_EXEC_SINK), one vocabulary
// window, no third installer family.

// apt/yum/brew/gem/cargo/pipx have no scoped form — sink + install verb is the
// whole test. Windowed to 80 chars so the verb belongs to THIS installer.
const SYSTEM_INSTALLER_WINDOW_RE = /\b(?:pipx|apt|apt-get|yum|dnf|brew|gem|cargo)\b[^;\n]{0,80}?\b(?:install|add)\b/i;
// pip is read separately because a pip install can be venv-scoped (#89 class 4).
// The capture keeps any path prefix on the pip binary (`.venv/bin/pip`) and the
// trailing window carries the scope flags, which sit AFTER the verb
// (`pip install --target ./vendor x`).
const PIP_INSTALL_WINDOW_RE = /(?:^|[^\w./-])((?:[^\s;\n"'`]+)\/)?pip\d?(?:\.\d+)?(?![\w./-])[^;\n]{0,80}?\binstall\b[^;\n]{0,80}/gi;
const PIP_WINDOW_SCOPE_FLAG_RE = /(?:^|[\s"'])(?:--target|-t|--prefix|--root|--python)(?:=|\s)/i;

/**
 * A pip install on this surface that mutates the HOST, not a venv.
 *
 * `hasUnscopedPipInstall` reads argv and stays authoritative whenever the
 * install IS a shell statement. When a sink hides the argv inside a STRING
 * (`os.system("pip install x")`) the tokeniser sees one opaque token, so the
 * SAME scope proofs are applied to the window instead: an explicit target
 * prefix, a venv-pathed pip binary, or a venv created in the same payload.
 * The #89 class 4 relief has to survive the write path —
 * `.venv/bin/pip install -r requirements.txt` is not a host mutation and must
 * not be re-gated just because the file also contains an exec sink.
 */
function pipInstallMutatesHost(text: string): boolean {
  if (hasUnscopedPipInstall(text)) return true;
  const venvs = venvPrefixesCreatedIn(text);
  PIP_INSTALL_WINDOW_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = PIP_INSTALL_WINDOW_RE.exec(text)) !== null) {
    if (PIP_WINDOW_SCOPE_FLAG_RE.test(m[0])) continue;                // --target/--prefix/--root/--python
    const prefix = (m[1] ?? '').replace(/\/$/, '').replace(/\/bin$/i, '');
    if (prefix) {
      if (VENV_DIR_MARKER.test(prefix)) continue;                     // …/my-venv/bin/pip
      if (venvs.some(v => v === prefix || prefix.endsWith(`/${v.replace(/^\.\//, '')}`) || v === `./${prefix}`)) continue;
    }
    return true;
  }
  return false;
}

/**
 * An interpreter sink on this surface that runs a non-npm install.
 *
 * Sink, installer vocabulary and install verb are read off the whole authored
 * surface, which covers the inline shape (`os.system("apt-get install -y
 * curl")`) AND the variable-indirection shape (`cmd = "apt-get install -y
 * curl"; os.system(cmd)`) with one test — the string and the sink that runs it
 * are authored together either way, at any distance, which is strictly more
 * than a proximity window would catch.
 *
 * #386 relief is intact: a payload with NO sink, that only stores/prints/echoes
 * the install string, never reaches the vocabulary test.
 */
function interpreterSinkRunsInstall(text: string): boolean {
  if (!INTERPRETER_EXEC_SINK.test(text)) return false;
  if (SYSTEM_INSTALLER_WINDOW_RE.test(text)) return true;
  return pipInstallMutatesHost(text);
}

/** True when the surface genuinely INVOKES a package install of any family. */
function packageInstallInvoked(text: string, depth = 0): boolean {
  return packageInstallGlobalInvoked(text, depth) || systemInstallInvoked(text, depth);
}

/**
 * The non-npm half — pip/pipx/apt/apt-get/yum/dnf/brew/gem/cargo. Split out of
 * `packageInstallInvoked` so the write-content proposer (#387) can ask about a
 * SYSTEM install without an npm-global invocation answering for it (that one
 * already proposes its own, louder signal).
 *
 * Same discipline as the global disposer: interpreter sink, then the bodies the
 * shell executes, then tokenised command-position statements; fail closed on
 * `eval` and on a `$`-hidden command word.
 */
function systemInstallInvoked(text: string, depth = 0): boolean {
  if (depth > MAX_INLINE_RECURSION + 2) return true;
  // pip is answered by its own argv walk, wherever it appears: it is the one
  // installer whose scope has to be read off argv (#89 class 4), and it is the
  // one the DANGEROUS table does not carry, so this is also what makes the
  // write path PROPOSE the installs the exec path proposes (#387).
  if (hasUnscopedPipInstall(text)) return true;
  if (interpreterSinkRunsInstall(text)) return true;
  if (depth < MAX_INLINE_RECURSION) {
    for (const body of collectExecutableBodies(text)) {
      if (body && systemInstallInvoked(body, depth + 1)) return true;
    }
  }
  for (const stmt of disposerStatements(text)) {
    if (!/\b(?:pip\d?|pipx|apt|apt-get|yum|dnf|brew|gem|cargo)\b/i.test(stmt)) continue;
    if (/\beval\b/.test(stmt)) return true;
    const tokens = tokeniseStatement(stmt).map(tok => {
      if ((tok.startsWith('"') && tok.endsWith('"')) || (tok.startsWith("'") && tok.endsWith("'"))) {
        return tok.slice(1, -1);
      }
      return tok;
    });
    // `bash -c '…'` / `sh -c '…'` inline programs, stepping over value-taking
    // options so the `-c` is still reached — the global disposer already walks
    // these and the system family was the only one that did not.
    if (depth < MAX_INLINE_RECURSION) {
      for (let i = 0; i < tokens.length; i++) {
        const b = commandBaseName(tokens[i]);
        if (!/^(?:bash|sh|zsh|ksh|dash|ash)$/.test(b)) continue;
        for (let j = i + 1; j < tokens.length; j++) {
          if (isInlineProgramFlag(b, tokens[j])) {
            if (systemInstallInvoked(tokens[j + 1] ?? '', depth + 1)) return true;
            break;
          }
          if (BASH_VALUE_OPTION.test(tokens[j])) { j++; continue; }
          if (!tokens[j].startsWith('-')) break;
        }
      }
    }
    for (let i = 0; i < tokens.length; i++) {
      if (tokens[i].startsWith('$') && gitAtCommandPosition(tokens, i)) return true;
      const base = commandBaseName(tokens[i]);
      // pip/pip3 deliberately excluded here: `restHasInstall` cannot see a venv
      // or `--target` prefix, so confirming pip on the verb alone would re-gate
      // `.venv/bin/pip install -r requirements.txt`. `hasUnscopedPipInstall`
      // above owns it — argv-accurately, including a venv created earlier in
      // the same payload — and reaches inside `bash -c '…'` by recursion.
      if (!PACKAGE_INSTALLERS.test(base) || NPM_FAMILY.test(base) || PIP_TOKEN_RE.test(base)) continue;
      if (!gitAtCommandPosition(tokens, i)) continue;
      if (restHasInstall(tokens.slice(i + 1))) return true;
    }
  }
  return false;
}

function restHasInstall(rest: readonly string[]): boolean {
  return rest.some(a => /^(?:install|add)$/i.test(a));
}

// Short-flag classifiers for a `git branch` delete. A branch flag is a single
// dash cluster and git parses `-df`/`-fd` as delete+force together, so each
// tests for the presence of its letter anywhere in the cluster. Case-sensitive:
// `-D` (canonical force-delete) is distinct from `-d` (safe merged delete).
const GIT_BRANCH_CANON_DELETE = /^-[A-Za-z]*D[A-Za-z]*$/;   // -D, -vD — force-delete of an unmerged branch
const GIT_BRANCH_DELETE_FLAG = /^-[A-Za-z]*d[A-Za-z]*$/;    // -d, -df, -fd
const GIT_BRANCH_FORCE_FLAG = /^-[A-Za-z]*f[A-Za-z]*$/;     // -f, -df, -fd

/**
 * True when a statement genuinely performs a DESTRUCTIVE git delete:
 *   - `git branch` force-delete of an unmerged branch — `-D`, or a delete flag
 *     (`-d`/`--delete`) paired with a force flag (`-f`/`--force`), separated or
 *     clustered (`-df`/`-fd`). A bare `-d`/`--delete` (no force) deletes only a
 *     MERGED branch — git refuses it otherwise — so it is NOT confirmed here.
 *   - `git push` remote-branch delete — `--delete`, or a `:`-prefixed
 *     (empty-source) refspec (`git push origin :main`).
 *
 * The disposer for `git-delete-branch`, same shape and reasoning as
 * gitForcePushInvoked (#195): the regex proposes on vocabulary, this confirms an
 * INVOCATION. Tokenised, so a quoted `-m "git branch --delete --force"` message
 * is ONE token that is never the branch subcommand (kills the prose FP); quote
 * stripping means `git branch "-d" "-f"` reads as the flags git actually sees
 * (kills the quoting evasion). Command-position anchored, recurses into
 * `bash -c '…'`, fails closed on `eval`/`$`.
 */
function gitDeleteBranchInvoked(text: string, depth = 0): boolean {
  return gitInvocationDisposer(
    text,
    (sub, args) => {
      if (sub === 'branch') {
        const hasCanon = args.some(a => GIT_BRANCH_CANON_DELETE.test(a));
        const hasDelete = args.some(a => a === '--delete' || GIT_BRANCH_DELETE_FLAG.test(a));
        const hasForce = args.some(a => a === '--force' || GIT_BRANCH_FORCE_FLAG.test(a));
        return hasCanon || (hasDelete && hasForce);
      }
      if (sub === 'push') {
        return args.some(a => a === '--delete' || (a.startsWith(':') && a.length > 1));
      }
      return false;
    },
    depth,
  );
}

// ── Read-only firewall inspection (issue #193) ───────────────────────────────
//
// `modify-network-firewall` matched the TOOL and never the verb, so `ufw status`,
// `iptables -L`, `firewall-cmd --state` and `netplan get` gated exactly as hard
// as `ufw disable` and `iptables -F`. Reading the firewall's state is what a
// security-monitoring script does sixteen times before breakfast; it changes
// nothing. Hit live on Friday-Mac, where a read-only `--getglobalstate` sweep
// tripped a *modify* rule.
//
// Fail-closed by construction: this returns true only when EVERY firewall
// invocation on the surface is one it positively recognises as read-only. An
// unknown tool, an unparsed shape, a flag not on the list, or no recognised
// invocation at all (the token was in folded source, or behind an expansion)
// all keep the gate.
const FIREWALL_TOOL_RE = /^(?:ip6?tables(?:-(?:save|restore|nft|legacy))?|ufw|nft|netplan|firewall-cmd)$/i;

/** Per tool: does this argv read state without changing it? */
function firewallArgvIsReadOnly(tool: string, args: readonly string[]): boolean {
  const rest = args.filter(a => a !== '');
  switch (tool.toLowerCase()) {
    case 'ufw':
      // `ufw status [verbose|numbered]`, `ufw show …`, `ufw version`.
      return /^(?:status|show|version|--version)$/i.test(rest[0] ?? '');
    case 'nft':
      // `nft list …` / `nft describe …`. Everything else (add/flush/delete) writes.
      return /^(?:list|describe|-v|--version|-h|--help)$/i.test(rest[0] ?? '');
    case 'netplan':
      return /^(?:get|status|info|--version)$/i.test(rest[0] ?? '');
    case 'firewall-cmd':
      // Query flags only. `--permanent`/`--zone=` are modifiers that change
      // nothing on their own, so they are permitted alongside a query — but a
      // single unrecognised flag keeps the gate.
      return rest.length > 0 && rest.every(a =>
        /^--(?:state|list-\S*|get-\S*|query-\S*|info-\S*|permanent|zone=\S*|policy=\S*|version|help)$/i.test(a));
    default: {
      // iptables family. Every flag must be an inspection or a selector; any
      // chain-editing flag (-A -D -I -R -F -X -N -P -Z -E) keeps the gate.
      // `-Z` zeroes counters — a write, however small — so it is NOT here.
      if (rest.length === 0) return false;                    // bare `iptables` prints usage, but do not guess
      let sawList = false;
      for (let i = 0; i < rest.length; i++) {
        const a = rest[i];
        if (!a.startsWith('-')) continue;                     // table / chain name
        if (/^(?:-L|--list|-S|--list-rules)$/i.test(a)) { sawList = true; continue; }
        if (/^(?:-n|--numeric|-v|--verbose|-x|--exact|--line-numbers|-w|--wait)$/.test(a)) continue;
        if (/^(?:-t|--table)$/i.test(a)) { i++; continue; }   // takes a value
        if (/^-[LSnvx]+$/.test(a)) { sawList = /[LS]/.test(a); continue; }   // clustered short flags
        return false;                                         // anything else writes
      }
      return sawList;
    }
  }
}

/** True when every firewall invocation on the surface only READS state. */
function firewallCallsAreReadOnly(text: string): boolean {
  let seen = false;
  for (const stmt of splitCommandStatements(text)) {
    const tokens = tokeniseStatement(stmt);
    if (tokens.length === 0) continue;
    const i = commandWordIndex(tokens);
    if (i >= tokens.length) continue;
    const base = commandBaseName(tokens[i]);
    if (!FIREWALL_TOOL_RE.test(base)) {
      // The tool named anywhere OTHER than command position — an argument, a
      // quoted string, a path — is not an invocation this predicate can vouch
      // for. If it is the only occurrence, `seen` stays false and the gate holds.
      continue;
    }
    seen = true;
    if (!firewallArgvIsReadOnly(base, tokens.slice(i + 1))) return false;
  }
  return seen;
}

function hasUnscopedPipInstall(text: string): boolean {
  if (!/\bpip\d?\b/i.test(text) || !/\binstall\b/i.test(text)) return false;
  const venvs = venvPrefixesCreatedIn(text);
  for (const stmt of splitCommandStatements(text)) {
    const tokens = tokeniseStatement(stmt);
    const start = commandWordIndex(tokens);
    if (start >= tokens.length) continue;
    // `pip install …` or `uv pip install …`.
    let pipAt = start;
    if (/^uvx?$/i.test(commandBaseName(tokens[start])) && tokens[start + 1] === 'pip') pipAt = start + 1;
    const pipMatch = PIP_TOKEN_RE.exec(tokens[pipAt]);
    if (!pipMatch) continue;
    const rest = tokens.slice(pipAt + 1);
    if (!rest.some(t => t === 'install')) continue;
    if (rest.some(t => PIP_SCOPE_FLAG_RE.test(t))) continue;          // explicit target prefix
    const dir = pipMatch[1];                                          // '' for a bare `pip`
    if (dir) {
      const prefix = dir.replace(/\/bin$/i, '');
      if (VENV_DIR_MARKER.test(prefix)) continue;                     // …/my-venv/bin/pip
      if (venvs.some(v => v === prefix || prefix.endsWith(`/${v.replace(/^\.\//, '')}`) || v === `./${prefix}`)) continue;
    }
    return true;
  }
  return false;
}


// ── Container-confined host mutation (issue #128) ──────────────────────────
//
// A package install inside a throwaway container is not host mutation: the
// layer is discarded when the container exits. Blocked live while setting up a
// clean-box install test for our own product — the workflow the rule exists to
// permit, gated by the rule meant to catch host changes.
//
// The downgrade is an ALLOWLIST OF PROOFS, never a denylist of dangers, because
// a container is only a boundary while it is sealed. Any of the following means
// it is not, and the gate stays exactly as it was:
//   --privileged / --cap-add           → host capabilities
//   -v /:… or /etc, /usr, /var, /boot  → the host filesystem is inside
//   --pid/--net/--ipc/--uts=host       → a host namespace is shared
//   chroot / nsenter / mount in the
//     inner command                    → an explicit escape to the host
//   --user root with a host mount      → covered by the mount rule above
// An unrecognised shape is never downgraded.
const CONTAINER_RUN_RE = /\b(?:docker|podman|nerdctl)\s+(?:compose\s+)?run\b/i;
const CONTAINER_ESCAPE_RE = new RegExp([
  '--privileged',
  '--cap-add',
  '--pid\\s*=\\s*host', '--net(?:work)?\\s*=\\s*host', '--ipc\\s*=\\s*host', '--uts\\s*=\\s*host',
  '--userns\\s*=\\s*host',
  // A host bind-mount: -v/--volume/--mount whose SOURCE is the host root or a
  // system directory. A project-relative or $PWD mount is not an escape.
  '(?:^|\\s)(?:-v|--volume)\\s*=?\\s*["\']?/(?:\\s|:|["\']|$)',
  '(?:^|\\s)(?:-v|--volume)\\s*=?\\s*["\']?/(?:etc|usr|bin|sbin|boot|var|lib|root|home|dev|proc|sys)\\b',
  '--mount[^\\s]*\\bsource=/(?:etc|usr|bin|sbin|boot|var|lib|root|home|dev|proc|sys)?\\b',
  // An explicit break-out in the inner command.
  '\\bchroot\\b', '\\bnsenter\\b', '(?<![-\\w])mount\\b',
].join('|'), 'i');

/**
 * True when EVERY statement that carries an install verb is inside a container
 * run that shows no escape marker. One un-contained install anywhere keeps the
 * gate for the whole call — a container run in statement 1 must never launder a
 * host install in statement 2.
 */
/**
 * Every `rm` target in this text is a WORKSPACE-CONFINED path (#170).
 *
 * Danger in a delete is a property of the TARGET, not the verb. `rm -rf /`
 * ends a machine; `rm -rf .next` is the first line of every JavaScript build
 * on earth. Until now `recursive-force-delete` fired on the flags alone, so
 * the guard hard-blocked `cd dashboard && rm -rf .next && npm run build` at
 * the catastrophic tier — no prompt, no appeal. Measured over 2,420 real tool
 * calls (30 Jul – 2 Aug), deletes of build artefacts and scratch directories
 * were the single largest source of denied honest work.
 *
 * That matters more than the inconvenience: an agent taught that denials are
 * noise starts routing around them, and this codebase has already caught one
 * of its own cron workers reaching for the disable switch. Precision IS the
 * security property.
 *
 * Confined means, for EVERY target on the line:
 *   - a relative path that cannot climb out (no leading `/` or `~`, no `..`), or
 *   - a path under a temp root the agent owns.
 * Anything absolute, home-rooted, glob-rooted, or variable-expanded is NOT
 * confined — a `$VAR` could be `/`, and this must never gamble on that.
 *
 * `delete-root-or-home` is a separate, target-aware rule and is deliberately
 * untouched: `rm -rf /`, `~`, `$HOME`, `/etc` all still hard-block through it.
 * This exemption only removes the verb-only signal, never the target one.
 */
// Command position for `rm` is not only "after a statement separator": a
// subshell, a brace group and a command substitution all open one too. The
// original class stopped at `;&|`, so `rm -rf dist && out=$(rm -rf /etc/foo)`
// parsed as ONE confined statement and the substitution's target was never
// examined — a confined delete laundered an unconfined one on the same line
// (measured, #196). Openers are separators for the arg span as well, so the
// substitution's arguments end at its `)` rather than swallowing the rest.
const RM_STATEMENT_RE = /(^|[;&|(){}`\n]|\$\()\s*(?:sudo\s+)?rm\b([^;&|(){}`\n]*)/gi;
// Every occurrence of `rm` as a bare word — the accounting baseline for the
// check below. The lookarounds exclude `rm` inside a path or an identifier
// (`build/rm-cache`, `src/rm/x`), which is not a delete verb at all and must
// not cost the exemption.
const RM_WORD_RE = /(?<![\w./-])rm(?![\w./-])/gi;
/** Beyond this many standalone delete statements the line is not analysable. */
const RM_STATEMENT_SCAN_LIMIT = 64;

type ConfinedCwd =
  | { kind: 'workspace'; rel: string }
  | { kind: 'abs'; path: string }
  | { kind: 'uncertain' };

function joinPathParts(base: string, child: string): string {
  const left = base.replace(/\/+$/, '');
  const right = child.replace(/^\/+/, '');
  if (!left) return `/${right}`;
  if (!right) return left;
  return `${left}/${right}`;
}

/** Darwin /private/tmp is /tmp; /private/var/tmp is /var/tmp. */
function normalizeDarwinTempAliases(p: string): string {
  return p
    .replace(/^\/private\/tmp(?=\/|$)/i, '/tmp')
    .replace(/^\/private\/var\/tmp(?=\/|$)/i, '/var/tmp')
    .replace(/^\/private\/var\/folders(?=\/|$)/i, '/var/folders')
    .replace(/\/{2,}/g, '/');
}

/**
 * Lexical canonical form: `.` segments and duplicate slashes collapsed, no
 * trailing slash, Darwin temp aliases applied. One path has one spelling here,
 * so `./x`, `x`, `x/` and `/tmp/./x` vs `/tmp/x` stop being different strings.
 *
 * `..` is deliberately NOT resolved: a parent segment only means what the
 * filesystem says it means once a symlink is in the path. Callers treat a
 * token containing one as unreadable rather than pretending this walk read it.
 */
function canonicalisePathLexically(p: string): string {
  const absolute = p.startsWith('/');
  const body = p.split('/').filter(seg => seg !== '' && seg !== '.').join('/');
  return normalizeDarwinTempAliases(absolute ? `/${body}` : body);
}

/** A confined temp child, never the temp root itself. */
function isConfinedAbsolute(p: string): boolean {
  const n = normalizeDarwinTempAliases(p).replace(/\/+$/, '');
  const lower = n.toLowerCase();
  return ['/tmp/', '/var/tmp/', '/var/folders/'].some(prefix => lower.startsWith(prefix));
}

/**
 * Resolve existing components (so a symlink parent is followed) and append
 * any missing tail lexically. Returns null on ELOOP / EACCES / special files.
 */
function resolveExistingPrefix(p: string): string | null {
  const trimmed = p.length > 1 ? p.replace(/\/+$/, '') : p;
  const parts = trimmed.split('/').filter(Boolean);
  let current = '';
  for (let i = 0; i < parts.length; i++) {
    const next = `${current}/${parts[i]}`;
    try {
      const st = lstatSync(next);
      if (st.isSymbolicLink()) {
        try { current = realpathSync(next); }
        catch { return null; }
        continue;
      }
      if (!st.isDirectory() && !st.isFile()) return null;
      try { current = realpathSync(next); }
      catch { current = next; }
    } catch (err) {
      const code = (err as NodeJS.ErrnoException | undefined)?.code;
      if (code === 'ENOENT') {
        const rest = parts.slice(i).join('/');
        return current ? `${current}/${rest}` : `/${rest}`;
      }
      return null;
    }
  }
  return current || trimmed;
}

function parseCdDest(stmt: string): string | 'bad' {
  const m = stmt.match(/^\s*cd\b(.*)$/i);
  if (!m) return 'bad';
  const rest = (m[1] ?? '').trim();
  if (!rest) return 'bad';
  const positional = rest.split(/\s+/)
    .map(t => t.replace(/^[\"']|[\"']$/g, ''))
    .filter(t => t && !t.startsWith('-'));
  if (positional.length !== 1) return 'bad';
  const dest = positional[0]!;
  if (dest === '-' || /[$`*?~]/.test(dest) || dest.includes('..')) return 'bad';
  return dest;
}

function applyCdDest(cwd: ConfinedCwd, dest: string): ConfinedCwd {
  if (cwd.kind === 'uncertain') return cwd;
  if (dest.startsWith('/')) return { kind: 'abs', path: dest };
  if (cwd.kind === 'abs') return { kind: 'abs', path: joinPathParts(cwd.path, dest) };
  return { kind: 'workspace', rel: cwd.rel ? joinPathParts(cwd.rel, dest) : dest };
}

/**
 * A statement stripped of the shell furniture that hides a `cd` from a
 * leading-anchor test: the grouping characters a subshell / brace group leaves
 * on the ends (`(cd /`, `{ cd /`) and the two wrappers that still leave `cd`
 * the real command (`builtin cd /`, `command cd /`).
 *
 * Measured on the #339 build: every one of those spellings walked straight past
 * `^cd\b`, so a root-level relative delete kept the workspace cwd and the
 * exemption ALLOWED it — the fail-open direction, one wrapper away from the
 * case #339 had just closed.
 */
function unwrapCdStatement(stmt: string): string {
  let s = stmt.replace(/^[\s(){}]+/, '').replace(/[\s(){}]+$/, '');
  for (let prev = ''; s !== prev; ) {
    prev = s;
    s = s.replace(/^(?:builtin|command)\s+/i, '');
  }
  return s;
}

function isInlineShellStatement(s: string): boolean {
  return /^(?:(?:builtin|command|env|nohup|exec)\s+)*(?:bash|sh|zsh|ksh|dash|ash)\b/i.test(s);
}

/**
 * Nested surfaces a relative delete can hide in: unquoted `(…)` / `$(…)` /
 * backticks, plus `bash -c '…'` (and friends). Missing `-c` program text is
 * unreadable — fail closed. Depth is owned by the caller.
 */
function nestedDeleteSurfaces(text: string): { bodies: string[]; unreadable: boolean } {
  const bodies = collectExecutableBodies(text);
  let unreadable = false;
  for (const stmt of disposerStatements(text)) {
    const tokens = tokeniseStatement(stmt);
    for (let i = 0; i < tokens.length; i++) {
      const base = commandBaseName(tokens[i]!);
      if (!/^(?:bash|sh|zsh|ksh|dash|ash)$/.test(base)) continue;
      for (let j = i + 1; j < tokens.length; j++) {
        if (isInlineProgramFlag(base, tokens[j]!)) {
          const prog = tokens[j + 1];
          if (!prog) unreadable = true;
          else bodies.push(prog);
          break;
        }
        if (BASH_VALUE_OPTION.test(tokens[j]!)) { j++; continue; }
        if (!tokens[j]!.startsWith('-')) break;
      }
    }
  }
  return { bodies, unreadable };
}

// A `cd` / `pushd` / `popd` ANYWHERE in a statement the cd parser could not
// read as a clean destination (`eval "cd /"`, `foo=$(cd /)`, a shell whose
// program is quoted). The directory may have moved and this walk cannot say
// where, so the only honest answer is "uncertain" — which costs the exemption
// rather than betting the cwd is still the workspace. Hyphen excluded from the
// boundary so a hyphenated identifier (`docker-cd-helper`) is not a cd (#188).
const CD_WORD_RE = /(?<![\w-])(?:cd|pushd|popd)(?![\w-])/i;

/** Cwd in effect just before `end`, walking cd / pushd and failing closed on ||. */
function cwdBefore(text: string, end: number): ConfinedCwd {
  const slice = text.slice(0, end);
  let cwd: ConfinedCwd = { kind: 'workspace', rel: '' };
  let quote: string | null = null;
  let stmt = '';
  const flush = (sep: string): void => {
    const s = unwrapCdStatement(stmt);
    stmt = '';
    if (!s) return;
    if (/^pushd\b|^popd\b/i.test(s)) {
      cwd = { kind: 'uncertain' };
    } else if (/^cd\b/i.test(s)) {
      const dest = parseCdDest(s);
      cwd = dest === 'bad' ? { kind: 'uncertain' } : applyCdDest(cwd, dest);
    } else if (CD_WORD_RE.test(s) && !isInlineShellStatement(s)) {
      cwd = { kind: 'uncertain' };
    }
    if (sep === '||' || sep === '|') cwd = { kind: 'uncertain' };
  };
  for (let i = 0; i < slice.length; i++) {
    const c = slice[i]!;
    if (c === '\\' && quote !== "'" && i + 1 < slice.length) {
      stmt += c + slice[++i];
      continue;
    }
    if (quote) {
      stmt += c;
      if (c === quote) quote = null;
      continue;
    }
    if (c === '"' || c === "'") { quote = c; stmt += c; continue; }
    if (c === ';' || c === '&' || c === '|' || c === '\n' || c === '\r') {
      let sep = c;
      if ((c === '&' || c === '|') && slice[i + 1] === c) { sep = c + c; i++; }
      flush(sep);
      continue;
    }
    stmt += c;
  }
  // The leftover statement, with no separator of its own. `rm` is at command
  // position after openers cwdBefore does not split on (`` ` ``, `$(`, `(`), so
  // dropping the tail dropped the `cd` in ``cd / `rm -rf x` `` entirely.
  flush('');
  return cwd;
}

function effectiveDeleteTarget(tok: string, cwd: ConfinedCwd): string | 'uncertain' {
  if (tok.startsWith('/')) return tok;
  if (cwd.kind === 'uncertain') return 'uncertain';
  if (cwd.kind === 'abs') return joinPathParts(cwd.path, tok);
  return cwd.rel ? joinPathParts(cwd.rel, tok) : tok;
}

/**
 * Same-line ln -s / cp -s destinations. Unreadable dest taints the whole line.
 *
 * The mint is identified by ARGV, not by the statement's leading literal: the
 * command word is located with the shared `commandWordIndex` walk, so a
 * path-qualified (`/bin/ln`) or wrapper-fronted (`command ln`, `env FOO=1 ln`,
 * `exec ln`) mint taints exactly like a bare `ln`. Matching the first word made
 * one wrapper word enough to carry a mint straight past this rule (#339) — the
 * same lesson as #188/#193, so it uses the same tokenising machinery rather
 * than a longer list of spellings. `command -v ln` resolves to `ln` but carries
 * no `-s`, so a lookup is still not a mint.
 *
 * The destination is READ OFF THE ARGV, not off the last positional: `ln -s -t
 * DIR SRC` puts the link at `DIR/SRC`, and `-t`'s value is not an operand at
 * all, so the last-positional rule recorded the SOURCE as the destination and
 * left the real link untainted. It is then placed against the cwd in effect at
 * the mint STATEMENT (the same `cwdBefore` walk the deletes use), because
 * `cd /tmp && ln -s … ./x` and `ln -s … /tmp/x` mint the same link. An option
 * shape this walk cannot place is not a proof of anything: fail closed (#339,
 * Athena review).
 */
// The ln / cp option surface, split by whether an option eats the argv word
// after it. Everything outside these tables is a shape this walk cannot place,
// and an unplaced option is what turns a source into a "destination" — so the
// parse fails closed rather than guessing. Long options carrying an OPTIONAL
// value (`--backup`, `--preserve`, `--reflink`, `--update`, `--context`) only
// ever take it as `--name=VALUE`, so they belong with the no-arg forms.
const MINT_LONG_NO_ARG = new Set([
  'symbolic', 'symbolic-link', 'force', 'interactive', 'logical', 'physical',
  'dereference', 'no-dereference', 'no-target-directory', 'relative', 'verbose',
  'directory', 'archive', 'attributes-only', 'copy-contents', 'link', 'no-clobber',
  'parents', 'recursive', 'remove-destination', 'strip-trailing-slashes',
  'one-file-system', 'backup', 'preserve', 'no-preserve', 'reflink', 'sparse',
  'update', 'context', 'help', 'version',
]);
/** Long options whose value is the next argv word when written without `=`. */
const MINT_LONG_ARG = new Set(['target-directory', 'suffix']);
/** Short option letters that take no value, so they bundle in any order. */
const MINT_SHORT_NO_ARG = 'abcdfFhHiLlnpPrRsTuvwxXZ';
/** Short letters whose value is the rest of the bundle, else the next word. */
const MINT_SHORT_ARG = 'tS';

type MintArgv = { targetDir: string | null; positional: string[] };

/**
 * getopt for the mint verbs: operands separated from options, `-t` / `-S`
 * values consumed rather than mistaken for operands. Returns 'unreadable' for
 * every shape it cannot prove — an unknown option (which may or may not eat
 * the next word), a value flag with nothing after it, a second `-t`.
 */
function parseMintArgv(args: readonly string[]): MintArgv | 'unreadable' {
  const positional: string[] = [];
  let targetDir: string | null = null;
  let optionsEnded = false;
  for (let i = 0; i < args.length; i++) {
    const arg = args[i]!;
    if (optionsEnded || arg === '-' || !arg.startsWith('-')) { positional.push(arg); continue; }
    if (arg === '--') { optionsEnded = true; continue; }
    if (arg.startsWith('--')) {
      const eq = arg.indexOf('=');
      const name = (eq < 0 ? arg.slice(2) : arg.slice(2, eq)).toLowerCase();
      if (MINT_LONG_ARG.has(name)) {
        const value = eq < 0 ? args[++i] : arg.slice(eq + 1);
        if (value === undefined) return 'unreadable';
        if (name === 'target-directory') {
          if (targetDir !== null) return 'unreadable';
          targetDir = value;
        }
        continue;
      }
      if (!MINT_LONG_NO_ARG.has(name)) return 'unreadable';
      continue;
    }
    for (let k = 1; k < arg.length; k++) {
      const letter = arg[k]!;
      if (MINT_SHORT_ARG.includes(letter)) {
        const value = k + 1 < arg.length ? arg.slice(k + 1) : args[++i];
        if (value === undefined) return 'unreadable';
        if (letter === 't') {
          if (targetDir !== null) return 'unreadable';
          targetDir = value;
        }
        break;
      }
      if (!MINT_SHORT_NO_ARG.includes(letter)) return 'unreadable';
    }
  }
  return { targetDir, positional };
}

/** The paths a parsed mint creates, as written — 'unreadable' if it cannot say. */
function mintDestSpellings(argv: MintArgv): string[] | 'unreadable' {
  const { targetDir, positional } = argv;
  if (positional.length === 0) return 'unreadable';
  // Two or more operands and no `-t`: the last one names the link. When it is
  // an existing DIRECTORY the link lands underneath it instead, which the
  // prefix test in `mintTaintsTarget` already covers — so the operand as
  // written is the safe over-approximation, and no stat is needed.
  if (targetDir === null && positional.length >= 2) {
    return [positional[positional.length - 1]!];
  }
  // `-t DIR SRC…`, and the one-operand form whose DIR is the cwd: every source
  // is linked as DIR/basename(SRC).
  const dir = targetDir ?? '.';
  const out: string[] = [];
  for (const source of positional) {
    const name = commandBaseName(source.replace(/\/+$/, ''));
    if (!name || name === '.' || /[$`*?~]/.test(name)) return 'unreadable';
    out.push(joinPathParts(dir, name));
  }
  return out;
}

/**
 * A mint destination in the frame the delete targets are judged in: absolute
 * where it can be, workspace-relative while the cwd walk is still in the
 * workspace, 'uncertain' where it cannot be placed at all. A relative dest
 * under a cwd this walk lost is NOT assumed to be in the workspace.
 */
function resolveMintDest(dest: string, cwd: ConfinedCwd): string | 'uncertain' {
  if (!dest || /[$`*?~]/.test(dest) || dest.includes('..')) return 'uncertain';
  const lexical = canonicalisePathLexically(dest);
  if (!lexical) return 'uncertain';
  if (lexical.startsWith('/')) return lexical;
  if (cwd.kind === 'uncertain') return 'uncertain';
  if (cwd.kind === 'abs') return canonicalisePathLexically(joinPathParts(cwd.path, lexical));
  return canonicalisePathLexically(cwd.rel ? joinPathParts(cwd.rel, lexical) : lexical);
}

function symlinkMintTaint(text: string): { all: boolean; dests: string[] } {
  const dests: string[] = [];
  let all = false;
  for (const stmt of quoteAwareStatementSpans(text)) {
    const tokens = tokeniseStatement(stmt.text);
    const cmd = commandWordIndex(tokens);
    const base = commandBaseName(tokens[cmd] ?? '').toLowerCase();
    if (base !== 'ln' && base !== 'cp') continue;
    const args = tokens.slice(cmd + 1);
    // Superset test, deliberately loose: it decides only whether this
    // invocation is a mint AT ALL, so a `cp` with no `-s` never pays for the
    // strict parse below. `--symbolic-link` is cp's spelling of `--symbolic`.
    const symbolic = args.some(a => a.startsWith('--')
      ? /^--symbolic(?:-link)?$/.test(a)
      : a.startsWith('-') && a.includes('s'));
    if (!symbolic) continue;
    const argv = parseMintArgv(args);
    if (argv === 'unreadable') { all = true; continue; }
    const spellings = mintDestSpellings(argv);
    if (spellings === 'unreadable') { all = true; continue; }
    const cwd = cwdBefore(text, stmt.index);
    for (const spelled of spellings) {
      const resolved = resolveMintDest(spelled, cwd);
      if (resolved === 'uncertain') { all = true; continue; }
      dests.push(resolved);
    }
  }
  return { all, dests };
}

/**
 * Does a delete of `target` reach through the minted `dest`?
 *
 * Both sides are canonicalised first. Comparing the spellings as WRITTEN meant
 * a mint could be renamed out of its own taint by a dot segment — `./x` did
 * not taint `x/child`, `/tmp/./x` did not taint `/tmp/x/child` — while naming
 * the very same link (#339, Athena review).
 */
function mintTaintsTarget(target: string, dest: string): boolean {
  const a = canonicalisePathLexically(target);
  const b = canonicalisePathLexically(dest);
  if (!a || !b) return false;
  return a === b || a.startsWith(b.endsWith('/') ? b : `${b}/`);
}

/** At least one statement on the line begins with a standalone delete verb. */
function hasStandaloneRmStatement(text: string): boolean {
  RM_STATEMENT_RE.lastIndex = 0;
  return RM_STATEMENT_RE.test(text);
}

function deleteTargetsAreWorkspaceConfined(text: string, depth = 0): boolean {
  const nested = nestedDeleteSurfaces(text);
  if (nested.unreadable) return false;
  for (const body of nested.bodies) {
    if (!hasStandaloneRmStatement(body)) continue;
    // Budget exhausted. The `bash -c` statement holding this body is exempt
    // from the cd-uncertainty rule (`isInlineShellStatement`) precisely BECAUSE
    // the recursion reads the body — so abandoning the recursion here handed
    // that exemption to a delete nobody analysed, and a third nested `bash -c`
    // could hide `cd /` plus a relative recursive delete (#339). A delete this
    // walk cannot reach is not a proof of confinement: fail closed.
    if (depth >= MAX_INLINE_RECURSION) return false;
    if (!deleteTargetsAreWorkspaceConfined(body, depth + 1)) return false;
  }
  const mint = symlinkMintTaint(text);
  if (mint.all) return false;
  RM_STATEMENT_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  let sawTarget = false;
  let statements = 0;
  while ((m = RM_STATEMENT_RE.exec(text)) !== null) {
    if (++statements > RM_STATEMENT_SCAN_LIMIT) return false;
    const cwd = cwdBefore(text, m.index);
    const args = m[2] ?? '';
    for (const raw of args.split(/\s+/)) {
      const tok = raw.trim().replace(/^["']|["']$/g, '');
      if (!tok || tok.startsWith('-')) continue;
      sawTarget = true;
      if (/[$`*?~]/.test(tok)) return false;
      if (tok.includes('..')) return false;
      if (/^\.[.\/]*$/.test(tok)) return false;
      const effective = effectiveDeleteTarget(tok, cwd);
      if (effective === 'uncertain') return false;
      if (mint.dests.some(d => mintTaintsTarget(effective, d) || mintTaintsTarget(tok, d))) {
        return false;
      }
      if (!effective.startsWith('/')) continue;
      const resolved = resolveExistingPrefix(effective);
      if (resolved === null) return false;
      if (!isConfinedAbsolute(resolved)) return false;
    }
  }
  if (!sawTarget) return false;
  RM_WORD_RE.lastIndex = 0;
  const occurrences = (text.match(RM_WORD_RE) ?? []).length;
  return occurrences === statements;
}

function installsAreContainerConfined(text: string): boolean {
  if (!CONTAINER_RUN_RE.test(text)) return false;
  if (CONTAINER_ESCAPE_RE.test(text)) return false;
  let sawInstall = false;
  for (const segment of quoteAwareStatements(text)) {
    if (!SYSTEM_INSTALL_RE.test(segment)) continue;
    sawInstall = true;
    // The install must sit on the SAME containerised command line, not merely
    // nearby: a quoted mention of a container run in one segment must never
    // launder a bare host install in the next.
    if (!CONTAINER_RUN_RE.test(segment)) return false;
  }
  return sawInstall;
}

/**
 * Split on shell separators that are OUTSIDE quotes.
 *
 * The shared `splitCommandStatements` deliberately splits on every separator
 * regardless of quoting — the fail-safe choice for rules that must not be
 * evaded by quoting. The question here is the opposite one ("is this install
 * part of the container's own command line?"), and for that a separator inside
 * the container runner's quoted program belongs to the CONTAINER, not the host.
 * Kept local so the fail-safe splitter stays exactly as it is.
 */
function quoteAwareStatements(text: string): string[] {
  return quoteAwareStatementSpans(text).map(s => s.text);
}

/**
 * The same split, keeping each statement's OFFSET in the original text. The
 * mint rule needs it: "which directory was this `ln` run from" is a question
 * about the statement's position, and `cwdBefore` answers it by walking the
 * prefix (#339).
 */
function quoteAwareStatementSpans(text: string): Array<{ text: string; index: number }> {
  const out: Array<{ text: string; index: number }> = [];
  let cur = '';
  let start = 0;
  let quote: string | null = null;
  const take = (at: number, part: string): void => {
    if (!cur) start = at;
    cur += part;
  };
  const flush = (): void => {
    if (cur.trim()) out.push({ text: cur, index: start });
    cur = '';
  };
  for (let i = 0; i < text.length; i++) {
    const c = text[i]!;
    if (c === '\\' && quote !== "'" && i + 1 < text.length) {
      take(i, c + text[i + 1]!);
      i++;
      continue;
    }
    if (quote) {
      take(i, c);
      if (c === quote) quote = null;
      continue;
    }
    if (c === '"' || c === "'") { quote = c; take(i, c); continue; }
    if (c === ';' || c === '&' || c === '|' || c === '\n' || c === '\r') { flush(); continue; }
    take(i, c);
  }
  flush();
  return out;
}

// Credential VALUE shapes. Shared by the command-line hint and the folded-
// source hint. These match key material itself, never an identifier.
const SECRET_VALUE_SHAPE = String.raw`sk-[a-z0-9-]{12,}|ghp_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{12,}|xox[baprs]-[A-Za-z0-9-]{10,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`;
// #173: a `secret=` / `password=` assignment is only a hint when the RHS is a
// LITERAL value. `secret = subprocess.run(...)` and `secret=$(op item get …)`
// are names and expansions — matching them punished vault-backed code and
// was evaded by renaming the variable to `cred`. `secret=` (equals) still
// matches the suffix of `client_secret=` so `curl -d client_secret=…`
// stays a command-line value (#185). `secret:` (colon) is word-bounded so
// JSON `"client_secret": varname` is not an assignment. Unquoted literals
// are a single token that is not a call (`subprocess.run` is rejected).
const SECRET_LITERAL_ASSIGNMENT = String.raw`(?:(?:^|[^A-Za-z0-9_])(?:password|secret)["']?\s*:\s*|(?:password|secret)["']?\s*=\s*)(?:["'][^"'\n]{6,}["']|[A-Za-z0-9_+\-/]{6,}(?![A-Za-z0-9_+\-/.(]))`;
const SECRET_HINT = new RegExp(`(?:${SECRET_VALUE_SHAPE}|${SECRET_LITERAL_ASSIGNMENT})`, 'i');
/**
 * The secret hint for FOLDED PROGRAM SOURCE (#175) — credential LITERALS only.
 *
 * Inside program source `secret=` is field VOCABULARY: every OAuth client on
 * earth contains `'client_secret': cfg.secret` next to a `requests.post` to
 * its token endpoint. The command-line hint (#173) is now value-gated the
 * same way for assignments; this regex stays quoted-literals-only because
 * an unquoted token in source is an identifier, not a curl -d value.
 */
const FOLDED_SOURCE_SECRET_HINT = new RegExp(
  `(?:${SECRET_VALUE_SHAPE}|(?:^|[^A-Za-z0-9_])(?:password|secret)["']?\\s*[=:]\\s*["'][^"'\\n]{6,}["'])`,
  'i',
);

/** True when a secret hint in this region is not wholly a comment/string. */
function secretHintExecutedIn(text: string, region: ScanRegion): boolean {
  const hint = region.lang === 'sh' ? SECRET_HINT : FOLDED_SOURCE_SECRET_HINT;
  const slice = text.slice(region.start, region.end);
  const g = new RegExp(hint.source, hint.flags.includes('g') ? hint.flags : `${hint.flags}g`);
  const data = region.lang === 'sh' ? [] : scriptDataRanges(text, region);
  let m: RegExpExecArray | null;
  while ((m = g.exec(slice)) !== null) {
    if (m[0].length === 0) { g.lastIndex++; continue; }
    const a = region.start + m.index;
    const b = a + m[0].length;
    const assignment = /(?:password|secret)["']?\s*[=:]/i.test(m[0]);
    // Value shapes (sk-, ghp_, JWT, PEM) count even inside a string — that
    // string is the credential. An assignment inside a comment or docstring
    // is payload and must not fire (#173). The regex may consume one
    // non-word prefix character (`"""secret =`); classify from the
    // identifier so the opener quote does not poke out of the data range.
    const ident = m[0].search(/(?:password|secret)/i);
    const identStart = a + (ident >= 0 ? ident : 0);
    if (assignment && data.some(([s, e]) => identStart >= s && b <= e)) continue;
    return true;
  }
  return false;
}

const EXTERNAL_EGRESS = /\b(curl|wget|fetch|nc|netcat|scp|rsync|http\.post|requests\.post|fetch\()/i;

// Outbound DATA on a network call (issue #73.2): a read-only GET carries nothing
// off-host, so a docs / releases fetch is not egress. Egress requires an actual
// payload — a non-GET method or a body/data/upload flag. This is what separates
// `web_fetch https://docs.openclaw.ai` (allow) from `curl -X POST … -d @dump`
// (approval). URL text is deliberately NOT scanned for the words post/put so a
// path like `/output` or `/put-item` cannot be mistaken for a write.
const OUTBOUND_DATA_FLAGS =
  /(?:-X|--request)\s*(?:POST|PUT|PATCH|DELETE)\b|(?:^|\s)-d\b|--data(?:-\w+)?\b|--json\b|--form\b|(?:^|\s)-F\b|--upload-file\b|(?:^|\s)-T\b|\bupload\s+to\b/i;

function hasOutboundData(args: Record<string, unknown>, execSurface: string): boolean {
  if (OUTBOUND_DATA_FLAGS.test(execSurface)) return true;
  const method = String((args?.method ?? args?.httpMethod ?? args?.verb) ?? '').toUpperCase();
  if (method && method !== 'GET' && method !== 'HEAD') return true;
  for (const k of ['body', 'data', 'json', 'form', 'payload', 'formData', 'files']) {
    const v = args?.[k];
    if (typeof v === 'string' && v.length > 0) return true;
    if (v && typeof v === 'object') return true;
  }
  return false;
}

function firstMatch(patterns: Pattern[], text: string): string | null {
  for (const p of patterns) if (p.re.test(text)) return p.signal;
  return null;
}
function allMatches(patterns: Pattern[], text: string): string[] {
  return patterns.filter(p => p.re.test(text)).map(p => p.signal);
}

function fmtSpan(s: string): string { return s.trim().replace(/\s+/g, ' ').slice(0, 80); }

/** Like allMatches, but also captures the matched span for actionable reason codes. */
function matchSpans(patterns: Pattern[], text: string): Array<{ signal: string; span: string }> {
  const out: Array<{ signal: string; span: string }> = [];
  for (const p of patterns) {
    const m = text.match(p.re);
    if (m) out.push({ signal: p.signal, span: fmtSpan(m[0]) });
  }
  return out;
}

// ── Span classification (issue #84): mention-vs-intent, generalised ──────────
// The general mechanism that replaces the per-incident FP carve-outs (#71-73):
// before block-vs-warn, classify WHERE a dangerous pattern sits — executed shell
// code vs a quoted DATA argument vs a URL/mention — and drop matches that are
// confidently mentions. Fail-closed by construction: a match is downgraded ONLY
// when it is unambiguously a mention; anything uncertain stays 'executed'. This
// composes with (does not replace) commandScanText's comment/heredoc stripping.
// Raised from 8192 (issue #89): the classifier's whole job is now to tell a
// folded script's SOURCE from a shell command, and a real script is routinely
// larger than 8KB. Everything the cap protects is still bounded — buildSpanCtx
// is one linear pass, classification is a range lookup, and MAX_CLASSIFY_ITERS
// bounds the per-pattern re-scan. Over the cap the guard still fails CLOSED
// (unclassified = executed), so a huge input can only ever gate more, not less.
const SPAN_CLASSIFY_CAP = 32_768;
// A URL token ends at a shell WORD/STATEMENT boundary, not just whitespace —
// `\S+` would swallow a `;`/`&`/`|`-chained executed command straight into the
// "URL" (adversarial review: `curl https://x/a;rm${IFS}-rf${IFS}/`). Excluding
// the shell-active metacharacters keeps the token to the actual URL.
const RE_URL_TOKEN = /https?:\/\/[^\s;&|<>()`'"\\]+/gi;
// `eval` can re-run ANY captured text, wherever it came from, so it stays a
// global fail-closed switch: with `eval` anywhere in the command, no quoted span
// is downgraded. (`x="rm -rf /"; eval $x`.)
//
// The other three reactivators the old blunt `CMD_REACTIVATOR` also tested for —
// `$(…)`, backticks and `$VAR` — are NOT global switches any more (issue #89).
// They disabled the #84 classifier on essentially every real command, because a
// command substitution somewhere in a long compound line has nothing to do with
// whether a quote three statements earlier is data. They are replaced by two
// precise, local rules that cover exactly the same adversarial cases:
//
//   1. A substitution span INSIDE a quote is excised from that quote's data
//      range, so `echo "$(rm -rf /)"` and ``echo "`rm -rf /`"`` stay executed.
//   2. A quote that is itself INSIDE a substitution is never data, so
//      `Y=$(echo "rm -rf /")` — whose output can be re-expanded — stays executed.
//
// A quote in ASSIGNMENT position (`VAR="rm -rf /"`) is likewise never data, so
// `VAR="rm -rf /" && $VAR` stays executed. Together these are strictly tighter
// than the old switch on the adversarial floor and vastly more precise on real
// commands.
const EVAL_REACTIVATOR = /\beval\b/;
// Commands whose QUOTED arguments are pure DATA — they cannot execute the quote.
// This is an ALLOWLIST, deliberately, not a denylist of interpreters: a quote is
// downgraded ONLY when its statement's command word is a recognised data command,
// so a novel/unknown executable defaults to EXECUTED and can never fail open on
// an unrecognised quoted-content runner (`ssh host "…"`, `docker run … sh -c "…"`,
// `su - u -c "…"`, `flock -c "…"`, `chroot … sh -c "…"` all stay executed). Matched
// against the statement prefix after stripping env-assignments/sudo. Extensible —
// the follow-on audit-mined allowlist (#84 rec #5) would feed this set.
// `git grep` / `git log` join the read-only search verbs (issue #89): a pattern
// argument to a searcher is the thing being LOOKED FOR, never run. `sed` and
// `awk` are deliberately excluded — `s///e` and `system()` execute their data.
const DATA_COMMAND = /^(?:grep|egrep|fgrep|zgrep|rg|ripgrep|ag|ack|ug|ugrep|pt|echo|printf|jq|git\s+(?:commit|tag|stash|grep|log)\b)/i;

// Long-form flags whose value is human TEXT, for any command (issue #89 classes
// 3 and 7). `openclaw message send --text "…"`, `gh pr comment --body "…"` and
// `gh issue create --title/--body "…"` were gated — and, for a body quoting
// `rm -rf /`, HARD-DENIED — because the guard scanned the message the operator
// was sending as if it were the command they were running. Issue #89 records
// this class blocking the operator while filing #89 itself.
//
// Only long forms are admitted. Short flags are ambiguous across tools (`-m` is
// python's module selector, docker's memory limit, git's message) and `-d`/`-F`
// carry an actual network payload, which is egress and must stay gated.
const TEXT_FLAG = /(?:^|\s)--(?:text|body|message|comment|description|title|content|caption|note|summary|prompt|subject)(?:=|\s+)$/i;

// A command that can EXECUTE an argument. A text-flag value under one of these
// gets no pass — this is a belt-and-braces denylist on top of the fact that no
// interpreter takes `--text`, so a novel `--text`-accepting executor cannot be
// smuggled in. Matched against the statement's command word.
const EXEC_COMMAND_WORD =
  /^(?:bash|sh|zsh|ksh|dash|ash|python[\d.]*|node|nodejs|ruby|perl|php|eval|exec|source|ssh|scp|docker|podman|kubectl|nsenter|chroot|busybox|xargs|find|flock|watch|make|awk|sed|su|runuser|systemd-run|at|batch)$/i;

// Anything that hands a string to a shell / evaluator from inside interpreter
// source. Deliberately GENEROUS — a false hit here only means the region is
// scanned more strictly (fail-closed), while a miss would let a literal that IS
// executed be dropped. `getattr(`/`__import__` are included because they are the
// standard ways to reach `os.system` without naming it.
const SHELL_OUT_SINK =
  /\bos\.(?:system|popen|exec\w*|spawn\w*)\b|\bsubprocess\b|\bPopen\b|\bpopen\b|\bcheck_(?:call|output)\b|\bgetoutput\b|\bgetstatusoutput\b|shell\s*=\s*True|\bcommands\.\w|\bpty\.\w|\b__import__\b|\bgetattr\s*\(|\b(?:exec|eval)\s*\(|child_process|\bexecSync\b|\bexecFileSync\b|\bspawnSync\b|\bexecFile\b|\bnew\s+Function\b|\bsystem\s*\(|\bqx[({[/]|\bIPC::|%x[({[]|\bshell_exec\b|\bpassthru\b|\bproc_open\b|`/;

/** How each interpreter language delimits comments and string literals. */
interface ScriptLangRules {
  lineComment: readonly string[];
  blockComment?: readonly [string, string];
  /** Quote delimiters, longest first so `"""` wins over `"`. */
  quotes: readonly string[];
  /** Backslash escapes inside these quote delimiters. */
  escapes: boolean;
  /** The language has `/…/flags` regex literals (JS). */
  regexLiterals?: boolean;
}
/** Characters after which a `/` in JS starts a REGEX literal, not a division. */
const JS_REGEX_POSITION = /[=(,:[!&|?{};+\-*%~^<>]$/;
const SCRIPT_LANG_RULES: Record<Exclude<ScriptLang, 'sh'>, ScriptLangRules> = {
  // Ruby/Perl/PHP backticks EXECUTE a shell command, so they are never listed as
  // quote delimiters — their contents stay `executed`, which is the point.
  python: { lineComment: ['#'], quotes: ['"""', "'''", '"', "'"], escapes: true },
  node: { lineComment: ['//'], blockComment: ['/*', '*/'], quotes: ['"', "'", '`'], escapes: true, regexLiterals: true },
  ruby: { lineComment: ['#'], quotes: ['"', "'"], escapes: true },
  perl: { lineComment: ['#'], quotes: ['"', "'"], escapes: true },
  php: { lineComment: ['//', '#'], blockComment: ['/*', '*/'], quotes: ['"', "'"], escapes: true },
};

/**
 * A contiguous slice of the scan surface and what KIND of text it is.
 *
 * `sh` regions are shell command text — every rule in this file is written for
 * them and they are scanned exactly as before. A non-`sh` region is interpreter
 * SOURCE folded in by #138: its lines are not shell statements and its string
 * literals are not commands unless the region shells out.
 */
interface ScanRegion {
  start: number;
  end: number;
  lang: ScriptLang;
  /** The region hands a string to a shell/evaluator somewhere. */
  hasSink: boolean;
  /**
   * The region's text came from a FILE the guard folded in (#138), not from the
   * command the caller wrote. Only these get the catastrophic→dangerous payload
   * downgrade: an inline `python3 -c '…'` / heredoc body is the exec surface the
   * caller authored and is the classic RCE vector, so a shell-out sink there
   * keeps its literals `executed` exactly as before (#84's adversarial floor).
   */
  folded: boolean;
  /**
   * #184 — path of the folded file this region was read from (as invoked /
   * resolved). Absent for inline command / heredoc / -c program regions.
   */
  sourcePath?: string;
  /**
   * #184 — invocation chain from the root command's script to this file,
   * e.g. `scripts/github-backup.sh → resilience/sync-code-backup.sh`.
   */
  chain?: string;
}

/** Comment and string-literal CONTENT ranges inside one interpreter-source region. */
function scriptDataRanges(text: string, region: ScanRegion): Array<[number, number]> {
  if (region.lang === 'sh') return [];
  const rules = SCRIPT_LANG_RULES[region.lang];
  const out: Array<[number, number]> = [];
  let i = region.start;
  const end = region.end;
  const startsWith = (at: number, s: string): boolean => text.startsWith(s, at);

  while (i < end) {
    const lc = rules.lineComment.find(c => startsWith(i, c));
    if (lc !== undefined) {
      const nl = text.indexOf('\n', i);
      const stop = nl < 0 || nl > end ? end : nl;
      out.push([i, stop]);
      i = stop;
      continue;
    }
    if (rules.blockComment && startsWith(i, rules.blockComment[0])) {
      const close = text.indexOf(rules.blockComment[1], i + rules.blockComment[0].length);
      const stop = close < 0 || close > end ? end : close + rules.blockComment[1].length;
      out.push([i, stop]);
      i = stop;
      continue;
    }
    // A JS `/…/flags` regex literal is data too — the operator's own guard-regex
    // probes (`node -e "const re = /curl.*\| *sh/i"`) were being read as the
    // commands they describe. `//` and `/*` are handled above, and the `/` only
    // opens a regex in expression position, so a division is never swallowed.
    if (rules.regexLiterals && text[i] === '/') {
      // Look BACK a bounded number of characters for the preceding token — never
      // slice the whole prefix, which would make this O(n²) over a `/`-dense
      // program (measured: a 20k one-liner of regex literals hung the scan).
      let k = i - 1;
      while (k >= region.start && (text[k] === ' ' || text[k] === '\t' || text[k] === '\n' || text[k] === '\r')) k--;
      const prev = k < region.start ? '' : text[k];
      const isReturn = k >= region.start + 5 && text.startsWith('return', k - 5);
      if (prev === '' || JS_REGEX_POSITION.test(prev) || isReturn) {
        let j = i + 1;
        let inClass = false;
        while (j < end) {
          const c = text[j];
          if (c === '\\') { j += 2; continue; }
          if (c === '\n') break;                       // unterminated — not a regex after all
          if (c === '[') inClass = true;
          else if (c === ']') inClass = false;
          else if (c === '/' && !inClass) break;
          j++;
        }
        if (j < end && text[j] === '/') {
          out.push([i + 1, j]);
          i = j + 1;
          continue;
        }
      }
    }
    const q = rules.quotes.find(d => startsWith(i, d));
    if (q !== undefined) {
      const contentStart = i + q.length;
      let j = contentStart;
      while (j < end) {
        if (rules.escapes && text[j] === '\\') { j += 2; continue; }
        if (startsWith(j, q)) break;
        j++;
      }
      // An unterminated literal runs to the end of the region — treat the rest
      // as literal, which is what the interpreter would report as a syntax error
      // anyway and is the conservative read for a truncated fold.
      out.push([contentStart, Math.min(j, end)]);
      i = Math.min(j + q.length, end);
      continue;
    }
    i++;
  }
  return out;
}

// Precomputed mention regions for one `text`, built ONCE (O(n)) so per-match
// classification is a cheap range lookup — matchAll over a backtracking-prone
// pattern would otherwise re-scan the whole string per match (O(n³), a ReDoS).
interface SpanCtx {
  urls: Array<[number, number]>;        // [start,end) of each http(s) URL token
  dataQuotes: Array<[number, number]>;  // CONTENT ranges (open+1..close) of quotes that are pure data args
  substitutions: Array<[number, number]>; // `$(…)` / backtick spans — executed even inside a data quote
  scriptLiterals: Array<[number, number]>; // comment + string-literal ranges in interpreter-source regions
  /** Literals whose OWN LINE calls a shell-out sink — the argument of an
   *  `os.system(…)` / `execSync(…)` is a command, not a payload. */
  sinkArgLiterals: Array<[number, number]>;
  regions: ScanRegion[];                // non-`sh` regions only; `sh` behaves exactly as before
}
// Per-pattern iteration cap: after this many mention-only occurrences with no
// executed one, fail CLOSED (keep the signal). Bounds worst-case work.
//
// The re-scan is the expensive half of classification — each extra occurrence
// is another `exec` of a bridge-heavy pattern across the whole surface. On a
// short command 64 of those are free; on a 30k quote-dense one they are not
// (measured 472ms before this budget, against ~7ms for the single-match path).
// So the budget SHRINKS as the surface grows. Cutting it early fails CLOSED —
// the signal is kept — so a large input can only ever gate more, never less.
const MAX_CLASSIFY_ITERS = 64;
const MAX_CLASSIFY_ITERS_LARGE = 6;
const LARGE_SURFACE = 8_192;
/** How far back a quote may look for its own command word / text flag. */
const QUOTE_PREFIX_CAP = 512;

function buildSpanCtx(text: string, regions: readonly ScanRegion[] = []): SpanCtx {
  const urls: Array<[number, number]> = [];
  RE_URL_TOKEN.lastIndex = 0;
  let u: RegExpExecArray | null;
  while ((u = RE_URL_TOKEN.exec(text)) !== null) urls.push([u.index, u.index + u[0].length]);

  const scriptRegions = regions.filter(r => r.lang !== 'sh');
  const scriptLiterals: Array<[number, number]> = [];
  const sinkArgLiterals: Array<[number, number]> = [];
  for (const r of scriptRegions) {
    for (const range of scriptDataRanges(text, r)) {
      // A literal that IS a shell-out call's argument stays a command:
      // `os.system('rm -rf /')` is the textbook shape and must keep hard-
      // blocking. Attribution is by line, deliberately — it is the cheap,
      // conservative half of the problem. When it misses (the call split over
      // lines, or the string bound to a variable first) the literal falls back
      // to the payload tier, which still gates; it never becomes an allow.
      const lineStart = Math.max(r.start, text.lastIndexOf('\n', range[0]) + 1);
      let lineEnd = text.indexOf('\n', range[1]);
      if (lineEnd < 0 || lineEnd > r.end) lineEnd = r.end;
      (SHELL_OUT_SINK.test(text.slice(lineStart, lineEnd)) ? sinkArgLiterals : scriptLiterals).push(range);
    }
  }

  // Shell quote/substitution scanning runs over the SHELL regions only — an
  // apostrophe in a Python comment must not open a shell quote that swallows
  // the rest of the surface.
  const shellRanges: Array<[number, number]> = regions.length === 0
    ? [[0, text.length]]
    : regions.filter(r => r.lang === 'sh').map(r => [r.start, r.end] as [number, number]);

  const dataQuotes: Array<[number, number]> = [];
  const substitutions: Array<[number, number]> = [];
  // `eval` can re-run any captured text, so with one present NO quote is data.
  const evalPresent = EVAL_REACTIVATOR.test(text);

  for (const [rangeStart, rangeEnd] of shellRanges) {
    let q: string | null = null;
    let open = -1;
    let stmtStart = rangeStart;
    // Command-substitution nesting. A quote opened at depth > 0 is inside a
    // `$(…)`/backtick whose OUTPUT may be re-expanded, so it is never data.
    let depth = 0;
    const subStack: number[] = [];
    for (let i = rangeStart; i < rangeEnd; i++) {
      const c = text[i];
      // Bash escaping (adversarial review): a `\` OUTSIDE quotes, or inside a
      // DOUBLE quote, escapes the next char — so `\"` opens/closes nothing.
      // (Single quotes take no escapes in bash.) Without this, `echo \"; rm -rf
      // /\"` opened a fake data-quote around the executed `; rm -rf /`.
      if (c === '\\' && (q === null || q === '"')) { i++; continue; }
      // A substitution opens even INSIDE a double quote — that is exactly the
      // `echo "$(rm -rf /)"` case — and single quotes suppress it.
      if (q !== "'" && (text.startsWith('$(', i) || c === '`')) {
        if (c === '`' && depth > 0 && subStack.length > 0 && text[subStack[subStack.length - 1]] === '`') {
          substitutions.push([subStack.pop() as number, i + 1]);
          depth--;
          continue;
        }
        subStack.push(i);
        depth++;
        if (c !== '`') i++;                       // consume the `(` of `$(`
        continue;
      }
      if (c === ')' && depth > 0 && subStack.length > 0 && text[subStack[subStack.length - 1]] !== '`') {
        substitutions.push([subStack.pop() as number, i + 1]);
        depth--;
        continue;
      }
      if (q) {
        if (c === q) {                    // quote closes at i
          // The prefix slice is CAPPED. Without it a single statement carrying
          // thousands of quotes copies its whole head once per quote — O(n²),
          // measured at +145ms on a 30k quote-dense command. A command word
          // more than QUOTE_PREFIX_CAP chars before its own quoted argument
          // cannot be recognised, so that quote simply stays executed: the cap
          // can only ever cost a downgrade, never grant one.
          const prefixStart = Math.max(stmtStart, open - QUOTE_PREFIX_CAP);
          const truncated = prefixStart > stmtStart;
          const prefix = text.slice(prefixStart, open);
          const bare = truncated
            ? ''
            : prefix.replace(/^\s+/, '').replace(/^(?:\w+=\S*\s+)*/, '').replace(/^(?:sudo|doas)\s+/, '');
          // A quote is DATA when, in its own statement:
          //   - the command word is a recognised data command (allowlist), or
          //   - it is the value of a long-form text flag on a non-executor.
          // A quote in command position, in assignment position, inside a
          // command substitution, or after any other command, stays executed.
          const isAssignment = /(?:^|\s)(?:export\s+|local\s+|declare\s+\S+\s+)?\w+(?:\[[^\]]*\])?\+?=$/.test(prefix);
          const isDataCommand = !truncated && DATA_COMMAND.test(bare);
          const isTextFlag = !truncated && TEXT_FLAG.test(prefix)
            && !EXEC_COMMAND_WORD.test(bare.trim().split(/\s+/)[0] ?? '');
          if (!evalPresent && depth === 0 && !isAssignment && (isDataCommand || isTextFlag)) {
            dataQuotes.push([open + 1, i]);
          }
          q = null;
        }
        continue;
      }
      if (c === '"' || c === "'") { q = c; open = i; continue; }
      if (c === ';' || c === '\n' || c === '|' || c === '&' || c === '(') stmtStart = i + 1;
    }
    // An unclosed substitution runs to the end of the range — treat it as open
    // (fail-closed: everything after it is executed, not quoted data).
    while (subStack.length > 0) substitutions.push([subStack.pop() as number, rangeEnd]);
  }
  return { urls, dataQuotes, substitutions, scriptLiterals, sinkArgLiterals, regions: scriptRegions };
}

/**
 * What a matched span IS, which decides what it may contribute:
 *  - `executed`  — real command text. Contributes at its rule's own tier.
 *  - `payload`   — a string literal in interpreter source that DOES shell out
 *                  somewhere. Not proven inert, so never dropped; but not
 *                  command position either, so a catastrophic rule is capped at
 *                  the dangerous tier rather than hard-denying (issue #89).
 *  - `mention`   — confidently inert. Dropped.
 */
type SpanClass = 'executed' | 'payload' | 'mention';

function contains(ranges: ReadonlyArray<[number, number]>, start: number, end: number): boolean {
  for (const [s, e] of ranges) if (start >= s && end <= e) return true;
  return false;
}
function intersects(ranges: ReadonlyArray<[number, number]>, start: number, end: number): boolean {
  for (const [s, e] of ranges) if (start < e && end > s) return true;
  return false;
}

/** Did this match begin by consuming a SHELL command-position anchor? */
function isShellAnchorChar(text: string, at: number): boolean {
  const c = text[at];
  if (c === '\n' || c === '\r' || c === ';' || c === '&' || c === '(') return true;
  return c === '$' && text[at + 1] === '(';
}

/**
 * True when the match at `at` sits in a shell redirect destination
 * (`> path`, `>>"path"`, `>"$HOME/…"`, `1> path`, `2>> path`).
 * Used so path-target signals are not demoted to 'mention' merely because the
 * destination token is quoted (#89 dual-review quoted-redirect hole).
 */
function pathTargetIsRedirectDestination(text: string, at: number): boolean {
  // Path-target match often starts mid-token (`.shieldcortex/...` after
  // `$HOME/` or `/home/u/`). Walk back across path chars and quotes until a
  // redirect operator. Glued forms count, including quoted destinations:
  //   echo>"$HOME/.shieldcortex/approvals/x"
  //   echo>path
  //   printf %s x>>"$HOME/..."
  let i = at - 1;
  if (i >= 0 && (text[i] === '"' || text[i] === "'")) i--;
  while (i >= 0 && /[A-Za-z0-9_./$~{}:-]/.test(text[i]!)) i--;
  while (i >= 0 && (text[i] === ' ' || text[i] === '\t')) i--;
  if (i >= 0 && (text[i] === '"' || text[i] === "'")) i--;
  while (i >= 0 && (text[i] === ' ' || text[i] === '\t')) i--;
  // optional noclobber bar: `>|` / `>>|`
  if (i >= 0 && text[i] === '|') i--;
  if (i < 0 || text[i] !== '>') return false;
  i--;
  if (i >= 0 && text[i] === '>') i--;
  if (i >= 0 && /\d/.test(text[i]!)) i--;
  if (i < 0) return true;
  const c = text[i]!;
  // boundary OR glued to preceding token (echo>path / printf '{}'>path)
  return (
    c === ' ' || c === '\t' || c === ';' || c === '|' || c === '&' || c === '\n'
    || c === '"' || c === "'"
    || /[A-Za-z0-9_./-]/.test(c)
  );
}

function classifyWithCtx(
  ctx: SpanCtx,
  start: number,
  end: number,
  text: string,
  pathTarget = false,
): SpanClass {
  // 1) URL — inert data being fetched; only becomes code via `curl … | bash`,
  //    whose pipe-to-shell pattern's span CROSSES the URL (not contained in it).
  //    Path-target rules keep this exemption: a URL path segment naming
  //    `.shieldcortex/approvals` is a reference, not access.
  if (contains(ctx.urls, start, end)) return 'mention';

  // 1b) Path-target + shell redirect: a quoted (or bare) path that is the
  //     destination of `>` / `>>` IS access, not a data-argument mention.
  //     Without this, `echo x >"$HOME/.shieldcortex/approvals/x.json"` dropped
  //     touch-approval-store at the quoted-data step below (#89 dual-review).
  if (pathTarget && pathTargetIsRedirectDestination(text, start)) return 'executed';

  // 2) Quoted DATA — the span sits fully inside a data-argument quote. A span
  //    crossing a quote boundary (`"rm" -rf /`) is contained in no quote range,
  //    and a span touching a command substitution INSIDE that quote is executed
  //    (`echo "$(rm -rf /)"`). Path-target names inside a pure echo/printf
  //    string stay mentions (reference, not open).
  if (contains(ctx.dataQuotes, start, end) && !intersects(ctx.substitutions, start, end)) return 'mention';

  // 3) Interpreter source (issue #89). Shell regions never reach here.
  //    Path-target rules stop here: naming the path IS the access, whether the
  //    naming happens in shell text or in a string literal a script is about to
  //    hand to open()/json.dump().
  if (pathTarget) return 'executed';
  for (const r of ctx.regions) {
    if (start < r.start || end > r.end) continue;
    // 3a) A comment, or a string literal: not a command unless the region hands
    //     strings to a shell somewhere.
    // A match that merely TOUCHES a literal is treated the same as one wholly
    // inside it. In interpreter source there is no executed shell text outside
    // literals, so a span that straddles a literal boundary — the corpus shape
    // `'git-force-push': r'git push --force'`, one match across two adjacent
    // dict-value literals — cannot be a shell command either.
    // 3a-i) The literal is a shell-out call's own argument — that IS a command.
    if (intersects(ctx.sinkArgLiterals, start, end)) return 'executed';
    if (intersects(ctx.scriptLiterals, start, end)) {
      if (!r.hasSink) return 'mention';
      return r.folded ? 'payload' : 'executed';
    }
    // 3b) A match that CONSUMED a shell command-position anchor is anchored in
    //     the wrong language: inside Python or JS source a newline, `;`, `&` and
    //     `(` are ordinary punctuation, not statement separators. `at =
    //     tok['access_token']` is an assignment and `print(at[:4])` is a call —
    //     neither is at(1). This holds whether or not the region shells out: a
    //     bare source line is never a shell statement.
    //
    //     `|` and `>` are deliberately NOT anchor characters here —
    //     `redirect-to-block-device` is an unanchored rule that legitimately
    //     starts with one.
    if (isShellAnchorChar(text, start)) return 'mention';
    // 3c) #188: bare code matching an UNANCHORED rule (`sudo`, `rm`, `curl`)
    //     used to fall straight through to 'executed'. But a shell verb sitting
    //     in interpreter code position is an identifier, not a command:
    //     `sudo = ["michael", "admin"]` is an assignment, and Python has no way
    //     to execute the name `sudo`. The ONLY route from this region to a shell
    //     is a string handed to a sink — and 3a-i above already classified those
    //     literals 'executed', which is what keeps write-then-exec closed.
    //     So bare code takes exactly the same tiers as a literal (3a): inert
    //     when the region never shells out, demoted to payload when it does and
    //     the source was folded from a file on disk, and unchanged ('executed')
    //     for an inline program the agent wrote into the command itself.
    //     The #138 shell-script parity table is untouched: a folded `.sh` region
    //     is language 'sh' and never enters this loop.
    if (!r.hasSink) return 'mention';
    return r.folded ? 'payload' : 'executed';
  }
  return 'executed';
}

type MatchTier = 'executed' | 'payload';
interface ClassifiedMatch {
  signal: string;
  span: string;
  tier: MatchTier;
  /** #184 — present when the match sits inside a folded file region. */
  source?: string;
  line?: number;
  chain?: string;
}

/**
 * #184 — locate the folded ScanRegion that owns `at` and compute a 1-based
 * line number within that region's text. Inline/heredoc regions have no path.
 */
function provenanceAt(
  text: string,
  at: number,
  regions: readonly ScanRegion[],
): { source?: string; line?: number; chain?: string } {
  for (const r of regions) {
    if (!r.folded || !r.sourcePath) continue;
    if (at < r.start || at >= r.end) continue;
    const before = text.slice(r.start, at);
    const line = before.split('\n').length; // 1-based within region
    return {
      source: r.sourcePath,
      line,
      chain: r.chain ?? r.sourcePath,
    };
  }
  return {};
}

function withProvenance(
  match: { signal: string; span: string; tier: MatchTier },
  text: string,
  at: number,
  regions: readonly ScanRegion[],
): ClassifiedMatch {
  const p = provenanceAt(text, at, regions);
  return p.source ? { ...match, ...p } : match;
}

/** Like matchSpans, but a pattern's signal survives only if at least one of its
 *  occurrences is classified 'executed' or 'payload' — mention-only matches
 *  (URL / quoted data / inert interpreter source) are dropped (#84, #89).
 *  Fail-closed: over the length cap, or if none of the first MAX_CLASSIFY_ITERS
 *  occurrences is a clear mention, the signal is kept as executed. */
/**
 * Rules whose match is a TARGET, not a verb (#89 review, 31 Jul 2026).
 *
 * The interpreter-source downgrade asks "is this span executed shell text?".
 * That is the right question for a verb like `rm` or `curl`, which is only
 * dangerous when it runs. It is the WRONG question for a sensitive path: a
 * script names its target inside a string literal precisely BECAUSE it is
 * about to operate on it — `open('~/.ssh/id_rsa')` is the attack, not a
 * mention of one. Downgrading those to 'mention' reopened the self-approval
 * hole #127 closed (`python3 -c "…json.dump(…approvals.json…)"`).
 *
 * So path-target signals skip the interpreter-source downgrade entirely. They
 * keep the two purely-textual exemptions above it — a path inside a URL, or in
 * a quoted data argument — because those genuinely are references, not access.
 */

// ── #89 read-only inspection of guard-owned stores ───────────────────────────
//
// Live FP (Jarvis 2026-08-14): pure `ls`/`cat` of the approvals store required
// approval — self-referential deadlock on enforced hosts.
//
// Carve-out policy (Grok 4.6 multi-round floor on #292): FAIL CLOSED.
// When ANY statement names a guard store, EVERY statement and EVERY pipeline
// stage in the whole command must be a pure shell observation verb. That
// closes sibling mint (`ls store; python Path.home() writer`), background
// tails (`ls store & python …`), and path-smuggling pipes. Nested exec,
// redirects into the store, and touch-sensitive-path stay gated.

const GUARD_STORE_PATH_RE = /\.shieldcortex[\\/]+(?:approvals\b|DECISIONS\.md\b|leases\b)/i;

/** Verbs that only OBSERVE. No interpreters, editors, find, yq, jq. */
const STORE_READONLY_VERB_RE =
  /^(?:ls|dir|cat|head|tail|less|more|stat|file|wc|grep|egrep|fgrep|rg|ag|ack|realpath|readlink|basename|dirname|test|\[|echo|printf)$/i;

/**
 * Redirect / tee / noclobber. Glued forms (`echo>path`, `echo>$p`) count —
 * no required whitespace before `>`. Fd-to-fd dups (`2>&1`, `>&2`) excluded.
 */
const STORE_MUTATION_RE = new RegExp(
  [
    String.raw`(?:^|[\s;|&])(?:rm|mv|cp|install|tee|truncate|chmod|chown|chgrp|touch|mkdir|rmdir|ln|dd|shred|wipe)\b`,
    // any non-fd-dup redirect: `>`, `>>`, `>|`, glued or spaced
    String.raw`>{1,2}\|?(?!&\d)`,
    // rg --pre can execute a writer
    String.raw`\brg\b[^|\n]*\s--pre\b`,
  ].join('|'),
  'i',
);

/** Nested execution keeps the gate. */
const STORE_NESTED_EXEC_RE = /\$\(|`|<\(|>\(|\beval\b|\bsource\b|\b\.\s+\/|\bfunction\b|[\w.-]+\s*\(\s*\)\s*\{/i;

/**
 * Split on statement separators without treating `2>&1` / `>&` / `|&` as
 * job-control boundaries. Bare `&` (background) IS a boundary.
 */
function splitShellStatements(cmd: string): string[] {
  const out: string[] = [];
  let cur = '';
  for (let i = 0; i < cmd.length; i++) {
    const c = cmd[i]!;
    const n = cmd[i + 1];
    if (c === '\n' || c === ';') {
      if (cur.trim()) out.push(cur);
      cur = '';
      continue;
    }
    if (c === '&' && n === '&') {
      if (cur.trim()) out.push(cur);
      cur = '';
      i++;
      continue;
    }
    if (c === '|' && n === '|') {
      if (cur.trim()) out.push(cur);
      cur = '';
      i++;
      continue;
    }
    // bare `&` background — not `>&` / `2>&1` / `|&`
    if (c === '&') {
      const prev = cur.length ? cur[cur.length - 1] : '';
      if (prev !== '>' && prev !== '|') {
        if (cur.trim()) out.push(cur);
        cur = '';
        continue;
      }
    }
    cur += c;
  }
  if (cur.trim()) out.push(cur);
  return out;
}

/**
 * True when the whole command is pure shell inspection of a guard store.
 * Fail closed on unknown verbs, nested execution, redirects, siblings, and
 * any non-readonly pipeline stage.
 */
export function guardStoreAccessIsReadOnly(text: string): boolean {
  const cmd = String(text || '');
  if (!GUARD_STORE_PATH_RE.test(cmd)) return false;
  if (STORE_MUTATION_RE.test(cmd)) return false;
  if (STORE_NESTED_EXEC_RE.test(cmd)) return false;

  const parts = splitShellStatements(cmd);
  if (parts.length === 0) return false;

  // When any statement names the store, EVERY statement must be readonly.
  for (const raw of parts) {
    const part = raw.trim();
    if (!part) continue;
    let s = part.replace(/^(?:[A-Za-z_][\w]*=([^\s]*)\s+)+/, '');
    s = s.replace(/^sudo\s+(?:-E\s+)?/, '');
    const stages = s.split('|').map(x => x.trim()).filter(Boolean);
    for (const stage of stages) {
      const word = stage.replace(/^(?:[A-Za-z_][\w]*=([^\s]*)\s+)+/, '').split(/\s+/)[0] ?? '';
      const base = word.split('/').pop() ?? word;
      if (!STORE_READONLY_VERB_RE.test(base)) return false;
    }
  }
  return true;
}

const PATH_TARGET_SIGNALS = new Set(['touch-sensitive-path', 'touch-approval-store', 'touch-decisions-ledger']);

/** #342 — interpreter-API recursive-delete call spans (not shell verbs). */
const INTERPRETER_RECURSIVE_DELETE_SPAN =
  /(?:shutil\s*\.\s*rmtree|os\s*\.\s*removedirs|FileUtils\s*\.\s*rm_rf|\brm\s*\(|(?:fs\s*\.\s*)?(?:promises\s*\.\s*)?rm(?:Sync)?\s*\()/i;





/**
 * Byte ranges that came from a folded file in a NON-SHELL language (#165).
 *
 * The DANGEROUS/SENSITIVE rules are written in shell vocabulary — `kill`,
 * `apt-get install`, `sudo`, `.env`. Inside a JavaScript or Python file those
 * are identifiers, properties and string literals, not commands. #160 wired
 * script folding into the Claude Code hook, which pointed those shell rules at
 * arbitrary program source on the surface that gates every Bash call, and the
 * result was that ordinary work stopped: `npm test` gated on a runner
 * containing `process.kill(process.pid, sig)`, and `node dist/index.js` gated
 * because our OWN CLI bundle contains the rule vocabulary in its remedy strings.
 *
 * Folded SHELL source is excluded from this — a `.sh` file really is shell, and
 * `systemctl stop nginx` inside one must still gate. So the distinction is the
 * language of the region, never "was it folded".
 *
 * What is deliberately NOT relaxed: CATASTROPHIC still matches everywhere
 * (that is the write-then-exec threat #160 exists to catch), and any region
 * with a shell-out sink is already treated as a command surface upstream.
 */
function foldedNonShellRanges(regions: readonly ScanRegion[]): Array<[number, number]> {
  return regions
    .filter(r => r.folded && r.lang !== 'sh' && !r.hasSink)
    .map(r => [r.start, r.end] as [number, number]);
}

/** True when EVERY occurrence of `re` in `text` sits inside a folded non-shell region. */
function onlyInFoldedNonShell(re: RegExp, text: string, ranges: Array<[number, number]>): boolean {
  if (ranges.length === 0) return false;
  const g = new RegExp(re.source, re.flags.includes('g') ? re.flags : re.flags + 'g');
  g.lastIndex = 0;
  let m: RegExpExecArray | null;
  let seen = false;
  let guard = 0;
  while ((m = g.exec(text)) !== null && guard++ < 200) {
    seen = true;
    const at = m.index;
    if (!ranges.some(([a, b]) => at >= a && at < b)) return false;   // one outside → keep the signal
    if (m[0].length === 0) g.lastIndex++;
  }
  return seen;
}

function matchSpansClassified(
  patterns: Pattern[],
  text: string,
  regions: readonly ScanRegion[] = [],
): ClassifiedMatch[] {
  const out: ClassifiedMatch[] = [];
  // Fail-closed on huge input: unclassified means executed, so an oversized
  // surface can only ever gate MORE, never less.
  if (text.length > SPAN_CLASSIFY_CAP) {
    return matchSpans(patterns, text).map(m => ({ ...m, tier: 'executed' as const }));
  }
  const ctx = buildSpanCtx(text, regions);
  // On a large surface the re-scan budget is shared across ALL patterns, not
  // spent per pattern — a pipe/quote-dense string makes several patterns
  // backtrack, and k of them each re-scanning is k times the cost.
  let sharedBudget = text.length > LARGE_SURFACE ? MAX_CLASSIFY_ITERS_LARGE : Infinity;
  for (const p of patterns) {
    const m0 = text.match(p.re);
    if (!m0) continue;
    const pathTarget = PATH_TARGET_SIGNALS.has(p.signal);
    // Fast path: the first occurrence is executed → keep immediately (the common
    // case for a real command). Only search further when it's not.
    const s0 = m0.index ?? 0;
    const c0raw = classifyWithCtx(ctx, s0, s0 + m0[0].length, text, pathTarget);
    // #342: interpreter API recursive-delete is the effect, not a mention.
    const c0 = (c0raw === 'mention'
      && p.signal === 'recursive-force-delete'
      && INTERPRETER_RECURSIVE_DELETE_SPAN.test(m0[0]))
      ? 'executed' as const
      : c0raw;
    if (c0 === 'executed') {
      out.push(withProvenance(
        { signal: p.signal, span: fmtSpan(m0[0]), tier: 'executed' },
        text, s0, regions,
      ));
      continue;
    }
    let best: { span: string; tier: MatchTier; at: number } | null =
      c0 === 'payload' ? { span: m0[0], tier: 'payload', at: s0 } : null;
    if (sharedBudget <= 0) {
      // Out of re-scan budget: fail CLOSED — keep the signal at the executed
      // tier rather than spend unbounded time proving it is a mention.
      out.push(withProvenance(
        { signal: p.signal, span: fmtSpan(m0[0]), tier: 'executed' },
        text, s0, regions,
      ));
      continue;
    }
    const g = p.re.global ? p.re : new RegExp(p.re.source, p.re.flags + 'g');
    let iters = 0;
    for (const m of text.matchAll(g)) {
      const s = m.index ?? 0;
      const cRaw = classifyWithCtx(ctx, s, s + m[0].length, text, pathTarget);
      const c = (cRaw === 'mention'
        && p.signal === 'recursive-force-delete'
        && INTERPRETER_RECURSIVE_DELETE_SPAN.test(m[0]))
        ? 'executed' as const
        : cRaw;
      if (c === 'executed') { best = { span: m[0], tier: 'executed', at: s }; break; }
      if (c === 'payload' && best === null) best = { span: m[0], tier: 'payload', at: s };
      sharedBudget--;
      if (++iters >= MAX_CLASSIFY_ITERS || sharedBudget <= 0) {
        best = { span: m[0], tier: 'executed', at: s };
        break;
      }  // fail-closed
    }
    if (best !== null) {
      out.push(withProvenance(
        { signal: p.signal, span: fmtSpan(best.span), tier: best.tier },
        text, best.at, regions,
      ));
    }
  }
  return out;
}

// Remediation hints keyed by signal — turn an opaque "failure policy: deny" into
// an actionable message that names the rule, the matched span, and the fix
// (issue #73 item 5).
const REMEDIATION: Record<string, string> = {
  'pipe-download-to-shell': 'download to a file and inspect it before running (curl -o get.sh URL; less get.sh; sh get.sh)',
  'pipe-download-stdin-exec': 'the inline program executes its stdin, so the fetched bytes still run as code — download to a file and inspect it first',
  'decode-pipe-to-shell': 'the decoded/fetched bytes are executed as code by a bare interpreter — download to a file and inspect it first',
  'pipe-download-module-exec': 'the interpreter module (code/pty/pdb) runs its stdin as code, so the fetched bytes still execute — download to a file and inspect it first',
  'install-package-global': 'human authorisation required — run it yourself in a real terminal, or after a headless deny: shieldcortex approve --denial <actionId> (one-shot retry). Workspace-local install needs no global flag.',
  'install-package': 'human authorisation required — run the install yourself if intended, or shieldcortex approve --denial <actionId> after a headless deny',
  'registry-code-exec': 'review the package + source on the registry before running (npx/bunx/uvx/dlx fetch and execute immediately)',
  'privilege-escalation': 'run the specific privileged step yourself, or approve this exact command from your own terminal with `shieldcortex approve`',
  'external-egress': 'confirm the destination and payload before data leaves the host',
  'git-force-push': 'confirm the branch and remote; a force-push can overwrite others’ work',
  'file-delete': 'confirm the target path before deleting',
  'recursive-find-delete': 'confirm the target path before deleting — this recursively removes every match under it',
  'recursive-perms-system-dir': 'confirm this is intentional — recursive permission changes on a system directory can break the host',
  'truncate-to-zero': 'confirm the target file before truncating — this discards its contents',
  'dd-overwrite': 'confirm the destination before running dd — it overwrites the target without confirmation',
  'opaque-script-invocation': 'the guard could not read the invoked script, so its contents were not scanned — inspect the file before running it',
};

/** Compose a reason string that names the rule, the matched span, and a fix hint. */
function buildReason(
  prefix: string,
  signals: string[],
  span?: string,
  provenance?: { source?: string; line?: number; chain?: string },
): string {
  const parts = [`rule: ${signals.join(', ')}`];
  if (span) parts.push(`matched: "${span}"`);
  // #184: name the folded file + invocation chain when the match is not in the
  // command the operator typed. Without this the EDITH case is unfalsifiable —
  // operator opens github-backup.sh, finds no rm, and concludes the guard is broken.
  if (provenance?.source) {
    const where = provenance.line != null
      ? `${provenance.source}:${provenance.line}`
      : provenance.source;
    if (provenance.chain && provenance.chain !== provenance.source) {
      parts.push(`in: ${where} (via ${provenance.chain})`);
    } else {
      parts.push(`in: ${where}`);
    }
  }
  const hint = REMEDIATION[signals[0]];
  if (hint) parts.push(`fix: ${hint}`);
  return `${prefix} [${parts.join('; ')}]`;
}

/**
 * #184 dual-review: bind the displayed span and the `in:` provenance to the
 * SAME match. Prefer the first match that carries a folded source; otherwise
 * fall back to matches[0] for span-only (inline) evidence.
 */
function reasonEvidence(
  matches: readonly ClassifiedMatch[],
): { span?: string; provenance?: { source?: string; line?: number; chain?: string } } {
  if (matches.length === 0) return {};
  const withSource = matches.find(m => m.source);
  const pick = withSource ?? matches[0];
  const provenance = pick.source
    ? { source: pick.source, line: pick.line, chain: pick.chain }
    : undefined;
  return { span: pick.span, provenance };
}

function matchEvidence(
  matches: readonly ClassifiedMatch[],
): Array<{ signal: string; span: string; source?: string; line?: number; chain?: string }> {
  return matches.map(m => {
    const row: { signal: string; span: string; source?: string; line?: number; chain?: string } = {
      signal: m.signal,
      span: m.span,
    };
    if (m.source) row.source = m.source;
    if (m.line != null) row.line = m.line;
    if (m.chain) row.chain = m.chain;
    return row;
  });
}

// `find <path> -delete` / `find <path> -exec rm …` recursively deletes every
// match under <path> (issue #4475.5). Captures the search root so the caller
// can grade severity with isCriticalPath — the SAME root/home/system-dir/
// wildcard rule used for a structured delete tool's path (see 1a below).
//
// Issue #92 must-fix 1: this used to be ONE regex with a lazy bridge —
// `\bfind\b\s+(\S+)[^|;&\n]*?(?:-delete\b|-exec\s+(?:\/bin\/)?rm\b)/i` — but
// `(\S+)` and the following `[^|;&\n]*?` overlap almost completely (nearly
// every `\S` char is also `[^|;&\n]`), so a long separator-free string with
// no matching action forces the engine to retry the trailing scan at every
// possible split point of `(\S+)` — quadratic (measured 40k chars → 2.1s).
// Replaced with two cheap, non-overlapping boolean checks (find token
// present, delete action present) before ever extracting a path — no shared
// backtracking surface, so there is nothing to blow up.
const FIND_TOKEN_RE = /\bfind\b/i;
const FIND_DELETE_ACTION_RE = /-delete\b|-exec\s+(?:\/bin\/)?rm\b/i;
const FIND_PATH_RE = /\bfind\b\s+(\S+)/i;

/**
 * Cheap replacement for the old single lazy-bridged FIND_DELETE_RE. Scoped
 * per-statement (split on the same `|;&\n` boundaries the rest of this file
 * uses) so an unrelated `find` and `-delete` mention in two different
 * statements don't collide into a false match; the path is only extracted
 * from a statement that already carries both signals, and `\S+` in
 * FIND_PATH_RE has nothing conflicting after it, so it can't backtrack.
 */
function matchFindDelete(text: string): { 0: string; 1: string } | null {
  if (!FIND_TOKEN_RE.test(text) || !FIND_DELETE_ACTION_RE.test(text)) return null;
  for (const stmt of text.split(/[|;&\n]/)) {
    if (FIND_TOKEN_RE.test(stmt) && FIND_DELETE_ACTION_RE.test(stmt)) {
      const pathMatch = stmt.match(FIND_PATH_RE);
      if (pathMatch) return { 0: stmt.trim(), 1: pathMatch[1] };
    }
  }
  return null;
}

/** A path whose deletion is catastrophic: root, home, a top-level system dir, or a wildcard. */
export function isCriticalPath(path: string): boolean {
  const p = String(path || '').trim();
  if (!p) return false;
  if (/^(\/|~|\.|\*)$/.test(p)) return true;                    // /  ~  .  *
  if (/^(\/\*|~\/?\*|\.\/\*|\$HOME\/?\*?)$/.test(p)) return true; // /*  ~/*  ./*  $HOME
  if (/\*/.test(p) && p.length <= 3) return true;                // bare wildcard-ish
  if (/^\/(etc|usr|bin|sbin|boot|var|lib|lib64|sys|proc|root|dev|home|opt|srv)(\/?$|\/\*)/.test(p)) return true;
  if (/^~\/?$/.test(p) || /^\$HOME\/?$/.test(p)) return true;
  return false;
}

// npx/bunx narrowing (issue #92 must-fix, ALSO item — advisor-reviewed
// boundary, see PR #92 must-fix notes). npx/bunx resolve node_modules/.bin
// locally FIRST, so `npx tsc`, `npx jest`, `npx eslint`, `npx prettier` — and
// any other bare (or bare-scoped, unversioned) package name — overwhelmingly
// run an already-installed dev tool, not a live registry fetch. Gating every
// invocation was pure approval-noise. Only gate the shapes that are an
// EXPLICIT remote fetch:
//   - an auto-confirm / explicit-install flag: -y/--yes/-p/--package/-c/
//     --call/--registry/--ignore-existing;
//   - a version/tag pin: any `@` NOT at the start of its token is a version
//     delimiter (`tsc@5.4.0`, `@scope/pkg@next`) — the leading `@` of a
//     scoped package (`@angular/cli`) is the only "safe" `@` and is not a pin
//     by itself;
//   - an explicit URL / git ref / relative path / tarball.
// uvx (always creates a fresh ephemeral env — no local-bin reuse) and
// `pnpm/yarn dlx` (an explicit fetch-and-run subcommand) get no such pass;
// they are matched unconditionally by the DANGEROUS patterns above.
const NPX_BUNX_COMMAND_RE = /(?:^|[;&|(\n]|\$\()\s*(?:\w+=\S*\s+)*(?:sudo\s+)?(?:npx|bunx)\b/i;
/** npx's OWN flags that mean "fetch this from the registry and run it". */
const NPX_GATE_FLAG_RE = /^(?:-y|--yes|-p|--package(?:=.*)?|-c|--call(?:=.*)?|--registry(?:=.*)?|--ignore-existing)$/i;
/** npx flags that consume the FOLLOWING token as their value. */
const NPX_FLAG_TAKES_VALUE = /^(?:--node-arg|--shell|--userconfig|--cache|--npm)$/i;
// A non-whitespace char immediately followed by `@` is a version/tag pin —
// the leading `@` of a scope marker is always preceded by whitespace/start-
// of-string, so it never matches here.
const NPX_VERSION_PIN_RE = /\S@[\w.-]/;
const NPX_REMOTE_REF_RE = /^(?:github:|git\+|https?:\/\/|file:|\.{1,2}\/)|\.tgz$/i;

/**
 * Advance past env assignments, transparent process wrappers (and their own
 * flags / assignments / duration args) and shell keywords to the index of the
 * statement's real command word. Shared by `detectScriptInvocation` and
 * `isGatedNpxBunx` so both agree on what "command position" means.
 */
function commandWordIndex(tokens: readonly string[]): number {
  let i = 0;
  while (i < tokens.length) {
    const t = tokens[i];
    if (/^\w+=/.test(t) || SHELL_KEYWORD.test(t)) { i++; continue; }
    const wrapper = commandBaseName(t);
    if (!EXEC_WRAPPER.test(wrapper)) break;
    const takesValue = WRAPPER_FLAG_TAKES_VALUE[wrapper];
    i++;
    while (i < tokens.length) {
      const a = tokens[i];
      if (/^\w+=/.test(a) || /^\d+[smhd]?$/.test(a)) { i++; continue; }
      if (a.startsWith('-')) { i++; if (takesValue?.test(a)) i++; continue; }
      break;
    }
  }
  return i;
}

/**
 * npx / bunx: gate only a genuine REMOTE FETCH (issue #89 class 2).
 *
 * The previous implementation pattern-matched the whole statement for `-p`,
 * `-c` and `./…`. Those are npx's own options ONLY BEFORE the package spec —
 * after it they belong to the binary npx runs. So `npx tsc --noEmit -p
 * tsconfig.json` read tsc's project flag as npx's `--package`, and `npx tsx
 * ./probe.mts` read tsx's script argument as a relative package ref. Both are
 * type-checking / dev-tool runs off `node_modules/.bin`, and both were the
 * top registry-code-exec false positive in the live corpus.
 *
 * npx's argv is `npx [options] <spec> [args…]` — options run until the first
 * non-option token, which is the package spec. So walk it: gate flags are
 * looked for in the OPTION region, version pins and remote refs in the SPEC
 * only, and everything after the spec is ignored.
 *
 * Uses `commandWordIndex`, which also admits the transparent wrappers
 * (`timeout`, `env`, `nohup`, `sudo`, …). That closes a false NEGATIVE the old
 * command-position regex had: `timeout 30 npx -y pkg@latest` was not gated at all.
 */
function isGatedNpxBunx(text: string): boolean {
  if (!NPX_BUNX_COMMAND_RE.test(text) && !/\b(?:npx|bunx)\b/i.test(text)) return false;
  for (const stmt of splitCommandStatements(text)) {
    const tokens = tokeniseStatement(stmt);
    let i = commandWordIndex(tokens);
    if (i >= tokens.length) continue;
    if (!/^(?:npx|bunx)$/i.test(commandBaseName(tokens[i]))) continue;
    i++;
    for (; i < tokens.length; i++) {
      const t = tokens[i];
      if (!t.startsWith('-') || t === '-') break;      // first non-option token = the spec
      if (NPX_GATE_FLAG_RE.test(t)) return true;
      if (NPX_FLAG_TAKES_VALUE.test(t)) i++;
    }
    if (i >= tokens.length) continue;                  // bare `npx` — nothing is run
    const spec = tokens[i];
    if (NPX_VERSION_PIN_RE.test(spec) || NPX_REMOTE_REF_RE.test(spec)) return true;
  }
  return false;
}

function looksExternal(url: string, text: string): boolean {
  const hay = `${url} ${text}`;
  // An external host that isn't localhost / private RFC1918.
  if (/\b(localhost|127\.0\.0\.1|0\.0\.0\.0|::1|10\.\d|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)\b/i.test(hay)) return false;
  return /https?:\/\/[a-z0-9.-]+\.[a-z]{2,}/i.test(hay) || /[a-z0-9.-]+\.[a-z]{2,}\b/i.test(url);
}

// ── Use/mention discipline for shell commands ────────────────────────────────
// A dangerous token inside a real shell command is only an *action* if it sits
// in command position. If it is merely printed (`echo "rm -rf /"`) or commented
// (`# rm -rf /`) it is inert. We recognise those two unambiguous inert forms and
// refuse to recognise anything that could re-activate text — operators,
// redirection, command substitution, `eval`, or variable expansion.
//
// We deliberately DON'T strip quoted spans wholesale: `"rm" -rf /` quotes the
// command name yet still executes, so blanket quote-removal would be a bypass.
// Fail-safe by construction — when in doubt, the original command text is scanned.
//
// \n and \r are statement separators too (issue #4475.1): a literal newline in
// the command string acts exactly like `;` in a real shell (`echo x\nrm -rf /`
// runs `echo x` THEN `rm -rf /`), but isPurePrint only ever checked the FIRST
// token. Without \n\r here, that second, real statement was silently treated as
// part of a "pure print" and never scanned at all.
const SHELL_REACTIVATORS = /[;&|><`\n\r]|\$\(|\$\{|\$\w|\beval\b/;

/** A command whose sole effect is to print its arguments (cannot execute them). */
function isPurePrint(cmd: string): boolean {
  const c = cmd.trim();
  if (SHELL_REACTIVATORS.test(c)) return false;            // chaining / redirect / expansion → not pure
  const body = c.replace(/^(?:\w+=\S*\s+)*/, '').replace(/^sudo\s+/, '');
  return /^(?:echo|printf)\b/.test(body);
}

/** Strip `#` comments so a token mentioned only in a comment is not an action. */
function stripComments(cmd: string): string {
  return cmd.replace(/(^|\s)#[^\n]*/g, '$1 ');
}

// Interpreters that EXECUTE a heredoc body they read. If one of these introduces
// a heredoc, the body is code and must stay scanned (see stripQuotedHeredocs).
const HEREDOC_INTERPRETER = /\b(?:bash|sh|zsh|ksh|dash|python\d?|perl|ruby|node|php)\b/i;

/**
 * The file a heredoc intro/opener writes its body to, if any: `> file`, `>> file`,
 * or `tee [-a] file`. Returns the bare target token (quotes stripped) or null.
 * Ignores fd redirects (`2>`, `>&2`) and process substitution (`>(`).
 */
function heredocOutputFile(text: string): string | null {
  const redir = text.match(/(?<![>&\d])>>?\s*(['"]?)([^\s'"|;&()<>]+)\1/);
  if (redir) return redir[2];
  const tee = text.match(/\btee\b\s+(?:-\w+\s+)*(['"]?)([^\s'"|;&()<>]+)\1/);
  if (tee) return tee[2];
  return null;
}

/**
 * Which of `files` are invoked as an interpreter/`source` target somewhere in
 * `cmd` — `sh x.sh`, `bash ./run`, `. p.sh`, `python3 /tmp/p.py` — in command
 * position. The command-position anchor (start / `;` / `|` / `&` / `(` /
 * newline) stops the `.sh` in a filename from reading as the `sh` interpreter,
 * and `(?![\w.])` keeps the match to the whole filename token (`x.sh` ≠
 * `x.shrc`).
 *
 * All candidates are resolved in ONE pass over `cmd` via a combined
 * alternation, rather than one `new RegExp` + full rescan of `cmd` per file.
 * The latter made a command with k heredocs cost O(k × length(cmd)) — issue
 * #86-redos measured 125-236ms for 789 heredocs over a 50k-char command
 * (2ms pre-#86), and evaluateToolCall is synchronous on every tool call, so
 * that stalled the event loop. This is O(length(cmd)) regardless of k.
 */
function findInterpreterRunFiles(cmd: string, files: readonly string[]): Set<string> {
  const found = new Set<string>();
  const candidates = [...new Set(
    files
      .map(f => f.replace(/^['"]/, '').replace(/['"]$/, ''))
      .filter(f => f.length >= 2),
  )];
  if (candidates.length === 0) return found;

  const alternation = candidates
    .map((f, i) => `(?<f${i}>${f.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')})`)
    .join('|');
  const re = new RegExp(
    `(?:^|[\\n;|&(])\\s*(?:sudo\\s+)?(?:bash|sh|zsh|ksh|dash|python\\d?|perl|ruby|node|php|source|\\.)\\s+[^\\n;|&]*(?:${alternation})(?![\\w.])`,
    'g',
  );
  let m: RegExpExecArray | null;
  while ((m = re.exec(cmd)) !== null) {
    if (m.groups) {
      for (let i = 0; i < candidates.length; i++) {
        if (m.groups[`f${i}`] !== undefined) {
          found.add(candidates[i]);
          break;
        }
      }
    }
    if (m[0].length === 0) re.lastIndex++; // never spin forever on a zero-length match
  }
  // #194 — the alternation above matches the candidate ANYWHERE on an
  // interpreter's command line, so a file merely NAMED as an argument to some
  // OTHER program read as "the interpreter runs this file". `node
  // scripts/run-jest.mjs src/zz.test.ts` and `python3 -m pytest tests/test_x.py`
  // both kept their heredoc bodies scanned, which is the write-a-test-then-run-
  // it workflow: a fixture full of danger vocabulary, hard-blocked at the
  // catastrophic tier with no prompt. Blocked this box's own investigation
  // twice inside ten minutes.
  //
  // Program position is already defined once, in `detectScriptInvocations` —
  // which skips flags, understands `-c`/`-m`/`-e` inline programs, and recurses
  // into `bash -c`. Reuse it rather than write a second, divergent definition
  // (the recurring root cause in this file is a rule implemented twice).
  // Intersecting NARROWS `found`, so this can only ever keep more bodies inert;
  // the saturation guard below is what stops that being a bypass.
  if (found.size > 0) {
    const invoked = detectScriptInvocations(cmd);
    // Detection is capped (MAX_DETECTED_SCRIPTS). At the cap it may not have
    // reached a later real invocation, so trust the wider regex and keep every
    // body scanned — fail closed.
    if (invoked.length < MAX_DETECTED_SCRIPTS) {
      const runsFile = (candidate: string): boolean => invoked.some(({ path }) =>
        path === candidate
        || path.endsWith(`/${candidate}`)
        || candidate.endsWith(`/${path}`)
        || path === `./${candidate}`);
      for (const f of [...found]) if (!runsFile(f)) found.delete(f);
    }
  }
  return found;
}

/**
 * Neutralise the bodies of QUOTED heredocs (`<<'EOF'` / `<<"EOF"`).
 *
 * A quoted delimiter means the body is passed literally, unexpanded — it is a
 * data payload for its consumer (documentation for `gh issue create`, JSON for
 * `cat`/`jq`), never executed. Scanning that body for command patterns is a
 * mention-not-intent false positive: the jarvis `gh issue create` incident quoted
 * a `curl … | bash` example in the issue body via a heredoc (issue #71).
 *
 * Fail-safe by construction — the body stays scanned for the two re-activation
 * vectors, so this can never become a bypass:
 *   - an interpreter that itself reads the heredoc (`bash <<'EOF' … EOF`)
 *   - `eval` anywhere in the command (it can re-run captured heredoc text)
 */
const QUOTED_HEREDOC_RE = /(<<-?\s*(['"])([A-Za-z_]\w*)\2[^\n]*\n)([\s\S]*?)(\n[ \t]*\3\b)/g;

function stripQuotedHeredocs(cmd: string): string {
  if (!/<<-?\s*['"]/.test(cmd)) return cmd;      // no quoted heredoc → nothing to do
  if (/\beval\b/.test(cmd)) return cmd;          // re-activation risk → keep the body

  // Pass 1 (cheap, single scan): collect every file each heredoc's opener
  // redirects to (issue #86.2), so pass 2 below can resolve "does anything
  // else in this command execute that file" ONCE for all of them together —
  // see findInterpreterRunFiles for why that matters.
  const candidateFiles: string[] = [];
  for (const m of cmd.matchAll(QUOTED_HEREDOC_RE)) {
    const offset = m.index ?? 0;
    const lineStart = cmd.lastIndexOf('\n', offset) + 1;
    const introLine = cmd.slice(lineStart, offset);
    if (HEREDOC_INTERPRETER.test(introLine)) continue; // interpreter consumes it → not a candidate
    const outFile = heredocOutputFile(introLine + m[1]);
    if (outFile) candidateFiles.push(outFile);
  }
  const executedFiles = findInterpreterRunFiles(cmd, candidateFiles);

  return cmd.replace(
    QUOTED_HEREDOC_RE,
    (match: string, opener: string, _q: string, _delim: string, _body: string, closer: string, offset: number, whole: string) => {
      const lineStart = whole.lastIndexOf('\n', offset) + 1;
      const introLine = whole.slice(lineStart, offset);
      if (HEREDOC_INTERPRETER.test(introLine)) return match; // interpreter consumes it → keep
      // Two-step write-then-execute (issue #86.2): the body is redirected/tee'd to
      // a file that a LATER segment of the same compound command executes. The body
      // is code again, not inert data — keep it scanned. File-linked so a doc
      // heredoc written then `git add`/`cat`'d (no interpreter on it) still strips.
      const outFile = heredocOutputFile(introLine + opener);
      const cleanOutFile = outFile && outFile.replace(/^['"]/, '').replace(/['"]$/, '');
      if (cleanOutFile && executedFiles.has(cleanOutFile)) return match;
      return opener + closer;                                 // drop the inert body
    },
  );
}

/**
 * The text of a shell command that is actually *executed*, for danger scanning.
 * Returns '' for a pure print; neutralises quoted-heredoc bodies and comments
 * otherwise; never trusts quote removal (see note above) so it cannot be evaded
 * by quoting a command name.
 */
export function commandScanText(cmd: string): string {
  if (!cmd) return '';
  if (isPurePrint(cmd)) return '';
  return stripComments(stripQuotedHeredocs(cmd));
}

// ── Script-file invocation (issue #4) ────────────────────────────────────────
//
// Every rule above scans the EXEC SURFACE — the command string. So moving a
// dangerous command into a file and running `bash script.sh` bypassed all of
// them: the guard never read the file. (Confirmed live: a `curl -X DELETE`
// loop was blocked inline as `external-egress`, then ran ungated from a `.sh`.)
//
// The fix is a recognition helper (below) plus an INJECTED source resolver
// (`ToolGuardOptions.resolveScriptSource`) that the caller supplies. This file
// stays pure and synchronous — see the evaluateToolCall docblock for why that
// is load-bearing — and the fs-backed resolver lives at the interceptor / hook
// boundary. When no resolver is available, the invocation is still RECORDED
// (`opaque-script-invocation`, lowest surfaced tier) rather than silently
// unscanned: the gap becomes legible in the audit log instead of invisible.

/** Interpreters that take a SCRIPT FILE argument and execute its contents. */
const SCRIPT_INTERPRETER = /^(?:bash|sh|zsh|ksh|dash|ash|python\d?(?:\.\d+)?|node|nodejs|ruby|perl|php)$/;
/** Transparent process wrappers — they don't change WHAT is executed. Same set
 *  (plus `timeout`/`setsid`) as the modify-scheduler command-position rule. */
const EXEC_WRAPPER = /^(?:sudo|doas|env|nohup|time|stdbuf|nice|command|exec|setsid|ionice|timeout)$/;
/** Shell keywords that may sit in front of the real command word. */
const SHELL_KEYWORD = /^(?:then|else|elif|do|done|fi|in|\{|\}|!)$/;
/** Flags that consume the FOLLOWING token as their value (so it is not a path). */
const FLAG_TAKES_VALUE = /^(?:-o|-O|-X|-W|-r|--require|--rcfile|--init-file|--loader|--experimental-loader)$/;
/** Per-wrapper flags that take a separate value token — without these,
 *  `sudo -u bob bash run.sh` reads `bob` as the command word and the real
 *  interpreter is never seen. */
const WRAPPER_FLAG_TAKES_VALUE: Record<string, RegExp> = {
  sudo: /^-(?:u|g|p|C|D|R|T|h)$/,
  doas: /^-(?:u|C)$/,
  env: /^-(?:u|C|S)$/,
  timeout: /^-(?:s|k)$/,
  nice: /^-n$/,
  ionice: /^-(?:c|n|p)$/,
  stdbuf: /^-(?:i|o|e)$/,
};

/**
 * The language a folded script is executed as (issue #89).
 *
 * `sh` means "shell" — every rule in this file is written for shell command
 * text, so a `sh` region is scanned exactly as the command string is, and this
 * whole mechanism is a no-op for it. The other languages are INTERPRETER SOURCE:
 * their lines are not shell statements and their string literals are not
 * commands unless they reach a shell-out sink.
 */
export type ScriptLang = 'sh' | 'python' | 'node' | 'ruby' | 'perl' | 'php';
export interface DetectedScript { path: string; lang: ScriptLang; }

function langFromInterpreter(base: string): ScriptLang {
  if (/^python/.test(base)) return 'python';
  if (/^node/.test(base)) return 'node';
  if (base === 'ruby') return 'ruby';
  if (base === 'perl') return 'perl';
  if (base === 'php') return 'php';
  return 'sh';
}

function langFromPath(path: string): ScriptLang {
  const ext = /\.([a-z0-9]+)$/i.exec(path)?.[1]?.toLowerCase();
  switch (ext) {
    case 'py': case 'pyw': return 'python';
    case 'js': case 'mjs': case 'cjs': case 'ts': case 'mts': case 'cts': return 'node';
    case 'rb': return 'ruby';
    case 'pl': case 'pm': return 'perl';
    case 'php': return 'php';
    default: return 'sh';           // fail-closed: unknown ⇒ scanned as shell
  }
}

/** A path token worth resolving: explicitly relative/absolute/home-anchored. */
function looksLikePathToken(tok: string): boolean {
  return /^(?:\.{1,2}\/|\/|~\/)/.test(tok) && !/^\/dev\//.test(tok);
}

// Recognised executable INSTALL roots (issue #199). An extensionless file in
// one of these, invoked in command position, is an installed CLI — a Homebrew
// or npm shim whose body names its package manager by construction. Folding it
// read the launcher's plumbing as the operator's intent and denied a service
// restart as a global install; the class covers essentially every installed
// CLI on macOS.
//
// The boundary is the bare-name symmetry: `openclaw gateway restart` never
// folds (a bare command word is not a path token), so relieving the SPELT
// path of the same executable adds zero exposure — anything that could plant a
// malicious file in these roots could equally plant it on $PATH, where the
// guard never looked. Everything outside the relief stays folded: files WITH
// an extension (`/usr/local/bin/backup.sh` is a parked script, not a shim),
// project-local `./bin/…` dirs (exactly what folding exists for), and any file
// executed BY an interpreter (`bash /opt/homebrew/bin/x` runs it AS a script).
const INSTALLED_BIN_DIR_RE = new RegExp(
  '^(?:'
  + '/usr(?:/local)?/s?bin'                                  // /usr/bin /usr/sbin /usr/local/(s)bin
  + '|/s?bin'                                                // /bin /sbin
  + '|/opt/(?:homebrew|local)/s?bin'                         // Homebrew ARM / MacPorts
  + '|/(?:opt/homebrew|usr/local)/opt/[^/]+/s?bin'           // Homebrew keg-only …/opt/<pkg>/bin
  + '|/(?:opt/homebrew|usr/local)/Cellar/[^/]+/[^/]+/s?bin'  // Homebrew Cellar
  + '|/snap/bin'
  + '|/home/linuxbrew/\\.linuxbrew/s?bin'
  + '|(?:~|/home/[^/]+|/Users/[^/]+)/\\.(?:npm-global/bin|local/bin|cargo/bin|volta/bin|asdf/shims|nvm/versions/node/[^/]+/bin)'
  + '|(?:.*/)?node_modules/\\.bin'
  + ')/[^/]+$',
);

/** An extensionless executable in a recognised install root — see #199 above. */
function isInstalledBinaryPath(tok: string): boolean {
  return INSTALLED_BIN_DIR_RE.test(tok) && !/\.[A-Za-z0-9]+$/.test(commandBaseName(tok));
}

/** Does an interpreter flag mean "the program is inline / on stdin", not a file? */
function isInlineProgramFlag(interp: string, flag: string): boolean {
  const cluster = /^-[A-Za-z]+$/.test(flag) ? flag.slice(1) : '';
  if (/^(?:bash|sh|zsh|ksh|dash|ash)$/.test(interp)) {
    // Lowercase `c` in a short cluster is always -c (the uppercase -C is
    // noclobber); `s` is "read the program from stdin".
    return cluster.includes('c') || cluster.includes('s');
  }
  if (/^python/.test(interp)) return cluster.includes('c') || cluster.includes('m');
  if (/^node/.test(interp)) return /^(?:-e|-p|--eval|--print)$/.test(flag);
  if (/^(?:perl|ruby)$/.test(interp)) return cluster.toLowerCase().includes('e');
  if (interp === 'php') return cluster.includes('r');
  return false;
}

/** Split shell text into candidate statements. Command substitution, subshells
 *  and backticks open a new statement, exactly like `;`. */
function splitCommandStatements(text: string): string[] {
  return text.replace(/\$\(|[`()]/g, '\n').split(/[;&|\n\r]+/);
}

/**
 * Whitespace-split a statement into argv-ish tokens, keeping quoted spans
 * together. Hand-rolled (not a regex) so it is linear and cannot backtrack —
 * this runs on every tool call, on strings up to OVERSIZED_COMMAND_LENGTH.
 */
function tokeniseStatement(stmt: string): string[] {
  const out: string[] = [];
  let cur = '';
  let quote: string | null = null;
  for (let i = 0; i < stmt.length; i++) {
    const c = stmt[i];
    if (c === '\\' && quote !== "'" && i + 1 < stmt.length) { cur += stmt[++i]; continue; }
    if (quote) {
      if (c === quote) quote = null;
      else cur += c;
      continue;
    }
    if (c === '"' || c === "'") { quote = c; continue; }
    if (c === ' ' || c === '\t') { if (cur) { out.push(cur); cur = ''; } continue; }
    cur += c;
  }
  if (cur) out.push(cur);
  return out;
}

/** `/usr/bin/python3` → `python3`; quotes already stripped by the tokeniser. */
function commandBaseName(tok: string): string {
  const slash = tok.lastIndexOf('/');
  return slash >= 0 ? tok.slice(slash + 1) : tok;
}

const MAX_DETECTED_SCRIPTS = 8;
/** How deep to look inside `sh -c '…'` strings for a nested file invocation. */
const MAX_INLINE_RECURSION = 2;

/**
 * Paths of script FILES this command executes — the targets whose contents the
 * danger rules never saw before.
 *
 * Recognised shapes: `bash f.sh` (with intervening short flags, `bash -e f.sh`),
 * `python3 f.py` / `node f.js` / `ruby f.rb` / `perl f.pl`, `./f.sh` and other
 * explicit relative/absolute paths in command position, `source f.sh` / `. f.sh`,
 * and all of the above behind env-assignment / `env` / `sudo` / `nohup`-style
 * wrapper prefixes.
 *
 * Deliberately NOT recognised: `bash -c '<inline>'`. That inline program is
 * already part of the exec surface and already scanned — treating it as a file
 * would be both wrong and a resolver dead-end. (A file invocation *nested*
 * inside the inline string is still recognised, by recursing into it.)
 */
export function detectScriptInvocation(execSurface: string, depth = 0): string[] {
  return detectScriptInvocations(execSurface, depth).map(s => s.path);
}

/**
 * As `detectScriptInvocation`, but also reports which LANGUAGE each script is
 * executed as (issue #89). The language decides how the folded contents are
 * scanned: a shell script's lines are shell statements, a Python or JS file's
 * lines are not — see `SCRIPT_LANG_RULES` and `buildSpanCtx`.
 */
export function detectScriptInvocations(execSurface: string, depth = 0): DetectedScript[] {
  const found: DetectedScript[] = [];
  if (!execSurface || depth > MAX_INLINE_RECURSION) return found;

  const surface = maskSinkFreeInlinePrograms(execSurface);

  const add = (p: string, lang?: ScriptLang): void => {
    const clean = p.trim();
    if (!clean || clean === '-' || /^https?:\/\//i.test(clean)) return;
    const resolved = lang ?? langFromPath(clean);
    // De-duplicate on path AND language. Keying on path alone discarded a
    // SECOND invocation of the same file by a different interpreter, so
    // `node p.mjs` followed by `bash p.mjs` reported only `node` — which the
    // #217 region carve then trusted, relabelling a shell script as JavaScript
    // and turning a catastrophic block into an allow. Keeping both is strictly
    // more entries and every consumer treats extra invocations as more
    // dangerous, not less, so this only ever moves fail-closed.
    if (found.some(f => f.path === clean && f.lang === resolved)) return;
    if (found.length >= MAX_DETECTED_SCRIPTS) return;
    found.push({ path: clean, lang: resolved });
  };

  for (const stmt of splitCommandStatements(surface)) {
    if (found.length >= MAX_DETECTED_SCRIPTS) break;
    if (!stmt.trim()) continue;
    const tokens = tokeniseStatement(stmt);

    const i = commandWordIndex(tokens);
    if (i >= tokens.length) continue;

    const cmd = tokens[i];
    const base = commandBaseName(cmd);

    // `source f.sh` / `. f.sh` — always read BY THE SHELL, whatever the suffix.
    if (base === 'source' || cmd === '.') {
      const target = tokens[i + 1];
      if (target && !target.startsWith('-')) add(target, 'sh');
      continue;
    }

    if (SCRIPT_INTERPRETER.test(base)) {
      const lang = langFromInterpreter(base);
      for (let j = i + 1; j < tokens.length; j++) {
        const a = tokens[j];
        if (a === '-') break;                                   // program on stdin
        if (a === '<') continue;                                // `bash < f.sh`
        if (a.startsWith('<')) { add(a.slice(1), lang); break; }
        if (a.startsWith('>')) break;                           // redirect target, not a program
        if (a.startsWith('-')) {
          if (isInlineProgramFlag(base, a)) {
            // The inline program itself is already in the exec surface (and
            // already scanned); only follow a file invocation NESTED in it.
            if (/^(?:bash|sh|zsh|ksh|dash|ash)$/.test(base)) {
              for (const nested of detectScriptInvocations(tokens[j + 1] ?? '', depth + 1)) add(nested.path, nested.lang);
            }
            break;
          }
          if (FLAG_TAKES_VALUE.test(a)) j++;
          continue;
        }
        add(a, lang);
        break;
      }
      continue;
    }

    // `./f.sh`, `/opt/deploy/run`, `~/bin/task` — the kernel picks the
    // interpreter from the shebang, which the guard cannot see, so fall back to
    // the extension and default to shell (the fail-closed choice: shell is the
    // language every rule is written for). An installed CLI's shim is the one
    // exception (#199): its body is the launcher's plumbing, not the operator's
    // command, and the bare-name spelling of the same call never folds at all.
    if (looksLikePathToken(cmd) && !isInstalledBinaryPath(cmd)) add(cmd);
  }
  return found;
}

/** Per-file read cap. Larger than any hand-written script; a file over it is
 *  treated as opaque rather than truncated — truncating could cut past a danger
 *  signal, the same reasoning as OVERSIZED_COMMAND_LENGTH below. */
const MAX_SCRIPT_BYTES = 262_144;
/** Total folded content per tool call — the global bound on worst-case scan
 *  work, so the guard can never stall the host gateway (zeroth law). Measured
 *  on the ARM box: a full 256KB fold costs ~22ms of synchronous scanning; a
 *  real-world script (a few KB) is sub-millisecond. */
const MAX_FOLDED_BYTES = 262_144;
/** A script that invokes a script is followed, bounded. */
const MAX_SCRIPT_DEPTH = 3;
/** Backstop on how many files one tool call may fold. */
const MAX_SCRIPTS_PER_CALL = 12;

export interface ToolGuardOptions {
  /**
   * Resolve an invoked script path to its source text, or `null` when it cannot
   * be read. Supplied by the CALLER (interceptor / hook), never by this module —
   * that is what keeps `evaluateToolCall` pure and synchronous. Must never throw
   * and must never block (see the interceptor's fs-backed implementation).
   */
  resolveScriptSource?: (scriptPath: string) => string | null;
  /**
   * The reviewed-script allowlist check (#189). Given the path a command
   * invokes and the EXACT source text the resolver just returned for it,
   * answer whether a human has pinned this script — path AND content hash —
   * as reviewed (`shieldcortex allowlist add`). A reviewed file's source is
   * not folded into the scan surface: its content is human-vouched, and any
   * edit changes the hash and re-gates it on the next call.
   *
   * Same purity contract as `resolveScriptSource`: supplied by the caller,
   * must never throw, judged here as strict `=== true` so a confused
   * predicate (undefined, a promise, a truthy object) reads as "not
   * reviewed" — the allowlist can only ever fail closed. The COMMAND LINE
   * that invokes the script is always still scanned in full; review relieves
   * the file body only, never the invocation.
   */
  isReviewedScript?: (scriptPath: string, source: string) => boolean;
}

interface ScriptFold {
  /** Scan-ready text of every script whose source was resolved. */
  content: string;
  /** A script invocation was recognised but its contents could NOT be folded. */
  opaque: boolean;
  /** Byte ranges of `content` and the language each was folded from (issue #89). */
  regions: ScanRegion[];
  /** Paths whose source was exempted by the reviewed-script allowlist (#189) —
   *  surfaced on the verdict so every audit row shows review was exercised. */
  reviewed: string[];
}

/**
 * Resolve the scripts a command invokes and return their (comment-stripped)
 * contents for scanning. Bounded on every axis: depth, file count, per-file
 * size, total size, and a visited set that makes a source-cycle terminate.
 */
function foldScriptSources(
  execCommand: string,
  resolveScriptSource?: (scriptPath: string) => string | null,
  isReviewedScript?: (scriptPath: string, source: string) => boolean,
): ScriptFold {
  const roots = detectScriptInvocations(execCommand);
  if (roots.length === 0) return { content: '', opaque: false, regions: [], reviewed: [] };
  if (typeof resolveScriptSource !== 'function') return { content: '', opaque: true, regions: [], reviewed: [] };

  const visited = new Set<string>();
  // #184: carry the invocation chain so a nested match can name every hop.
  const queue: Array<{ path: string; lang: ScriptLang; depth: number; chain: string[] }> =
    roots.map(r => ({ path: r.path, lang: r.lang, depth: 1, chain: [r.path] }));
  const parts: string[] = [];
  const regions: ScanRegion[] = [];
  const reviewed: string[] = [];
  let total = 0;
  let cursor = 0;                                       // offset of the next part within `content`
  let opaque = false;

  while (queue.length > 0) {
    const next = queue.shift();
    if (!next) break;
    if (visited.has(next.path)) continue;              // cycle guard
    visited.add(next.path);
    if (visited.size > MAX_SCRIPTS_PER_CALL) { opaque = true; break; }

    let src: string | null = null;
    try {
      src = resolveScriptSource(next.path);
    } catch {
      src = null;                                       // a resolver must never break the call
    }
    if (typeof src !== 'string') { opaque = true; continue; }   // missing / unreadable
    if (src.length === 0) continue;                     // empty file — nothing to scan, not a gap
    if (src.includes('\0')) { opaque = true; continue; }        // binary
    if (src.length > MAX_SCRIPT_BYTES || total + src.length > MAX_FOLDED_BYTES) { opaque = true; continue; }

    // Reviewed-script allowlist (#189): checked HERE, against the exact bytes
    // just resolved — hash-then-fold on the same read, so there is no window
    // for the file to change between "verified" and "scanned" (the TOCTOU
    // that would exist if a CLI verified the hash up front). Strict `=== true`
    // and exception-swallowing keep a broken predicate indistinguishable from
    // "not reviewed". The file is skipped WITHOUT setting `opaque`: this is a
    // human's explicit decision, not a scan gap — but it is recorded, so an
    // audit row can never show a clean scan that silently omitted a file.
    // Review is PER FILE, never transitive. The pin's whole contract is
    // "path + content hash — any edit re-gates", and that can only hold for
    // bytes something actually hashes. This arm used to `continue` past the
    // nested-invocation queue below, so a reviewed SHELL script's children
    // were neither folded nor pinned: review a wrapper once and it
    // permanently exempted a mutable subtree.
    //
    // That is #93's write-then-exec with a human's review supplying the key —
    // an agent drops a payload into an unpinned helper, then runs the
    // reviewed parent that calls it, and nothing ever scans the payload.
    //
    // So a reviewed file still skips folding its OWN source (that is the #189
    // relief, intact), but its children are still discovered and folded
    // unless they are themselves pinned. Exempting a whole toolchain means
    // pinning each file in it — explicit, and each one re-gates on edit.
    //
    // Skipped WITHOUT setting `opaque`: this is a human's explicit decision,
    // not a scan gap — but it is recorded, so an audit row can never show a
    // clean scan that silently omitted a file.
    let isReviewed = false;
    if (typeof isReviewedScript === 'function') {
      try {
        isReviewed = isReviewedScript(next.path, src) === true;
      } catch {
        isReviewed = false;
      }
      if (isReviewed) reviewed.push(next.path);
    }

    // `commandScanText` only strips SHELL constructs (pure prints, `#` comments,
    // quoted heredocs). For interpreter source those are the wrong rules — a `#`
    // comment strip is harmless, but a Python `'…#…'` literal must not lose its
    // tail — so non-shell sources are folded verbatim and classified instead.
    // Computed even for a reviewed file, because its children still have to be
    // discovered from it.
    const reviewedScan = next.lang === 'sh'
      ? commandScanText(deobfuscateIfs(src))
      : deobfuscateIfs(src);
    if (isReviewed) {
      const nestedOfReviewed = next.lang === 'sh' ? detectScriptInvocations(reviewedScan) : [];
      if (nestedOfReviewed.length > 0) {
        if (next.depth >= MAX_SCRIPT_DEPTH) opaque = true;
        else for (const n of nestedOfReviewed) {
          if (!visited.has(n.path)) {
            queue.push({ path: n.path, lang: n.lang, depth: next.depth + 1, chain: [...next.chain, n.path] });
          }
        }
      }
      continue;
    }

    const scan = reviewedScan;
    total += src.length;
    if (parts.length > 0) cursor += 1;                  // the '\n' join separator
    regions.push({
      start: cursor,
      end: cursor + scan.length,
      lang: next.lang,
      hasSink: SHELL_OUT_SINK.test(scan),
      folded: true,
      // #184: path + chain so a match inside this region names its origin.
      sourcePath: next.path,
      chain: next.chain.join(' → '),
    });
    cursor += scan.length;
    parts.push(scan);

    // A non-shell script's own text is not a shell command line, so only a shell
    // region can name the next script to follow.
    const nested = next.lang === 'sh' ? detectScriptInvocations(scan) : [];
    if (nested.length > 0) {
      if (next.depth >= MAX_SCRIPT_DEPTH) opaque = true;         // depth exceeded — say so
      else for (const n of nested) {
        if (!visited.has(n.path)) {
          queue.push({ path: n.path, lang: n.lang, depth: next.depth + 1, chain: [...next.chain, n.path] });
        }
      }
    }
  }

  return { content: parts.join('\n'), opaque, regions, reviewed };
}

// ── Interpreter heredocs (issue #89) ─────────────────────────────────────────
//
// `stripQuotedHeredocs` neutralises a heredoc body that nothing executes. A body
// an INTERPRETER consumes is deliberately kept — it is code — but it is that
// interpreter's code, not shell. `python3 - <<'PY' … PY` is a Python program:
// its `PATTERNS = {'recursive-force-delete': r'rm -rf'}` is a dict of strings and
// its `at = tok['access_token']` is an assignment. Locate those bodies so the
// span classifier can treat them as the interpreter source they are.
/**
 * Writing a FILE is a sink too, once the body's language is being trusted (#217).
 *
 * `SHELL_OUT_SINK` knows process sinks. A written-then-executed body that only
 * writes a file looks inert to it, so its literals get masked as data — but
 *
 *     cat > gen.mjs <<'EOF'
 *     writeFileSync('/tmp/g.sh', 'rm -rf /');
 *     EOF
 *     node gen.mjs && bash /tmp/g.sh
 *
 * is the write-then-execute threat (#160) one level deeper: the literal IS the
 * command, it just travels via a file. Caught by the must-not-break fixture
 * while building the #217 fix, which had made this exact case allow.
 *
 * Deliberately broad and used ONLY on this path. A false "has sink" costs
 * nothing but the pre-#217 behaviour — the body stays scanned as shell, which
 * is what it did before — whereas a miss re-opens #160.
 */
const FILE_WRITE_SINK =
  /\bwriteFile(?:Sync)?\b|\bappendFile(?:Sync)?\b|\bcreateWriteStream\b|\bfs\.write|\bwriteSync\b|\bopenSync\s*\(|\bopen\s*\([^)]*['"](?:[wax]\+?|r\+)['"]|\bwrite_text\b|\bwrite_bytes\b|\bos\.(?:write|open)\b|\bshutil\.(?:copy|move)\w*|\bfile_put_contents\b|\bIO\.write\b|\bFile\.write\b|\bFile\.open\s*\([^)]*['"][wax]/;

/**
 * The executed file's OUTPUT escaping into the shell — a pipe, or a redirect
 * into anything but a discard.
 *
 * The sink test above is BODY-local, and that is only half the threat. What
 * matters is where the process's output GOES:
 *
 *     cat > g.mjs <<'EOF'
 *     console.log("<destructive command>");
 *     EOF
 *     node g.mjs | bash
 *
 * has no sink token in the body at all — the pipe IS the sink, and it lives in
 * the surrounding shell. Same for `>> ~/.zshrc`, `| tee -a`, and
 * `> gen.sh && bash gen.sh`. Each is the #160 write-then-execute threat with
 * the literal travelling by stdout instead of by file, and each was a
 * catastrophic block before #217 relaxed this path.
 *
 * A discard (`> /dev/null`, `2>/dev/null`) or a genuine fd-to-fd redirect
 * (`2>&1`) is exempt: it discards or re-points diagnostics rather than
 * carrying the output anywhere, and `node probe.mjs 2>/dev/null` is exactly
 * the shape #217 exists to keep relieved. An fd NUMBER prefix alone (`1>`,
 * `2>`) is not exempt — `1>/tmp/x.sh` and `2>/tmp/x.sh` write to a real file
 * exactly like a bare `>`, just with the fd spelled out.
 */
/**
 * Write targets that cannot become executable content. Everything else is
 * assumed to be able to — including a path we cannot see.
 *
 * A file write is only a sink when what it writes can later RUN. Gating on
 * "does something else in this command run a script" was wrong twice over: it
 * missed a body appending to `~/.zshrc` (executed at the next login, outside
 * this command entirely), and it fired on a probe writing `/tmp/report.json`
 * because `detectScriptInvocations` had parsed the report path out of the body
 * text as a spurious invocation.
 *
 * Default-armed, relaxed only on proof: the write is inert only when EVERY
 * path-shaped literal in the body carries a data extension.
 */
const INERT_WRITE_TARGET =
  /\.(?:json|jsonl|ndjson|txt|md|csv|tsv|log|ya?ml|xml|html?|png|jpe?g|svg|lock)$/i;

/** Write-sink function names. Arguments are extracted by a tiny balanced
 * scanner below, not by `[^)]*`: nested helper calls such as
 * `writeFileSync(resolve('/tmp/report.json'), '/tmp/stage2')` must not truncate
 * the call at `resolve(...)` and accidentally let a later non-inert argument
 * disappear.
 */
const WRITE_CALL_NAME_RE =
  /\b(writeFile(?:Sync)?|appendFile(?:Sync)?|createWriteStream|fs\.write\w*|writeSync|openSync|open|write_text|write_bytes|os\.(?:write|open)|shutil\.(?:copy|move)\w*|file_put_contents|IO\.write|File\.write|File\.open)\s*\(/g;

type WriteCall = { name: string; args: string | null };

function writeCalls(body: string): WriteCall[] {
  const out: WriteCall[] = [];
  WRITE_CALL_NAME_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = WRITE_CALL_NAME_RE.exec(body)) !== null) {
    const start = WRITE_CALL_NAME_RE.lastIndex;
    let depth = 1;
    let quote: '"' | "'" | '`' | null = null;
    let escaped = false;
    let i = start;
    for (; i < body.length; i++) {
      const ch = body[i];
      if (quote) {
        if (escaped) { escaped = false; continue; }
        if (ch === '\\') { escaped = true; continue; }
        if (ch === quote) quote = null;
        continue;
      }
      if (ch === '"' || ch === "'" || ch === '`') { quote = ch; continue; }
      if (ch === '(') { depth++; continue; }
      if (ch === ')') {
        depth--;
        if (depth === 0) break;
      }
    }
    if (depth === 0) {
      out.push({ name: m[1], args: body.slice(start, i) });
      WRITE_CALL_NAME_RE.lastIndex = i + 1;
    } else {
      // Malformed/unbalanced write call: do not try to prove it inert.
      out.push({ name: m[1], args: null });
      WRITE_CALL_NAME_RE.lastIndex = start;
    }
  }
  return out;
}

function splitTopLevelArgs(args: string): string[] {
  const out: string[] = [];
  let start = 0;
  let depth = 0;
  let quote: '"' | "'" | '`' | null = null;
  let escaped = false;
  for (let i = 0; i < args.length; i++) {
    const ch = args[i];
    if (quote) {
      if (escaped) { escaped = false; continue; }
      if (ch === '\\') { escaped = true; continue; }
      if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') { quote = ch; continue; }
    if (ch === '(' || ch === '[' || ch === '{') { depth++; continue; }
    if (ch === ')' || ch === ']' || ch === '}') { depth = Math.max(0, depth - 1); continue; }
    if (ch === ',' && depth === 0) {
      out.push(args.slice(start, i).trim());
      start = i + 1;
    }
  }
  out.push(args.slice(start).trim());
  return out;
}

function targetArgIndexes(name: string): number[] {
  if (/^(?:shutil\.(?:copy|move)\w*)$/.test(name)) return [0, 1];
  if (/^(?:writeSync|fs\.write\w*|os\.write)$/.test(name)) return [];
  return [0];
}

function targetExprIsProvablyInert(expr: string): boolean {
  const trimmed = expr.trim();
  const m = /^(['"])([^'"\n]*)\1$/.exec(trimmed);
  if (!m) return false;
  return INERT_WRITE_TARGET.test(m[2]);
}

function fileWriteIsSink(body: string): boolean {
  if (!FILE_WRITE_SINK.test(body)) return false;
  const calls = writeCalls(body);
  // Sink vocabulary matched, but no call shape this extraction can see
  // inside — a path built at runtime, most likely. Assume it can execute.
  if (calls.length === 0) return true;
  // Per call, and only on target-bearing argument positions: a data string or
  // encoding (`'utf8'`) is not a filename and must not turn a JSON/log write
  // back into a shell sink. Unproven/dynamic targets still fail closed.
  return calls.some(call => {
    if (call.args === null) return true;
    const args = splitTopLevelArgs(call.args);
    const targets = targetArgIndexes(call.name).map(i => args[i]).filter((v): v is string => v !== undefined);
    if (targets.length === 0) return true;
    return targets.some(t => !targetExprIsProvablyInert(t));
  });
}

function outputEscapesToShell(text: string, outFile: string): boolean {
  const esc = outFile.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  // After the file name, on the same statement: a single `|` (not `||`), or a
  // `>`/`>>` — with or without a leading fd number — whose target is not a
  // discard (`/dev/null`) or a fd-to-fd redirect (`&1`, `&2`, …). The fd
  // number itself confers no exemption: `1>/tmp/x.sh` and `2>/tmp/x.sh` write
  // to a real file exactly like a bare `>` does.
  const re = new RegExp(`${esc}[^\\n;&]*?(?:\\|(?!\\|)|>>?\\s*(?!(?:/dev/null|&\\d)))`);
  return re.test(text);
}

const ANY_HEREDOC_RE = /<<-?\s*(['"]?)([A-Za-z_]\w*)\1[^\n]*\n([\s\S]*?)(?:\n[ \t]*\2\b|$)/g;
const HEREDOC_INTERP_TOKEN = /\b(bash|sh|zsh|ksh|dash|python[\d.]*|node|nodejs|ruby|perl|php)\b(?![\w/-])/gi;

function interpreterHeredocRegions(text: string): ScanRegion[] {
  if (!text.includes('<<')) return [];
  const found: Array<{ region: ScanRegion; outFile: string | null }> = [];
  /**
   * #217 — heredocs with NO interpreter on the intro line whose body is written
   * to a file: `cat > probe.mjs <<'EOF' … EOF; node probe.mjs`.
   *
   * The body is re-armed (correctly — the file IS executed), but it was then
   * scanned with SHELL rules, so a JavaScript string literal `"rm -rf /"` read
   * as a live command and hard-blocked at the catastrophic tier. The language
   * of such a body is decided by whatever later RUNS the file, which is not
   * knowable on the intro line, so these are resolved in a second pass below.
   *
   * The asymmetry this removes, measured: `python3 - <<'PY' … PY` (interpreter
   * consumes the heredoc) returned benign, while the same literals written to a
   * file and executed returned catastrophic.
   */
  const written: Array<{ start: number; end: number; body: string; outFile: string }> = [];
  const candidateFiles: string[] = [];
  ANY_HEREDOC_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = ANY_HEREDOC_RE.exec(text)) !== null) {
    const lineStart = text.lastIndexOf('\n', m.index) + 1;
    const introLine = text.slice(lineStart, m.index);
    const interp = introLine.match(HEREDOC_INTERP_TOKEN);
    const nlEarly = m[0].indexOf('\n');
    if (!interp) {
      // No interpreter here, but if the body lands in a file the second pass
      // may still find one that runs it.
      const target = heredocOutputFile(introLine + m[0].slice(0, nlEarly + 1));
      const cleaned = target ? target.replace(/^['"]/, '').replace(/['"]$/, '') : null;
      if (cleaned) {
        const s = m.index + nlEarly + 1;
        written.push({ start: s, end: s + m[3].length, body: m[3], outFile: cleaned });
      }
      continue;                                         // nothing executes it as code
    }
    const lang = langFromInterpreter(commandBaseName(interp[interp.length - 1].toLowerCase()));
    if (lang === 'sh') continue;                        // a shell heredoc IS shell — unchanged
    const nl = m[0].indexOf('\n');
    const bodyStart = m.index + nl + 1;
    const bodyEnd = bodyStart + m[3].length;
    // Two-step write-then-execute (issue #86.2), which applies to an
    // interpreter heredoc too: `python3 - <<'PY' > gen.sh … PY; bash gen.sh`
    // GENERATES the shell that later runs. The body's own text is then the
    // source of a command after all, so it must keep being scanned as shell.
    const outFile = heredocOutputFile(introLine + m[0].slice(0, nl + 1));
    const clean = outFile ? outFile.replace(/^['"]/, '').replace(/['"]$/, '') : null;
    if (clean) candidateFiles.push(clean);
    found.push({
      region: { start: bodyStart, end: bodyEnd, lang, hasSink: SHELL_OUT_SINK.test(m[3]), folded: false },
      outFile: clean,
    });
  }
  // #217 second pass: resolve each written-then-executed body by the language of
  // whatever actually runs it. `detectScriptInvocations` is the single
  // definition of program position in this file — it skips flags, understands
  // inline-program flags and recurses into `bash -c` — and it already carries
  // the lang, so reuse it rather than add a second, divergent notion of which
  // interpreter runs what (the recurring root cause in this file is a rule
  // implemented twice).
  const carved: ScanRegion[] = [];
  if (written.length > 0) {
    const invoked = detectScriptInvocations(text);
    // At the detection cap a later real invocation may not have been reached,
    // so claim nothing and leave every body scanned as shell — fail closed.
    if (invoked.length < MAX_DETECTED_SCRIPTS) {
      for (const w of written) {
        const runs = invoked.filter(({ path }) =>
          path === w.outFile
          || path.endsWith(`/${w.outFile}`)
          || w.outFile.endsWith(`/${path}`)
          || path === `./${w.outFile}`);

        // EVERY invocation must agree, and none may be a shell.
        //
        // Taking the FIRST match was a bypass: `detectScriptInvocations` used to
        // de-duplicate on path alone, so `node p.mjs` followed by `bash p.mjs`
        // resolved to `node`, relabelled a shell script as JavaScript, and
        // turned a catastrophic block into an allow. One prefixed token did it,
        // and `node p.mjs; bash p.mjs` is an ordinary thing to type.
        //
        // Note the direction. `findInterpreterRunFiles` uses this same matching
        // to NARROW its set, which can only keep more bodies scanned — fail
        // closed. Reusing it to WIDEN a relaxation makes the identical
        // imprecision fail OPEN, so ambiguity here must resolve the other way.
        if (runs.length === 0 || runs.some(r => r.lang === 'sh')) continue;
        const langs = new Set(runs.map(r => r.lang));
        if (langs.size > 1) continue;                     // disagreement is ambiguity

        carved.push({
          start: w.start,
          end: w.end,
          lang: runs[0].lang,
          // Literals stay live when the body can reach a process
          // (`child_process`, `execSync`), when it can WRITE a file another
          // command runs, or when the RUN STATEMENT's own wiring carries the
          // output into the shell (`| bash`, `>> ~/.zshrc`). The last is not a
          // property of the body at all, which is exactly why the body-local
          // test missed it.
          hasSink: SHELL_OUT_SINK.test(w.body)
            // A file write matters when what it writes can later RUN — see
            // `fileWriteIsSink`. `writeFileSync('/tmp/report.json', …)` in a
            // probe is data; `'/tmp/g.sh'` or `~/.zshrc` is a command in
            // transit, whether or not this command is the thing that runs it.
            || fileWriteIsSink(w.body)
            || outputEscapesToShell(text, w.outFile),
          folded: false,
        });
      }
    }
  }

  if (found.length === 0) return carved;
  const executedFiles = findInterpreterRunFiles(text, candidateFiles);
  return [
    ...found.filter(f => !(f.outFile && executedFiles.has(f.outFile))).map(f => f.region),
    ...carved,
  ];
}

/**
 * The INLINE program of `python3 -c '…'` / `node -e '…'` / `perl -e` / `ruby -e`
 * / `php -r` is interpreter source too — a JS regex literal in `node -e` is not
 * an egress pipe, and the operator's own guard-probing one-liners were being
 * hard-denied for containing the patterns they test (issue #89 class 1).
 *
 * `folded: false`, so a sink-bearing inline program keeps its literals executed:
 * `python3 -c "import os; os.system('rm -rf /')"` is the textbook RCE shape and
 * stays a hard block, exactly as #84's adversarial floor requires. Only the
 * sink-FREE case — a program that provably cannot reach a shell — is relaxed.
 *
 * `bash -c '…'` is deliberately absent: that program IS shell.
 */
const INLINE_PROGRAM_RE =
  /(?:^|[\s;&|(])((?:\S*\/)?(?:python[\d.]*|node|nodejs|ruby|perl|php))((?:\s+-\S+)*?)\s+(-\S+)\s+/g;

function inlineProgramRegions(text: string): ScanRegion[] {
  if (!/\s-[cerp]\b|--eval\b|--print\b/.test(text)) return [];
  const out: ScanRegion[] = [];
  INLINE_PROGRAM_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = INLINE_PROGRAM_RE.exec(text)) !== null) {
    const base = commandBaseName(m[1]);
    const lang = langFromInterpreter(base);
    if (lang === 'sh' || !isInlineProgramFlag(base, m[3])) continue;
    // The program starts right after the flag. It is normally ONE shell-quoted
    // argument; take that quote's contents when so, otherwise the rest of the
    // line. Offsets are computed against `text` directly — never against a
    // rewritten copy — so a region can never drift off its source bytes.
    const progStart = m.index + m[0].length;
    const q = text[progStart];
    let progEnd: number;
    if (q === '"' || q === "'") {
      let j = progStart + 1;
      while (j < text.length) {
        if (q === '"' && text[j] === '\\') { j += 2; continue; }
        if (text[j] === q) break;
        j++;
      }
      progEnd = Math.min(j, text.length);
      out.push({ start: progStart + 1, end: progEnd, lang, hasSink: SHELL_OUT_SINK.test(text.slice(progStart + 1, progEnd)), folded: false });
    } else {
      const nl = text.indexOf('\n', progStart);
      progEnd = nl < 0 ? text.length : nl;
      out.push({ start: progStart, end: progEnd, lang, hasSink: SHELL_OUT_SINK.test(text.slice(progStart, progEnd)), folded: false });
    }
    INLINE_PROGRAM_RE.lastIndex = Math.max(progEnd, m.index + m[0].length);
  }
  return out;
}

/**
 * #190 — a path literal inside an inline interpreter program is not a command.
 *
 * `splitCommandStatements` treats `(` and `)` as statement breaks, because in
 * shell they are. Applied to an inline interpreter program they are not: the
 * Python one-liner `python3 -c "json.load(open('~/x.jsonl'))"` splits into a
 * statement whose only token is `~/x.jsonl`, which reads as a path in command
 * position — so the guard folded the DATA FILE and, `.jsonl` being no code
 * extension, scanned its contents as SHELL. Any one-liner that opened a log,
 * a JSON baseline or a CSV was denied for whatever substrings that data
 * happened to contain. Worst case is self-inflicted: ShieldCortex's own audit
 * log records the tokens that tripped past denials, so reading it back to
 * investigate a denial produced another one. A guard whose telemetry cannot be
 * read is a guard that cannot be debugged.
 *
 * Same family as #188 — shell rules applied to a non-shell code position — and
 * resolved the same way #89 resolves it: by what the region can REACH. A
 * sink-free program provably cannot start a process, so nothing in it is an
 * invocation and it is masked out (length-preserving, so every offset computed
 * against the original text stays valid). A program that CAN shell out —
 * `os.system('bash /tmp/x.sh')` — keeps its text and its nested invocation is
 * still found, because there the path really is in command position.
 */
function maskSinkFreeInlinePrograms(text: string): string {
  const regions = inlineProgramRegions(text).filter(r => !r.hasSink);
  if (regions.length === 0) return text;
  let out = text;
  for (const r of regions) out = out.slice(0, r.start) + ' '.repeat(r.end - r.start) + out.slice(r.end);
  return out;
}

/**
 * Split `[0, length)` into the shell ranges left over once `carved` regions are
 * removed, so every byte of the scan surface belongs to exactly one region.
 */
function withShellComplement(carved: readonly ScanRegion[], length: number): ScanRegion[] {
  const sorted = [...carved].sort((a, b) => a.start - b.start);
  const out: ScanRegion[] = [];
  let at = 0;
  for (const r of sorted) {
    if (r.start < at) continue;                 // overlapping/nested — the outer region already covers it
    if (r.start > at) out.push({ start: at, end: r.start, lang: 'sh', hasSink: false, folded: false });
    out.push(r);
    at = Math.max(at, r.end);
  }
  if (at < length) out.push({ start: at, end: length, lang: 'sh', hasSink: false, folded: false });
  return out;
}

// ── Write-content payload scan (issue #93) ───────────────────────────────────

/**
 * Scan write-family CONTENT with the same CATASTROPHIC/DANGEROUS sets the
 * command surface uses. Matches are EXECUTED intent, not mentions: the caller
 * only sends content bound for a script-like / memory / shebang target, where
 * the agent is authoring code (or instructions a future turn re-reads), so the
 * mention-vs-intent question is already answered by where the bytes land.
 *
 * Windowed via forEachWindow rather than truncated: per-regex work stays at the
 * same ReDoS bound as the 50k command cap, but a payload past the cut point is
 * still scanned — padding a script with filler must not clear the gate.
 *
 * The statement-level FP disposers the command path applies are applied here
 * too, so a build script's `rm -rf .next` or a commit-message helper quoting
 * "git push -f" does not gate at write time when the identical text would not
 * gate at exec time.
 */
function scanWriteContentPayload(content: string): {
  catastrophic: Array<{ signal: string; span: string }>;
  dangerous: Array<{ signal: string; span: string }>;
} {
  const catastrophic: Array<{ signal: string; span: string }> = [];
  const dangerous: Array<{ signal: string; span: string }> = [];
  const seen = new Set<string>();
  forEachWindow(content, (w) => {
    const text = deobfuscateIfs(w);
    for (const m of matchSpans(CATASTROPHIC, text)) {
      if (m.signal === 'recursive-force-delete' && deleteTargetsAreWorkspaceConfined(text)) continue;
      if (!seen.has(m.signal)) { seen.add(m.signal); catastrophic.push(m); }
    }
    // A catastrophic hit already decides the verdict — skip the dangerous pass.
    if (catastrophic.length > 0) return true;
    for (const m of matchSpans(DANGEROUS, text)) {
      if (m.signal === 'file-delete' && deleteTargetsAreWorkspaceConfined(text)) continue;
      if (m.signal === 'git-force-push' && !gitForcePushInvoked(text)) continue;
      if (m.signal === 'git-delete-branch' && !gitDeleteBranchInvoked(text)) continue;
      if (m.signal === 'modify-network-firewall' && firewallCallsAreReadOnly(text)) continue;
      if (m.signal === 'install-package' && installsAreContainerConfined(text)) continue;
      // #386: quoted install vocabulary in scripts/logs is not an install.
      if (m.signal === 'install-package-global' && !packageInstallGlobalInvoked(text)) continue;
      if (m.signal === 'install-package' && !packageInstallInvoked(text)) continue;
      if (!seen.has(m.signal)) { seen.add(m.signal); dangerous.push(m); }
    }
    // #387 — PROPOSE what the exec path proposes. The DANGEROUS table carries
    // SYSTEM_INSTALL_RE (apt/yum/brew/gem/cargo) only: `pip` was moved out to
    // `hasUnscopedPipInstall` because it has to be read as argv to tell a host
    // mutation from a venv-scoped one, and `evaluateToolCall` calls that on the
    // EXEC surface alone. So a written script whose body really runs
    // `pip install x` — even a plain shebang `.sh` — was never proposed here,
    // let alone confirmed, and an install reached only through an interpreter
    // sink is not table vocabulary at all. The confirmations above are the same
    // functions, so nothing widens: this only asks the question on this path.
    if (!seen.has('install-package')
        && systemInstallInvoked(text)
        // #128 stays exactly as strong: an install sealed inside a throwaway
        // container mutates the container, not the host.
        && !installsAreContainerConfined(text)) {
      seen.add('install-package');
      PIP_INSTALL_WINDOW_RE.lastIndex = 0;
      const span = SYSTEM_INSTALL_RE.exec(text)?.[0]
        ?? PIP_INSTALL_WINDOW_RE.exec(text)?.[0]
        ?? 'package install';
      dangerous.push({ signal: 'install-package', span: fmtSpan(span) });
    }
  });
  return { catastrophic, dangerous };
}

// ── Main entry point ─────────────────────────────────────────────────────────

// A command this long is already anomalous for an interactive tool call — cap
// it as a hardening backstop (issue #86-redos), independent of whatever makes
// commandScanText fast for any *particular* shape today. Over-cap is flagged
// as a dangerous signal (worth a human nod) rather than silently truncated —
// truncating first would risk scanning past a real danger signal that sits
// beyond the cut point, the same bypass scan-windows.ts's windowing exists to
// avoid for the (much larger, file-content) scanners elsewhere in the guard.
const OVERSIZED_COMMAND_LENGTH = 50_000;

const ACTION_BY_FAMILY: Record<ToolFamily, string> = {
  read: 'read_file',
  write: 'edit_file',
  delete: 'delete_file',
  exec: 'execute_command',
  network: 'api_call',
  git: 'git_operation',
  memory: 'remember',
  unknown: 'unknown_action',
};

/**
 * Evaluate a single tool call and return a guard verdict.
 *
 * Pure and synchronous — no I/O. The interceptor decides how to ENFORCE the
 * verdict (block / prompt / warn) based on its own posture; this function only
 * RECOGNISES and recommends.
 *
 * Purity is load-bearing and must stay: this runs on EVERY tool call, and
 * `src/cli/doctor.ts` + `src/setup/openclaw-selfcheck.ts` drive it with
 * synthetic commands whose paths deliberately do not exist. Reading the script
 * a command points at (issue #4) therefore comes in through the caller-supplied
 * `options.resolveScriptSource` seam — no `fs` here, ever.
 */
export function evaluateToolCall(
  toolName: string,
  args: Record<string, unknown> = {},
  config?: IronDomeConfig,
  options?: ToolGuardOptions,
): ToolGuardVerdict {
  // #412 — close the tool-input bag before extractors run.
  // Exec/git: enforce (unknown keys fail closed — smuggled payloads cannot hide).
  // Other families: annotate (strip unknowns) so messaging/read tools with
  // free-form fields are not false-positive blocked; extractors never see junk keys.
  {
    const fam = schemaFamilyForTool(toolName);
    const mode = (fam === 'exec' || fam === 'git') ? 'enforce' : 'annotate';
    const validated = validateToolInput(toolName, args, mode);
    if (!validated.ok) {
      return verdict(
        'block',
        'dangerous',
        classifyFamily(toolName),
        'invalid_tool_input',
        `tool input rejected: ${validated.reason}`,
        ['invalid-tool-input', validated.code.toLowerCase().replace(/_/g, '-')],
      );
    }
    args = validated.args;
  }

  const family = classifyFamily(toolName);
  const command = deobfuscateIfs(extractCommand(args));
  const path = extractPath(args);
  const url = extractUrl(args);

  // Memory tools are handled by the dedicated memory-defence pipeline elsewhere.
  if (family === 'memory') {
    return verdict('allow', 'benign', family, 'remember', 'memory tool — handled by memory defence pipeline', []);
  }
  // Read-only tools never execute their args — a search query or path that
  // merely *mentions* "rm -rf" is not an action. Short-circuit before scanning.
  if (family === 'read') {
    return verdict('allow', 'benign', family, 'read_file', 'read-only operation', []);
  }

  // #93: write-family CONTENT is path-gated. Ordinary docs/data stay
  // field-discipline (prose may mention `rm -rf /` without gating). Script-like
  // paths, memory ledgers, and shebang bodies are AUTHORING code/instructions —
  // scan that content with the same CATASTROPHIC/DANGEROUS sets as commands.
  // Clean scans return allow/sensitive so #95 auditAllows records that the write
  // was seen (production hosts otherwise looked Bash-only for weeks).
  // #93: only DIRTY write-content hits return early. A clean content scan must
  // fall through so path-tier rules (touch-sensitive-path, approval-store, …)
  // still run — content add-on, not a short-circuit that blanks path policy.
  let writeContentScannedClean = false;
  if (family === 'write') {
    const writeContent = extractWriteContent(args);
    const scanThisWrite = writeContent.length > 0
      && (isScriptLikeWritePath(path)
        || isMemoryWritePath(path)
        || writeContentLooksExecutable(writeContent));
    if (scanThisWrite) {
      const memory = isMemoryWritePath(path);
      // #341: memory markdown is instruction prose — neutralize quoted mentions
      // before the command-pattern scan. Scripts keep raw bytes.
      const scanBody = (memory && /\.md$/i.test(path) && !writeContentLooksExecutable(writeContent))
        ? neutralizeMarkdownCommandMentions(writeContent)
        : writeContent;
      const hits = scanWriteContentPayload(scanBody);
      if (hits.catastrophic.length > 0) {
        const signals = ['write-content-catastrophic', ...hits.catastrophic.map(m => m.signal)];
        const span = hits.catastrophic[0]?.span;
        const reason = memory
          ? buildReason('memory-write payload is a catastrophic command', signals, span)
          : buildReason('write-content payload is a catastrophic command', signals, span);
        return verdict(
          'block',
          'catastrophic',
          family,
          ACTION_BY_FAMILY[family],
          reason,
          [...new Set(signals)],
          hits.catastrophic.map(m => ({ signal: m.signal, span: m.span })),
        );
      }
      if (hits.dangerous.length > 0) {
        const signals = ['write-content-dangerous', ...hits.dangerous.map(m => m.signal)];
        const span = hits.dangerous[0]?.span;
        const reason = memory
          ? buildReason('memory-write payload is a dangerous command', signals, span)
          : buildReason('write-content payload is a dangerous command', signals, span);
        return verdict(
          'require_approval',
          'dangerous',
          family,
          ACTION_BY_FAMILY[family],
          reason,
          [...new Set(signals)],
          hits.dangerous.map(m => ({ signal: m.signal, span: m.span })),
        );
      }
      writeContentScannedClean = true;
    }
  }

  // Field discipline: danger patterns scan the EXECUTION SURFACE
  // (command/path/url) only — never content the agent produces on ordinary
  // docs/data writes (a message body, runbook prose). #93 carves out script /
  // memory / shebang write targets above. See commandScanText for the
  // printed/commented-token suppression within a shell command.
  const execCommand = commandScanText(command);
  const execSurface = [execCommand, path, url].filter(Boolean).join('   ');

  // Script-file invocation (issue #4): `bash deploy.sh` used to hide EVERY rule
  // below behind a file the guard never opened. Detection runs on the COMMAND
  // only — never on a path/url argument — so an `Edit`/`Write` whose target
  // merely *is* a script is untouched, preserving the field discipline above.
  // An oversized command is already flagged (and already anomalous); skip the
  // work rather than tokenise 50k+ chars of it.
  const fold: ScriptFold = command.length > OVERSIZED_COMMAND_LENGTH
    ? { content: '', opaque: false, regions: [], reviewed: [] }
    : foldScriptSources(execCommand, options?.resolveScriptSource, options?.isReviewedScript);

  // #189: every verdict minted past this point records which files the
  // reviewed-script allowlist exempted from folding — including a `block`
  // from the command line itself, so a post-incident reading of the audit
  // row can see review was in play even when it didn't change the outcome.
  const withReview = (v: ToolGuardVerdict): ToolGuardVerdict =>
    fold.reviewed.length > 0 ? { ...v, reviewedScripts: [...fold.reviewed] } : v;
  // Folded script source is appended, never substituted: the command surface is
  // scanned exactly as before, so no existing verdict can change direction.
  const scanSurface = fold.content ? `${execSurface}\n${fold.content}` : execSurface;

  // Which slices of `scanSurface` are SHELL and which are interpreter SOURCE
  // (issue #89). Every rule below is written for shell command text; a folded
  // Python/JS file and an interpreter-consumed heredoc are not that, and the
  // span classifier needs to know which is which before it decides whether a
  // match is an action or a payload. A `sh` region behaves exactly as before,
  // so this is a no-op for a plain shell command.
  // Over the classification cap the span classifier fails closed and never
  // consults the region map, so building one is pure cost — skip it. This keeps
  // the pathological 50k-command path (issue #86-redos) at its measured budget.
  const scriptRegions: ScanRegion[] = scanSurface.length > SPAN_CLASSIFY_CAP ? [] : [
    ...interpreterHeredocRegions(execCommand),
    ...inlineProgramRegions(execCommand),
    ...fold.regions.map(r => ({
      ...r,
      start: r.start + execSurface.length + 1,          // +1 for the '\n' join
      end: r.end + execSurface.length + 1,
    })),
  ];
  const regions = scriptRegions.length > 0
    ? withShellComplement(scriptRegions, scanSurface.length)
    : [];
  // Recorded at the lowest surfaced tier when a script's contents could not be
  // read (no resolver, unreadable, oversized, binary, too deep). Never a gate on
  // its own — the doctor/selfcheck probes and plenty of legitimate calls hit it.
  const opaqueSignals = fold.opaque ? ['opaque-script-invocation'] : [];

  // 1) Catastrophic — hard block, cannot fail open, ignores config.
  // Span-classified (#84): a catastrophic token inside a URL or a quoted DATA
  // argument is a mention, not intent (`grep "rm -rf /" log`, a fetched URL
  // whose path contains "rm-rf") — but any executed occurrence still hard-blocks.
  const catastrophicMatches = matchSpansClassified(CATASTROPHIC, scanSurface, regions)
    // #170: drop the VERB-only delete signal when every target on the line is
    // workspace-confined. The TARGET-aware rule (`delete-root-or-home`) is not
    // in this filter, so `rm -rf /` and friends are unaffected — which the
    // suite pins in both directions.
    .filter(m => !(m.signal === 'recursive-force-delete'
      && deleteTargetsAreWorkspaceConfined(scanSurface)));
  const catastrophicExecuted = catastrophicMatches.filter(m => m.tier === 'executed');
  if (catastrophicExecuted.length > 0) {
    const catastrophicSignals = catastrophicExecuted.map(m => m.signal);
    const ev = reasonEvidence(catastrophicExecuted);
    return withReview(verdict('block', 'catastrophic', family, ACTION_BY_FAMILY[family],
      buildReason('catastrophic operation blocked', catastrophicSignals, ev.span, ev.provenance),
      [...catastrophicSignals, ...opaqueSignals],
      matchEvidence(catastrophicExecuted)));
  }
  // A catastrophic pattern that only appears as a PAYLOAD LITERAL inside
  // interpreter source that shells out somewhere is not proven inert (so it is
  // never allowed) and is not command position either (so it must not hard-deny
  // a background worker for reading its own audit log — issue #89 class 1). It
  // is carried down to the approval tier instead.
  const catastrophicPayload = catastrophicMatches.filter(m => m.tier === 'payload');

  // 1a) A structured delete tool carries its target as a path, not a command —
  // deleting a critical path (root, home, a system dir, a wildcard) is catastrophic.
  if (family === 'delete' && isCriticalPath(path)) {
    return withReview(verdict('block', 'catastrophic', family, 'delete_file',
      `catastrophic delete of a critical path (${path})`, ['delete-critical-path']));
  }

  // 1b) `find <path> -delete` / `find <path> -exec rm …` (issue #4475.5) is
  // catastrophic when <path> is root/home/a system dir/a wildcard — same rule
  // as 1a. A non-critical path still recursively deletes everything under it,
  // so it is folded into the DANGEROUS signals below (dangerSignals) instead.
  const findDeleteMatch = matchFindDelete(scanSurface);
  // #170: a find-delete NARROWED by a filename/path filter is a targeted sweep
  // — computed here because both the dangerous-signal assembly below and the
  // file-delete exemption need the same answer for the same statement.
  const findDeleteIsFiltered = findDeleteMatch
    ? /\s-(?:name|iname|path|ipath|regex)\s+\S+/.test(findDeleteMatch[0])
    : false;
  if (findDeleteMatch && isCriticalPath(findDeleteMatch[1])) {
    return withReview(verdict('block', 'catastrophic', family, ACTION_BY_FAMILY[family],
      buildReason('catastrophic operation blocked', ['recursive-find-delete'], findDeleteMatch[0].trim().replace(/\s+/g, ' ').slice(0, 80)),
      ['recursive-find-delete', ...opaqueSignals],
      [{ signal: 'recursive-find-delete', span: fmtSpan(findDeleteMatch[0]) }]));
  }

  // 1c) Secret exfiltration: external egress carrying a credential/secret.
  const egressCommand = fold.content ? `${execCommand}\n${fold.content}` : execCommand;
  const egress = family === 'network' || EXTERNAL_EGRESS.test(egressCommand) || EXTERNAL_EGRESS.test(url);
  // #175 / #173: hint is surface-aware AND value-gated. Shell regions use
  // SECRET_HINT (literal values + key-material shapes). Interpreter source
  // uses FOLDED_SOURCE_SECRET_HINT (quoted literals / key material only).
  // Matches wholly inside a comment or string are payload, not a credential
  // in flight. Tool args stay on the command-line hint — they are values.
  let secretSighted = SECRET_HINT.test(rawStringArgs(args));
  if (!secretSighted) {
    const slices = regions.length > 0
      ? regions
      : [{ start: 0, end: scanSurface.length, lang: 'sh' as const, hasSink: false, folded: false }];
    secretSighted = slices.some((r) => secretHintExecutedIn(scanSurface, r));
  }
  if (egress && secretSighted && looksExternal(url, scanSurface)) {
    return withReview(verdict('block', 'catastrophic', family, 'data_exfiltration',
      'blocked likely secret exfiltration (credential bound for an external host)', ['secret-egress', ...opaqueSignals]));
  }

  const canonical = ACTION_BY_FAMILY[family];
  // NOTE (#118): a family-level `autoApprove` branch used to sit here with an
  // empty body — dead code that read as if config could soften a verdict. It
  // never did. `autoApprove` is applied by the CALLERS (scripts/pre-tool-hook.mjs
  // and plugins/openclaw/interceptor.ts) against the finished verdict, which is
  // the right layer: this function stays a pure classifier that config cannot
  // talk out of a verdict. Per-command operator approval lives in
  // ./action-approvals.ts and is likewise consumed by the callers.

  // 2) Dangerous — recognised, effectful, worth a human nod → require approval.
  // Span-classified (#84): same mention-vs-intent filter as catastrophic above.
  // #188: a DANGEROUS token whose every occurrence is a PAYLOAD LITERAL inside
  // FOLDED interpreter source is shell vocabulary in a language that is not
  // shell — an identifier, a comment, a dict key. #165 already drew this line,
  // but only for files with NO shell-out sink: one `subprocess.run` anywhere
  // re-armed every rule against every literal in the whole file. That is the
  // shape of a security-monitoring script, and it hard-denied one for 2.5 days
  // (`sudo = ["michael", "admin"]  # macOS admin group = sudo equivalent`).
  // The relief is deliberately narrow and cannot reopen write-then-exec:
  //   - a literal that is a shell-out call's OWN argument is 'executed' (3a-i),
  //   - a folded `.sh` file is shell and never reaches the payload tier,
  //   - CATASTROPHIC payload still gates here via `catastrophicPayload`,
  //   - path-target rules never reach the payload tier at all (naming the path
  //     IS the access), so `id_rsa` in folded source is untouched by this.
  // Demoted, not dropped: the signals are surfaced at the sensitive tier below
  // so the match stays auditable instead of vanishing.
  const dangerClassified = matchSpansClassified(DANGEROUS, scanSurface, regions);
  const dangerPayloadOnly = dangerClassified.filter(m => m.tier === 'payload');
  const dangerMatches = [...catastrophicPayload, ...dangerClassified.filter(m => m.tier === 'executed')]
    // #170: same target-not-verb principle as the catastrophic tier. A delete
    // whose every target is workspace-confined (`rm -rf .next`, a scratch dir
    // under /tmp) is ordinary work and must not need a human nod — that is the
    // shape that produced most of the measured denials of honest engineering.
    // Anything absolute, home-rooted, glob- or variable-expanded is untouched.
    .filter(m => !(m.signal === 'file-delete'
      && family !== 'delete'
      && (deleteTargetsAreWorkspaceConfined(scanSurface)
        // The `rm` embedded in a FILTERED find's -exec belongs to that sweep,
        // not to a standalone delete statement — if no standalone rm exists on
        // the line, the sweep's own (allowed) verdict covers it.
        || (findDeleteIsFiltered && !hasStandaloneRmStatement(scanSurface)))));
  let dangerSignals = dangerMatches.map(m => m.signal);
  let dangerSpan = dangerMatches[0]?.span;
  // #192: evidence for the final verdict, keyed by signal so the filters below
  // (container-confined, force-push-invoked, firewall-read-only) drop a
  // signal's evidence simply by dropping the signal.
  // #184: keep full provenance (source/line/chain) alongside the span.
  const dangerEvidence = new Map<string, ClassifiedMatch>();
  for (const m of dangerMatches) if (!dangerEvidence.has(m.signal)) dangerEvidence.set(m.signal, m);
  // A pip install scoped to a venv / an explicit target prefix mutates that
  // prefix, not the host (issue #89 class 4) — it falls through to the
  // sensitive-but-allowed tier below, exactly like a workspace-local npm install.
  if (hasUnscopedPipInstall(scanSurface) && !dangerSignals.includes('install-package')) {
    dangerSignals.push('install-package');
    dangerSpan = dangerSpan ?? 'pip install';
    if (!dangerEvidence.has('install-package')) {
      dangerEvidence.set('install-package', { signal: 'install-package', span: 'pip install', tier: 'executed' });
    }
  }
  // A system install confined to a sealed throwaway container mutates that
  // container, not the host (issue #128) — drop the host-mutation signal. The
  // confinement check is an allowlist of proofs: any privilege, host mount,
  // host namespace or explicit break-out keeps the gate, and an install
  // outside the container run keeps it for the whole call.
  if (dangerSignals.includes('install-package') && installsAreContainerConfined(scanSurface)) {
    dangerSignals = dangerSignals.filter(sig => sig !== 'install-package');
  }
  // Force-push must be an invocation, not vocabulary (issue #195): talking
  // ABOUT a force-push — in a commit message, a log-capture CLI's prose — is
  // not performing one.
  if (dangerSignals.includes('git-force-push') && !gitForcePushInvoked(scanSurface)) {
    dangerSignals = dangerSignals.filter(sig => sig !== 'git-force-push');
  }
  // Same discipline for branch/ref deletes (#182): naming `git branch --delete
  // --force` in a commit message or a `--grep` pattern is prose, not a delete.
  // The argv parser also strips flag quoting, so the `git branch "-d" "-f"`
  // evasion is confirmed rather than slipped.
  if (dangerSignals.includes('git-delete-branch') && !gitDeleteBranchInvoked(scanSurface)) {
    dangerSignals = dangerSignals.filter(sig => sig !== 'git-delete-branch');
  }
  // Reading the firewall's state changes nothing (issue #193). The rule matched
  // the tool and never the verb, so a status sweep gated as hard as a flush.
  if (dangerSignals.includes('modify-network-firewall') && firewallCallsAreReadOnly(scanSurface)) {
    dangerSignals = dangerSignals.filter(sig => sig !== 'modify-network-firewall');
  }
  // #89: pure inspection of the approval store / decisions ledger is not a
  // mutation. Drop the path-target signal so diagnostics are not deadlocked
  // against the store the remediation tells them to reconcile. Mutating
  // shapes keep the gate (STORE_MUTATION_RE fails closed above).
  if ((dangerSignals.includes('touch-approval-store') || dangerSignals.includes('touch-decisions-ledger'))
      && guardStoreAccessIsReadOnly(scanSurface)) {
    dangerSignals = dangerSignals.filter(
      sig => sig !== 'touch-approval-store' && sig !== 'touch-decisions-ledger',
    );
  }
  // External egress is a potential exfil vector — but only when the call carries
  // a payload OFF-host. A read-only GET (docs / releases fetch) leaves nothing
  // behind and is not egress (issue #73.2). Secret-bearing egress already hard
  // blocked at step 1b above regardless of method.
  if (egress && looksExternal(url, scanSurface) && hasOutboundData(args, scanSurface)) {
    dangerSignals.push('external-egress');
    dangerSpan = dangerSpan ?? (url || 'external host');
    dangerEvidence.set('external-egress', {
      signal: 'external-egress',
      span: fmtSpan(url || 'external host'),
      tier: 'executed',
    });
  }
  // A structured delete tool is inherently a delete, even with no "rm" in any arg.
  if (family === 'delete' && !dangerSignals.includes('file-delete')) dangerSignals.push('file-delete');
  // A `find -delete` / `find -exec rm` on a non-critical path (1b already
  // returned catastrophic for a critical one) is still a recognised recursive delete.
  // #170: a find-delete NARROWED by a filename/type filter is a targeted sweep
  // (`-name "*.lock" -delete`), not tree removal — the shape every maintenance
  // script on earth uses to clear stale locks. Blocking it stopped a nightly
  // backup at 01:00 and taught the agent running it to ask for an allowlist
  // wide enough to cover all deletes, which would have been far worse than the
  // bug. An UNFILTERED find-delete still gates: it really does remove
  // everything beneath its root, and the suite pins that direction too.
  // (`findDeleteIsFiltered` is computed with the match above, pre-assembly.)
  if (findDeleteMatch && !findDeleteIsFiltered && !dangerSignals.includes('recursive-find-delete')) {
    dangerSignals.push('recursive-find-delete');
    dangerSpan = dangerSpan ?? findDeleteMatch[0].trim().replace(/\s+/g, ' ').slice(0, 80);
    dangerEvidence.set('recursive-find-delete', {
      signal: 'recursive-find-delete',
      span: fmtSpan(findDeleteMatch[0]),
      tier: 'executed',
    });
  }
  // npx/bunx (issue #92 must-fix, ALSO item): only an explicit remote-fetch
  // shape counts as registry-code-exec — see isGatedNpxBunx for the boundary.
  // uvx / pnpm-yarn dlx are unconditional matches already captured by the
  // DANGEROUS patterns above.
  if (isGatedNpxBunx(scanSurface) && !dangerSignals.includes('registry-code-exec')) {
    dangerSignals.push('registry-code-exec');
    dangerSpan = dangerSpan ?? (scanSurface.match(NPX_BUNX_COMMAND_RE)?.[0]?.trim() ?? 'npx/bunx');
    dangerEvidence.set('registry-code-exec', {
      signal: 'registry-code-exec',
      span: fmtSpan(scanSurface.match(NPX_BUNX_COMMAND_RE)?.[0] ?? 'npx/bunx'),
      tier: 'executed',
    });
  }
  // An anomalously long command is worth a human nod on its own (issue
  // #86-redos) — flagged here, after every catastrophic check above has
  // already had first refusal, so this can only ever ADD an approval gate,
  // never soften a block.
  if (command.length > OVERSIZED_COMMAND_LENGTH) {
    dangerSignals.push('oversized-command');
    dangerSpan = dangerSpan ?? `command is ${command.length} chars (cap ${OVERSIZED_COMMAND_LENGTH})`;
    dangerEvidence.set('oversized-command', {
      signal: 'oversized-command',
      span: `command is ${command.length} chars (cap ${OVERSIZED_COMMAND_LENGTH})`,
      tier: 'executed',
    });
  }
  if (dangerSignals.length > 0) {
    const action = dangerActionFor(dangerSignals, family);
    const surviving = [...new Set(dangerSignals)]
      .map(s => dangerEvidence.get(s))
      .filter((m): m is ClassifiedMatch => m !== undefined);
    const ev = reasonEvidence(surviving);
    // Prefer classified span/provenance; fall back to first-write dangerSpan
    // when evidence was synthetic (no ClassifiedMatch).
    const spanForReason = ev.span ?? dangerSpan;
    return withReview(verdict('require_approval', 'dangerous', family, action,
      buildReason('recognised dangerous operation requires approval', dangerSignals, spanForReason, ev.provenance),
      [...dangerSignals, ...opaqueSignals],
      matchEvidence(surviving)));
  }

  // 3) Sensitive-but-routine — allow, but tag so the interceptor can announce.
  // Dangerous vocabulary demoted at #188 rides along here: allowed, but named,
  // so a reviewer can still see what the folded source said.
  const payloadSignals = [...new Set(dangerPayloadOnly.map(m => m.signal))];
  const sensitiveSignal = firstMatch(SENSITIVE, scanSurface);
  if (sensitiveSignal) {
    const extra = writeContentScannedClean ? ['write-content-scanned'] : [];
    return withReview(verdict('allow', 'sensitive', family, canonical, `sensitive operation (${sensitiveSignal})`,
      [sensitiveSignal, ...payloadSignals, ...opaqueSignals, ...extra]));
  }
  if (payloadSignals.length > 0) {
    const payloadMatches = payloadSignals.flatMap(s => {
      const m = dangerPayloadOnly.find(x => x.signal === s);
      return m ? [m] : [];
    });
    const ev = reasonEvidence(payloadMatches);
    return withReview(verdict('allow', 'sensitive', family, canonical,
      buildReason(
        'dangerous vocabulary appears only as data inside folded script source',
        payloadSignals,
        ev.span ?? dangerPayloadOnly[0]?.span,
        ev.provenance,
      ),
      [...payloadSignals, ...opaqueSignals],
      matchEvidence(payloadMatches)));
  }

  // 3a) A script invocation whose contents could NOT be read (issue #4). Allowed
  // — this is the normal shape of agent work and must not become a gate — but
  // recorded at the sensitive tier so the unscanned gap is auditable instead of
  // invisible. When the source IS resolvable and clean, nothing is added here
  // and the verdict is bit-for-bit what it was before this change.
  if (opaqueSignals.length > 0) {
    return withReview(verdict('allow', 'sensitive', family, canonical,
      buildReason('script contents were not scanned', opaqueSignals), opaqueSignals));
  }

  // 4) A bare exec/network/write/git call with no dangerous signal is treated as
  // benign so the guard does not interrupt routine work (npm test, git status…).
  // (Read-only and memory tools already short-circuited to allow above.)
  // #93: a clean script/memory/shebang content scan upgrades to sensitive so
  // #95 auditAllows records that the write was seen (not silent like Bash-only).
  if (writeContentScannedClean) {
    return withReview(verdict(
      'allow',
      'sensitive',
      family,
      canonical,
      'write-content scanned — no dangerous signal detected',
      ['write-content-scanned', ...opaqueSignals],
    ));
  }
  return withReview(verdict('allow', 'benign', family, canonical, 'no dangerous signal detected', []));
}

function dangerActionFor(signals: string[], family: ToolFamily): string {
  if (signals.includes('git-force-push')) return 'force_push';
  if (signals.includes('git-delete-branch')) return 'delete_branch';
  if (signals.includes('file-delete')) return 'delete_file';
  if (signals.includes('privilege-escalation')) return 'sudo_command';
  if (signals.includes('stop-process-or-service')) return 'stop_service';
  if (signals.includes('modify-network-firewall')) return 'modify_firewall';
  if (signals.includes('install-package') || signals.includes('install-package-global')) return 'install_package';
  if (signals.includes('registry-code-exec')) return 'run_registry_package';
  if (signals.includes('modify-scheduler')) return 'modify_cron';
  if (signals.includes('external-egress')) return 'network_egress';
  if (signals.includes('touch-sensitive-path')) return 'access_secret_path';
  if (signals.includes('wipe-history-or-logs')) return 'wipe_logs';
  if (signals.includes('decode-pipe-to-shell')) return 'execute_command';
  if (signals.includes('recursive-find-delete')) return 'delete_file';
  if (signals.includes('recursive-perms-system-dir')) return 'change_permissions';
  if (signals.includes('truncate-to-zero')) return 'delete_file';
  if (signals.includes('dd-overwrite')) return 'delete_file';
  return ACTION_BY_FAMILY[family];
}

/** Concatenate all top-level string argument values (bounded) for pattern scanning. */
/**
 * String args that can EXECUTE, for the secret-sighting surface (#185).
 *
 * `description` is excluded. It is the human-facing label of a tool call —
 * prose ABOUT an action, with no execution path of any kind. Scanning it with
 * command-line-grade secret patterns produced a live catastrophic auto-deny on
 * 2 Aug 05:00: a worker refreshing an OAuth token wrote "client_secret=…" in
 * its own description — narrating its job accurately — and was blocked for the
 * narration while the command itself was clean. That teaches every agent to
 * write vaguer descriptions, which degrades the audit trail this product
 * exists to keep honest.
 *
 * This is the guard's own field discipline (see the exec-surface comment at
 * the top of evaluateToolCall): danger patterns scan the EXECUTION surface,
 * never agent-produced prose. The command, paths, urls, env maps and stdin
 * payloads all still scan — a secret in any of those is a secret somewhere a
 * shell can see it.
 */
function rawStringArgs(args: Record<string, unknown>): string {
  const parts: string[] = [];
  for (const [k, v] of Object.entries(args ?? {})) {
    // `command` is scanned via execSurface/regions. Re-testing it here
    // would ignore interpreter regions and re-apply the shell hint to a
    // Python docstring (#173). `description` is prose (#185).
    if (k === 'description' || k === 'command') continue;
    if (typeof v === 'string') parts.push(v);
    else if (Array.isArray(v)) parts.push(v.filter(x => typeof x === 'string').join(' '));
  }
  const joined = parts.join(' ');
  return joined.length > 20000 ? joined.slice(0, 20000) : joined;
}

function verdict(
  decision: ToolGuardDecision,
  severity: ToolGuardSeverity,
  family: ToolFamily,
  action: string,
  reason: string,
  signals: string[],
  matches?: Array<{ signal: string; span: string; source?: string; line?: number; chain?: string }>,
): ToolGuardVerdict {
  return matches && matches.length > 0
    ? { decision, severity, family, action, reason, signals, matches }
    : { decision, severity, family, action, reason, signals };
}
