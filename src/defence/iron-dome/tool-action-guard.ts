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

import type { IronDomeConfig } from './config.js';

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
  // rm targeting a root-ish / home / wildcard path
  { re: /\brm\b[^|;&\n]*\s(?:-\w+\s+)*(?:\/|~|\$HOME|\/\*|\*|\.\/\*)(?:\s|$)/i, signal: 'delete-root-or-home' },
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
  { re: /\b(?:shred|wipe)\b[^|;&\n]*\/dev\//i, signal: 'shred-device' },
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
  { re: /\bgit\b[^|\n]*\bpush\b[^|\n]*(--force\b|-f\b|\+)/i, signal: 'git-force-push' },
  { re: /\bgit\b[^|\n]*\b(branch\s+-D|push\b[^|\n]*--delete|push\b[^|\n]*\s:)/i, signal: 'git-delete-branch' },
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
  { re: /\b(systemctl|service)\b[^|\n]*\b(stop|disable|mask)\b|(?<![.\w])(kill|pkill|killall)\b/i, signal: 'stop-process-or-service' },
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
  { re: /\b(?:npm|yarn|pnpm|bun)\b(?=[^|;&\n]*(?:\s['"]?-g\b['"]?|--global(?![\w-])|\bglobal\s+add\b))(?=[^|;&\n]*\s(?:install|add)(?=\s|$|[|;&\n]))|\b(?:npm|pnpm|bun)\s+(?:i(?:n(?:s(?:t(?:a(?:ll?)?)?)?)?)?|isnt(?:all)?)\b[^|;&\n]*(?:\s['"]?-g\b['"]?|--global(?![\w-]))/i, signal: 'install-package-global' },
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
  // approval. Any command that so much as names the store path goes to the
  // operator — who is the only party with a legitimate reason to touch it.
  { re: /\.shieldcortex[\\/]+approvals\b/i, signal: 'touch-approval-store' },
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
  const out: string[] = [];
  let cur = '';
  let quote: string | null = null;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '\\' && quote !== "'" && i + 1 < text.length) { cur += c + text[++i]; continue; }
    if (quote) {
      cur += c;
      if (c === quote) quote = null;
      continue;
    }
    if (c === '"' || c === "'") { quote = c; cur += c; continue; }
    if (c === ';' || c === '&' || c === '|' || c === '\n' || c === '\r') {
      if (cur.trim()) out.push(cur);
      cur = '';
      continue;
    }
    cur += c;
  }
  if (cur.trim()) out.push(cur);
  return out;
}

const SECRET_HINT = /(sk-[a-z0-9-]{12,}|ghp_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{12,}|xox[baprs]-[A-Za-z0-9-]{10,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|password\s*[=:]\s*\S{6,}|secret\s*[=:]\s*\S{6,})/i;
/**
 * The secret hint for FOLDED PROGRAM SOURCE (#175) — credential LITERALS only.
 *
 * SECRET_HINT's generic `secret= / password=` arms are written for a command
 * line, where whatever follows the `=` is a real value by construction. Inside
 * program source the same shape is field VOCABULARY: every OAuth client on
 * earth contains `'client_secret': cfg.secret` next to a `requests.post` to
 * its token endpoint — that is a credential doing its job, not leaving home.
 * When #160 pointed the fold at the Claude Code hook, that one reading turned
 * secret-egress into a blanket auto-deny of ordinary business automation:
 * three separate production scripts (inbox cleanup, two Xero syncs) were
 * catastrophic-blocked in a single evening, none of which move a secret
 * anywhere it does not belong. Same defect class as `process.kill` matching
 * the shell `kill` (#165): shell vocabulary applied to program identifiers.
 *
 * So folded non-shell source gates on what a command line cannot fake — a
 * hard credential literal (key material itself), or a QUOTED literal secret
 * assignment (`password = "hunter2abc"`). An identifier / expression on the
 * right-hand side (`'client_secret': cfg['secret']`) is code shape, and code
 * shape alone is not evidence of exfiltration. Folded SHELL scripts keep the
 * full SECRET_HINT — a folded .sh IS command text, and `curl -d
 * secret=$(cat …)` inside one must gate exactly as it would inline.
 */
const FOLDED_SOURCE_SECRET_HINT = /(sk-[a-z0-9-]{12,}|ghp_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{12,}|xox[baprs]-[A-Za-z0-9-]{10,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|(?:password|secret)["']?\s*[=:]\s*["'][^"'\n]{6,}["'])/i;
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

function classifyWithCtx(
  ctx: SpanCtx,
  start: number,
  end: number,
  text: string,
  pathTarget = false,
): SpanClass {
  // 1) URL — inert data being fetched; only becomes code via `curl … | bash`,
  //    whose pipe-to-shell pattern's span CROSSES the URL (not contained in it).
  if (contains(ctx.urls, start, end)) return 'mention';
  // 2) Quoted DATA — the span sits fully inside a data-argument quote. A span
  //    crossing a quote boundary (`"rm" -rf /`) is contained in no quote range,
  //    and a span touching a command substitution INSIDE that quote is executed
  //    (`echo "$(rm -rf /)"`).
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
    //     Bare code matching an UNANCHORED rule (`sudo`, `rm`, `curl`) is
    //     untouched and still contributes, which is what keeps the #138
    //     script-file parity table at its current tiers. `|` and `>` are
    //     deliberately NOT anchor characters here — `redirect-to-block-device`
    //     is an unanchored rule that legitimately starts with one.
    if (isShellAnchorChar(text, start)) return 'mention';
    break;
  }
  return 'executed';
}

type MatchTier = 'executed' | 'payload';
interface ClassifiedMatch { signal: string; span: string; tier: MatchTier; }

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
const PATH_TARGET_SIGNALS = new Set(['touch-sensitive-path', 'touch-approval-store']);


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
    const c0 = classifyWithCtx(ctx, s0, s0 + m0[0].length, text, pathTarget);
    if (c0 === 'executed') {
      out.push({ signal: p.signal, span: fmtSpan(m0[0]), tier: 'executed' });
      continue;
    }
    let best: { span: string; tier: MatchTier } | null =
      c0 === 'payload' ? { span: m0[0], tier: 'payload' } : null;
    if (sharedBudget <= 0) {
      // Out of re-scan budget: fail CLOSED — keep the signal at the executed
      // tier rather than spend unbounded time proving it is a mention.
      out.push({ signal: p.signal, span: fmtSpan(m0[0]), tier: 'executed' });
      continue;
    }
    const g = p.re.global ? p.re : new RegExp(p.re.source, p.re.flags + 'g');
    let iters = 0;
    for (const m of text.matchAll(g)) {
      const s = m.index ?? 0;
      const c = classifyWithCtx(ctx, s, s + m[0].length, text, pathTarget);
      if (c === 'executed') { best = { span: m[0], tier: 'executed' }; break; }
      if (c === 'payload' && best === null) best = { span: m[0], tier: 'payload' };
      sharedBudget--;
      if (++iters >= MAX_CLASSIFY_ITERS || sharedBudget <= 0) { best = { span: m[0], tier: 'executed' }; break; }  // fail-closed
    }
    if (best !== null) out.push({ signal: p.signal, span: fmtSpan(best.span), tier: best.tier });
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
  'install-package-global': 'review the package + source, then install it explicitly if intended (a workspace-local install needs no global flag)',
  'install-package': 'review the package + source, then run the install yourself if intended',
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
function buildReason(prefix: string, signals: string[], span?: string): string {
  const parts = [`rule: ${signals.join(', ')}`];
  if (span) parts.push(`matched: "${span}"`);
  const hint = REMEDIATION[signals[0]];
  if (hint) parts.push(`fix: ${hint}`);
  return `${prefix} [${parts.join('; ')}]`;
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

  const add = (p: string, lang?: ScriptLang): void => {
    const clean = p.trim();
    if (!clean || clean === '-' || /^https?:\/\//i.test(clean)) return;
    if (found.some(f => f.path === clean) || found.length >= MAX_DETECTED_SCRIPTS) return;
    found.push({ path: clean, lang: lang ?? langFromPath(clean) });
  };

  for (const stmt of splitCommandStatements(execSurface)) {
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
    // language every rule is written for).
    if (looksLikePathToken(cmd)) add(cmd);
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
}

interface ScriptFold {
  /** Scan-ready text of every script whose source was resolved. */
  content: string;
  /** A script invocation was recognised but its contents could NOT be folded. */
  opaque: boolean;
  /** Byte ranges of `content` and the language each was folded from (issue #89). */
  regions: ScanRegion[];
}

/**
 * Resolve the scripts a command invokes and return their (comment-stripped)
 * contents for scanning. Bounded on every axis: depth, file count, per-file
 * size, total size, and a visited set that makes a source-cycle terminate.
 */
function foldScriptSources(
  execCommand: string,
  resolveScriptSource?: (scriptPath: string) => string | null,
): ScriptFold {
  const roots = detectScriptInvocations(execCommand);
  if (roots.length === 0) return { content: '', opaque: false, regions: [] };
  if (typeof resolveScriptSource !== 'function') return { content: '', opaque: true, regions: [] };

  const visited = new Set<string>();
  const queue: Array<{ path: string; lang: ScriptLang; depth: number }> =
    roots.map(r => ({ path: r.path, lang: r.lang, depth: 1 }));
  const parts: string[] = [];
  const regions: ScanRegion[] = [];
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

    // `commandScanText` only strips SHELL constructs (pure prints, `#` comments,
    // quoted heredocs). For interpreter source those are the wrong rules — a `#`
    // comment strip is harmless, but a Python `'…#…'` literal must not lose its
    // tail — so non-shell sources are folded verbatim and classified instead.
    const scan = next.lang === 'sh'
      ? commandScanText(deobfuscateIfs(src))
      : deobfuscateIfs(src);
    total += src.length;
    if (parts.length > 0) cursor += 1;                  // the '\n' join separator
    regions.push({ start: cursor, end: cursor + scan.length, lang: next.lang, hasSink: SHELL_OUT_SINK.test(scan), folded: true });
    cursor += scan.length;
    parts.push(scan);

    // A non-shell script's own text is not a shell command line, so only a shell
    // region can name the next script to follow.
    const nested = next.lang === 'sh' ? detectScriptInvocations(scan) : [];
    if (nested.length > 0) {
      if (next.depth >= MAX_SCRIPT_DEPTH) opaque = true;         // depth exceeded — say so
      else for (const n of nested) if (!visited.has(n.path)) queue.push({ ...n, depth: next.depth + 1 });
    }
  }

  return { content: parts.join('\n'), opaque, regions };
}

// ── Interpreter heredocs (issue #89) ─────────────────────────────────────────
//
// `stripQuotedHeredocs` neutralises a heredoc body that nothing executes. A body
// an INTERPRETER consumes is deliberately kept — it is code — but it is that
// interpreter's code, not shell. `python3 - <<'PY' … PY` is a Python program:
// its `PATTERNS = {'recursive-force-delete': r'rm -rf'}` is a dict of strings and
// its `at = tok['access_token']` is an assignment. Locate those bodies so the
// span classifier can treat them as the interpreter source they are.
const ANY_HEREDOC_RE = /<<-?\s*(['"]?)([A-Za-z_]\w*)\1[^\n]*\n([\s\S]*?)(?:\n[ \t]*\2\b|$)/g;
const HEREDOC_INTERP_TOKEN = /\b(bash|sh|zsh|ksh|dash|python[\d.]*|node|nodejs|ruby|perl|php)\b(?![\w/-])/gi;

function interpreterHeredocRegions(text: string): ScanRegion[] {
  if (!text.includes('<<')) return [];
  const found: Array<{ region: ScanRegion; outFile: string | null }> = [];
  const candidateFiles: string[] = [];
  ANY_HEREDOC_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = ANY_HEREDOC_RE.exec(text)) !== null) {
    const lineStart = text.lastIndexOf('\n', m.index) + 1;
    const introLine = text.slice(lineStart, m.index);
    const interp = introLine.match(HEREDOC_INTERP_TOKEN);
    if (!interp) continue;                              // nothing executes it as code
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
  if (found.length === 0) return [];
  const executedFiles = findInterpreterRunFiles(text, candidateFiles);
  return found.filter(f => !(f.outFile && executedFiles.has(f.outFile))).map(f => f.region);
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

  // Field discipline: danger patterns scan the EXECUTION SURFACE
  // (command/path/url) only — never content the agent produces
  // (a message body, file contents). See commandScanText for the
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
    ? { content: '', opaque: false, regions: [] }
    : foldScriptSources(execCommand, options?.resolveScriptSource);
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
  const catastrophicMatches = matchSpansClassified(CATASTROPHIC, scanSurface, regions);
  const catastrophicExecuted = catastrophicMatches.filter(m => m.tier === 'executed');
  if (catastrophicExecuted.length > 0) {
    const catastrophicSignals = catastrophicExecuted.map(m => m.signal);
    return verdict('block', 'catastrophic', family, ACTION_BY_FAMILY[family],
      buildReason('catastrophic operation blocked', catastrophicSignals, catastrophicExecuted[0].span),
      [...catastrophicSignals, ...opaqueSignals]);
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
    return verdict('block', 'catastrophic', family, 'delete_file',
      `catastrophic delete of a critical path (${path})`, ['delete-critical-path']);
  }

  // 1b) `find <path> -delete` / `find <path> -exec rm …` (issue #4475.5) is
  // catastrophic when <path> is root/home/a system dir/a wildcard — same rule
  // as 1a. A non-critical path still recursively deletes everything under it,
  // so it is folded into the DANGEROUS signals below (dangerSignals) instead.
  const findDeleteMatch = matchFindDelete(scanSurface);
  if (findDeleteMatch && isCriticalPath(findDeleteMatch[1])) {
    return verdict('block', 'catastrophic', family, ACTION_BY_FAMILY[family],
      buildReason('catastrophic operation blocked', ['recursive-find-delete'], findDeleteMatch[0].trim().replace(/\s+/g, ' ').slice(0, 80)),
      ['recursive-find-delete', ...opaqueSignals]);
  }

  // 1c) Secret exfiltration: external egress carrying a credential/secret.
  const egressCommand = fold.content ? `${execCommand}\n${fold.content}` : execCommand;
  const egress = family === 'network' || EXTERNAL_EGRESS.test(egressCommand) || EXTERNAL_EGRESS.test(url);
  // #175: the secret hint is surface-aware. The command line, the tool args and
  // folded SHELL scripts take the full SECRET_HINT (they are command text);
  // folded PROGRAM source takes the literals-only hint, because `client_secret:`
  // next to a token-endpoint POST is what an OAuth client IS, and matching it
  // catastrophic-blocked three production scripts in one evening. The split is
  // by region language, never by "was it folded" — the same line #165 drew.
  let secretSighted = SECRET_HINT.test(`${execSurface}   ${rawStringArgs(args)}`);
  if (!secretSighted && fold.content) {
    for (const r of fold.regions) {
      const slice = fold.content.slice(r.start, r.end);
      if ((r.lang === 'sh' ? SECRET_HINT : FOLDED_SOURCE_SECRET_HINT).test(slice)) {
        secretSighted = true;
        break;
      }
    }
  }
  if (egress && secretSighted && looksExternal(url, scanSurface)) {
    return verdict('block', 'catastrophic', family, 'data_exfiltration',
      'blocked likely secret exfiltration (credential bound for an external host)', ['secret-egress', ...opaqueSignals]);
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
  const dangerMatches = [...catastrophicPayload, ...matchSpansClassified(DANGEROUS, scanSurface, regions)];
  let dangerSignals = dangerMatches.map(m => m.signal);
  let dangerSpan = dangerMatches[0]?.span;
  // A pip install scoped to a venv / an explicit target prefix mutates that
  // prefix, not the host (issue #89 class 4) — it falls through to the
  // sensitive-but-allowed tier below, exactly like a workspace-local npm install.
  if (hasUnscopedPipInstall(scanSurface) && !dangerSignals.includes('install-package')) {
    dangerSignals.push('install-package');
    dangerSpan = dangerSpan ?? 'pip install';
  }
  // A system install confined to a sealed throwaway container mutates that
  // container, not the host (issue #128) — drop the host-mutation signal. The
  // confinement check is an allowlist of proofs: any privilege, host mount,
  // host namespace or explicit break-out keeps the gate, and an install
  // outside the container run keeps it for the whole call.
  if (dangerSignals.includes('install-package') && installsAreContainerConfined(scanSurface)) {
    dangerSignals = dangerSignals.filter(sig => sig !== 'install-package');
  }
  // External egress is a potential exfil vector — but only when the call carries
  // a payload OFF-host. A read-only GET (docs / releases fetch) leaves nothing
  // behind and is not egress (issue #73.2). Secret-bearing egress already hard
  // blocked at step 1b above regardless of method.
  if (egress && looksExternal(url, scanSurface) && hasOutboundData(args, scanSurface)) {
    dangerSignals.push('external-egress');
    dangerSpan = dangerSpan ?? (url || 'external host');
  }
  // A structured delete tool is inherently a delete, even with no "rm" in any arg.
  if (family === 'delete' && !dangerSignals.includes('file-delete')) dangerSignals.push('file-delete');
  // A `find -delete` / `find -exec rm` on a non-critical path (1b already
  // returned catastrophic for a critical one) is still a recognised recursive delete.
  if (findDeleteMatch && !dangerSignals.includes('recursive-find-delete')) {
    dangerSignals.push('recursive-find-delete');
    dangerSpan = dangerSpan ?? findDeleteMatch[0].trim().replace(/\s+/g, ' ').slice(0, 80);
  }
  // npx/bunx (issue #92 must-fix, ALSO item): only an explicit remote-fetch
  // shape counts as registry-code-exec — see isGatedNpxBunx for the boundary.
  // uvx / pnpm-yarn dlx are unconditional matches already captured by the
  // DANGEROUS patterns above.
  if (isGatedNpxBunx(scanSurface) && !dangerSignals.includes('registry-code-exec')) {
    dangerSignals.push('registry-code-exec');
    dangerSpan = dangerSpan ?? (scanSurface.match(NPX_BUNX_COMMAND_RE)?.[0]?.trim() ?? 'npx/bunx');
  }
  // An anomalously long command is worth a human nod on its own (issue
  // #86-redos) — flagged here, after every catastrophic check above has
  // already had first refusal, so this can only ever ADD an approval gate,
  // never soften a block.
  if (command.length > OVERSIZED_COMMAND_LENGTH) {
    dangerSignals.push('oversized-command');
    dangerSpan = dangerSpan ?? `command is ${command.length} chars (cap ${OVERSIZED_COMMAND_LENGTH})`;
  }
  if (dangerSignals.length > 0) {
    const action = dangerActionFor(dangerSignals, family);
    return verdict('require_approval', 'dangerous', family, action,
      buildReason('recognised dangerous operation requires approval', dangerSignals, dangerSpan),
      [...dangerSignals, ...opaqueSignals]);
  }

  // 3) Sensitive-but-routine — allow, but tag so the interceptor can announce.
  const sensitiveSignal = firstMatch(SENSITIVE, scanSurface);
  if (sensitiveSignal) {
    return verdict('allow', 'sensitive', family, canonical, `sensitive operation (${sensitiveSignal})`,
      [sensitiveSignal, ...opaqueSignals]);
  }

  // 3a) A script invocation whose contents could NOT be read (issue #4). Allowed
  // — this is the normal shape of agent work and must not become a gate — but
  // recorded at the sensitive tier so the unscanned gap is auditable instead of
  // invisible. When the source IS resolvable and clean, nothing is added here
  // and the verdict is bit-for-bit what it was before this change.
  if (opaqueSignals.length > 0) {
    return verdict('allow', 'sensitive', family, canonical,
      buildReason('script contents were not scanned', opaqueSignals), opaqueSignals);
  }

  // 4) A bare exec/network/write/git call with no dangerous signal is treated as
  // benign so the guard does not interrupt routine work (npm test, git status…).
  // (Read-only and memory tools already short-circuited to allow above.)
  return verdict('allow', 'benign', family, canonical, 'no dangerous signal detected', []);
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
function rawStringArgs(args: Record<string, unknown>): string {
  const parts: string[] = [];
  for (const v of Object.values(args ?? {})) {
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
): ToolGuardVerdict {
  return { decision, severity, family, action, reason, signals };
}
