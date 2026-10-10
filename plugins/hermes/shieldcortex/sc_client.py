"""
ShieldCortex defence client for the Hermes plugin.

Calls ShieldCortex's local REST API. Tool calls go through
`POST /api/v1/action-guard` (the same `evaluateToolCall` the Claude hook and
OpenClaw interceptor run). Content scanning stays on `POST /api/v1/scan`.
Hermes is Python; ShieldCortex is Node — REST is the clean cross-runtime
boundary (no CLI text-scraping, no in-process bridge).

Auth: the API requires a Bearer token (the server writes it to
`~/.shieldcortex/.api-token`, 0600). We read it from `SHIELDCORTEX_API_TOKEN`
or that file and send `Authorization: Bearer …`. Without it the API answers 401
and — being fail-open — the gate silently degrades to a no-op. That exact gap
(no auth header → invisible 401 → never actually scans) was caught in the
ATHENA Hermes dogfood, 2026-06-29; wiring the token closes it.

Failure posture (issue #59 / WS2): if the scanner is unreachable or errors, we
return an `available=False` verdict — and the caller runs the dependency-free
`fallback_catastrophic_match` below. A match fails CLOSED (blocked); anything
else still fails open with a loud `gate_degraded` log, because the fallback
recognising nothing is not evidence the call is safe, only that it isn't one
of the handful of unambiguous shapes. A down scanner still never wedges an
agent doing normal work.
"""
from __future__ import annotations

import json
import os
import re
from typing import Optional
import urllib.request

# Unambiguous catastrophic shapes for the fail-closed fallback (issue #59/WS2).
# Ported from — and kept in sync with — FALLBACK_CATASTROPHIC_PATTERNS in
# scripts/pre-tool-hook.mjs and plugins/openclaw/interceptor.ts. Narrow by
# design: essentially-never-benign shapes only, so a broken scanner fails
# closed on "rm -rf /"-class commands without turning every tool call into a
# denial. The content scanned here is the tool name + JSON-encoded args (see
# _tool_content in __init__.py) — JSON escaping keeps spaces/pipes/slashes
# literal, so the shapes survive encoding.
_FALLBACK_CATASTROPHIC = [
    re.compile(r"\brm\b[^|;&\n]*?(?:(?<![\w./-])-\w*r\w*f\w*|(?<![\w./-])-\w*f\w*r\w*|(?=[^|;&\n]*--recursive)(?=[^|;&\n]*--force))", re.I),
    re.compile(r"\brm\b[^|;&\n]*\s(?:-\w+\s+)*(?:/|~|\$HOME|/\*|\*|\./\*)(?:\s|$)", re.I),
    re.compile(r":\s*\(\s*\)\s*\{\s*:\s*\|\s*:?\s*&?\s*\}\s*;\s*:"),
    re.compile(r"\bmkfs(\.\w+)?\b", re.I),
    re.compile(r"\bdd\b[^|;&\n]*\bof=/dev/(sd|nvme|hd|disk|mmcblk|vd)", re.I),
    re.compile(r"\b(fdisk|parted|sgdisk|wipefs|blkdiscard)\b", re.I),
    re.compile(
        r"\b(?:curl|wget|fetch)\b[^\n|]*\|(?:[^\n|]*\|)*\s*(?:\w+=\S*\s+)*(?:sudo\s+)?(?:env\s+)?(?:\w+=\S*\s+)*"
        r"(?:bash|sh|zsh|ksh|python\d?|perl|ruby|node)\b(?!(?:\s+-[a-z]+)*\s+-[cem]\b)",
        re.I,
    ),
    re.compile(r"\b(?:curl|wget|fetch)\b[^|\n]*\|[^\n]*\bpython\d?\b[^\n]*\s-m\s*(?:code|pty|pdb)(?![\w.])", re.I),
    re.compile(r"\bch(?:mod|own)\b[^|;&\n]*(?:-\w*R\w*|--recursive)\b[^|;&\n]*\s/(?:\s|$)", re.I),
]


def fallback_catastrophic_match(content: str) -> bool:
    """True when `content` matches an unambiguous catastrophic shape (fail-closed tier)."""
    if not content:
        return False
    return any(p.search(content) for p in _FALLBACK_CATASTROPHIC)


# #503: database / cloud / infrastructure teardown — mirrors the guard's destroy-data-or-infra row.
# A verb's second gap stops at the next copy of that verb, so a verb-dense line is linear. A verb reached
# through a newline, before it or inside `s3 rm`, keeps the plain gap (same matches as before).
# Quoted data is a mention here too: see fallback_dangerous_match.
_FALLBACK_DESTROY_ROW = re.compile(r'''(?:^|[;&|(\n"'`]|\$\()\s*(?:\w+=\S*\s+)*(?:sudo\s+)?(?:(?:env|nohup|timeout|time|stdbuf|nice|ionice|setsid|command|exec)\b(?:\s+(?:-{1,2}\S+|\w+=\S*|\d+[smhd]?))*\s+)*(?:sudo\s+)?(?:[\w.~-]*/)*(?:(?:psql|mysql|mariadb|sqlite3|sqlcmd|duckdb|clickhouse(?:-client)?|cockroach)\b[^\n]*\b(?:drop\s+(?:database|schema|table)\b|truncate\s+(?:table\s+)?(?!-)[\w."`[\]]|delete\s+from\s+[\w."`[\]]+\s*(?:;|["']|$))|dropdb\b|mysqladmin\b[^|;&\n]*\sdrop\b|mongo(?:sh)?\b[^\n]*(?:dropDatabase|\.drop)\s*\(|redis-cli\b[^|;&\n]*\bflush(?:all|db)\b|(?:terraform|tofu|terragrunt)\b[^|;&\n]*\s(?:destroy\b|(?<=\n)apply\b[^|;&\n]*\s-destroy\b|apply\b(?:(?!\sapply\b)[^|;&\n])*\s-destroy\b)|pulumi\b[^|;&\n]*\s(?:destroy|down)\b|kubectl\b[^|;&\n]*\s(?:(?<=\n)delete\b[^|;&\n]*|delete\b(?:(?!\sdelete\b)[^|;&\n])*)\s(?:ns|namespaces?|pvc?|persistentvolumes?|persistentvolumeclaims?|deploy(?:ments?)?|statefulsets?|sts|nodes?|crds?|customresourcedefinitions?|all)\b(?![-.])|kubectl\b[^|;&\n]*\s(?:(?<=\n)delete\b[^|;&\n]*|delete\b(?:(?!\sdelete\b)[^|;&\n])*)\s--all\b|helm\b[^|;&\n]*\s(?:uninstall|delete)\b|aws\b[^|;&\n]*\s(?:terminate-instances|delete-[\w-]+|rb|(?<=\n)s3\s+rm\b[^|;&\n]*\s--recursive|s3(?=[^\S\n]*\n)\s+rm\b[^|;&\n]*\s--recursive|s3[^\S\n]+rm\b(?:(?!\ss3\s+rm\b)[^|;&\n])*\s--recursive)\b|gcloud\b[^|;&\n]*\sdelete\b|gsutil\b[^|;&\n]*\s(?:rb\b|(?<=\n)rm\b[^|;&\n]*\s-\w*r|rm\b(?:(?!\srm\b)[^|;&\n])*\s-\w*r)|az\b[^|;&\n]*\s(?:group|vm)\s+delete\b|doctl\b[^|;&\n]*\s(?:delete|rm)\b|gh\s+(?:repo\s+delete\b|api\b[^|;&\n]*(?:-X|--method)[\s=]*DELETE\b)|docker(?:-compose)?\b[^|;&\n]*\s(?:system\s+prune|volume\s+(?:prune|rm)|(?<=\n)down\b[^|;&\n]*\s(?:-v|--volumes)\b|down\b(?:(?!\sdown\b)[^|;&\n])*\s(?:-v|--volumes)\b)|(?:flyctl|fly)\s+(?:apps?\s+(?:destroy|delete)|destroy|volumes?\s+(?:destroy|delete)|postgres\s+(?:destroy|delete))\b|heroku\s+(?:apps:destroy|pg:reset)\b|vercel\s+(?:rm|remove)\b|wrangler\s+delete\b)''', re.I)

# Dangerous tier of the fail-closed fallback (issue #59) — ported from
# tool-action-guard.ts's DANGEROUS list, kept in sync with the OpenClaw
# interceptor + Claude Code hook. Blocked (enforcing) when the scanner is
# unreachable, instead of the pre-#59 fail-open. Mirrors the real (narrowed)
# patterns so read-only forms (crontab -l, npm ls -g, git status) still pass.
_FALLBACK_DANGEROUS = [
    re.compile(r"\brm\b|\bunlink\b|\brmdir\b|(?:(?:^|[;&|(\n]|\$\()\s*(?:\w+=\S*\s+)*(?:sudo\s+)?|\bxargs\s+(?:-{1,2}\S+\s+)*|-exec\s+)shred\b", re.I),
    re.compile(r"\bsudo\b|\bdoas\b|\bsu\s", re.I),
    re.compile(r"\bgit\b[^|\n]*\bpush\b[^|\n]*(--force\b|-f\b|\+)", re.I),
    re.compile(r"\bgit\b[^|\n]*\b(branch\s+-D|push\b[^|\n]*--delete|push\b[^|\n]*\s:)", re.I),
    re.compile(r"\b(systemctl|service)\b[^|\n]*\b(stop|disable|mask)\b|\b(kill|pkill|killall)\b", re.I),
    re.compile(r"\b(iptables|ufw|nft|netplan|firewall-cmd)\b", re.I),
    re.compile(r"\b(?:apt|apt-get|yum|dnf|brew|pip|pip3|gem|cargo)\b[^|\n]*\b(?:install|add)\b", re.I),
    re.compile(
        r"\b(?:npm|yarn|pnpm|bun)\b(?=[^|;&\n]*(?:\s['\"]?-g\b['\"]?|--global(?![\w-])|\bglobal\s+add\b))"
        r"(?=[^|;&\n]*\s(?:install|add)(?=\s|$|[|;&\n]))|"
        r"\b(?:npm|pnpm|bun)\s+(?:i(?:n(?:s(?:t(?:a(?:ll?)?)?)?)?)?|isnt(?:all)?)\b[^|;&\n]*(?:\s['\"]?-g\b['\"]?|--global(?![\w-]))",
        re.I,
    ),
    re.compile(
        r"(?:^|[;&|(\n]|\$\()\s*(?:\w+=\S*\s+)*(?:sudo\s+)?"
        r"(?:(?:env|nohup|time|stdbuf|nice)\b(?:\s+(?:-{1,2}\S+|\w+=\S*|\d+))*\s+)*(?:sudo\s+)?"
        r"(?:crontab\b(?!\s+-l\b)|at\b(?!\s+-l\b)(?!\s*$))|/etc/cron|"
        r"\bsystemd-run\b[^|;&\n]*--on-(?:calendar|active|boot|startup|unit-active|unit-inactive)\b",
        re.I,
    ),
    re.compile(r"\bdd\b[^|;&\n]*\bof=", re.I),
    re.compile(r"\bch(?:mod|own)\b[^|;&\n]*(?:-\w*R\w*|--recursive)\b[^|;&\n]*\s/(?:etc|usr|var|home|bin|sbin|boot|lib|lib64|opt|root)(?:/\*?)?(?:\s|$)", re.I),
    re.compile(r"\btruncate\b[^|;&\n]*(?:-s\s*0\b|--size(?:=|\s+)0\b)", re.I),
    re.compile(r"\bhistory\s+-c\b|\.bash_history|truncate\b[^|\n]*\.log", re.I),
    _FALLBACK_DESTROY_ROW,
    # #505: `.ssh` behind any home root + `authorized_keys` as a path segment — mirrors the guard row.
    re.compile(r"/etc/(passwd|shadow|sudoers)|(?:~|\$\{?HOME\}?|/home/[^\s/'\"]+|/root|/Users/[^\s/'\"]+)/\.ssh(?![\w.-])|(?:^|[\s'\"=:/])\.ssh/authorized_keys2?\b|/authorized_keys2?\b|id_rsa|\.aws/credentials|\.env\b", re.I),
    # #505: a shell write shape onto a login/interactive startup file — mirrors the guard row.
    re.compile(
        r"(?:(?:>>?|>\|)(?:[ \t]|\\\n)*|\btee\b(?:(?:[ \t]|\\\n)+(?:--?[\w-]+(?:=\S*)?|'[^'\n]*'|\"[^\"\n]*\"|[^\s'\"|;&<>\\-][^\s'\"|;&<>\\]*))*(?:[ \t]|\\\n)+|\bsed\b(?=[^|;&\n]*[ \t](?:-[a-zA-Z]*i|--in-place))[^|;&\n]*(?:[ \t]|\\\n)+)['\"]?(?:[^\s'\"|;&<>]*/)?"
        r"(?:\.(?:bashrc|zshrc|zprofile|zshenv|zlogin|zlogout|profile|bash_profile|bash_login|bash_logout)(?![\w.-])|\.config/fish/config\.fish\b)|"
        r"\b(?:cp|mv|install)\b[^|;&\n]*(?:[ \t]|\\\n)+['\"]?(?:[^\s'\"|;&<>]*/)?"
        r"(?:\.(?:bashrc|zshrc|zprofile|zshenv|zlogin|zlogout|profile|bash_profile|bash_login|bash_logout)(?![\w.-])|\.config/fish/config\.fish\b)['\"]?\s*(?=$|[|;&\n])",
        re.I,
    ),
    re.compile(r"(?:^|[;&|(\n]|\$\()\s*(?:\w+=\S*\s+)*(?:sudo\s+)?uvx\b", re.I),
    re.compile(r"(?:^|[;&|(\n]|\$\()\s*(?:\w+=\S*\s+)*(?:sudo\s+)?(?:pnpm|yarn)\b[^|;&\n]*\bdlx\b", re.I),
    re.compile(r"\b(?:base64|openssl|xxd|cat|http)\b[^\n|]*\|(?:[^\n|]*\|)*\s*(?:\w+=\S*\s+)*(?:sudo\s+)?(?:bash|sh|zsh|ksh|python\d?|perl|ruby|node)\b(?:\s+-)?\s*(?:[;&|\n]|$)", re.I),
    re.compile(r"--action-guard-(?:disable|advisory|enforce-when-ready)\b|\biron-dome\s+deactivate\b", re.I),
    re.compile(r"\b(?:npm|yarn|pnpm|bun)\b[^|;&\n]*\b(?:uninstall|remove)\b[^|;&\n]*\b(?:shieldcortex|@drakon-systems/shieldcortex-realtime)\b", re.I),
    re.compile(r"\.shieldcortex[\\/]+config\.json\b", re.I),
]

# Same command/path/url field set the guard extracts — narrow, not the whole
# args object (a benign `description` must never gate).
_FALLBACK_SURFACE_KEYS = (
    "command", "cmd", "script", "code", "input", "shell", "run",
    # #509 r6 S2: typed-shell payload keys, kept in sync with the other two.
    "data", "text", "literal",
    "path", "file_path", "filePath", "file", "target", "destination", "dir", "directory",
    "url", "uri", "endpoint", "href", "host", "to",
)


def fallback_surface(args: dict) -> str:
    """Join the raw exec-surface values (command/path/url) from a tool's args.

    The fallback scans this, not the JSON-wrapped tool blob, so command-position
    anchors in the dangerous patterns fire the same way they do on the other
    two runtime surfaces. Capped at 4 KB (kept in sync with the interceptor +
    hook FALLBACK_SCAN_CAP) — an unbounded scan over crafted input is a ReDoS
    vector; dangerous shapes appear early in any real command.
    """
    if not isinstance(args, dict):
        return ""
    parts = []
    for k in _FALLBACK_SURFACE_KEYS:
        v = args.get(k)
        if isinstance(v, str) and v:
            parts.append(v)
        # Kept in sync with plugins/openclaw/interceptor.ts and
        # scripts/pre-tool-hook.mjs: an ARGV ARRAY under one of these keys is a
        # real host shape the guard this fallback stands in for already reads
        # (`rawStringArgs` joins string arrays), so the degraded scan must read
        # it too, or it is strictly weaker than the evaluator it replaces on the
        # tier documented as an unconditional deny (#522 r7 FIND-4).
        elif isinstance(v, (list, tuple)):
            joined = " ".join(e for e in v if isinstance(e, str))
            if joined:
                parts.append(joined)
    return "   ".join(parts)[:4096]


# #503: quoted DATA, ported to the blunt fallback. The destroy-data-or-infra row
# counts an opening quote as a command start, so `bash -c '...'` and
# `ssh host '...'` wrappers are seen. The real guard then drops a match inside
# a quoted argument of a data command (`classifyWithCtx`: DATA_COMMAND /
# TEXT_FLAG in tool-action-guard.ts); this fallback did not, so
# `grep -F "<teardown>" RUNBOOK.md` blocked here and allowed with the scanner
# up. Mirrors that step, narrower and fail-closed: no quote is data when the
# text has nested execution or eval, or pipes into anything but a read-only
# filter (grep, head, sort, jq, tee, ...); a quote is data only under a data command or as a long text
# flag's value on a non-executor; a match is dropped only inside ONE data
# quote; an unclosed quote is never data; no quote is data when the text pairs
# quotes the shell does not (review R3 on #626): a quote in a comment, an
# ANSI-C `$'...'`, heredoc text, or `${...}` with its own nested quotes.
# Used only for _FALLBACK_DESTROY_ROW.
# Kept in sync with plugins/openclaw/interceptor.ts and scripts/pre-tool-hook.mjs.
_FALLBACK_NESTED_EXEC = re.compile(r"\$\(|`|<\(|>\(|\beval\b|\bsource\b|\b\.\s+/|\bfunction\b|[\w.-]+\s*\(\s*\)\s*\{", re.I)
_FALLBACK_DATA_COMMAND = re.compile(r"(?:grep|egrep|fgrep|zgrep|rg|ripgrep|ag|ack|ug|ugrep|pt|echo|printf|jq|git\s+(?:commit|tag|stash|grep|log))(?=\s|$)", re.I)
_FALLBACK_TEXT_FLAG = re.compile(r"(?:^|\s)--(?:text|body|message|comment|description|title|content|caption|note|summary|prompt|subject)(?:=|\s+)$", re.I)
_FALLBACK_EXEC_WORD = re.compile(r"(?:bash|sh|zsh|ksh|dash|ash|python[\d.]*|node|nodejs|ruby|perl|php|eval|exec|source|ssh|scp|docker|podman|kubectl|nsenter|chroot|busybox|xargs|find|flock|watch|make|awk|sed|su|runuser|systemd-run|at|batch)", re.I)
_FALLBACK_UNSAFE_PIPE = re.compile(r"(?<!\|)\|(?!\|)&?(?![ \t]*(?:grep|egrep|fgrep|zgrep|rg|ag|ack|head|tail|less|more|wc|sort|uniq|cut|tr|jq|cat|tee|column|nl|fold|fmt)(?:[ \t\n|;&)]|$))")  # `||` is not a pipe
_FALLBACK_QUOTE_UNMODELLED = re.compile(r"\$'|<<|\$\{")  # quotes the walk below would mis-pair
_FALLBACK_WORD_BREAK = " \t\n\r\v\f;&|()<>"  # a `#` after one of these (or at the start) opens a comment
_FALLBACK_ASSIGNMENT = re.compile(r"(?:^|\s)(?:export\s+|local\s+|declare\s+\S+\s+)?\w+(?:\[[^\]]*\])?\+?=$")
_FALLBACK_QUOTE_PREFIX_CAP = 512  # a command word further back is not recognised (the quote stays executed)
_FALLBACK_INERT_MATCH_CAP = 64  # inert matches looked past before the row fails closed


def _fallback_data_quote_ranges(text: str) -> list:
    """`(open, close + 1)` of every quoted data argument, or [] when none can be trusted."""
    if _FALLBACK_NESTED_EXEC.search(text) or _FALLBACK_QUOTE_UNMODELLED.search(text):
        return []
    ranges, unquoted = [], []  # quote contents blanked, so the pipe check never reads quoted text
    q, open_at, stmt_start, i, n = None, -1, 0, 0, len(text)
    comment_checked_to = 0  # end of the last line already found free of quotes after a `#`
    while i < n:
        c = text[i]
        if c == "\\" and q != "'":  # bash escaping: outside quotes and inside "..."
            unquoted.append("  " if q else text[i:i + 2])
            i += 2
            continue
        if q:
            unquoted.append(" ")
            if c == q:
                prefix = text[stmt_start:open_at]
                if open_at - stmt_start <= _FALLBACK_QUOTE_PREFIX_CAP:
                    bare = re.sub(r"^(?:sudo|doas)\s+", "", re.sub(r"^(?:\w+=\S*\s+)*", "", prefix.lstrip()))
                    word = (bare.split() or [""])[0]
                    if not _FALLBACK_ASSIGNMENT.search(prefix) and (
                        _FALLBACK_DATA_COMMAND.match(bare)
                        or (_FALLBACK_TEXT_FLAG.search(prefix) and not _FALLBACK_EXEC_WORD.fullmatch(word))
                    ):
                        ranges.append((open_at, i + 1))
                q = None
            i += 1
            continue
        unquoted.append(c)
        if c in "\"'":
            q, open_at = c, i
        elif c in ";\n|&(":
            stmt_start = i + 1
        elif c == "#" and i >= comment_checked_to and (i == 0 or text[i - 1] in _FALLBACK_WORD_BREAK):
            # A comment runs to the end of the line, and a quote in it is no
            # quote to the shell. Rather than model it (a `\ #` is not one),
            # trust no quote at all when one is there. Kept walking either way.
            eol = text.find("\n", i)
            comment_checked_to = n if eol < 0 else eol
            if text.find('"', i, comment_checked_to) >= 0 or text.find("'", i, comment_checked_to) >= 0:
                return []
        i += 1
    return [] if _FALLBACK_UNSAFE_PIPE.search("".join(unquoted)) else ranges


def _fallback_executed_match(rx, text: str) -> bool:
    """True when `rx` matches somewhere outside a quoted data argument."""
    ranges, inert, pos = None, 0, 0
    while True:
        m = rx.search(text, pos)
        if m is None:
            return False
        if ranges is None:
            ranges = _fallback_data_quote_ranges(text)
        if not any(a <= m.start() and m.end() <= b for a, b in ranges):
            return True
        inert += 1
        if inert >= _FALLBACK_INERT_MATCH_CAP:
            return True  # fail closed
        pos = m.start() + 1  # overlapping re-scan: a match starting inside this one is still checked


def fallback_dangerous_match(content: str) -> bool:
    """True when `content` matches a recognised-dangerous shape (fail-closed when enforcing)."""
    if not content:
        return False
    return any(
        _fallback_executed_match(p, content) if p is _FALLBACK_DESTROY_ROW else p.search(content)
        for p in _FALLBACK_DANGEROUS
    )


# #509 R4-1: the guard self-protection floor. DUPLICATED from tool-action-guard.ts
# `GUARD_SELF_PROTECTION_SIGNALS`; held equal by enforcement-surface-parity. A
# verdict carrying one of these is enforced even when enforce=False (advisory).
SELF_PROTECTION_SIGNALS = (
    "touch-approval-store",
    "touch-decisions-ledger",
    "touch-guard-config",
    "disable-action-guard",
)

# The outage-scan shapes for those signals: the guard's own approval store
# (readiness state + transition record live there too), the lease ledger, the
# config file, and the disable/uninstall shapes already in _FALLBACK_DANGEROUS.
#
# #509 r5 (finding 9): plus the #501 policy-lock rows the other two fallbacks
# carry at `disable-action-guard` — the env seams that choose the lock reader,
# the OS lock root, and the harness/host settings files that load the guard.
# Without them an outage with SHIELDCORTEX_ENFORCE=0 let
# `echo {} > ~/.claude/settings.json` through. Kept in sync with
# FALLBACK_DANGEROUS_PATTERNS in scripts/pre-tool-hook.mjs and
# plugins/openclaw/interceptor.ts; enforcement-surface-parity compares the
# DECISIONS on a shared table, not only the signal names.
_FALLBACK_SELF_PROTECTION = [
    (re.compile(r"\.shieldcortex[\\/]+approvals\b", re.I), False),
    # #509 r6 S2: the r5 classifier shapes, verbatim from the other two
    # fallbacks — the guard directory itself moved/copied over/deleted (verb at
    # command position), and guard state reached relatively after `cd` into it.
    # #509 r7 (PR #610 review): a long non-matching command must not backtrack
    # quadratically — 100 KiB of newlines took 20-35 s per row. `\n` is itself an
    # anchor, so the blank run after one excludes it ([^\S\n]), and the argument
    # gap stops at `(`. The gaps carry NO length bound: a `{0,512}` bound let
    # padding inside the scan cap hide a real match, and the 4096-char cap in
    # fallback_surface() is the bound on what these rows are ever fed.
    (re.compile(
        r"(?:^|[;&|(\n`]|\$\()[^\S\n]*(?:\w+=\S*\s+)*(?:sudo\s+(?:-\S+\s+)*)?(?:mv|cp|rm|rmdir|rsync|ln|install)\s(?:[^;&|\n(]*?\s)?"
        r"[\"']?[^\s;&|\"'`]*\.shieldcortex(?:[\\/]+approvals)?[\\/]*[\"']?(?=$|[\s;&|)])",
        re.I,
    ), False),
    (re.compile(
        r"(?:^|[\s;&|(])(?:cd|pushd)\s+(?:--\s+)?[\"']?[^\s;&|\"'`]*\.shieldcortex[\\/]*[\"']?(?=$|[\s;&|)])[\s\S]*?"
        r"(?:(?:^|[\s;&|(<>='\"])(?:\.[\\/])?(?:approvals|DECISIONS\.md|leases|config\.json)(?=$|[\s;&|)\\/'\"])|"
        r"[;&|(\n][^\S\n]*(?:sudo\s+)?(?:mv|cp|rm|rmdir|rsync|ln|install)\s(?:[^;&|\n(]*?\s)?[\"']?[.\\/*]*[.*][.\\/*]*[\"']?(?=$|[\s;&|)]))",
        re.I,
    ), False),
    (re.compile(r"\.shieldcortex[\\/]+(?:DECISIONS\.md|leases)\b", re.I), False),
    (re.compile(r"--action-guard-(?:disable|advisory|enforce-when-ready)\b|\biron-dome\s+deactivate\b", re.I), False),
    (re.compile(r"\b(?:npm|yarn|pnpm|bun)\b[^|;&\n]*\b(?:uninstall|remove)\b[^|;&\n]*\b(?:shieldcortex|@drakon-systems/shieldcortex-realtime)\b", re.I), False),
    (re.compile(r"\.shieldcortex[\\/]+config\.json\b", re.I), False),
    (re.compile(r"\bSHIELDCORTEX_(?:DIST_ROOT|PROTECTED_ROOT)\s*=", re.I), False),
    # (pattern, lock_path): a lock-path row is skipped for pure inspection.
    (re.compile(r"/etc/shieldcortex(?:\.conf\b|[\\/]|(?![\w.-]))", re.I), True),
    (re.compile(r"(?:^|[\s'\"=:(\\/])\.claude[\\/]+settings(?:\.local)?\.json\b", re.I), True),
    (re.compile(r"(?:^|[\s'\"=:(\\/])\.openclaw[\\/]+openclaw\.json\b", re.I), True),
]

# The hook's fallbackLockPathAccessIsReadOnly, ported: pure shell inspection
# of a lock path is not an attempt on it. Fail-closed on an env-seam
# assignment, a redirect, nested execution and any unknown verb.
_FALLBACK_LOCK_ENV_SEAM = re.compile(r"\bSHIELDCORTEX_(?:DIST_ROOT|PROTECTED_ROOT)\s*=", re.I)
_FALLBACK_LOCK_READ_VERB = re.compile(
    r"^(?:ls|dir|cat|head|tail|less|more|stat|file|wc|grep|egrep|fgrep|rg|ag|ack|realpath|readlink|basename|dirname|test|\[|echo|printf|jq)$",
    re.I,
)
_FALLBACK_GIT_READ_SUB = re.compile(r"^(?:log|show|diff|status|blame|ls-files)$", re.I)
_FALLBACK_REDIRECT = re.compile(r">{1,2}\|?(?!&\d)")
_FALLBACK_NESTED_EXEC = re.compile(r"\$\(|`|<\(|>\(|\beval\b|\bsource\b|\b\.\s+/|\bfunction\b|[\w.-]+\s*\(\s*\)\s*\{", re.I)


def _fallback_git_stage_writes(stage: str) -> bool:
    for raw in stage.split():
        token = raw.replace("'", "").replace('"', "")
        if re.match(r"^-o(?:$|[^-])", token) or re.match(r"^--(?:output|ext-diff)\b", token, re.I):
            return True
    return False


def _fallback_lock_access_is_read_only(text: str, tool_name=None) -> bool:
    if not text or _FALLBACK_LOCK_ENV_SEAM.search(text):
        return False
    seg = [x for x in re.split(r"__|\.|:|/", str(tool_name or "").lower()) if x]
    if seg and _FALLBACK_READ_TOOLS.match(seg[-1]):
        return True
    if _FALLBACK_REDIRECT.search(text) or _FALLBACK_NESTED_EXEC.search(text):
        return False
    saw_stage = False
    for raw in re.split(r"[\n;&|]+", text):
        stage = raw.strip()
        if not stage:
            continue
        saw_stage = True
        stage = re.sub(r"^(?:[A-Za-z_]\w*=\S*\s+)+", "", stage)
        stage = re.sub(r"^sudo\s+(?:-E\s+)?", "", stage)
        toks = stage.split()
        word = toks[0] if toks else ""
        base = word.split("/")[-1] or word
        if re.match(r"^git$", base, re.I):
            sub = next((t for t in toks[1:] if not t.startswith("-")), "")
            if not _FALLBACK_GIT_READ_SUB.match(sub) or _fallback_git_stage_writes(stage):
                return False
            continue
        if not _FALLBACK_LOCK_READ_VERB.match(base):
            return False
    return saw_stage


def fallback_self_protection_match(content: str, tool_name=None) -> bool:
    """True when `content` touches guard state or config (never advisory)."""
    if not content:
        return False
    lock_read_only = _fallback_lock_access_is_read_only(content, tool_name)
    return any(p.search(content) for p, lock_path in _FALLBACK_SELF_PROTECTION if not (lock_path and lock_read_only))


# #505: startup-file WRITE target, ported to the blunt fallback. The real guard
# gates a Write/Edit whose TARGET is a shell startup file on the path alone
# (`isShellStartupWritePath`): a PATH prepend written there carries no
# dangerous verb, so no content regex can see it. The DANGEROUS row above
# covers the SHELL spellings only; a tool write carries the target as a path
# argument, so in degraded mode the same write was invisible. Mirrors the
# guard's WRITE_TOOLS / READ_TOOLS split; kept in sync with
# scripts/pre-tool-hook.mjs and plugins/openclaw/interceptor.ts.
_FALLBACK_READ_TOOLS = re.compile(
    r"^(read|read_file|cat|less|more|head|tail|view|open|get|glob|grep|search|find|ls|list|list_files|stat|pwd|which|web_search|websearch)$"
)
_FALLBACK_WRITE_TOOLS = re.compile(r"(write|edit|create|update|patch|append|save|mkdir|move|copy|cp|mv|rename|chmod|chown)")
_FALLBACK_WRITE_PATH_KEYS = ("path", "file_path", "filePath", "file", "target", "destination")
_FALLBACK_SHELL_STARTUP_PATH = re.compile(
    r"(?:^|[\\/])(?:\.(?:bashrc|zshrc|zprofile|zshenv|zlogin|zlogout|profile|bash_profile|bash_login|bash_logout)|\.config[\\/]fish[\\/]config\.fish)$",
    re.I,
)


def fallback_write_target_match(tool_name, args) -> Optional[str]:
    """'modify-shell-startup' when a write-family tool targets a shell startup file, else None.

    Read-family tools never gate; a tool with no write-like name never gates
    here (the pattern table still applies to its surface). Only path-bearing
    keys are read — never `command`.
    """
    seg = (str(tool_name or "").lower().replace("__", "/").replace(".", "/").replace(":", "/")).split("/")
    seg = next((x for x in reversed(seg) if x), "")
    if not seg or _FALLBACK_READ_TOOLS.match(seg) or not _FALLBACK_WRITE_TOOLS.search(seg):
        return None
    if not isinstance(args, dict):
        return None
    for k in _FALLBACK_WRITE_PATH_KEYS:
        v = args.get(k)
        if isinstance(v, str) and _FALLBACK_SHELL_STARTUP_PATH.search(v.strip()):
            return "modify-shell-startup"
    return None


DEFAULT_BASE_URL = os.environ.get("SHIELDCORTEX_API_URL", "http://127.0.0.1:3001")
TOKEN_FILE = os.path.expanduser("~/.shieldcortex/.api-token")

# Remote strings enter hook messages in ShieldCortex's voice. Bound + flatten
# so a misbound local service cannot inject a message boundary or an unbounded
# prompt. Same threat model as the unknown-decision 32-char echo.
_REMOTE_REASON_LIMIT = 400
_REMOTE_CTRL = re.compile(r"[\x00-\x1f\x7f]+")


def sanitize_remote_reason(value, *, limit: int = _REMOTE_REASON_LIMIT) -> str:
    """Coerce a remote reason to a single-line bounded string. Non-strings → ''."""
    if not isinstance(value, str):
        return ""
    cleaned = _REMOTE_CTRL.sub(" ", value)
    cleaned = " ".join(cleaned.split())
    if len(cleaned) > limit:
        return cleaned[:limit]
    return cleaned


def _api_token() -> str | None:
    """Bearer token for the ShieldCortex API: env first, then ~/.shieldcortex/.api-token."""
    env = os.environ.get("SHIELDCORTEX_API_TOKEN", "").strip()
    if env:
        return env
    try:
        with open(TOKEN_FILE, encoding="utf-8") as fh:
            tok = fh.read().strip()
            return tok or None
    except OSError:
        return None


class Verdict:
    """Normalised result of a ShieldCortex scan."""

    __slots__ = ("result", "threats", "reason", "available")

    def __init__(self, result: str, threats, reason: object = "", available: bool = True):
        self.result = (result or "ALLOW").upper()  # ALLOW | BLOCK | QUARANTINE | ERROR
        self.threats = [t for t in threats if isinstance(t, str)][:32] if isinstance(threats, list) else []
        self.reason = sanitize_remote_reason(reason)
        self.available = available  # False => scanner unreachable (fail-open)

    @property
    def blocked(self) -> bool:
        return self.result in ("BLOCK", "QUARANTINE")

    def __repr__(self) -> str:
        return f"Verdict(result={self.result!r}, threats={self.threats!r}, available={self.available})"


def _post(url, body: bytes, timeout: float, opener, headers: dict):
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with opener(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


class ActionGuardVerdict:
    """Normalised result of POST /api/v1/action-guard (evaluateToolCall)."""

    __slots__ = ("decision", "signals", "reason", "available")

    def __init__(self, decision: str, signals, reason: object = "", available: bool = True):
        self.decision = (decision or "allow").lower()  # allow | require_approval | block
        if isinstance(signals, list):
            self.signals = [s for s in signals if isinstance(s, str)][:32]
        else:
            self.signals = []
        self.reason = sanitize_remote_reason(reason)
        self.available = available

    def __repr__(self) -> str:
        return (
            f"ActionGuardVerdict(decision={self.decision!r}, "
            f"signals={self.signals!r}, available={self.available})"
        )


def evaluate_tool_call(
    tool: str,
    args: dict | None = None,
    *,
    base_url: str | None = None,
    timeout: float = 4.0,
    opener=urllib.request.urlopen,
) -> ActionGuardVerdict:
    """Ask ShieldCortex's Action Guard for a verdict. Never raises."""
    base = (base_url or DEFAULT_BASE_URL).rstrip("/")
    body = json.dumps(
        {
            "tool": tool,
            "args": args if isinstance(args, dict) else {},
            "source": {"type": "tool", "identifier": "hermes"},
        }
    ).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    token = _api_token()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        data = _post(f"{base}/api/v1/action-guard", body, timeout, opener, headers)
    except Exception as exc:
        return ActionGuardVerdict("allow", [], f"scanner unreachable: {exc}", available=False)

    # A 200 JSON body is not a verdict. Missing/unknown `decision` used to
    # coerce to allow + available=True, which skipped the #59 fallback and
    # failed open on the advertised bound plane (wrong local service, proxy
    # envelope, future field rename). Treat it as unavailable so the
    # catastrophic/dangerous fallback still runs.
    if not isinstance(data, dict):
        return ActionGuardVerdict("allow", [], "malformed action-guard response", available=False)
    decision_raw = data.get("decision")
    if not isinstance(decision_raw, str) or not decision_raw.strip():
        return ActionGuardVerdict(
            "allow", [], "malformed action-guard response: missing decision", available=False,
        )
    decision = decision_raw.strip().lower()
    if decision not in ("allow", "require_approval", "block"):
        shown = decision[:32]
        return ActionGuardVerdict(
            "allow", [], f"unknown action-guard decision: {shown!r}", available=False,
        )
    signals = data.get("signals") or []
    if not isinstance(signals, list):
        signals = []
    return ActionGuardVerdict(decision, signals, data.get("reason"), available=True)


def scan(
    content: str,
    *,
    title: str = "hermes",
    source_type: str = "tool",
    source_id: str = "hermes",
    base_url: str | None = None,
    timeout: float = 4.0,
    opener=urllib.request.urlopen,
) -> Verdict:
    """Scan `content` through ShieldCortex. Never raises — returns a Verdict."""
    base = (base_url or DEFAULT_BASE_URL).rstrip("/")
    body = json.dumps(
        {"content": content, "title": title, "source": {"type": source_type, "identifier": source_id}}
    ).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    token = _api_token()
    if token:
        headers["Authorization"] = f"Bearer {token}"  # never logged
    try:
        data = _post(f"{base}/api/v1/scan", body, timeout, opener, headers)
    except Exception as exc:  # network / HTTP / parse error -> fail OPEN
        return Verdict("ERROR", [], f"scanner unreachable: {exc}", available=False)

    fw = (data or {}).get("firewall") or {}
    result = fw.get("result", "ALLOW")
    threats = fw.get("threatIndicators") or fw.get("threats") or []
    reason = fw.get("reason", "")
    return Verdict(result, threats, reason, available=True)
