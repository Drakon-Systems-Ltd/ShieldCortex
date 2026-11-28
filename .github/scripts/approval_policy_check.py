#!/usr/bin/env python3
"""approval-policy check: dependency-free (Python 3 stdlib only).

Reads .github/approval-policy.yml (from the DEFAULT branch, never the PR head), the PR's
changed files, reviews, comments and CI results, and posts the commit status
`approval-policy` on the PR head: success only when every requirement of every
matched path class is evidenced at the exact head. It fails closed: an unparseable
or unknown-key policy, an unclassified path, a truncated file list, a missing patch
on a migration file, or any API error gives `failure` (or exits non-zero).

Modes:
  --validate POLICY                      parse + schema-check the policy, exit 0/1
  --fixture FIXTURE.json --policy P      evaluate offline data (tests), print JSON result
  --event EVENT.json --policy P          GitHub Actions: evaluate PR(s) named by the event, post status
  --repo OWNER/NAME --pr N --policy P    evaluate one PR via the API (add --dry-run to not post)

The evidence formats are defined in skills/fleet-doctrine/references/review-protocol.md (P10):
  REVIEW head <sha> | <seat>: APPROVE|CHANGES_REQUESTED|NO VERDICT ... | reports: ...
  INDEPENDENT REVIEW PANEL head <sha> | <seat>: ... | ...
  FABLE GREEN-LIGHT head <sha> | decision: <DECISION> | ref: <path>
  MIGRATION GATE head <sha> | downgrade: <evidence> | backward-compatible: yes | backup: <id>
Only comments by the policy's trusted lane/owner logins count; formal GitHub reviews
count only from trusted fleet/owner logins and only at the exact head.
"""
import json
import os
import re
import sys
import urllib.error
import urllib.request

STATUS_CONTEXT = "approval-policy"
API = os.environ.get("GITHUB_API_URL", "https://api.github.com")


class PolicyError(Exception):
    pass


# --------------------------------------------------------------------------- YAML subset
# Supported: block mappings, block lists of scalars or mappings, flow lists of scalars
# [a, "b"], plain/single/double-quoted scalars, true/false, integers, full-line and
# trailing comments. Anything else (tabs, anchors, aliases, tags, block scalars, flow
# mappings, duplicate keys, multi-docs) is rejected so the policy can never be
# read differently by a person and by this script.

_FORBIDDEN_START = ("&", "*", "!", "|", ">", "{", "%", "@", "`")


def _strip_comment(line):
    out, q = [], None
    for i, ch in enumerate(line):
        if q:
            out.append(ch)
            if ch == q:
                q = None
            continue
        if ch in ("'", '"'):
            q = ch
        elif ch == "#" and (i == 0 or line[i - 1] in " \t"):
            break
        out.append(ch)
    if q:
        raise PolicyError("unterminated quote: %r" % line)
    return "".join(out).rstrip()


def _scalar(tok, lineno):
    tok = tok.strip()
    if tok == "":
        raise PolicyError("line %d: empty value" % lineno)
    if tok[0] in ('"', "'"):
        if len(tok) < 2 or tok[-1] != tok[0]:
            raise PolicyError("line %d: bad quoted scalar %r" % (lineno, tok))
        body = tok[1:-1]
        if tok[0] == '"':
            if "\\" in body:
                raise PolicyError("line %d: escapes not supported" % lineno)
        else:
            body = body.replace("''", "'")
        return body
    if tok.startswith(_FORBIDDEN_START) or tok in ("~", "null", "Null", "NULL"):
        raise PolicyError("line %d: unsupported YAML construct %r" % (lineno, tok))
    if tok.startswith("[") or tok.endswith("]"):
        if not (tok.startswith("[") and tok.endswith("]")):
            raise PolicyError("line %d: bad flow list %r" % (lineno, tok))
        inner = tok[1:-1].strip()
        if not inner:
            return []
        items, cur, q = [], [], None
        for ch in inner:
            if q:
                cur.append(ch)
                if ch == q:
                    q = None
            elif ch in ("'", '"'):
                q = ch
                cur.append(ch)
            elif ch == ",":
                items.append("".join(cur))
                cur = []
            elif ch in "[]{}":
                raise PolicyError("line %d: nested flow collections not supported" % lineno)
            else:
                cur.append(ch)
        items.append("".join(cur))
        return [_scalar(x, lineno) for x in items]
    if ": " in tok or tok.endswith(":"):
        raise PolicyError("line %d: unexpected mapping in scalar %r" % (lineno, tok))
    if tok in ("true", "True"):
        return True
    if tok in ("false", "False"):
        return False
    if tok.lower() in ("yes", "no", "on", "off"):
        raise PolicyError("line %d: ambiguous boolean %r; use true/false or quote it" % (lineno, tok))
    if re.fullmatch(r"-?[0-9]+", tok):
        return int(tok)
    return tok


def parse_yaml_subset(text):
    if "\t" in text:
        raise PolicyError("tabs are not allowed")
    lines = []
    for n, raw in enumerate(text.splitlines(), 1):
        if raw.strip() in ("---", "...") :
            raise PolicyError("line %d: document markers not supported" % n)
        s = _strip_comment(raw)
        if s.strip():
            lines.append((n, len(s) - len(s.lstrip(" ")), s.strip()))
    if not lines:
        raise PolicyError("empty policy")
    pos = [0]

    def parse_block(indent):
        n, ind, content = lines[pos[0]]
        if ind != indent:
            raise PolicyError("line %d: bad indentation" % n)
        if content.startswith("- ") or content == "-":
            return parse_list(indent)
        return parse_map(indent)

    def parse_map(indent, first=None):
        out = {}
        while pos[0] < len(lines):
            n, ind, content = lines[pos[0]]
            if first is not None:
                content, ind, first = first, indent, None
            elif ind < indent:
                break
            elif ind > indent:
                raise PolicyError("line %d: unexpected indentation" % n)
            if content.startswith("- "):
                raise PolicyError("line %d: list item where a key was expected" % n)
            m = re.fullmatch(r"([A-Za-z0-9_.-]+):(?:\s+(.*))?", content)
            if not m:
                raise PolicyError("line %d: expected 'key: value', got %r" % (n, content))
            key, val = m.group(1), m.group(2)
            if key in out:
                raise PolicyError("line %d: duplicate key %r" % (n, key))
            pos[0] += 1
            if val is None or val == "":
                if pos[0] >= len(lines) or lines[pos[0]][1] <= indent:
                    raise PolicyError("line %d: key %r has no value" % (n, key))
                out[key] = parse_block(lines[pos[0]][1])
            else:
                out[key] = _scalar(val, n)
        return out

    def parse_list(indent):
        out = []
        while pos[0] < len(lines):
            n, ind, content = lines[pos[0]]
            if ind < indent:
                break
            if ind > indent:
                raise PolicyError("line %d: unexpected indentation" % n)
            if not (content.startswith("- ") or content == "-"):
                break
            item = content[1:].strip()
            if item == "":
                raise PolicyError("line %d: empty list item" % n)
            if re.match(r"[A-Za-z0-9_.-]+:(\s|$)", item):
                # mapping item: first key inline, the rest indented by 2 more
                sub_indent = indent + 2
                out.append(parse_map(sub_indent, first=item))
            else:
                pos[0] += 1
                out.append(_scalar(item, n))
        return out

    result = parse_block(0)
    if pos[0] != len(lines):
        n = lines[pos[0]][0]
        raise PolicyError("line %d: trailing content not parsed" % n)
    if not isinstance(result, dict):
        raise PolicyError("policy root must be a mapping")
    return result


# --------------------------------------------------------------------------- schema
TOP_KEYS = {"version", "repo", "lane", "trusted", "seats", "fleet_stand_in", "author_cannot_fill_seat", "ci", "fable",
            "classes", "default_class"}
TRUSTED_KEYS = {"owner", "lane", "fleet"}
CI_KEYS = {"require_at_least_one", "ignore"}
FABLE_KEYS = {"approve_decisions"}
CLASS_KEYS = {"name", "purpose", "paths", "labels", "titles", "require", "destructive_patterns", "destructive_stop"}
REQ_KEYS = {"seats", "any_seats", "fable", "owner", "migration_gate", "ci"}


def _need(cond, msg):
    if not cond:
        raise PolicyError(msg)


def _strlist(v, where, allow_empty=False):
    _need(isinstance(v, list) and all(isinstance(x, str) and x for x in v), "%s must be a list of strings" % where)
    _need(allow_empty or v, "%s must not be empty" % where)
    return v


def validate_policy(p):
    _need(isinstance(p, dict), "policy must be a mapping")
    unknown = set(p) - TOP_KEYS
    _need(not unknown, "unknown top-level key(s): %s" % ", ".join(sorted(unknown)))
    _need(p.get("version") == 1, "version must be 1")
    _need(isinstance(p.get("repo"), str) and "/" in p["repo"], "repo must be owner/name")
    t = p.get("trusted")
    _need(isinstance(t, dict), "trusted must be a mapping")
    _need(not (set(t) - TRUSTED_KEYS), "unknown trusted key(s)")
    for k in TRUSTED_KEYS:
        _strlist(t.get(k, []), "trusted.%s" % k, allow_empty=(k != "lane"))
    seats = p.get("seats")
    _need(isinstance(seats, dict) and seats, "seats must be a non-empty mapping of seat -> aliases")
    for s, al in seats.items():
        _strlist(al, "seats.%s" % s)
    _need(isinstance(p.get("fleet_stand_in", False), bool), "fleet_stand_in must be true/false")
    _need(isinstance(p.get("author_cannot_fill_seat", True), bool), "author_cannot_fill_seat must be true/false")
    ci = p.get("ci", {})
    _need(isinstance(ci, dict) and not (set(ci) - CI_KEYS), "ci has unknown keys")
    _need(isinstance(ci.get("require_at_least_one", True), bool), "ci.require_at_least_one must be bool")
    _strlist(ci.get("ignore", []), "ci.ignore", allow_empty=True)
    fb = p.get("fable", {})
    _need(isinstance(fb, dict) and not (set(fb) - FABLE_KEYS), "fable has unknown keys")
    _strlist(fb.get("approve_decisions", ["MERGE"]), "fable.approve_decisions")
    classes = p.get("classes")
    _need(isinstance(classes, list) and classes, "classes must be a non-empty list")
    names = set()
    for c in classes:
        _need(isinstance(c, dict), "each class must be a mapping")
        unk = set(c) - CLASS_KEYS
        _need(not unk, "class %r: unknown key(s) %s" % (c.get("name"), ", ".join(sorted(unk))))
        name = c.get("name")
        _need(isinstance(name, str) and re.fullmatch(r"[a-z0-9-]+", name or ""), "class name must be [a-z0-9-]+")
        _need(name not in names, "duplicate class %r" % name)
        names.add(name)
        _need(any(k in c for k in ("paths", "labels", "titles")), "class %r needs paths, labels or titles" % name)
        for k in ("paths", "labels", "titles", "destructive_patterns", "destructive_stop"):
            if k in c:
                _strlist(c[k], "class %s.%s" % (name, k))
        for rx in c.get("titles", []) + c.get("destructive_patterns", []) + c.get("destructive_stop", []):
            try:
                re.compile(rx)
            except re.error as e:
                raise PolicyError("class %s: bad regex %r: %s" % (name, rx, e))
        r = c.get("require")
        _need(isinstance(r, dict) and r, "class %r: require must be a non-empty mapping" % name)
        unk = set(r) - REQ_KEYS
        _need(not unk, "class %r: unknown requirement(s) %s" % (name, ", ".join(sorted(unk))))
        if "seats" in r:
            _strlist(r["seats"], "class %s.require.seats" % name)
            for s in r["seats"]:
                _need(s in seats, "class %r requires unknown seat %r" % (name, s))
        if "any_seats" in r:
            _need(isinstance(r["any_seats"], int) and not isinstance(r["any_seats"], bool) and r["any_seats"] >= 1,
                  "class %r: any_seats must be an integer >= 1" % name)
        for b in ("fable", "owner", "migration_gate", "ci"):
            if b in r:
                _need(isinstance(r[b], bool), "class %r: require.%s must be true/false" % (name, b))
        _need(r.get("ci", True) is True, "class %r: ci cannot be switched off" % name)
        _need(any(r.get(k) for k in ("seats", "any_seats", "owner")),
              "class %r must require seats, any_seats or owner" % name)
        if c.get("destructive_stop"):
            _need(c.get("destructive_patterns"), "class %r: destructive_stop needs destructive_patterns" % name)
        if c.get("destructive_patterns"):
            _need(r.get("migration_gate") is True, "class %r: destructive_patterns only on a migration_gate class" % name)
    dc = p.get("default_class")
    if dc is not None:
        _need(dc in names, "default_class %r is not a class" % dc)
    return p


def load_policy(path):
    try:
        with open(path, encoding="utf-8") as f:
            text = f.read()
    except OSError as e:
        raise PolicyError("cannot read policy %s: %s" % (path, e))
    return validate_policy(parse_yaml_subset(text))


# --------------------------------------------------------------------------- matching
def glob_to_regex(pat):
    anchored = pat.startswith("/")
    pat = pat.lstrip("/")
    i, out = 0, []
    while i < len(pat):
        if pat.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pat.startswith("**", i):
            out.append(".*")
            i += 2
        elif pat[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pat[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pat[i]))
            i += 1
    body = "".join(out)
    if not anchored and "/" not in pat:
        body = "(?:.*/)?" + body  # bare name: match at any depth
    if pat.endswith("/"):
        body += ".*"
    return re.compile(r"\A" + body + r"\Z", re.I)  # case-insensitive: errs towards matching (stricter)


def classify(policy, pr, files):
    """Return (per_file: {path: [class names]}, pr_level: [class names], problems)."""
    classes = policy["classes"]
    default = policy.get("default_class")
    compiled = {c["name"]: [glob_to_regex(g) for g in c.get("paths", [])] for c in classes}
    labels = {l.lower() for l in pr.get("labels", [])}
    title = pr.get("title", "")
    pr_level = []
    for c in classes:
        if any(l.lower() in labels for l in c.get("labels", [])) or any(
                re.search(rx, title, re.I) for rx in c.get("titles", [])):
            pr_level.append(c["name"])
    per_file, problems = {}, []
    for f in files:
        names = [f["filename"]] + ([f["previous_filename"]] if f.get("previous_filename") else [])
        hit = []
        for c in classes:
            if c["name"] == default:
                continue
            if any(rx.match(n) for rx in compiled[c["name"]] for n in names):
                hit.append(c["name"])
        if not hit and default and any(rx.match(n) for rx in compiled[default] for n in names):
            hit = [default]
        if not hit:
            problems.append("unclassified path: %s" % f["filename"])
        per_file[f["filename"]] = hit
    return per_file, pr_level, problems


# --------------------------------------------------------------------------- evidence
VERDICT_RX = re.compile(r"\b(NO[ _]VERDICT|CHANGES[ _]REQUESTED|APPROVED?|BLOCK(?:ED|ING)?|REJECT(?:ED)?)\b", re.I)
NEGATION_RX = re.compile(r"(?:\b(?:not|never|cannot)\b|n't)\s+(?:be\s+)?$", re.I)
REVIEW_LINE_RX = re.compile(r"^(?:INDEPENDENT REVIEW PANEL|REVIEW)\s+head\s+([0-9a-f]{7,40})\b(.*)$", re.I | re.M)
FABLE_RX = re.compile(r"^FABLE GREEN-LIGHT\s+head\s+([0-9a-f]{7,40})\s*\|\s*decision:\s*([^|\n]+?)\s*(?:\|\s*ref:\s*(\S[^|\n]*))?\s*$", re.I | re.M)
# fleet accounts (Tars, Case, ...) often post their verdict as a comment: "**APPROVE** at `<sha>`"
FLEET_COMMENT_RX = re.compile(r"\b(APPROVE|CHANGES[ _]REQUESTED)\b\W{0,4}\s*(?:at|@)\s*`?([0-9a-f]{7,40})\b", re.I)
MIG_RX = re.compile(r"^MIGRATION GATE\s+head\s+([0-9a-f]{7,40})\s*\|(.*)$", re.I | re.M)
EMPTY_EVIDENCE_RX = re.compile(r"^(none|no|n/?a|tbd|todo|skip(ped)?|-+|\?+)$|\b(not\s+(tested|run|taken|done)|untested|no\s+backup|pending)\b", re.I)


def _head_match(sha, head):
    return len(sha) >= 7 and head.lower().startswith(sha.lower())


def _negated(text, pos):
    return bool(NEGATION_RX.search(text[max(0, pos - 20):pos].replace("*", "")))


def _verdict(text):
    """First verdict word after a seat label. A negated APPROVE ("not approve", "would not approve",
    "NOT APPROVED") is a CHANGES_REQUESTED, never an approval."""
    m = VERDICT_RX.search(text)
    if not m:
        return "NO_VERDICT"
    v = m.group(1).upper().replace(" ", "_")
    if v.startswith("APPROVE"):
        return "CHANGES_REQUESTED" if _negated(text, m.start()) else "APPROVE"
    if v.startswith(("BLOCK", "REJECT", "CHANGES")):
        return "CHANGES_REQUESTED"
    return "NO_VERDICT"


def seat_of(label, seats):
    lab = label.strip().lower()
    for s, aliases in seats.items():
        for a in aliases:
            a = a.lower()
            if lab == a or lab.endswith("/" + a) or lab.endswith("-" + a):
                return s
    return None


def _norm_decision(d):
    return re.sub(r"\s+", " ", d.strip().upper())


def gather_evidence(policy, pr, reviews, comments):
    head = pr["head_sha"]
    t = policy["trusted"]
    low = lambda xs: {x.lower() for x in xs}  # GitHub logins are case-insensitive
    comment_authors = low(t.get("lane", [])) | low(t.get("owner", []))
    fleet = low(t.get("fleet", []))
    owner = low(t.get("owner", []))
    seats = policy["seats"]
    approve_decisions = {_norm_decision(d) for d in policy.get("fable", {}).get("approve_decisions", ["MERGE"])}
    author = (pr.get("author") or "").lower()
    ev = {"seat": {}, "fable": None, "fable_negative": None, "migration_gate": None,
          "fleet_approve": [], "blocks": [], "owner_approve": False, "ignored": 0}
    # per fleet/owner login: a timeline of (time, kind, verdict, sha, login); the newest entry wins,
    # whether it came from a comment or a formal review
    timeline = {}
    for c in sorted(comments, key=lambda c: c.get("created_at") or ""):
        login = (c.get("user") or "").lower()
        body = c.get("body") or ""
        if login in fleet and login not in comment_authors:
            last = None
            for m in FLEET_COMMENT_RX.finditer(body):
                verdict = m.group(1).upper().replace(" ", "_")
                if verdict == "APPROVE" and _negated(body, m.start()):
                    verdict = "CHANGES_REQUESTED"
                last = (verdict, m.group(2))
            if last:  # the last verdict in a comment is the author's current one
                timeline.setdefault(login, []).append((c.get("created_at") or "", "comment", last[0], last[1], c.get("user")))
            continue
        if login not in comment_authors:
            ev["ignored"] += 1
            continue
        for m in REVIEW_LINE_RX.finditer(body):
            if not _head_match(m.group(1), head):
                continue
            for part in m.group(2).split("|"):
                if ":" not in part:
                    continue
                label, rest = part.split(":", 1)
                s = seat_of(label, seats)
                if s:
                    ev["seat"][s] = _verdict(rest)  # later comments override earlier at the same head
        for m in FABLE_RX.finditer(body):
            if not _head_match(m.group(1), head):
                continue
            dec = _norm_decision(m.group(2))
            if dec in approve_decisions:  # exact decision only: "MERGE BLOCKED" is not "MERGE"
                ev["fable"], ev["fable_negative"] = dec, None
            else:
                ev["fable"], ev["fable_negative"] = None, dec
        for m in MIG_RX.finditer(body):
            if not _head_match(m.group(1), head):
                continue
            kv = {}
            for part in m.group(2).split("|"):
                if ":" in part:
                    k, v = part.split(":", 1)
                    kv[k.strip().lower()] = v.strip()
            ok = all(kv.get(k) and not EMPTY_EVIDENCE_RX.search(kv[k]) for k in ("downgrade", "backup")) and \
                kv.get("backward-compatible", "").lower() == "yes"
            ev["migration_gate"] = bool(ok)
    for r in reviews:
        u = (r.get("user") or "").lower()
        if (u in fleet or u in owner) and r.get("state") in ("APPROVED", "CHANGES_REQUESTED", "DISMISSED"):
            v = {"APPROVED": "APPROVE"}.get(r["state"], r["state"])
            timeline.setdefault(u, []).append((r.get("submitted_at") or "", "review", v, r.get("commit_id") or "", r.get("user")))
    for u, items in timeline.items():
        items.sort(key=lambda x: x[0])
        when, kind, verdict, sha, orig = items[-1]
        if verdict == "CHANGES_REQUESTED":
            ev["blocks"].append("%s %sCHANGES_REQUESTED at %s" % (orig, "comment " if kind == "comment" else "", sha[:7]))
            continue
        if verdict != "APPROVE" or not sha or not _head_match(sha, head):
            continue
        if u in owner and kind == "review":
            ev["owner_approve"] = True  # only a formal GitHub review from the owner, never a comment
        if u in fleet and not (policy.get("author_cannot_fill_seat") and u == author):
            ev["fleet_approve"].append(orig)
    for s, v in ev["seat"].items():
        if v == "CHANGES_REQUESTED":
            ev["blocks"].append("seat %s CHANGES_REQUESTED at head" % s)
    return ev


def ci_state(policy, checks, statuses):
    ignore = set(x.lower() for x in policy.get("ci", {}).get("ignore", [])) | {STATUS_CONTEXT}
    seen, bad, pending = 0, [], []
    for c in checks:
        if (c.get("name") or "").lower() in ignore:
            continue
        seen += 1
        if c.get("status") != "completed":
            pending.append(c.get("name"))
        elif c.get("conclusion") not in ("success", "neutral", "skipped"):
            bad.append("%s=%s" % (c.get("name"), c.get("conclusion")))
    latest = {}
    for s in statuses:  # API returns newest first; keep the first per context
        latest.setdefault(s.get("context"), s)
    for ctx, s in latest.items():
        if (ctx or "").lower() in ignore:
            continue
        seen += 1
        if s.get("state") == "pending":
            pending.append(ctx)
        elif s.get("state") != "success":
            bad.append("%s=%s" % (ctx, s.get("state")))
    if bad:
        return False, "CI red: " + ", ".join(bad)
    if pending:
        return False, "CI pending: " + ", ".join(pending)
    if seen == 0 and policy.get("ci", {}).get("require_at_least_one", True):
        return False, "no CI result on head"
    return True, "CI green (%d)" % seen


# --------------------------------------------------------------------------- evaluate
def evaluate(policy, pr, files, reviews, comments, checks, statuses):
    head = pr["head_sha"]
    fails = []
    if pr.get("state", "open") != "open":
        return {"state": "skip", "reasons": ["PR not open"], "classes": []}
    if pr.get("draft"):
        fails.append("draft PR")
    if pr.get("changed_files") is not None and pr["changed_files"] != len(files):
        fails.append("file list truncated (%d of %d)" % (len(files), pr["changed_files"]))
    if not files:
        fails.append("no changed files listed")
    per_file, pr_level, problems = classify(policy, pr, files)
    fails += problems
    by_name = {c["name"]: c for c in policy["classes"]}
    matched = sorted(set(pr_level) | {n for ns in per_file.values() for n in ns})
    req = {"seats": set(), "any_seats": 0, "fable": False, "owner": False, "migration_gate": False}
    for n in matched:
        r = by_name[n]["require"]
        req["seats"] |= set(r.get("seats", []))
        req["any_seats"] = max(req["any_seats"], r.get("any_seats", 0))
        for b in ("fable", "owner", "migration_gate"):
            req[b] = req[b] or bool(r.get(b))
    # destructive migrations are owner-only, and a missing patch cannot be ruled out
    owner_why = []
    for n in matched:
        pats = by_name[n].get("destructive_patterns")
        if not pats:
            continue
        rxs = [re.compile(p, re.I) for p in pats]
        stops = [re.compile(p, re.I) for p in by_name[n].get("destructive_stop", [])]
        for f in files:
            if n not in per_file.get(f["filename"], []):
                continue
            patch = f.get("patch")
            if patch is None:
                req["owner"] = True
                owner_why.append("no patch for migration %s: destructive change not ruled out" % f["filename"])
                continue
            added_lines, skipping = [], False
            for l in patch.splitlines():
                body = l[1:] if l[:1] in "+- " else l
                if l.startswith("@@"):
                    # a hunk header names its enclosing function: "@@ -1,2 +1,3 @@ def downgrade():"
                    ctx = l.split("@@", 2)[-1]
                    skipping = bool(stops) and any(rx.search(ctx.strip()) for rx in stops)
                    continue
                if stops and any(rx.search(body) for rx in stops):
                    skipping = True  # the reverse (downgrade) half is not what runs on deploy
                    continue
                if skipping and re.match(r"\s*def\s+\w+", body):
                    skipping = False  # next top-level function: back to scanning
                if not skipping and l.startswith("+") and not l.startswith("+++"):
                    added_lines.append(body)
            added = "\n".join(added_lines)
            if any(rx.search(added) for rx in rxs):
                req["owner"] = True
                owner_why.append("destructive migration %s" % f["filename"])
    ev = gather_evidence(policy, pr, reviews, comments)
    fails += ev["blocks"]
    ok_ci, ci_msg = ci_state(policy, checks, statuses)
    if not ok_ci:
        fails.append(ci_msg)
    approved = {s for s, v in ev["seat"].items() if v == "APPROVE"}
    missing = sorted(req["seats"] - approved)
    stand_ins = list(ev["fleet_approve"]) if policy.get("fleet_stand_in") else []
    # each fleet APPROVE at head fills one missing seat
    while missing and stand_ins:
        missing.pop()
        stand_ins.pop()
    if missing:
        fails.append("needs APPROVE at %s from seat(s): %s" % (head[:7], ", ".join(missing)))
    have_any = len(approved) + (len(ev["fleet_approve"]) if policy.get("fleet_stand_in") else 0)
    if req["any_seats"] and have_any < req["any_seats"]:
        fails.append("needs %d reviewer APPROVE at %s (have %d)" % (req["any_seats"], head[:7], have_any))
    if req["fable"] and not ev["fable"]:
        fails.append("needs FABLE GREEN-LIGHT at %s%s" % (
            head[:7], " (latest decision: %s)" % ev["fable_negative"] if ev["fable_negative"] else ""))
    if req["migration_gate"] and not ev["migration_gate"]:
        fails.append("needs MIGRATION GATE comment at %s (downgrade, backward-compatible: yes, backup)" % head[:7])
    if req["owner"] and not ev["owner_approve"]:
        fails += owner_why
        fails.append("owner-only: needs the owner's own GitHub APPROVE at %s; policy cannot approve this" % head[:7])
    state = "success"
    if fails:
        state = "pending" if all(f.startswith("CI pending") for f in fails) else "failure"
    return {
        "state": state,
        "reasons": fails,
        "classes": matched,
        "required": {"seats": sorted(req["seats"]), "any_seats": req["any_seats"], "fable": req["fable"],
                     "owner": req["owner"], "migration_gate": req["migration_gate"]},
        "evidence": {"seats": ev["seat"], "fleet_approve": ev["fleet_approve"], "fable": ev["fable"],
                     "migration_gate": ev["migration_gate"], "owner_approve": ev["owner_approve"],
                     "ci": ci_msg},
        "per_file": per_file,
    }


def describe(result):
    if result["state"] == "success":
        d = "OK [%s]" % ",".join(result["classes"])
    else:
        d = "; ".join(result["reasons"])
    return d if len(d) <= 140 else d[:137] + "..."


# --------------------------------------------------------------------------- GitHub I/O
def _req(method, path, token, body=None):
    url = path if path.startswith("http") else API + path
    data = json.dumps(body).encode() if body is not None else None
    rq = urllib.request.Request(url, data=data, method=method, headers={
        "Authorization": "Bearer " + token, "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "approval-policy-check"})
    with urllib.request.urlopen(rq, timeout=30) as resp:
        link = resp.headers.get("Link", "")
        return json.loads(resp.read().decode() or "null"), link


def _paged(path, token, key=None):
    out, url = [], path + ("&" if "?" in path else "?") + "per_page=100"
    for _ in range(40):
        data, link = _req("GET", url, token)
        out += data[key] if key else data
        m = re.search(r'<([^>]+)>;\s*rel="next"', link)
        if not m:
            return out
        url = m.group(1)
    raise RuntimeError("pagination limit hit for %s" % path)


def fetch(repo, num, token):
    p, _ = _req("GET", "/repos/%s/pulls/%d" % (repo, num), token)
    pr = {"number": num, "head_sha": p["head"]["sha"], "title": p.get("title", ""), "state": p["state"],
          "draft": p.get("draft", False), "labels": [l["name"] for l in p.get("labels", [])],
          "changed_files": p.get("changed_files"), "author": p["user"]["login"]}
    files = [{"filename": f["filename"], "previous_filename": f.get("previous_filename"),
              "status": f.get("status"), "patch": f.get("patch")}
             for f in _paged("/repos/%s/pulls/%d/files" % (repo, num), token)]
    reviews = [{"user": (r.get("user") or {}).get("login"), "state": r.get("state"),
                "commit_id": r.get("commit_id"), "submitted_at": r.get("submitted_at")}
               for r in _paged("/repos/%s/pulls/%d/reviews" % (repo, num), token)]
    comments = [{"user": (c.get("user") or {}).get("login"), "body": c.get("body"), "created_at": c.get("created_at")}
                for c in _paged("/repos/%s/issues/%d/comments" % (repo, num), token)]
    checks = [{"name": c.get("name"), "status": c.get("status"), "conclusion": c.get("conclusion")}
              for c in _paged("/repos/%s/commits/%s/check-runs" % (repo, pr["head_sha"]), token, key="check_runs")]
    statuses = _paged("/repos/%s/commits/%s/statuses" % (repo, pr["head_sha"]), token)
    return pr, files, reviews, comments, checks, statuses


def post_status(repo, sha, state, desc, token, target=None):
    body = {"state": state, "context": STATUS_CONTEXT, "description": desc}
    if target:
        body["target_url"] = target
    _req("POST", "/repos/%s/statuses/%s" % (repo, sha), token, body)


def prs_from_event(event, repo, token):
    """[(pr number, head sha from the event or None)]"""
    if isinstance(event.get("pull_request"), dict):
        return [(event["pull_request"]["number"], (event["pull_request"].get("head") or {}).get("sha"))]
    if "issue" in event:
        return [(event["issue"]["number"], None)] if event["issue"].get("pull_request") else []
    for key in ("workflow_run", "check_suite"):
        if key in event:
            wr = event[key]
            nums = [(p["number"], (p.get("head") or {}).get("sha")) for p in wr.get("pull_requests") or []]
            if not nums and wr.get("head_sha"):
                data, _ = _req("GET", "/repos/%s/commits/%s/pulls" % (repo, wr["head_sha"]), token)
                nums = [(p["number"], p["head"]["sha"]) for p in data if p.get("state") == "open"]
            return nums
    if "inputs" in event and str(event["inputs"].get("pr", "")).isdigit():
        return [(int(event["inputs"]["pr"]), None)]
    return []


def _evaluate_live(policy, repo, num, token, backtest):
    pr, files, reviews, comments, checks, statuses = fetch(repo, num, token)
    if backtest:  # observe-style replay of a closed/merged PR; never posts
        pr["state"] = "open"
    return pr, evaluate(policy, pr, files, reviews, comments, checks, statuses)


def run_pr(policy, repo, num, token, dry, target, backtest=False, event_sha=None):
    """Evaluate, then evaluate again from fresh data and post only when both agree (up to 3 tries).
    A run that started on stale data therefore cannot overwrite a newer result with an older one.
    Any error posts failure on the head (from the API or, failing that, the event)."""
    pr, res, sha = None, None, event_sha
    try:
        for _ in range(3):
            pr, res = _evaluate_live(policy, repo, num, token, backtest)
            sha = pr["head_sha"]
            pr2, res2 = _evaluate_live(policy, repo, num, token, backtest)
            if pr2["head_sha"] == sha and res2["state"] == res["state"] and res2["reasons"] == res["reasons"]:
                break
            res = None
        if res is None:
            res = {"state": "failure", "reasons": ["evidence kept changing during evaluation; re-run"], "classes": []}
    except Exception as e:  # fail closed
        res = {"state": "failure", "reasons": ["check error: %s" % e], "classes": []}
    print(json.dumps({"pr": num, **res}, indent=1, default=list))
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as f:
            f.write("### approval-policy PR #%d: %s\n\n" % (num, res["state"]))
            for r in res["reasons"]:
                f.write("- %s\n" % r)
            f.write("\nclasses: %s\n\n" % ", ".join(res.get("classes", [])))
    if res["state"] == "skip":
        return True
    if dry:
        return pr is not None
    if not sha:
        print("no head sha known for #%d; nothing posted, so nothing is green" % num, file=sys.stderr)
        return False
    post_status(repo, sha, res["state"], describe(res), token, target)
    return True


def main(argv):
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--policy")
    ap.add_argument("--validate")
    ap.add_argument("--fixture")
    ap.add_argument("--event")
    ap.add_argument("--repo")
    ap.add_argument("--pr", type=int)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--backtest", action="store_true", help="evaluate a merged/closed PR as if open; implies --dry-run")
    a = ap.parse_args(argv)
    if a.validate:
        try:
            p = load_policy(a.validate)
        except PolicyError as e:
            print("INVALID: %s" % e)
            return 1
        print("OK: %d classes (%s)" % (len(p["classes"]), ", ".join(c["name"] for c in p["classes"])))
        return 0
    if a.fixture:
        with open(a.fixture, encoding="utf-8") as f:
            fx = json.load(f)
        try:
            policy = load_policy(a.policy)
            res = evaluate(policy, fx["pr"], fx["files"], fx.get("reviews", []), fx.get("comments", []),
                           fx.get("checks", []), fx.get("statuses", []))
        except PolicyError as e:
            res = {"state": "failure", "reasons": ["policy error: %s" % e], "classes": []}
        print(json.dumps(res, indent=1, default=list))
        return 0 if res["state"] == "success" else 1
    token = os.environ.get("GITHUB_TOKEN", "")
    repo = a.repo or os.environ.get("GITHUB_REPOSITORY", "")
    if not token or not repo:
        print("GITHUB_TOKEN and repo are required", file=sys.stderr)
        return 2
    target = None
    if os.environ.get("GITHUB_RUN_ID"):
        target = "%s/%s/actions/runs/%s" % (os.environ.get("GITHUB_SERVER_URL", "https://github.com"), repo,
                                            os.environ["GITHUB_RUN_ID"])
    nums = [(a.pr, None)] if a.pr else []
    if a.event:
        with open(a.event, encoding="utf-8") as f:
            nums = prs_from_event(json.load(f), repo, token)
    try:
        policy = load_policy(a.policy)
    except PolicyError as e:
        # fail closed: mark every PR we were asked about red
        for n, ev_sha in nums:
            try:
                p, _ = _req("GET", "/repos/%s/pulls/%d" % (repo, n), token)
                if not a.dry_run and p["state"] == "open":
                    post_status(repo, p["head"]["sha"], "failure", ("policy error: %s" % e)[:140], token, target)
            except Exception as e2:
                print("could not post failure for #%d: %s" % (n, e2), file=sys.stderr)
                if ev_sha and not a.dry_run:
                    post_status(repo, ev_sha, "failure", ("policy error: %s" % e)[:140], token, target)
        print("policy error: %s" % e, file=sys.stderr)
        return 1
    if not nums:
        print("no PR in this event; nothing to do")
        return 0
    ok = True
    for n, ev_sha in nums:
        ok = run_pr(policy, repo, n, token, a.dry_run or a.backtest, target, a.backtest, ev_sha) and ok
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
