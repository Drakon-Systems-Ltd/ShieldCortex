/**
 * #923 r11 (r10 Grok BLOCKER, r10 Astra B1): transcript spellings whose
 * anchors are SPLIT across an expansion. No single piece of the word names
 * the transcript; the shell joins the pieces before the command runs. Shared
 * by the shell-words, transcript-floor (live, outage, real-inode effect) and
 * owner-tty log-only suites so every plane judges the same rows.
 *
 * `joinedSpellings(H, SRC, F)` returns `[label, command]` rows, each of which
 * bash runs as a write of `H/.claude/projects/p/F` (the effect oracle in
 * claude-transcript-floor-923 executes every one in a scratch home; the
 * arithmetic row needs `H/.claude/projects/x1y/` to exist, and the
 * into-directory rows copy a source named `F` beside `SRC`).
 */
export function joinedSpellings(H: string, SRC: string, F: string): Array<[string, string]> {
  const tail = `ude/projects/p/${F}`;
  const globLeaf = F.replace(/\.jsonl$/, '.js[o]nl');
  const srcAs = SRC.replace(/[^/]*$/, F);
  return [
    // r10 Grok BLOCKER, verbatim shapes.
    ['${unset:-…} holds the tail', `cp ${SRC} ${H}/.cla\${unset:-${tail}}`],
    ['$(printf %s …) holds the tail', `cp ${SRC} ${H}/.cla$(printf %s ${tail})`],
    ['A=…; B=…; $A$B', `A=${H}/.cla; B=${tail}; cp ${SRC} $A$B`],
    // Same-command assignments, every way the command spells them.
    ['A=…; ${A}ude/…', `A=${H}/.cla; cp ${SRC} \${A}${tail}`],
    ['export A=… B=…; "$A$B"', `export A=${H}/.cla B=${tail}; cp ${SRC} "$A$B"`],
    ['local A=… inside a function', `f() { local A=${H}/.cla; cp ${SRC} \${A}${tail}; }; f`],
    ['split across &&', `A=${H}/.cla && B=${tail} && cp ${SRC} $A$B`],
    ['split across two expansions', `cp ${SRC} ${H}/\${u:-.cla}\${v:-${tail}}`],
    ['backtick holds the tail', `cp ${SRC} ${H}/.cla\`printf %s ${tail}\``],
    ['$((…)) beside a joined anchor', `A=${H}/.cla; cp ${SRC} \${A}ude/projects/x$((1))y/../p/${F}`],
    // r10 Astra B1: composed globs, no literal anchor left.
    ['glob .cl[a]ude + proj[e]cts', `cp ${SRC} ${H}/.cl[a]ude/proj[e]cts/p/${F}`],
    ['glob .cl* + proj*', `cp ${SRC} ${H}/.cl*/proj*/p/${F}`],
    ['glob .cl[a]ude + .js[o]nl leaf', `cp ${SRC} ${H}/.cl[a]ude/projects/p/${globLeaf}`],
    // r11 sibling sweep.
    ['brace sequence {a..a}', `cp ${SRC} ${H}/.cl{a..a}ude/projects/p/${F}`],
    ["ANSI-C $'…\\0junk' (bash cuts at the NUL)", `cp ${SRC} ${H}/$'.claude\\0junk'/projects/p/${F}`],
    ['heredoc inside $(…)', `cp ${SRC} "$(cat <<'E'\n${H}/.cla\nE\n)"${tail}`],
    ['~ prefix, tail inside ${…}', `cp ${SRC} ~/.cla\${u:-${tail}}`],
    ['<(…) feeds the anchor', `cp ${SRC} "$(cat <(printf %s ${H}/.cla))"${tail}`],
    ['eval of a joined string', `A='cp ${SRC} ${H}/.cla'; B='${tail}'; eval "$A$B"`],
    ['bash -c of a joined word', `A=${H}/.cla bash -c 'cp ${SRC} "$A"${tail}'`],
    ['printf -v built variable', `printf -v A %s%s ${H}/.cla ${tail}; cp ${SRC} "$A"`],
    ['read <<< built variable', `read -r A <<< ${H}/.cla; cp ${SRC} "\${A}${tail}"`],
    ['for-loop variable', `for d in ${H}/.cla; do cp ${SRC} "\${d}${tail}"; done`],
    ['extglob @(a)', `shopt -s extglob\ncp ${SRC} ${H}/.cl@(a)ude/projects/p/${F}`],
    ['printf octal escape builds the dot', `cp ${SRC} ${H}/$(printf '\\056cla')${tail}`],
    // r11 sweep: the command composes `<dir>/<basename of source>`; the
    // source is a `.jsonl` named like the transcript (`srcAs`).
    ['cp into the transcript directory', `cp ${srcAs} ${H}/.claude/projects/p/`],
    ['cp -t the transcript directory', `cp -t ${H}/.claude/projects/p ${srcAs}`],
    ['cp into a joined transcript directory', `A=${H}/.cla; cp ${srcAs} \${A}ude/projects/p`],
  ];
}

/** Ordinary commands of the same shapes that must NOT reach the floor. */
export function joinedControls(H: string, SRC: string, F: string): Array<[string, string]> {
  return [
    ['joined variables naming an ordinary file', `A=/tmp/x; B=out.jsonl; cp ${SRC} $A$B`],
    ['cat of the composed glob alias (a read)', `cat ${H}/.cl[a]ude/proj[e]cts/p/${F}`],
    ['ls of a composed glob directory (a read)', `ls ${H}/.cl*/proj*/`],
    ['expansion only before a literal .claude tail (auto-memory)', `cp ${SRC} $HOME/.claude/projects/p/memory/MEMORY.md`],
    ['an ordinary glob copy', 'cp src/*.ts dist/'],
    ['composed glob onto auto-memory, not a transcript', `cp ${SRC} ${H}/.cl*/proj*/p/memory/MEMORY.md`],
  ];
}
