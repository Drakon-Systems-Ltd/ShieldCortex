/**
 * #466 — what a GitHub Actions workflow actually EXECUTES, as opposed to what
 * it merely mentions.
 *
 * The scanner-claim rule in release-audit-claims.test.ts used to ask whether
 * the concatenated text of `.github/workflows` contained the scanner's name.
 * Review broke it with one file:
 *
 *     # snyk is not installed or run
 *
 * and `snyk: no-known-vulnerabilities` was permitted back into SKILL.md. A
 * comment is not a step. Neither is a `name:`, and neither is a step carrying
 * `if: false`.
 *
 * So the rule reads the executable surface instead: the values of `run:` and
 * `uses:` keys, from mappings that are not switched off. That needs structure,
 * which needs a parse — `js-yaml` is present in the tree only as a transitive
 * dependency of a coverage tool, not as a declared dev dependency, and adding
 * one for a test is an install this branch is not permitted to make. What
 * follows is therefore a deliberately small YAML subset reader: block mappings,
 * block sequences, plain and quoted scalars, block scalars (`|`, `>`) and
 * comments. Flow collections are kept as opaque scalars, which is enough
 * because `run:` and `uses:` are never written as `[...]` or `{...}`.
 *
 * Direction of error matters more than completeness here. Anything this reader
 * fails to understand is simply absent from the executable surface, so the
 * scanner claim is REFUSED rather than permitted — the same direction the rest
 * of the gate fails in. A parser bug can cost a true claim; it cannot buy a
 * false one.
 */

/** A node of the YAML subset. */
export type WorkflowNode =
  | { kind: 'scalar'; value: string }
  | { kind: 'map'; entries: Array<[string, WorkflowNode]> }
  | { kind: 'seq'; items: WorkflowNode[] };

interface SourceLine {
  indent: number;
  body: string;
}

/**
 * Drop comments, keeping `#` that is inside a quoted scalar.
 *
 * YAML only starts a comment at the beginning of a line or after whitespace,
 * which is what makes `uses: acme/scan@v1#sha` and `run: echo 'a # b'` safe.
 */
export function stripComment(line: string): string {
  let quote: string | null = null;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (quote) {
      if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      continue;
    }
    if (ch === '#' && (i === 0 || /\s/.test(line[i - 1]))) {
      return line.slice(0, i);
    }
  }
  return line;
}

function readLines(text: string): SourceLine[] {
  const out: SourceLine[] = [];
  for (const raw of text.split(/\r?\n/)) {
    const withoutComment = stripComment(raw);
    const body = withoutComment.trimEnd();
    if (body.trim() === '' || body.trim() === '---' || body.trim() === '...') continue;
    out.push({ indent: body.length - body.trimStart().length, body: body.trimStart() });
  }
  return out;
}

/** `key: |`, `key: >-`, `key: |+2` … — a block scalar header. */
function blockScalarHeader(value: string): boolean {
  return /^[|>][+-]?\d*$/.test(value.trim());
}

const KEY = /^("[^"]*"|'[^']*'|[^:#]+?)\s*:(\s.*|)$/;

function unquote(value: string): string {
  const trimmed = value.trim();
  if (trimmed.length >= 2 && (trimmed[0] === '"' || trimmed[0] === "'") && trimmed.at(-1) === trimmed[0]) {
    return trimmed.slice(1, -1);
  }
  return trimmed;
}

/**
 * Parse the lines from `start` that belong to a node at column `indent`.
 * Returns the node and the index of the first line that does not.
 */
function parseNode(lines: SourceLine[], start: number, indent: number): { node: WorkflowNode; next: number } {
  if (start >= lines.length || lines[start].indent < indent) {
    return { node: { kind: 'scalar', value: '' }, next: start };
  }

  // Sequence: a run of `- ...` entries at this column.
  if (lines[start].body === '-' || lines[start].body.startsWith('- ')) {
    const items: WorkflowNode[] = [];
    let i = start;
    while (i < lines.length && lines[i].indent === indent && (lines[i].body === '-' || lines[i].body.startsWith('- '))) {
      const inline = lines[i].body.slice(1).trimStart();
      if (inline === '') {
        // `-` alone: the item is whatever is indented under it.
        const { node, next } = parseNode(lines, i + 1, indent + 1);
        items.push(node);
        i = next;
        continue;
      }
      // `- key: value` starts a mapping whose column is where `key` begins.
      const itemIndent = indent + (lines[i].body.length - inline.length);
      const rewritten: SourceLine[] = [...lines];
      rewritten[i] = { indent: itemIndent, body: inline };
      const { node, next } = parseNode(rewritten, i, itemIndent);
      items.push(node);
      i = next;
    }
    return { node: { kind: 'seq', items }, next: i };
  }

  // Mapping: a run of `key: ...` entries at this column.
  const match = lines[start].body.match(KEY);
  if (!match) {
    // Not something this reader models (a multi-line flow collection, say).
    // Consume it and everything nested under it, contributing nothing.
    let i = start + 1;
    while (i < lines.length && lines[i].indent > indent) i++;
    return { node: { kind: 'scalar', value: lines[start].body }, next: i };
  }

  const entries: Array<[string, WorkflowNode]> = [];
  let i = start;
  while (i < lines.length && lines[i].indent === indent) {
    const entry = lines[i].body.match(KEY);
    if (!entry) break;
    const key = unquote(entry[1]);
    const inlineValue = entry[2].trim();
    if (blockScalarHeader(inlineValue)) {
      const bodyLines: string[] = [];
      let j = i + 1;
      while (j < lines.length && lines[j].indent > indent) {
        bodyLines.push(lines[j].body);
        j++;
      }
      entries.push([key, { kind: 'scalar', value: bodyLines.join('\n') }]);
      i = j;
      continue;
    }
    if (inlineValue !== '') {
      entries.push([key, { kind: 'scalar', value: unquote(inlineValue) }]);
      // A key with an inline value owns nothing nested; skip any continuation.
      let j = i + 1;
      while (j < lines.length && lines[j].indent > indent) j++;
      i = j;
      continue;
    }
    // No inline value: the child is whatever is indented under the key. A
    // sequence may sit at the SAME column as its key, which is legal YAML.
    const childStart = i + 1;
    if (
      childStart < lines.length &&
      (lines[childStart].indent > indent ||
        (lines[childStart].indent === indent &&
          (lines[childStart].body === '-' || lines[childStart].body.startsWith('- '))))
    ) {
      const { node, next } = parseNode(lines, childStart, lines[childStart].indent);
      entries.push([key, node]);
      i = next;
      continue;
    }
    entries.push([key, { kind: 'scalar', value: '' }]);
    i = childStart;
  }
  return { node: { kind: 'map', entries }, next: i };
}

export function parseWorkflow(text: string): WorkflowNode {
  const lines = readLines(text);
  if (lines.length === 0) return { kind: 'map', entries: [] };
  return parseNode(lines, 0, lines[0].indent).node;
}

/**
 * Is this `if:` value a switch that is off?
 *
 * Only an unconditionally false condition disables a step. A real condition
 * (`if: github.ref == 'refs/heads/main'`) means the step runs in CI on some
 * runs, which is enough to back a claim that the tool is wired up — so
 * anything that is not plainly false counts as executable.
 */
export function isDisabledCondition(value: string): boolean {
  const inner = unquote(value)
    .replace(/^\$\{\{\s*/, '')
    .replace(/\s*\}\}$/, '')
    .trim()
    .toLowerCase();
  return ['false', 'off', 'no', '0', ''].includes(unquote(inner));
}

/**
 * Every `run:`/`uses:` value in the document that is not switched off.
 *
 * `if: false` prunes the whole mapping it appears in — for a step that is the
 * step, for a job that is the job and every step in it.
 */
export function executableSurface(node: WorkflowNode, out: string[] = []): string[] {
  if (node.kind === 'seq') {
    for (const item of node.items) executableSurface(item, out);
    return out;
  }
  if (node.kind !== 'map') return out;
  const condition = node.entries.find(([key]) => key === 'if');
  if (condition && condition[1].kind === 'scalar' && isDisabledCondition(condition[1].value)) {
    return out;
  }
  for (const [key, child] of node.entries) {
    if ((key === 'run' || key === 'uses') && child.kind === 'scalar') {
      out.push(child.value);
      continue;
    }
    executableSurface(child, out);
  }
  return out;
}

/** The executable surface of one workflow file, lowercased for matching. */
export function workflowExecutableText(text: string): string {
  return executableSurface(parseWorkflow(text)).join('\n').toLowerCase();
}
