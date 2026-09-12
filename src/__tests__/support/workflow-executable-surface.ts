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
 * So the rule reads the executable surface instead. Two questions have to be
 * answered separately, and getting either wrong reopens the hole:
 *
 *   WHERE — only `jobs.<id>.steps[].run`, `jobs.<id>.steps[].uses` and
 *   `jobs.<id>.uses` (a reusable-workflow call) are places GitHub Actions will
 *   execute anything. Review broke an earlier version that collected any nested
 *   key spelled `run` or `uses` anywhere in the document, with a job-level
 *
 *       env:
 *         run: snyk
 *
 *   which permitted the claim while the only real step printed "skipped". An
 *   `env:`, a `with:`, an `outputs:` or a matrix value is data, not a step.
 *
 *   WHAT — the value has to INVOKE the scanner, not contain its name. The same
 *   review got `run: echo "snyk is not installed"` past a surface that was then
 *   substring-matched. So a `run:` backs a claim only when the scanner is the
 *   command a statement starts, and a `uses:` only when the scanner names the
 *   action's owner or repository. See `invokesScanner`.
 *
 * Both need structure, which needs a parse — `js-yaml` is present in the tree
 * only as a transitive dependency of a coverage tool, not as a declared dev
 * dependency, and adding one for a test is an install this branch is not
 * permitted to make. What follows is therefore a deliberately small YAML subset
 * reader: block mappings, block sequences, plain and quoted scalars, block
 * scalars (`|`, `>`) and comments. Flow collections are kept as opaque scalars,
 * which is enough because `run:` and `uses:` are never written as `[...]` or
 * `{...}`.
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

/** The spellings GitHub Actions reads as an unconditionally false `if:`. */
const FALSY_LITERALS = ['false', 'off', 'no', '0', ''];

/**
 * Is this `if:` value a switch that is off?
 *
 * Only an unconditionally false condition disables a step. A real condition
 * (`if: github.ref == 'refs/heads/main'`) means the step runs in CI on some
 * runs, which is enough to back a claim that the tool is wired up — so
 * anything that is not plainly false counts as executable. That asymmetry is
 * deliberate and it is the one place this module errs towards PERMITTING: a
 * condition nobody can evaluate without GitHub's context is a step that runs
 * somewhere.
 *
 * `${{ false && github.event_name == 'push' }}` is still plainly false, though,
 * and review found a step hidden behind exactly that. A conjunction is false
 * whenever any conjunct is, so a trivially-constant falsy conjunct disables the
 * step. Nothing else is evaluated: a `||` anywhere means a false operand
 * decides nothing, so the whole condition reads as unknown and the step counts.
 */
export function isDisabledCondition(value: string): boolean {
  const inner = unquote(
    unquote(value)
      .replace(/^\$\{\{\s*/, '')
      .replace(/\s*\}\}$/, '')
      .trim(),
  ).toLowerCase();
  if (FALSY_LITERALS.includes(inner)) return true;
  if (inner.includes('||')) return false;
  return inner.split('&&').some((conjunct) => FALSY_LITERALS.includes(unquote(conjunct.trim())));
}

/** One thing a workflow will execute, and which kind of key put it there. */
export interface ExecutableStep {
  kind: 'run' | 'uses';
  value: string;
}

/** The value of `key` in a mapping, or `undefined`. */
function entry(node: WorkflowNode, key: string): WorkflowNode | undefined {
  if (node.kind !== 'map') return undefined;
  return node.entries.find(([k]) => k === key)?.[1];
}

/** Does this job or step carry an `if:` that is unconditionally false? */
function isSwitchedOff(node: WorkflowNode): boolean {
  const condition = entry(node, 'if');
  return condition?.kind === 'scalar' && isDisabledCondition(condition.value);
}

/** A non-empty scalar at `key`, or `undefined`. */
function scalarAt(node: WorkflowNode, key: string): string | undefined {
  const found = entry(node, key);
  if (found?.kind !== 'scalar' || found.value === '') return undefined;
  return found.value;
}

/**
 * Everything the workflow will execute, read from the only three places
 * GitHub Actions executes anything.
 *
 * `jobs.<id>.steps[]` carries `run:` and `uses:`; `jobs.<id>.uses` is a
 * reusable-workflow call, which has no steps of its own. Every other position
 * in the document — `env:`, `with:`, `outputs:`, `strategy.matrix`, a `name:`,
 * anything this reader failed to model — contributes nothing, so a value parked
 * under a key merely SPELLED `run` is not a step.
 *
 * `if: false` prunes what it guards: on a step that is the step, on a job that
 * is the job and every step in it.
 */
export function executableSurface(doc: WorkflowNode): ExecutableStep[] {
  const out: ExecutableStep[] = [];
  const jobs = entry(doc, 'jobs');
  if (jobs?.kind !== 'map') return out;
  for (const [, job] of jobs.entries) {
    if (job.kind !== 'map' || isSwitchedOff(job)) continue;
    const reusable = scalarAt(job, 'uses');
    if (reusable !== undefined) out.push({ kind: 'uses', value: reusable });
    const steps = entry(job, 'steps');
    if (steps?.kind !== 'seq') continue;
    for (const step of steps.items) {
      if (step.kind !== 'map' || isSwitchedOff(step)) continue;
      for (const kind of ['run', 'uses'] as const) {
        const value = scalarAt(step, kind);
        if (value !== undefined) out.push({ kind, value });
      }
    }
  }
  return out;
}

/** Everything one workflow file will execute. */
export function workflowExecutableSteps(text: string): ExecutableStep[] {
  return executableSurface(parseWorkflow(text));
}

/** The executable surface of one workflow file, lowercased for matching. */
export function workflowExecutableText(text: string): string {
  return workflowExecutableSteps(text)
    .map((step) => step.value)
    .join('\n')
    .toLowerCase();
}

/**
 * Wrappers that hand their tail to another command, longest first so `pnpm dlx`
 * is stripped as a unit rather than leaving `dlx` behind as the command.
 */
const COMMAND_WRAPPERS: ReadonlyArray<readonly string[]> = [
  ['pnpm', 'dlx'],
  ['pnpm', 'exec'],
  ['yarn', 'dlx'],
  ['npm', 'exec'],
  ['npx'],
  ['bunx'],
  ['yarn'],
];

/**
 * The statements a `run:` script starts, as token lists.
 *
 * A `run:` is a shell script: newlines and `;` separate statements, and `&&`,
 * `||` and `|` chain them, so `npm ci && npx snyk test` invokes two commands.
 *
 * `${{ … }}` expressions collapse to one token first. GitHub substitutes them
 * into the script before any shell sees it, and they contain spaces —
 * `SNYK_TOKEN=${{ secrets.SNYK_TOKEN }} snyk test` would otherwise tokenise
 * into five words whose first is an assignment and whose second is
 * `secrets.SNYK_TOKEN`. They can also contain `&&`, which would split one
 * statement into two.
 *
 * Nothing here models quoting, subshells or `$(…)` — anything this misses is a
 * statement whose command goes unrecognised, which refuses a true claim rather
 * than permitting a false one.
 */
function statementsIn(script: string): string[][] {
  return script
    .replace(/\$\{\{[^}]*\}\}/g, '${{expression}}')
    .split(/[\n;]|&&|\|\||\|/)
    .map((statement) => statement.trim().split(/\s+/).filter((token) => token !== ''))
    .filter((tokens) => tokens.length > 0);
}

/** The command a statement actually invokes, past its env assignments and wrappers. */
function invokedCommand(tokens: readonly string[]): string | undefined {
  let rest = [...tokens];
  // `SNYK_TOKEN=… snyk test` — a leading assignment is not the command.
  while (rest.length > 0 && /^[A-Za-z_][A-Za-z0-9_]*=/.test(rest[0])) rest = rest.slice(1);
  for (;;) {
    const wrapper = COMMAND_WRAPPERS.find((w) => w.every((token, i) => rest[i] === token));
    if (!wrapper) break;
    rest = rest.slice(wrapper.length);
    // `npx --yes snyk test` — nor are the wrapper's own flags.
    while (rest.length > 0 && rest[0].startsWith('-')) rest = rest.slice(1);
  }
  return rest[0];
}

/**
 * Does `segment` name the scanner, as a whole word?
 *
 * `snyk`, `snyk-action` and `trivy_scan` do; `snykish` does not. Without the
 * boundary this would be the substring match it replaces, one level down.
 */
function namesScanner(segment: string, scanner: string): boolean {
  if (segment === scanner) return true;
  return segment.startsWith(scanner) && /[^a-z0-9]/.test(segment[scanner.length] ?? '');
}

/**
 * Does this `uses:` reference an action published by, or named after, the
 * scanner? `snyk/actions/node@v1` and `aquasecurity/trivy-action@0.24.0` do.
 *
 * Only `owner/repo` counts. A local `uses: ./.github/actions/snyk` is refused
 * on purpose: the directory name is a label on a composite action whose own
 * steps this function is not looking at, which is precisely the "named, not
 * run" mistake one level deeper.
 */
function usesScannerAction(reference: string, scanner: string): boolean {
  const segments = reference.split('@')[0].toLowerCase().split('/');
  if (segments.length < 2 || segments[0] === '.' || segments[0] === '') return false;
  return segments.slice(0, 2).some((segment) => namesScanner(segment, scanner));
}

/**
 * Does anything in this executable surface INVOKE the named scanner?
 *
 * A `run:` counts when the scanner is the command a statement starts, past any
 * env assignments and any `npx`/`bunx`/`yarn`/`pnpm dlx` wrapper — so
 * `run: npx snyk test` counts and `run: echo "snyk is not installed"` does not.
 * A `uses:` counts when the scanner names the action's owner or repository.
 *
 * A scanner with no workflow form at all — `dependabot`, which is configured in
 * `.github/dependabot.yml` and never invoked by a step — can therefore never
 * satisfy this, and a SKILL.md claiming it would be refused. That is the safe
 * direction and the same one the rest of this module errs in: a rule that
 * cannot see the evidence must not assume it.
 */
export function invokesScanner(steps: readonly ExecutableStep[], scanner: string): boolean {
  const name = scanner.toLowerCase();
  return steps.some((step) => {
    const value = step.value.toLowerCase();
    return step.kind === 'uses'
      ? usesScannerAction(value, name)
      : statementsIn(value).some((tokens) => {
          const command = invokedCommand(tokens);
          return command !== undefined && namesScanner(command.split('/').pop() ?? '', name);
        });
  });
}
