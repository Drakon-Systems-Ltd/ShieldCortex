/**
 * Docs/help contract: a named `shieldcortex setup <host>` wires that host
 * without asking; only bare `setup` asks before wiring each host (#766).
 *
 * What the shipped source does (pinned by the first describe block):
 *   - `setup` with no target prints the host table and `offerUnwiredHosts`
 *     asks once overall and once per host before it wires anything; only
 *     `--yes` / `--install-detected` skips those prompts;
 *   - `setup claude` (and every other host target) goes straight to that
 *     host's installer with no prompt on the way — `setup claude` is
 *     `setupClaudeMd({})`, the same call a bare `install` makes;
 *   - that Claude Code install writes `~/.claude/CLAUDE.md`, the MCP server
 *     entry in `~/.claude.json`, the hooks in `~/.claude/settings.json`, and
 *     copies the cortex-memory hook into `~/.claude/hooks/cortex-memory/`
 *     (the hook installer treats `~/.claude` as a hook root, and step 1 has
 *     just created it).
 *
 * On 5.9.0 the postinstall banner said "Asks before wiring." under a
 * `shieldcortex setup` next step, the top-level help said setup "asks before
 * wiring each", and `setup --help` said it "offers to wire each unwired host"
 * — none of which scoped the prompt to the bare form. The copy now does; the
 * behaviour is unchanged. The banner rows must also stay one box: every line
 * between the borders has the same visible width once the colour escapes
 * are stripped.
 *
 * Text only: files are read and matched. Nothing here runs postinstall, setup,
 * install, quickstart or a hook, and nothing touches the home directory.
 * Dependency-free (node:test) and NOT part of the Jest suite:
 *
 *   node --test scripts/docs-contract/setup-target-wiring-copy.node-test.mjs
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const read = (...rel) => fs.readFileSync(path.join(REPO_ROOT, ...rel), 'utf8');

/** Body of the block opened by the first `{` after `marker`, by brace matching. */
function blockAfter(src, marker) {
  const at = src.indexOf(marker);
  assert.ok(at > -1, `marker not found: ${marker}`);
  const open = src.indexOf('{', at);
  let depth = 0;
  for (let i = open; i < src.length; i++) {
    if (src[i] === '{') depth++;
    else if (src[i] === '}' && --depth === 0) return src.slice(open, i + 1);
  }
  throw new Error(`unbalanced block after ${marker}`);
}

/** Text from `start` up to (not including) `end`. */
function between(src, start, end) {
  const a = src.indexOf(start);
  assert.ok(a > -1, `start not found: ${start}`);
  const b = src.indexOf(end, a + start.length);
  assert.ok(b > a, `end not found after start: ${end}`);
  return src.slice(a, b);
}

const oneLine = (s) => s.replace(/\s+/g, ' ');

/**
 * Body of the async function declared at `marker`. `blockAfter` would stop at
 * the first `{`, which for a function with an inline object-typed parameter
 * is the parameter type, so this starts from the return annotation instead.
 */
function asyncFnBody(src, marker) {
  const at = src.indexOf(marker);
  assert.ok(at > -1, `marker not found: ${marker}`);
  const ret = src.indexOf('): Promise<', at);
  assert.ok(ret > at, `return annotation not found after ${marker}`);
  return blockAfter(src.slice(ret), '): Promise<');
}

// SGR escapes, whether a real ESC byte or the `\x1b[..m` text a JS string
// literal spells it with (postinstall.mjs is read as source, not executed).
const stripAnsi = (s) => s.replace(/(?:\x1b|\\x1b)\[[0-9;]*m/g, '');

const CLAUDE_INSTALL_PATHS = [
  '~/.claude/CLAUDE.md',
  '~/.claude.json',
  '~/.claude.json.bak-shieldcortex',
  '~/.claude/hooks/cortex-memory/',
];
const CLAUDE_HOOKS_FILE_MARK = 'Claude Code hooks';

describe('source facts the copy describes', () => {
  const quickstart = read('src', 'setup', 'quickstart.ts');

  it('bare setup prints the table and asks before wiring; a named target does not', () => {
    const handler = blockAfter(quickstart, 'export async function handleQuickstartCommand(');
    // The prompting path is the no-target branch, and --yes is the only
    // auto-approve route into it.
    assert.match(handler, /if \(!target\) \{[\s\S]{0,300}?offerUnwiredHosts\(\{ mode: 'setup' \}\);/);
    assert.match(handler, /normalized === '--yes' \|\| normalized === '--install-detected'[\s\S]{0,300}?offerUnwiredHosts\(\{ mode: 'setup', autoApprove: true \}\);/);
    // A host word goes to runQuickstartTarget / wireHost with nothing asked.
    assert.match(handler, /case 'claude':\s+case 'openclaw':\s+case 'copilot':\s+case 'codex':\s+case 'security':\s+await runQuickstartTarget\(/);
    assert.match(handler, /normalized === 'hermes'[\s\S]{0,80}?await wireHost\('hermes'\);/);
    const target = blockAfter(quickstart, 'async function runQuickstartTarget(');
    assert.match(target, /case 'claude':[\s\S]{0,400}?await setupClaudeMd\(\{\}\);/);
    assert.doesNotMatch(target, /promptYesNo|offerUnwiredHosts|askActionGuardPosture|readline|confirm/);
  });

  it('offerUnwiredHosts asks once overall and once per host unless autoApprove', () => {
    const fn = asyncFnBody(read('src', 'setup', 'host-table.ts'), 'export async function offerUnwiredHosts(');
    assert.match(fn, /if \(!opts\.autoApprove\) \{\s+const any = await promptYesNo\('Wire the unwired hosts\?', true\);/);
    assert.match(fn, /opts\.autoApprove\s*\?\s*true\s*:\s*await promptYesNo\(`Install ShieldCortex for \$\{r\.label\}\?`, true\);/);
    assert.match(fn, /if \(!ok\) continue;\s+console\.log\(''\);\s+await wireHost\(r\.id\);/);
  });

  it('the Claude Code install writes the four paths the help names', () => {
    const claudeMd = read('src', 'setup', 'claude-md.ts');
    const install = asyncFnBody(claudeMd, 'export async function setupClaudeMd(');
    // 1. ~/.claude/CLAUDE.md
    assert.ok(claudeMd.includes("const claudeDir = path.join(os.homedir(), '.claude');"));
    assert.ok(claudeMd.includes("const claudeMdPath = path.join(claudeDir, 'CLAUDE.md');"));
    assert.ok(claudeMd.includes('fs.writeFileSync(claudeMdPath, newContent'));
    assert.match(install, /setupClaudeCode\(\);/);
    // 2. ~/.claude.json, mcpServers.memory
    assert.ok(claudeMd.includes("const mcpPath = path.join(os.homedir(), '.claude.json');"));
    assert.ok(claudeMd.includes('existing.mcpServers.memory = idealEntry;'));
    assert.ok(claudeMd.includes('writeJsonConfigWithBackup(mcpPath, existing);'));
    assert.match(install, /setupGlobalMcp\(\);/);
    // 3. ~/.claude/settings.json
    assert.match(install, /setupHooks\(options\);/);
    assert.ok(read('src', 'setup', 'settings-hooks.ts')
      .includes("return path.join(os.homedir(), '.claude', 'settings.json');"));
    // 4. ~/.claude/hooks/cortex-memory/ — the hook installer treats ~/.claude
    //    as a hook root, and the hook dir is `<root>/hooks/<HOOK_NAME>`.
    assert.match(install, /const hooksDirs = findAllHooksDirs\(\);[\s\S]{0,400}?await installOpenClawHook\(\);/);
    assert.match(install, /const hookExists = hooksDirs\.some\([\s\S]{0,120}?if \(hookExists\) \{[\s\S]{0,200}?await installOpenClawHook\(\);/);
    assert.ok(read('src', 'setup', 'json-config.ts').includes('.bak-shieldcortex'));
    assert.ok(read('src', 'setup', 'json-config.ts').includes('writeJsonConfigWithBackup'));
    const openclaw = read('src', 'setup', 'openclaw.ts');
    assert.ok(openclaw.includes("const HOOK_NAME = 'cortex-memory';"));
    assert.ok(openclaw.includes("export const HOOK_FILES = ['HOOK.md', 'handler.ts', 'runtime.mjs'] as const;"));
    assert.ok(blockAfter(openclaw, 'export function findAllHooksDirs(')
      .includes("{ config: '.claude', hooks: path.join(home, '.claude', 'hooks') },"));
    assert.ok(blockAfter(openclaw, 'function preferredHookDir(').includes('return path.join(hooksDir, HOOK_NAME);'));
  });
});

describe('scripts/postinstall.mjs next-step banner', () => {
  const post = read('scripts', 'postinstall.mjs');
  // The box: every console.log whose string opens with a cyan border glyph.
  const rows = post.split('\n')
    .filter((l) => /^\s*console\.log\('\\x1b\[36m[╭│╰]/.test(l))
    .map((l) => stripAnsi(/console\.log\('(.*)'\);/.exec(l)[1]));
  const text = rows.join('\n');

  it('is one box: a top border, content rows, a bottom border', () => {
    assert.ok(rows.length >= 3, `banner rows found: ${rows.length}`);
    assert.match(rows[0], /^╭─+╮$/);
    assert.match(rows[rows.length - 1], /^╰─+╯$/);
    for (const r of rows.slice(1, -1)) assert.match(r, /^│.*│$/);
    // Same height as the 5.9 banner plus the one scoping line.
    assert.equal(rows.length, 10);
  });

  it('every row has the same visible width once the colour escapes are stripped', () => {
    const widths = rows.map((r) => [...r].length);
    assert.equal(new Set(widths).size, 1, `visible widths differ: ${widths.join(', ')}`);
  });

  it('shows bare setup as the next step and scopes "asks before wiring" to it', () => {
    assert.match(text, /^│\s+shieldcortex setup\s+│$/m);
    // The 5.9 line, "Asks before wiring. Action Guard stays off.", was not
    // scoped; every mention now says "each" (each detected host).
    assert.doesNotMatch(text, /Asks before wiring(?! each)/);
    assert.match(text, /^│\s+Asks before wiring each\. Action Guard stays off\.\s+│$/m);
  });

  it('says a named host is wired without asking', () => {
    assert.match(text, /^│\s+setup <host> wires that host without asking\.\s+│$/m);
  });
});

describe('src/cli/setup-dispatch.ts SETUP_HELP', () => {
  const help = between(read('src', 'cli', 'setup-dispatch.ts'), 'export const SETUP_HELP = `', '`;');

  it('scopes the prompt to bare setup and says a named target wires without asking', () => {
    assert.doesNotMatch(help, /offers to wire/);
    assert.match(oneLine(help), /With no arguments it shows the detected-host table, asks before wiring each unwired host, and asks for an Action Guard posture on a terminal\./);
    assert.match(oneLine(help), /A named target skips the table and wires that host without asking\./);
  });

  it('the host Targets line says it installs now, without asking', () => {
    const targets = between(help, 'Targets:', '  security ');
    assert.match(oneLine(targets), /claude \| openclaw \| hermes \| copilot \| codex Install into that host now, without asking/);
    assert.doesNotMatch(targets, /Install into that one host$/m);
  });

  it('the install paragraph names each file the Claude Code install writes', () => {
    const para = between(help, 'install is the Claude Code install', 'quickstart [target]');
    assert.match(para, /Without asking, the Claude Code install can write:/);
    for (const p of CLAUDE_INSTALL_PATHS) {
      assert.match(para, new RegExp(`^  ${p.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&')}\\s+\\S`, 'm'), `missing ${p}`);
    }
    assert.match(para, /mcpServers.memory/);
    assert.match(oneLine(para), /HOOK.md, handler.ts, runtime.mjs/);
    assert.match(para, /any detected hook root already has cortex-memory/);
    assert.match(para, /bak-shieldcortex sibling when replaced/);
    assert.match(oneLine(para), /If the hook installer runs and an OpenClaw root is writable/);
    assert.match(para, /install or register the realtime plugin/);
    assert.match(para, /may restart the gateway/);
    assert.match(oneLine(para), /attempts to tighten owner-only permissions/);
    // Sentences the #708 Jest suite pins stay on one line.
    assert.match(para, /setup claude runs the same install as a bare install/);
    assert.match(para, /it is not the setup wizard/);
  });

  it('introduces no word that could read as "asks": --yes is the no-prompt form for all hosts', () => {
    assert.match(help, /--yes, --install-detected\s+Wire every detected host without prompting/);
    assert.doesNotMatch(help, /alias/i);
  });
});

describe('src/index.ts top-level --help setup entry', () => {
  const entry = between(read('src', 'index.ts'), '${cyan}setup${reset} [target]', '${cyan}install${reset}');

  it('scopes "asks before wiring" to bare setup', () => {
    assert.doesNotMatch(entry, /Start here: detects hosts, asks before wiring each/);
    assert.match(entry, /^\$\{cyan\}setup\$\{reset\} \[target\]\s+Start here: bare setup detects hosts, asks before wiring each$/m);
    for (const line of entry.split('\n').filter((l) => /asks before/.test(l))) {
      assert.match(line, /bare setup/, `unscoped "asks before" in: ${line.trim()}`);
    }
  });

  it('says a named host is wired without asking, before the Targets list', () => {
    assert.match(entry, /^\s+setup <host> \(e\.g\. setup claude\) wires that host without asking\n\s+Targets: claude, openclaw, hermes, copilot, codex, security$/m);
  });
});

describe('docs: the targeted form is described as wiring without asking', () => {
  it('docs/README-DETAILS.md install notes (moved from the README) name the files setup claude can write', () => {
    const para = read('docs/README-DETAILS.md').split('\n').find((l) => l.startsWith('`setup` is the onboarding command:'));
    assert.ok(para, 'README setup paragraph not found');
    assert.match(para, /runs the Claude Code install without asking/);
    for (const p of CLAUDE_INSTALL_PATHS) assert.ok(para.includes('`' + p + '`'), `README missing ${p}`);
    assert.match(para, /unless any detected hook root already has a cortex-memory directory/);
    assert.match(para, /writable OpenClaw root/);
    assert.match(para, /may restart the gateway/);
  });

  it('docs/quickstarts/mcp.md', () => {
    const line = read('docs', 'quickstarts', 'mcp.md').split('\n').find((l) => l.startsWith('`setup` shows the hosts it detects'));
    assert.ok(line, 'mcp.md setup paragraph not found');
    assert.match(line, /asks before wiring each one\. To skip the table and install for one host without asking, name it:/);
  });

  it('docs/UPDATING.md host-table section', () => {
    const line = read('docs', 'UPDATING.md').split('\n').find((l) => /prints one host table and asks before wiring/.test(l));
    assert.ok(line, 'UPDATING.md host-table paragraph not found');
    assert.match(line, /^Bare `setup` \(alias `quickstart`\) prints one host table and asks before wiring; `setup <host>` wires that host without asking\./);
  });

  it('skills/shieldcortex/SKILL.md setup disclosure', () => {
    const line = read('skills', 'shieldcortex', 'SKILL.md').split('\n').find((l) => l.startsWith('- **Setup is user-initiated'));
    assert.ok(line, 'SKILL.md setup bullet not found');
    assert.doesNotMatch(line, /and `quickstart` asks before each action\./);
    assert.match(line, /bare `quickstart` \/ `setup` asks before each action; a named host, as in `setup claude`, is wired without asking\./);
  });

  // The HOOK.md copies say `shieldcortex setup`, which asks before wiring —
  // the bare command, so that stays true (pinned by the memory-default
  // contract); this only checks no copy grew a targeted-form claim.
  for (const dir of [['hooks', 'openclaw', 'cortex-memory'], ['skills', 'shieldcortex', 'bundled', 'cortex-memory-hook']]) {
    it(`${dir.join('/')}/HOOK.md does not say setup <host> asks`, () => {
      assert.doesNotMatch(read(...dir, 'HOOK.md'), /setup (claude|openclaw|hermes|copilot|codex)`?,? which asks/);
    });
  }
});

describe('CHANGELOG.md #766 bullet (Unreleased, or the release that ships it)', () => {
  const bullet = read('CHANGELOG.md').split('\n')
    .find((l) => l.startsWith('- **`setup <host>` help and the install banner say it wires without asking (#766).**'));

  it('says the banner and help scope the prompt to bare setup, and that behaviour is unchanged', () => {
    assert.ok(bullet, '#766 bullet not found in CHANGELOG.md');
    assert.match(bullet, /bare `shieldcortex setup` asks before wiring each host/);
    assert.match(bullet, /`setup claude` \(or another named host\) wires that host directly/);
    assert.match(bullet, /lists the files the Claude Code install can write/);
    assert.match(bullet, /Behaviour is unchanged\./);
  });
});
