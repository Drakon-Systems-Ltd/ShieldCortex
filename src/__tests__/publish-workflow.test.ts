import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from '@jest/globals';

/**
 * Partial-publish recovery — root npm success + plugin failure used to green
 * on rerun. `.github/workflows/publish.yml` gated plugin check/publish,
 * both-package verification, and GitHub Release on root
 * `already_published == false`. GitHub Actions treats skipped-step outputs as
 * empty, so the plugin publish `if:` never became true and the job could skip
 * the missing plugin.
 *
 * These tests parse the workflow and evaluate `if:` the way Actions does.
 */

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const workflowPath = path.join(repoRoot, '.github', 'workflows', 'publish.yml');
const workflow = fs.readFileSync(workflowPath, 'utf8');

type Step = {
  name: string;
  id?: string;
  if?: string;
  body: string;
};

function parseNamedSteps(src: string): Step[] {
  const steps: Step[] = [];
  const chunks = src.split(/\n      - name: /).slice(1);
  for (const chunk of chunks) {
    const nl = chunk.indexOf('\n');
    const name = (nl === -1 ? chunk : chunk.slice(0, nl)).trim();
    const body = nl === -1 ? '' : chunk.slice(nl + 1);
    const headerEnd = body.search(/^\s{8}(?:run|uses):/m);
    const header = headerEnd === -1 ? body : body.slice(0, headerEnd);
    const id = header.match(/^\s{8}id: (\S+)/m)?.[1];
    const ifExpr = header.match(/^\s{8}if: (.+)$/m)?.[1]?.trim();
    steps.push({ name, id, if: ifExpr, body });
  }
  return steps;
}

function unquote(token: string): string {
  return token.slice(1, -1);
}

function evalAtom(atom: string): boolean {
  const m = atom
    .trim()
    .match(/^("(?:\\.|[^"])*"|'(?:\\.|[^'])*')\s*(==|!=)\s*("(?:\\.|[^"])*"|'(?:\\.|[^'])*')$/);
  if (!m) {
    throw new Error(`unhandled GitHub if atom: ${atom}`);
  }
  const left = unquote(m[1]);
  const right = unquote(m[3]);
  return m[2] === '==' ? left === right : left !== right;
}

function evalGhIf(
  expr: string | undefined,
  outputs: Record<string, Record<string, string>>,
  env: Record<string, string>,
): boolean {
  if (!expr) return true;
  const resolved = expr
    .replace(/steps\.([A-Za-z0-9_]+)\.outputs\.([A-Za-z0-9_]+)/g, (_all, step: string, key: string) =>
      JSON.stringify(outputs[step]?.[key] ?? ''),
    )
    .replace(/env\.([A-Za-z0-9_]+)/g, (_all, key: string) => JSON.stringify(env[key] ?? ''));
  return resolved.split('&&').every((part) => evalAtom(part));
}

function simulate(opts: { rootPublished: boolean; pluginPublished: boolean; hasClawhub?: boolean }): Record<string, boolean> {
  const steps = parseNamedSteps(workflow);
  const outputs: Record<string, Record<string, string>> = {};
  const env = { HAS_CLAWHUB_TOKEN: opts.hasClawhub === false ? '' : 'true' };
  const ran: Record<string, boolean> = {};

  for (const step of steps) {
    const shouldRun = evalGhIf(step.if, outputs, env);
    ran[step.name] = shouldRun;
    if (!shouldRun) continue;
    if (step.id === 'version_check') {
      outputs.version_check = { already_published: opts.rootPublished ? 'true' : 'false' };
    }
    if (step.id === 'plugin_version_check') {
      outputs.plugin_version_check = {
        plugin_already_published: opts.pluginPublished ? 'true' : 'false',
      };
    }
    if (step.id === 'tag') {
      outputs.tag = { tag: 'v4.54.14', version: '4.54.14' };
    }
  }
  return ran;
}

const steps = parseNamedSteps(workflow);
const byName = Object.fromEntries(steps.map((s) => [s.name, s]));

describe('publish.yml — per-package recovery', () => {
  it('rerun with root existing and plugin missing still checks, publishes, verifies plugin, and creates release', () => {
    const ran = simulate({ rootPublished: true, pluginPublished: false });
    expect(ran['Publish to npm']).toBe(false);
    expect(ran['Check plugin version']).toBe(true);
    expect(ran['Publish plugin to npm']).toBe(true);
    expect(ran['Verify both packages landed on npm at the expected version']).toBe(true);
    expect(ran['Create GitHub Release']).toBe(true);
    expect(ran['Skip root publish (already exists)']).toBe(true);
    expect(ran['Skip plugin publish (already exists)']).toBe(false);
  });

  it('root publish only runs when the root package is missing', () => {
    expect(simulate({ rootPublished: false, pluginPublished: false })['Publish to npm']).toBe(true);
    expect(simulate({ rootPublished: true, pluginPublished: false })['Publish to npm']).toBe(false);
  });

  it('plugin check is not gated on root already_published', () => {
    expect(byName['Check plugin version']?.if).toBeUndefined();
  });

  it('plugin publish depends only on the plugin missing', () => {
    expect(byName['Publish plugin to npm']?.if).toBe(
      "steps.plugin_version_check.outputs.plugin_already_published == 'false'",
    );
    expect(byName['Publish plugin to npm']?.if).not.toMatch(/version_check\.outputs\.already_published/);
  });

  it('both-package verification always runs and requires exact root+plugin versions', () => {
    const verify = byName['Verify both packages landed on npm at the expected version'];
    expect(verify?.if).toBeUndefined();
    expect(verify?.body).toContain('if [ "$MAIN_LATEST" != "$MAIN" ]');
    expect(verify?.body).toContain('if [ "$PLUGIN_LATEST" != "$PLUGIN" ]');
    expect(simulate({ rootPublished: true, pluginPublished: false })[verify!.name]).toBe(true);
    expect(simulate({ rootPublished: true, pluginPublished: true })[verify!.name]).toBe(true);
  });

  it('GitHub Release creation/update always runs', () => {
    expect(byName['Create GitHub Release']?.if).toBeUndefined();
    expect(simulate({ rootPublished: true, pluginPublished: false })['Create GitHub Release']).toBe(true);
    expect(simulate({ rootPublished: true, pluginPublished: true })['Create GitHub Release']).toBe(true);
  });

  it('skip messages name the package that is actually skipped', () => {
    const rootSkip = byName['Skip root publish (already exists)'];
    const pluginSkip = byName['Skip plugin publish (already exists)'];
    expect(rootSkip?.body).toMatch(/Skipping root npm publish/);
    expect(rootSkip?.body).not.toMatch(/Skipping publish - version already exists/);
    expect(pluginSkip?.body).toMatch(/Skipping plugin npm publish/);
    expect(pluginSkip?.body).toMatch(/shieldcortex-realtime/);
  });

  it('ClawHub remains independent of npm already_published', () => {
    expect(byName['Install ClawHub CLI']?.if).toBe("env.HAS_CLAWHUB_TOKEN == 'true'");
    expect(byName['Sync + verify ClawHub']?.if).toBe("env.HAS_CLAWHUB_TOKEN == 'true'");
    expect(byName['Skip ClawHub sync (missing token)']?.if).toBe("env.HAS_CLAWHUB_TOKEN != 'true'");
    const ran = simulate({ rootPublished: true, pluginPublished: false, hasClawhub: true });
    expect(ran['Sync + verify ClawHub']).toBe(true);
    const noToken = simulate({ rootPublished: false, pluginPublished: false, hasClawhub: false });
    expect(noToken['Sync + verify ClawHub']).toBe(false);
    expect(noToken['Skip ClawHub sync (missing token)']).toBe(true);
  });
});
