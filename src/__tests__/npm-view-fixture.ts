/**
 * #1109 review: `update`'s plugin step asks npm whether the exact plugin
 * version it is about to install is published (`npm view <pkg>@<pin>
 * version --json`) before it deletes or installs anything. Suites that script the
 * `openclaw` child through the step's injected `run` wrap it with this so
 * that one `npm view` call answers "published" and never reaches their
 * script (nor their recorded call list). Suites that test the publication
 * check itself script `npm` directly instead.
 */
type Run = (cmd: string, args: string[], opts?: unknown) => Promise<{ stdout: string; stderr: string }>;

export function answersNpmView<T>(run: T): T {
  const inner = run as unknown as Run;
  const wrapped: Run = (cmd, args, opts) => {
    if (cmd === 'npm' && args[0] === 'view') {
      const asked = String(args[1] ?? '');
      // `npm view … version --json` prints the one matching version as a JSON string.
      return Promise.resolve({ stdout: `${JSON.stringify(asked.slice(asked.lastIndexOf('@') + 1))}\n`, stderr: '' });
    }
    return inner(cmd, args, opts);
  };
  return wrapped as unknown as T;
}
