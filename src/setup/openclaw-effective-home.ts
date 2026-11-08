/**
 * The OpenClaw-effective home, shared by doctor and the Action Guard posture
 * reader (#922) so both read the same `openclaw.json`. Moved verbatim from
 * src/cli/doctor.ts.
 */
import os from 'os';
import path from 'path';

/**
 * OpenClaw-effective home for expanding `~` in OpenClaw paths — mirror of
 * resolveRawHomeDir (openclaw/src/infra/home-dir.ts): OPENCLAW_HOME (itself
 * `~`-expandable against HOME/USERPROFILE) > HOME > USERPROFILE >
 * os.homedir().
 *
 * #393 SOL r4 B2: a non-`~`, non-absolute OPENCLAW_HOME is returned verbatim
 * by resolveRawHomeDir and then path.resolve()d against the OPENCLAW PROCESS
 * cwd (home-dir.ts resolveEffectiveHomeDir) — doctor resolving it against its
 * OWN cwd probed a decoy tree while OpenClaw ran from another. The same
 * cwd-fallback fires when nothing resolves at all (resolveRequiredHomeDir).
 * Both shapes are unresolvable for doctor: OpenClaw stays bound with buses
 * unknown, never probed against a guessed root.
 */
export function openClawEffectiveHome(): { home: string } | { unresolvable: string } {
  const norm = (v: string | undefined): string | undefined => {
    const t = v?.trim();
    return t ? t : undefined;
  };
  const safeHomedir = (): string | undefined => {
    try {
      return norm(os.homedir());
    } catch {
      return undefined;
    }
  };
  const explicit = norm(process.env.OPENCLAW_HOME);
  if (explicit) {
    if (/^~($|[\\/])/.test(explicit)) {
      const fallback = norm(process.env.HOME) ?? norm(process.env.USERPROFILE) ?? safeHomedir();
      if (fallback) return { home: path.resolve(explicit.replace(/^~(?=$|[\\/])/, fallback)) };
      return { unresolvable: `OPENCLAW_HOME="${explicit}" has no HOME/USERPROFILE/homedir to expand ~ against — OpenClaw falls back to its own process cwd, which doctor cannot know` };
    }
    if (!path.isAbsolute(explicit)) {
      return { unresolvable: `OPENCLAW_HOME="${explicit}" is relative (\`~user\` included) — OpenClaw resolves it against its own process cwd, which doctor cannot know` };
    }
    return { home: path.resolve(explicit) };
  }
  const home = norm(process.env.HOME) ?? norm(process.env.USERPROFILE) ?? safeHomedir();
  if (home) return { home: path.resolve(home) };
  return { unresolvable: 'no OPENCLAW_HOME/HOME/USERPROFILE and os.homedir() unavailable — OpenClaw falls back to its own process cwd, which doctor cannot know' };
}
