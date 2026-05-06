/**
 * Project Context Module
 * Automatically detects and manages the active project scope for memory operations.
 *
 * Project key derivation is delegated to deriveProjectKey (mirroring
 * scripts/lib/project-key.mjs) so reads and writes share one source of truth.
 *
 * The "*" sentinel means "global/all projects" (no filtering).
 */

import { deriveProjectKey, basenameFromCwd } from './derive-project-key.js';

/** Sentinel value meaning "all projects" - no project filtering */
export const GLOBAL_PROJECT_SENTINEL = '*';

/** Currently active project (null = global/no filter) */
let activeProject: string | null = null;

/** How the project was detected */
let projectDetectionSource: 'env' | 'cwd' | 'none' = 'none';

/**
 * Extract project name from a file path (basename only, with noise-dir skip).
 * Retained for backwards compatibility with consumers that need just the
 * basename component. New code should call deriveProjectKey instead.
 */
export function extractProjectFromPath(path: string): string | null {
  return basenameFromCwd(path);
}

/**
 * Initialize project context from environment or working directory.
 * Call this once at server startup.
 *
 * Uses the shared deriveProjectKey helper, so the resolved key is identical
 * to whatever the .mjs hooks would resolve from the same cwd / env / config.
 */
export function initProjectContext(): void {
  // Env overrides — match deriveProjectKey's order. We track these separately
  // so projectDetectionSource keeps reporting 'env' when the user pinned the
  // project explicitly (visible in get_project / dashboard).
  const envProject = process.env.SHIELDCORTEX_PROJECT_KEY || process.env.CLAUDE_MEMORY_PROJECT;
  if (envProject) {
    const trimmed = envProject.trim();
    if (trimmed === GLOBAL_PROJECT_SENTINEL) {
      activeProject = null;
      projectDetectionSource = 'env';
    } else if (trimmed) {
      activeProject = trimmed;
      projectDetectionSource = 'env';
    }
    return;
  }

  // Otherwise: config override → projectAliases → git origin → basename.
  const cwd = process.cwd();
  const detected = deriveProjectKey(cwd);
  if (detected) {
    activeProject = detected;
    projectDetectionSource = 'cwd';
  } else {
    activeProject = null;
    projectDetectionSource = 'none';
  }
}

/**
 * Get the currently active project.
 * Returns null if in global scope.
 */
export function getActiveProject(): string | null {
  return activeProject;
}

/**
 * Get how the project was detected.
 */
export function getProjectDetectionSource(): 'env' | 'cwd' | 'none' {
  return projectDetectionSource;
}

/**
 * Resolve the effective project for a tool call.
 *
 * @param explicit - Explicitly provided project parameter (or undefined)
 * @returns The project to use, or null for global scope
 *
 * Logic:
 * - If explicit is "*", return null (global scope)
 * - If explicit is provided, use it
 * - Otherwise, use the auto-detected activeProject
 */
export function resolveProject(explicit: string | undefined): string | null {
  // "*" means global - no project filter
  if (explicit === GLOBAL_PROJECT_SENTINEL) {
    return null;
  }

  // Explicit project provided
  if (explicit && explicit.trim()) {
    return explicit.trim();
  }

  // Fall back to auto-detected project
  return activeProject;
}

/**
 * Manually set the active project.
 * Use null or "*" for global scope.
 */
export function setActiveProject(project: string | null): void {
  if (project === GLOBAL_PROJECT_SENTINEL) {
    activeProject = null;
  } else {
    activeProject = project;
  }
}

/**
 * Get project context info for display/debugging.
 */
export function getProjectContextInfo(): {
  project: string | null;
  source: 'env' | 'cwd' | 'none';
  isGlobal: boolean;
} {
  return {
    project: activeProject,
    source: projectDetectionSource,
    isGlobal: activeProject === null,
  };
}
