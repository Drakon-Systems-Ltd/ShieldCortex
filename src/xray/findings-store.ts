/**
 * X-Ray Findings Store
 *
 * Persistent storage for actionable X-Ray findings.
 * Tracks finding lifecycle: new -> reviewed -> ignored/resolved/quarantined
 */

import fs from 'fs';
import { mkdirSecure } from '../setup/state-permissions.js';
import path from 'path';
import os from 'os';
import crypto from 'crypto';
import type { XRayFinding, ActionableXRayFinding, FindingStatus } from './types.js';

const MAX_FINDINGS = 500;
const CLEANUP_AGE_MS = 30 * 24 * 60 * 60 * 1000; // 30 days

function defaultBasePath(): string {
  return path.join(os.homedir(), '.shieldcortex');
}

function ensureDir(dir: string): void {
  mkdirSecure(dir);
}

function findingDedupeKey(target: string, f: XRayFinding): string {
  return `${target}|${f.category}|${f.title}|${f.file ?? ''}|${f.line ?? ''}`;
}

export interface FindingsStore {
  addFindings(
    sourceId: string,
    sourceKind: 'scan' | 'watch',
    target: string,
    rawFindings: XRayFinding[],
  ): ActionableXRayFinding[];

  getFinding(id: string): ActionableXRayFinding | null;

  listFindings(filters?: {
    status?: FindingStatus;
    target?: string;
    severity?: string;
    limit?: number;
  }): ActionableXRayFinding[];

  updateFindingStatus(
    id: string,
    status: FindingStatus,
    note?: string,
  ): ActionableXRayFinding | null;

  deleteFinding(id: string): boolean;

  quarantineFile(
    id: string,
    note?: string,
  ): { moved: boolean; quarantinePath?: string; error?: string };

  getStats(): {
    total: number;
    new: number;
    reviewed: number;
    ignored: number;
    resolved: number;
    quarantined: number;
  };
}

export function createFindingsStore(basePath?: string): FindingsStore {
  const base = basePath ?? defaultBasePath();
  const findingsFile = path.join(base, 'xray-findings.json');
  const quarantineDir = path.join(base, 'quarantine', 'files');

  function readFindings(): ActionableXRayFinding[] {
    try {
      const data = fs.readFileSync(findingsFile, 'utf-8');
      return JSON.parse(data);
    } catch {
      return [];
    }
  }

  function writeFindings(findings: ActionableXRayFinding[]): void {
    ensureDir(base);
    // Atomic write: write to temp file then rename (prevents corruption on crash)
    const tmp = findingsFile + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(findings.slice(0, MAX_FINDINGS), null, 2));
    fs.renameSync(tmp, findingsFile);
  }

  return {
    addFindings(sourceId, sourceKind, target, rawFindings) {
      const now = new Date().toISOString();
      const existing = readFindings();

      // Dedupe against EVERY retained finding regardless of status (Phase 17
      // B5). Previously only `status === 'new'` findings seeded the dedupe set,
      // so a finding the user had already triaged — ignored, resolved,
      // reviewed or quarantined — resurfaced as a brand-new duplicate on every
      // re-scan, undoing their decision. Matching across all statuses respects
      // the prior triage. (Findings aged past the 30-day cleanup window below
      // are no longer retained, so they may legitimately reappear — that's the
      // intended TTL behaviour, not a dedupe miss.)
      const existingKeys = new Set(
        existing.map((f) => findingDedupeKey(f.target, f)),
      );

      const newFindings: ActionableXRayFinding[] = [];
      for (const f of rawFindings) {
        const key = findingDedupeKey(target, f);
        if (existingKeys.has(key)) continue;
        existingKeys.add(key);
        newFindings.push({
          ...f,
          id: crypto.randomUUID(),
          sourceId,
          sourceKind,
          target,
          status: 'new',
          detectedAt: now,
          updatedAt: now,
        });
      }

      // Cleanup: remove resolved/ignored findings older than 30 days
      const cutoff = Date.now() - CLEANUP_AGE_MS;
      const cleaned = existing.filter((f) => {
        if (f.status === 'new' || f.status === 'reviewed') return true;
        return new Date(f.updatedAt).getTime() > cutoff;
      });

      const merged = [...newFindings, ...cleaned].slice(0, MAX_FINDINGS);
      writeFindings(merged);
      return newFindings;
    },

    getFinding(id) {
      return readFindings().find((f) => f.id === id) ?? null;
    },

    listFindings(filters?) {
      let results = readFindings();
      if (filters?.status) results = results.filter((f) => f.status === filters.status);
      if (filters?.target) results = results.filter((f) => f.target.includes(filters.target!));
      if (filters?.severity) results = results.filter((f) => f.severity === filters.severity);
      if (filters?.limit) results = results.slice(0, filters.limit);
      return results;
    },

    updateFindingStatus(id, status, note?) {
      const findings = readFindings();
      const idx = findings.findIndex((f) => f.id === id);
      if (idx === -1) return null;

      findings[idx].status = status;
      findings[idx].updatedAt = new Date().toISOString();
      if (note) findings[idx].resolutionNote = note;

      writeFindings(findings);
      return findings[idx];
    },

    deleteFinding(id) {
      const findings = readFindings();
      const filtered = findings.filter((f) => f.id !== id);
      if (filtered.length === findings.length) return false;
      writeFindings(filtered);
      return true;
    },

    quarantineFile(id, note?) {
      const finding = this.getFinding(id);
      if (!finding) return { moved: false, error: 'Finding not found' };
      if (!finding.file) return { moved: false, error: 'Finding has no file path' };

      const sourcePath = path.isAbsolute(finding.file)
        ? finding.file
        : path.resolve(finding.target, finding.file);

      // Path traversal guard: resolved path must be under the scan target directory
      let resolvedSource: string;
      try { resolvedSource = fs.realpathSync(sourcePath); } catch { resolvedSource = path.resolve(sourcePath); }
      const resolvedTarget = path.resolve(finding.target);
      if (!resolvedSource.startsWith(resolvedTarget) && !path.isAbsolute(finding.file)) {
        return { moved: false, error: 'Path traversal blocked — file is outside the scan target directory' };
      }

      // Block quarantining system-critical files
      const blocked = ['/etc/', '/usr/', '/System/', '/bin/', '/sbin/', '/.ssh/', '/private/etc/'];
      if (blocked.some(p => resolvedSource.includes(p))) {
        return { moved: false, error: 'Cannot quarantine system files' };
      }

      if (!fs.existsSync(sourcePath)) {
        this.updateFindingStatus(id, 'quarantined', note || 'File not found — marked as quarantined');
        return { moved: false, error: 'Source file does not exist' };
      }

      const destName = `${Date.now()}-${path.basename(sourcePath)}`;
      const destPath = path.join(quarantineDir, destName);

      try {
        ensureDir(quarantineDir);
        fs.renameSync(sourcePath, destPath);
        this.updateFindingStatus(id, 'quarantined', note || `Moved to ${destPath}`);
        return { moved: true, quarantinePath: destPath };
      } catch (err) {
        return { moved: false, error: (err as Error).message };
      }
    },

    getStats() {
      const findings = readFindings();
      return {
        total: findings.length,
        new: findings.filter((f) => f.status === 'new').length,
        reviewed: findings.filter((f) => f.status === 'reviewed').length,
        ignored: findings.filter((f) => f.status === 'ignored').length,
        resolved: findings.filter((f) => f.status === 'resolved').length,
        quarantined: findings.filter((f) => f.status === 'quarantined').length,
      };
    },
  };
}

// Default singleton for convenience — uses ~/.shieldcortex/
const defaultStore = createFindingsStore();

export const addFindings = defaultStore.addFindings.bind(defaultStore);
export const getFinding = defaultStore.getFinding.bind(defaultStore);
export const listFindings = defaultStore.listFindings.bind(defaultStore);
export const updateFindingStatus = defaultStore.updateFindingStatus.bind(defaultStore);
export const deleteFinding = defaultStore.deleteFinding.bind(defaultStore);
export const quarantineFile = defaultStore.quarantineFile.bind(defaultStore);
export const getStats = defaultStore.getStats.bind(defaultStore);
