import fs from 'fs';
import { mkdirSecure } from '../setup/state-permissions.js';
import os from 'os';
import path from 'path';

import type { XRayResult } from './types.js';

const XRAY_DIR = path.join(os.homedir(), '.shieldcortex');
const HISTORY_FILE = path.join(XRAY_DIR, 'xray-history.json');
const ACTIVITY_FILE = path.join(XRAY_DIR, 'xray-activity.jsonl');
const WATCH_SESSIONS_FILE = path.join(XRAY_DIR, 'xray-watch-sessions.json');
const HISTORY_LIMIT = 25;
const ACTIVITY_LIMIT = 100;
const WATCH_SESSION_LIMIT = 20;
const ACTIVE_WATCH_THRESHOLD_MS = 90 * 1000;
const STALE_WATCH_RETENTION_MS = 24 * 60 * 60 * 1000;
const ENDED_WATCH_RETENTION_MS = 7 * 24 * 60 * 60 * 1000;

export type XRayTargetType = 'npm' | 'file' | 'dir';
export type XRayActivityKind = 'scan' | 'watch' | 'preinstall';
export type XRayActivityStatus = 'pass' | 'warn' | 'blocked' | 'detected';

export interface XRayHistoryEntry {
  id: string;
  target: string;
  targetType: XRayTargetType;
  deepScan: boolean;
  trustScore: number;
  riskLevel: XRayResult['riskLevel'];
  filesScanned: number;
  findingCount: number;
  scannedAt: string;
  result: {
    target: string;
    trustScore: number;
    riskLevel: XRayResult['riskLevel'];
    findings: XRayResult['findings'];
    filesScanned: number;
    scannedAt: string;
    deepScan: boolean;
  };
}

export interface XRayActivityEntry {
  id: string;
  kind: XRayActivityKind;
  status: XRayActivityStatus;
  target: string;
  targetType: XRayTargetType;
  deepScan: boolean;
  trustScore: number;
  riskLevel: XRayResult['riskLevel'];
  filesScanned: number;
  findingCount: number;
  scannedAt: string;
  summary: string;
}

export interface XRayWatchSessionEntry {
  id: string;
  root: string;
  deepScan: boolean;
  startedAt: string;
  lastHeartbeatAt: string;
  endedAt: string | null;
  active: boolean;
  state: 'active' | 'stale' | 'ended';
  changesDetected: number;
  findingsDetected: number;
  highestRiskLevel: XRayResult['riskLevel'];
  lastEventAt: string | null;
  lastEventSummary: string | null;
}

function ensureXRayDir(): void {
  if (!fs.existsSync(XRAY_DIR)) {
    mkdirSecure(XRAY_DIR);
  }
}

function makeId(): string {
  return `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

export function serializeXRayResult(result: XRayResult) {
  return {
    target: result.target,
    trustScore: result.trustScore,
    riskLevel: result.riskLevel,
    findings: result.findings,
    filesScanned: result.filesScanned,
    scannedAt: result.scannedAt.toISOString(),
    deepScan: result.deepScan,
  };
}

export function createHistoryEntry(result: XRayResult, targetType: XRayTargetType): XRayHistoryEntry {
  return {
    id: makeId(),
    target: result.target,
    targetType,
    deepScan: result.deepScan,
    trustScore: result.trustScore,
    riskLevel: result.riskLevel,
    filesScanned: result.filesScanned,
    findingCount: result.findings.length,
    scannedAt: result.scannedAt.toISOString(),
    result: serializeXRayResult(result),
  };
}

export function readHistory(): XRayHistoryEntry[] {
  try {
    const raw = fs.readFileSync(HISTORY_FILE, 'utf-8');
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

export function getHistoryEntry(id: string): XRayHistoryEntry | null {
  return readHistory().find((entry) => entry.id === id) ?? null;
}

export function appendHistory(entry: XRayHistoryEntry): void {
  ensureXRayDir();
  const existing = readHistory();
  fs.writeFileSync(
    HISTORY_FILE,
    JSON.stringify([entry, ...existing].slice(0, HISTORY_LIMIT), null, 2),
  );
}

export function appendActivity(entry: Omit<XRayActivityEntry, 'id'>): XRayActivityEntry {
  ensureXRayDir();
  const fullEntry: XRayActivityEntry = { id: makeId(), ...entry };
  fs.appendFileSync(ACTIVITY_FILE, `${JSON.stringify(fullEntry)}\n`);
  return fullEntry;
}

export function readActivity(limit = 25): XRayActivityEntry[] {
  try {
    const lines = fs.readFileSync(ACTIVITY_FILE, 'utf-8')
      .split('\n')
      .map((line) => line.trim())
      .filter(Boolean)
      .slice(-ACTIVITY_LIMIT);

    const entries = lines
      .map((line) => {
        try {
          return JSON.parse(line) as XRayActivityEntry;
        } catch {
          return null;
        }
      })
      .filter((entry): entry is XRayActivityEntry => entry !== null);

    return entries.reverse().slice(0, limit);
  } catch {
    return [];
  }
}

function normalizeWatchSession(entry: XRayWatchSessionEntry): XRayWatchSessionEntry {
  const heartbeatAge = Date.now() - new Date(entry.lastHeartbeatAt).getTime();
  const active = entry.active && heartbeatAge <= ACTIVE_WATCH_THRESHOLD_MS && entry.endedAt === null;
  const state: XRayWatchSessionEntry['state'] = entry.endedAt
    ? 'ended'
    : active
      ? 'active'
      : 'stale';
  return {
    ...entry,
    active,
    state,
  };
}

function loadWatchSessions(): XRayWatchSessionEntry[] {
  try {
    const raw = fs.readFileSync(WATCH_SESSIONS_FILE, 'utf-8');
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed.map((entry) => entry as XRayWatchSessionEntry);
  } catch {
    return [];
  }
}

function writeWatchSessions(entries: XRayWatchSessionEntry[]): void {
  ensureXRayDir();
  fs.writeFileSync(
    WATCH_SESSIONS_FILE,
    JSON.stringify(entries.slice(0, WATCH_SESSION_LIMIT), null, 2),
  );
}

function shouldRetainWatchSession(entry: XRayWatchSessionEntry): boolean {
  const now = Date.now();

  if (entry.state === 'active') return true;

  if (entry.state === 'stale') {
    return now - new Date(entry.lastHeartbeatAt).getTime() <= STALE_WATCH_RETENTION_MS;
  }

  if (entry.state === 'ended' && entry.endedAt) {
    return now - new Date(entry.endedAt).getTime() <= ENDED_WATCH_RETENTION_MS;
  }

  return false;
}

function cleanupWatchSessions(entries: XRayWatchSessionEntry[]): XRayWatchSessionEntry[] {
  return entries
    .map((entry) => normalizeWatchSession(entry))
    .filter((entry) => shouldRetainWatchSession(entry))
    .slice(0, WATCH_SESSION_LIMIT);
}

export function readWatchSessions(): XRayWatchSessionEntry[] {
  const cleaned = cleanupWatchSessions(loadWatchSessions());

  if (cleaned.length > 0 || fs.existsSync(WATCH_SESSIONS_FILE)) {
    writeWatchSessions(cleaned);
  }

  return cleaned;
}

export function startWatchSession(root: string, deepScan: boolean): XRayWatchSessionEntry {
  const now = new Date().toISOString();
  const entry: XRayWatchSessionEntry = {
    id: makeId(),
    root,
    deepScan,
    startedAt: now,
    lastHeartbeatAt: now,
    endedAt: null,
    active: true,
    state: 'active',
    changesDetected: 0,
    findingsDetected: 0,
    highestRiskLevel: 'SAFE',
    lastEventAt: null,
    lastEventSummary: null,
  };

  const existing = readWatchSessions().filter((session) => session.root !== root || !session.active);
  writeWatchSessions([entry, ...existing]);
  return entry;
}

function updateWatchSessionEntry(
  sessionId: string,
  updater: (entry: XRayWatchSessionEntry) => XRayWatchSessionEntry,
): XRayWatchSessionEntry | null {
  let updated: XRayWatchSessionEntry | null = null;
  const next = readWatchSessions().map((entry) => {
    if (entry.id !== sessionId) return entry;
    updated = normalizeWatchSession(updater(entry));
    return updated;
  });

  if (updated) {
    writeWatchSessions(next);
  }

  return updated;
}

export function heartbeatWatchSession(sessionId: string): XRayWatchSessionEntry | null {
  return updateWatchSessionEntry(sessionId, (entry) => ({
    ...entry,
    active: true,
    state: 'active',
    lastHeartbeatAt: new Date().toISOString(),
    endedAt: null,
  }));
}

const RISK_RANK: Record<XRayResult['riskLevel'], number> = {
  SAFE: 0,
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3,
  CRITICAL: 4,
};

export function recordWatchSessionEvent(
  sessionId: string,
  payload: {
    findingsDetected: number;
    riskLevel: XRayResult['riskLevel'];
    summary: string;
    scannedAt?: string;
  },
): XRayWatchSessionEntry | null {
  return updateWatchSessionEntry(sessionId, (entry) => {
    const nextRisk = RISK_RANK[payload.riskLevel] > RISK_RANK[entry.highestRiskLevel]
      ? payload.riskLevel
      : entry.highestRiskLevel;

    return {
      ...entry,
      active: true,
      state: 'active',
      lastHeartbeatAt: new Date().toISOString(),
      changesDetected: entry.changesDetected + 1,
      findingsDetected: entry.findingsDetected + payload.findingsDetected,
      highestRiskLevel: nextRisk,
      lastEventAt: payload.scannedAt ?? new Date().toISOString(),
      lastEventSummary: payload.summary,
    };
  });
}

export function endWatchSession(sessionId: string): XRayWatchSessionEntry | null {
  const now = new Date().toISOString();
  return updateWatchSessionEntry(sessionId, (entry) => ({
    ...entry,
    active: false,
    state: 'ended',
    lastHeartbeatAt: now,
    endedAt: now,
  }));
}

// ── Watch IPC (JSONL file for cross-process broadcast) ───────

export const DETECTION_EVENTS_FILE = path.join(XRAY_DIR, 'xray-detection-events.jsonl');

const MAX_EVENTS_FILE_SIZE = 512 * 1024;

export function emitDetectionEvent(event: {
  target: string;
  findingCount: number;
  riskLevel: string;
  severity: string;
  summary: string;
}): void {
  try {
    const stat = fs.statSync(DETECTION_EVENTS_FILE);
    if (stat.size > MAX_EVENTS_FILE_SIZE) {
      fs.writeFileSync(DETECTION_EVENTS_FILE, '');
    }
  } catch { /* File doesn't exist yet */ }

  const line = JSON.stringify({ ...event, timestamp: new Date().toISOString() }) + '\n';
  fs.appendFileSync(DETECTION_EVENTS_FILE, line);
}

export function readAndClearDetectionEvents(): Array<Record<string, unknown>> {
  try {
    if (!fs.existsSync(DETECTION_EVENTS_FILE)) return [];
    const tmp = DETECTION_EVENTS_FILE + '.processing';
    fs.renameSync(DETECTION_EVENTS_FILE, tmp);
    const data = fs.readFileSync(tmp, 'utf-8').trim();
    fs.unlinkSync(tmp);
    if (!data) return [];
    return data.split('\n').filter(Boolean).map((line) => JSON.parse(line));
  } catch {
    return [];
  }
}
