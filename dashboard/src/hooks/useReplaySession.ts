'use client';

import { useQuery } from '@tanstack/react-query';
import { authFetch, readApiError } from '@/lib/auth';
import { useEffect, useMemo, useState, useCallback } from 'react';

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3001';

export type ReplayKind =
  | 'prompt'
  | 'response'
  | 'tool_call'
  | 'tool_result'
  | 'tool_error'
  | 'hook_fire';

export interface ReplayEvent {
  id: number;
  session_id: string;
  project: string | null;
  ts: string;
  kind: ReplayKind;
  actor: string | null;
  payload: unknown;
  duration_ms: number | null;
  audit_id: number | null;
  created_at: string;
}

export interface ReplaySessionSummary {
  session_id: string;
  project: string | null;
  first_ts: string;
  last_ts: string;
  event_count: number;
}

export interface ReplaySessionDetail extends ReplaySessionSummary {
  kinds: Partial<Record<ReplayKind, number>>;
}

// ── Query hooks ───────────────────────────────────────────────────────

export function useReplaySessions(project?: string | null) {
  return useQuery<{ sessions: ReplaySessionSummary[]; total: number }>({
    queryKey: ['replay-sessions', project ?? null],
    queryFn: async () => {
      const qs = project ? `?project=${encodeURIComponent(project)}&limit=200` : '?limit=200';
      const res = await authFetch(`${API_URL}/api/sessions${qs}`);
      if (!res.ok) throw new Error(await readApiError(res, 'Failed to fetch sessions'));
      return res.json();
    },
    refetchInterval: 15000,
  });
}

export function useReplaySessionDetail(sessionId: string | null) {
  return useQuery<ReplaySessionDetail>({
    queryKey: ['replay-session', sessionId],
    enabled: !!sessionId,
    queryFn: async () => {
      const res = await authFetch(`${API_URL}/api/sessions/${encodeURIComponent(sessionId!)}`);
      if (!res.ok) throw new Error(await readApiError(res, 'Failed to fetch session'));
      return res.json();
    },
  });
}

export function useReplayEvents(sessionId: string | null) {
  return useQuery<{ events: ReplayEvent[]; total: number }>({
    queryKey: ['replay-events', sessionId],
    enabled: !!sessionId,
    queryFn: async () => {
      const res = await authFetch(
        `${API_URL}/api/sessions/${encodeURIComponent(sessionId!)}/events?limit=500`,
      );
      if (!res.ok) throw new Error(await readApiError(res, 'Failed to fetch events'));
      return res.json();
    },
  });
}

// ── Playback state machine ────────────────────────────────────────────
//
// Driven by `setTimeout` rather than requestAnimationFrame. Tab visibility
// (or the dashboard going to background) is fine — timeouts may drift but
// they don't drop events. RAF would pause entirely off-screen, which is
// the wrong behaviour for a replay scrubber where the user expects
// playback to continue while they read.

export type ReplaySpeed = 0.5 | 1 | 2 | 4;
export const REPLAY_SPEEDS: readonly ReplaySpeed[] = [0.5, 1, 2, 4];

/**
 * Min/max gap between events in real wall-clock ms. Real conversations
 * have long pauses (coffee breaks, lunch) — replaying those at full
 * speed is dull. Clamp to a 50ms..5s window so playback always feels
 * lively but step gaps are still proportional within reason.
 */
const MIN_STEP_MS = 50;
const MAX_STEP_MS = 5000;

export interface ReplayPlayback {
  events: ReplayEvent[];
  currentIndex: number;
  playing: boolean;
  speed: ReplaySpeed;
  /** Active event (or null when events is empty). */
  current: ReplayEvent | null;
  /** 0..1 progress through the session. */
  progress: number;
  /** Wall-clock-ms timestamp of each event for the scrubber. */
  timestamps: number[];
  play: () => void;
  pause: () => void;
  toggle: () => void;
  setSpeed: (s: ReplaySpeed) => void;
  cycleSpeed: (dir: 1 | -1) => void;
  setIndex: (idx: number) => void;
  stepForward: () => void;
  stepBack: () => void;
  jumpToStart: () => void;
  jumpToEnd: () => void;
}

export function useReplayPlayback(events: ReplayEvent[]): ReplayPlayback {
  const [currentIndex, setCurrentIndex] = useState(0);
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeedState] = useState<ReplaySpeed>(1);

  // Reset position when the events array identity changes (e.g. switching
  // sessions). Uses React's canonical setState-during-render pattern with
  // a tracked-events useState rather than a ref (refs aren't allowed in
  // render bodies under react-hooks lint rules).
  const [trackedEvents, setTrackedEvents] = useState<ReplayEvent[]>(events);
  if (trackedEvents !== events) {
    setTrackedEvents(events);
    setCurrentIndex(0);
    setPlaying(false);
  }

  // Pre-compute ms timestamps once per events list — saves parsing on
  // every render of the scrubber.
  const timestamps = useMemo(() => events.map((e) => Date.parse(e.ts)), [events]);

  // Driver: advance one step on a timer whose delay tracks the wall-clock
  // gap between adjacent events, scaled by `speed`. End-of-session is
  // handled by the timer callback (async) rather than synchronously in the
  // effect body, so we don't trip `react-hooks/set-state-in-effect`.
  const atEnd = currentIndex >= events.length - 1;
  useEffect(() => {
    if (!playing || atEnd) return;
    const gap = timestamps[currentIndex + 1] - timestamps[currentIndex];
    const dt = Math.max(MIN_STEP_MS, Math.min(MAX_STEP_MS, gap)) / speed;
    const handle = window.setTimeout(() => {
      setCurrentIndex((i) => {
        const next = Math.min(i + 1, events.length - 1);
        if (next >= events.length - 1) setPlaying(false);
        return next;
      });
    }, dt);
    return () => window.clearTimeout(handle);
  }, [playing, atEnd, currentIndex, speed, events.length, timestamps]);

  const play = useCallback(() => {
    if (events.length === 0) return;
    if (currentIndex >= events.length - 1) setCurrentIndex(0); // restart on click after end
    setPlaying(true);
  }, [events.length, currentIndex]);

  const pause = useCallback(() => setPlaying(false), []);
  const toggle = useCallback(() => setPlaying((p) => !p), []);

  const setSpeed = useCallback((s: ReplaySpeed) => setSpeedState(s), []);
  const cycleSpeed = useCallback((dir: 1 | -1) => {
    setSpeedState((s) => {
      const idx = REPLAY_SPEEDS.indexOf(s);
      const next = (idx + dir + REPLAY_SPEEDS.length) % REPLAY_SPEEDS.length;
      return REPLAY_SPEEDS[next];
    });
  }, []);

  const setIndex = useCallback(
    (idx: number) => {
      if (events.length === 0) return;
      const clamped = Math.max(0, Math.min(idx, events.length - 1));
      setCurrentIndex(clamped);
    },
    [events.length],
  );
  const stepForward = useCallback(() => setIndex(currentIndex + 1), [currentIndex, setIndex]);
  const stepBack = useCallback(() => setIndex(currentIndex - 1), [currentIndex, setIndex]);
  const jumpToStart = useCallback(() => setIndex(0), [setIndex]);
  const jumpToEnd = useCallback(() => setIndex(events.length - 1), [setIndex, events.length]);

  const current = events.length > 0 ? events[Math.min(currentIndex, events.length - 1)] : null;
  const progress = events.length > 1 ? currentIndex / (events.length - 1) : 0;

  return {
    events,
    currentIndex,
    playing,
    speed,
    current,
    progress,
    timestamps,
    play,
    pause,
    toggle,
    setSpeed,
    cycleSpeed,
    setIndex,
    stepForward,
    stepBack,
    jumpToStart,
    jumpToEnd,
  };
}
