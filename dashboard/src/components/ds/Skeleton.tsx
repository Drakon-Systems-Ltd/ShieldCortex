'use client';

import { cn } from '@/lib/utils';

interface SkeletonProps {
  className?: string;
}

// Terminal-loading-bar style: a row of decreasing-density block characters
// pulsing at low opacity. Falls back to a flat surface when collapsed to a
// height too small for text rendering.
export function Skeleton({ className }: SkeletonProps) {
  return (
    <div
      className={cn(
        'flex items-center overflow-hidden rounded-md bg-[var(--term-surface-2)] text-[var(--term-text-muted)] text-xs leading-none animate-pulse px-2',
        className,
      )}
      aria-busy="true"
      aria-live="polite"
    >
      <span className="select-none whitespace-nowrap tracking-tighter">
        █▓▓▓▒▒▒░░░░ ▓▓▒▒░░ █▓▒░ ▓▓▒░░ █▓▓▒░░░ ▓▒░░ █▒▒░
      </span>
    </div>
  );
}

export function PageSkeleton() {
  return (
    <div className="mx-auto max-w-7xl space-y-6 p-6">
      {/* Header skeleton */}
      <div className="space-y-2">
        <Skeleton className="h-3 w-24" />
        <Skeleton className="h-7 w-56" />
        <Skeleton className="h-4 w-80" />
      </div>

      {/* Tab bar skeleton */}
      <Skeleton className="h-10 w-96" />

      {/* Stat cards */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <Skeleton className="h-24" />
        <Skeleton className="h-24" />
        <Skeleton className="h-24" />
        <Skeleton className="h-24" />
      </div>

      {/* Content cards */}
      <div className="grid gap-6 lg:grid-cols-2">
        <Skeleton className="h-64" />
        <Skeleton className="h-64" />
      </div>
    </div>
  );
}
