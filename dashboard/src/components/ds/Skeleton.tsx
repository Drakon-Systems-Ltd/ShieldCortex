'use client';

import { cn } from '@/lib/utils';

interface SkeletonProps {
  className?: string;
}

/** Loading placeholder — flat shimmer block, motion-gated by Tailwind's
 *  animate-pulse (which respects prefers-reduced-motion via globals). */
export function Skeleton({ className }: SkeletonProps) {
  return (
    <div
      className={cn('animate-pulse rounded-md bg-[var(--sc-surface-2)] motion-reduce:animate-none', className)}
      aria-busy="true"
      aria-live="polite"
    />
  );
}

export function PageSkeleton() {
  return (
    <div className="space-y-4 p-6">
      <Skeleton className="h-7 w-56" />
      <Skeleton className="h-4 w-80" />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Skeleton className="h-24" />
        <Skeleton className="h-24" />
        <Skeleton className="h-24" />
        <Skeleton className="h-24" />
      </div>
      <Skeleton className="h-64" />
    </div>
  );
}
