'use client';

/**
 * HealthRing — Circular SVG progress ring showing overall brain health.
 *
 * Green (#10B981) when >70%, amber (#F59E0B) 40-70%, red (#EF4444) <40%.
 * Animated via CSS transition on stroke-dashoffset.
 */

interface HealthRingProps {
  percentage: number;
  size?: number;
  strokeWidth?: number;
}

export function HealthRing({
  percentage,
  size = 80,
  strokeWidth = 6,
}: HealthRingProps) {
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const clamped = Math.max(0, Math.min(100, percentage));
  const offset = circumference - (clamped / 100) * circumference;

  const color =
    clamped > 70 ? '#10B981' : clamped >= 40 ? '#F59E0B' : '#EF4444';

  return (
    <div className="relative inline-flex items-center justify-center">
      <svg
        width={size}
        height={size}
        viewBox={`0 0 ${size} ${size}`}
        className="-rotate-90"
      >
        {/* Background track */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke="currentColor"
          strokeWidth={strokeWidth}
          className="text-slate-700"
        />
        {/* Foreground progress arc */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth={strokeWidth}
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          style={{ transition: 'stroke-dashoffset 0.6s ease, stroke 0.4s ease' }}
        />
      </svg>

      {/* Centre percentage text */}
      <span
        className="absolute text-sm font-semibold"
        style={{ color }}
      >
        {Math.round(clamped)}%
      </span>
    </div>
  );
}
