'use client';

interface TrustGaugeProps {
  score: number;
  size?: number;
  label?: string;
}

export function TrustGauge({ score, size = 160, label }: TrustGaugeProps) {
  const radius = 42;
  const circumference = 2 * Math.PI * radius;
  const progress = (score / 100) * circumference;

  // Interpolate from coral (low) to cyan (high)
  const hue = score <= 50
    ? `var(--sc-danger)`
    : score <= 75
      ? `var(--sc-amber)`
      : `var(--sc-ok)`;

  const glow = score <= 50
    ? 'var(--sc-danger-soft)'
    : score <= 75
      ? 'rgba(245, 158, 11, 0.15)'
      : 'var(--sc-ok-soft)';

  return (
    <div className="flex flex-col items-center gap-2">
      <div className="relative" style={{ width: size, height: size }}>
        <svg viewBox="0 0 100 100" className="h-full w-full -rotate-90" style={{ filter: `drop-shadow(0 0 12px ${glow})` }}>
          {/* Track */}
          <circle
            cx="50" cy="50" r={radius}
            fill="none"
            stroke="var(--sc-surface-2)"
            strokeWidth="7"
          />
          {/* Progress */}
          <circle
            cx="50" cy="50" r={radius}
            fill="none"
            stroke={hue}
            strokeWidth="7"
            strokeDasharray={`${progress} ${circumference}`}
            strokeLinecap="round"
            className="transition-all duration-1000 ease-out"
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-3xl font-bold" style={{ color: hue }}>{score}</span>
          <span className="text-[11px] text-[var(--sc-text-muted)]">trust</span>
        </div>
      </div>
      {label && (
        <span className="text-xs font-medium text-[var(--sc-text-dim)]">{label}</span>
      )}
    </div>
  );
}
