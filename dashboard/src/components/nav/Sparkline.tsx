'use client';

interface SparklineProps {
  data: number[];   // 7 data points (7-day trend)
  color?: string;   // stroke colour, default cyan
  width?: number;   // default 24
  height?: number;  // default 10
}

export function Sparkline({
  data,
  color = '#22d3ee',
  width = 24,
  height = 10,
}: SparklineProps) {
  // Handle empty or single-point data gracefully
  if (!data || data.length === 0) return null;
  if (data.length === 1) {
    // Single point — render a dot in the centre
    return (
      <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`}>
        <circle cx={width / 2} cy={height / 2} r={1} fill={color} opacity={0.6} />
      </svg>
    );
  }

  const max = Math.max(...data, 1); // avoid division by zero
  const padding = 1;
  const innerW = width - padding * 2;
  const innerH = height - padding * 2;

  const points = data
    .map((value, i) => {
      const x = padding + (i / (data.length - 1)) * innerW;
      const y = padding + innerH - (value / max) * innerH;
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(' ');

  return (
    <svg
      width={width}
      height={height}
      viewBox={`0 0 ${width} ${height}`}
      className="shrink-0"
    >
      <polyline
        points={points}
        fill="none"
        stroke={color}
        strokeWidth={1}
        strokeLinecap="round"
        strokeLinejoin="round"
        opacity={0.6}
      />
    </svg>
  );
}
