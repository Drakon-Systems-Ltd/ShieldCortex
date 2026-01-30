'use client';

import { useMemo } from 'react';

export interface ActivityDay {
  date: string;
  count: number;
}

interface ActivityHeatmapProps {
  activity: ActivityDay[];
}

const CELL_SIZE = 12;
const CELL_GAP = 2;
const CELL_RADIUS = 2;
const WEEKS = 52;
const DAYS = 7;
const LEFT_LABEL_WIDTH = 30;
const TOP_LABEL_HEIGHT = 16;

const DAY_LABELS = ['', 'Mon', '', 'Wed', '', 'Fri', ''];
const MONTH_LABELS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

function getColor(count: number, max: number): string {
  if (count === 0) return '#0f172a'; // slate-900 (darker empty)
  const ratio = count / Math.max(max, 1);
  if (ratio < 0.25) return '#155e75'; // cyan-800
  if (ratio < 0.50) return '#0891b2'; // cyan-600
  if (ratio < 0.75) return '#06b6d4'; // cyan-500
  return '#22d3ee'; // cyan-400
}

export function ActivityHeatmap({ activity }: ActivityHeatmapProps) {
  const { grid, monthPositions, maxCount } = useMemo(() => {
    // Build lookup map
    const lookup = new Map<string, number>();
    for (const d of activity) {
      lookup.set(d.date, d.count);
    }

    // Today at start of day
    const today = new Date();
    today.setHours(0, 0, 0, 0);

    // Find the Saturday of the current week (end of last column)
    const todayDay = today.getDay(); // 0=Sun
    const endDate = new Date(today);
    endDate.setDate(today.getDate() + (6 - todayDay));

    // Start date is 52 weeks before endDate's Sunday
    const startDate = new Date(endDate);
    startDate.setDate(endDate.getDate() - (WEEKS * 7 - 1));

    const cells: Array<{ week: number; day: number; date: string; count: number }> = [];
    const months: Array<{ label: string; week: number }> = [];
    let lastMonth = -1;

    const cursor = new Date(startDate);
    for (let w = 0; w < WEEKS; w++) {
      for (let d = 0; d < DAYS; d++) {
        const dateStr = cursor.toISOString().slice(0, 10);
        const count = lookup.get(dateStr) || 0;
        cells.push({ week: w, day: d, date: dateStr, count });

        const month = cursor.getMonth();
        if (month !== lastMonth && d === 0) {
          months.push({ label: MONTH_LABELS[month], week: w });
          lastMonth = month;
        }

        cursor.setDate(cursor.getDate() + 1);
      }
    }

    const max = Math.max(...cells.map(c => c.count), 1);
    return { grid: cells, monthPositions: months, maxCount: max };
  }, [activity]);

  const svgWidth = LEFT_LABEL_WIDTH + WEEKS * (CELL_SIZE + CELL_GAP);
  const svgHeight = TOP_LABEL_HEIGHT + DAYS * (CELL_SIZE + CELL_GAP);

  return (
    <div className="bg-slate-900/50 rounded-lg p-4 overflow-x-auto">
      <svg width={svgWidth} height={svgHeight} className="text-slate-400">
        {/* Month labels */}
        {monthPositions.map((m, i) => (
          <text
            key={i}
            x={LEFT_LABEL_WIDTH + m.week * (CELL_SIZE + CELL_GAP)}
            y={12}
            fontSize={10}
            fill="currentColor"
          >
            {m.label}
          </text>
        ))}

        {/* Day labels */}
        {DAY_LABELS.map((label, i) =>
          label ? (
            <text
              key={i}
              x={0}
              y={TOP_LABEL_HEIGHT + i * (CELL_SIZE + CELL_GAP) + CELL_SIZE - 1}
              fontSize={10}
              fill="currentColor"
            >
              {label}
            </text>
          ) : null
        )}

        {/* Cells */}
        {grid.map((cell, i) => (
          <rect
            key={i}
            x={LEFT_LABEL_WIDTH + cell.week * (CELL_SIZE + CELL_GAP)}
            y={TOP_LABEL_HEIGHT + cell.day * (CELL_SIZE + CELL_GAP)}
            width={CELL_SIZE}
            height={CELL_SIZE}
            rx={CELL_RADIUS}
            fill={getColor(cell.count, maxCount)}
          >
            <title>{`${cell.date}: ${cell.count} memories`}</title>
          </rect>
        ))}
      </svg>
    </div>
  );
}
