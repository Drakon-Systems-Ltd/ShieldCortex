'use client';

import { useMemo, useState } from 'react';
import { ArrowDown, ArrowUp, ArrowUpDown } from 'lucide-react';
import { Skeleton } from '@/components/ds/Skeleton';
import { EmptyState } from '@/components/ds/EmptyState';
import { cn } from '@/lib/utils';

export interface Column<T> {
  key: string;
  header: React.ReactNode;
  /** Cell renderer. */
  cell: (row: T) => React.ReactNode;
  /** Provide to make the column sortable. */
  sortValue?: (row: T) => string | number;
  className?: string;
  headerClassName?: string;
}

interface TableProps<T> {
  columns: Column<T>[];
  rows: T[];
  rowKey: (row: T) => string | number;
  onRowClick?: (row: T) => void;
  selectedKey?: string | number | null;
  loading?: boolean;
  emptyMessage?: React.ReactNode;
  emptyAction?: React.ReactNode;
  /** Initial sort column key + direction. */
  initialSort?: { key: string; dir: 'asc' | 'desc' };
  className?: string;
}

/** Sortable table: sticky header, row actions via cells, empty + loading states. */
export function Table<T>({
  columns,
  rows,
  rowKey,
  onRowClick,
  selectedKey,
  loading = false,
  emptyMessage = 'Nothing here yet.',
  emptyAction,
  initialSort,
  className,
}: TableProps<T>) {
  const [sort, setSort] = useState<{ key: string; dir: 'asc' | 'desc' } | null>(initialSort ?? null);

  const sorted = useMemo(() => {
    if (!sort) return rows;
    const col = columns.find((c) => c.key === sort.key);
    if (!col?.sortValue) return rows;
    const sv = col.sortValue;
    return [...rows].sort((a, b) => {
      const av = sv(a);
      const bv = sv(b);
      const cmp = typeof av === 'number' && typeof bv === 'number' ? av - bv : String(av).localeCompare(String(bv));
      return sort.dir === 'asc' ? cmp : -cmp;
    });
  }, [rows, sort, columns]);

  const toggleSort = (key: string) => {
    setSort((s) => (s?.key === key ? { key, dir: s.dir === 'asc' ? 'desc' : 'asc' } : { key, dir: 'desc' }));
  };

  if (loading) {
    return (
      <div className="space-y-2">
        <Skeleton className="h-8" />
        <Skeleton className="h-8" />
        <Skeleton className="h-8" />
        <Skeleton className="h-8" />
      </div>
    );
  }

  if (rows.length === 0) {
    return <EmptyState message={emptyMessage} action={emptyAction} />;
  }

  return (
    <div className={cn('overflow-auto rounded-lg border border-[var(--sc-border)]', className)}>
      <table className="w-full border-collapse text-sm">
        <thead className="sticky top-0 z-10 bg-[var(--sc-surface-2)]">
          <tr>
            {columns.map((col) => (
              <th
                key={col.key}
                scope="col"
                className={cn('border-b border-[var(--sc-border)] px-3 py-2 text-left text-xs font-medium text-[var(--sc-text-muted)]', col.headerClassName)}
              >
                {col.sortValue ? (
                  <button
                    type="button"
                    onClick={() => toggleSort(col.key)}
                    className="inline-flex items-center gap-1 hover:text-[var(--sc-text)] focus-visible:outline-2 focus-visible:outline-[var(--sc-focus)]"
                    aria-label={`Sort by ${typeof col.header === 'string' ? col.header : col.key}`}
                  >
                    {col.header}
                    {sort?.key === col.key
                      ? sort.dir === 'asc' ? <ArrowUp size={11} aria-hidden /> : <ArrowDown size={11} aria-hidden />
                      : <ArrowUpDown size={11} aria-hidden className="opacity-40" />}
                  </button>
                ) : (
                  col.header
                )}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {sorted.map((row) => {
            const key = rowKey(row);
            const selected = selectedKey != null && key === selectedKey;
            return (
              <tr
                key={key}
                onClick={onRowClick ? () => onRowClick(row) : undefined}
                className={cn(
                  'border-b border-[var(--sc-border)] last:border-b-0',
                  onRowClick && 'cursor-pointer hover:bg-[var(--sc-surface-2)]',
                  selected && 'bg-[var(--sc-primary-soft)]',
                )}
              >
                {columns.map((col) => (
                  <td key={col.key} className={cn('px-3 py-2 align-top text-[var(--sc-text-dim)]', col.className)}>
                    {col.cell(row)}
                  </td>
                ))}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
