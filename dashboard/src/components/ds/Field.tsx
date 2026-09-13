'use client';

import { Search } from 'lucide-react';
import { forwardRef } from 'react';
import { cn } from '@/lib/utils';

const FIELD_CLASS =
  'h-8 rounded-md border border-[var(--sc-border)] bg-[var(--sc-surface)] px-2.5 text-sm text-[var(--sc-text)] placeholder:text-[var(--sc-text-muted)] transition-colors focus-visible:outline-2 focus-visible:outline-[var(--sc-focus)] disabled:opacity-50';

export const Input = forwardRef<HTMLInputElement, React.InputHTMLAttributes<HTMLInputElement>>(
  ({ className, ...props }, ref) => (
    <input ref={ref} className={cn(FIELD_CLASS, className)} {...props} />
  ),
);
Input.displayName = 'Input';

export const Select = forwardRef<HTMLSelectElement, React.SelectHTMLAttributes<HTMLSelectElement>>(
  ({ className, children, ...props }, ref) => (
    <select ref={ref} className={cn(FIELD_CLASS, 'pr-7', className)} {...props}>
      {children}
    </select>
  ),
);
Select.displayName = 'Select';

interface SearchInputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  containerClassName?: string;
}

export const SearchInput = forwardRef<HTMLInputElement, SearchInputProps>(
  ({ className, containerClassName, ...props }, ref) => (
    <div className={cn('relative', containerClassName)}>
      <Search size={13} aria-hidden className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-[var(--sc-text-muted)]" />
      <input ref={ref} type="search" className={cn(FIELD_CLASS, 'w-full pl-8', className)} {...props} />
    </div>
  ),
);
SearchInput.displayName = 'SearchInput';
