'use client';

import { useCallback, useState } from 'react';
import { usePathname, useRouter, useSearchParams } from 'next/navigation';
import { isHiddenRoute } from '@/components/layout/hidden-routes';

/**
 * `?tab=` state for a tabbed page. A click rewrites the URL so the URL tab
 * follows it — without that a deep link (`/protection?tab=audit`) keeps
 * winning and every other tab looks dead. Unknown and hidden tab ids fall
 * back to `defaultTab`.
 */
export function useUrlTab<T extends string>(
  page: string,
  validTabs: readonly T[],
  defaultTab: T,
  aliases: Partial<Record<string, T>> = {},
): [T, (next: T) => void] {
  const searchParams = useSearchParams();
  const pathname = usePathname();
  const router = useRouter();
  const raw = searchParams.get('tab');
  const normalised = raw !== null ? (aliases[raw] ?? raw) : null;
  const urlTab =
    normalised && validTabs.includes(normalised as T) && !isHiddenRoute(page, normalised)
      ? (normalised as T)
      : null;
  const [userTab, setUserTab] = useState<T>(defaultTab);

  const setTab = useCallback((next: T) => {
    setUserTab(next);
    const params = new URLSearchParams(searchParams.toString());
    if (next === defaultTab) params.delete('tab');
    else params.set('tab', next);
    const query = params.toString();
    router.replace(query ? `${pathname}?${query}` : pathname, { scroll: false });
  }, [defaultTab, pathname, router, searchParams]);

  return [urlTab ?? userTab, setTab];
}
