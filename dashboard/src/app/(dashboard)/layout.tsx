import { AppShell } from '@/components/layout/AppShell';
import { ToastProvider } from '@/components/ds/Toast';
import { BlockToastBridge } from '@/components/ds/BlockToastBridge';

export default function DashboardSectionLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <AppShell>
      {children}
      <ToastProvider />
      <BlockToastBridge />
    </AppShell>
  );
}
