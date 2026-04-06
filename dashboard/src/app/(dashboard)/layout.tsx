import { AppShell } from '@/components/layout/AppShell';
import { ToastProvider } from '@/components/ds/Toast';

export default function DashboardSectionLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <AppShell>
      {children}
      <ToastProvider />
    </AppShell>
  );
}
