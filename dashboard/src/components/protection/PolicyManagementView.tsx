'use client';

import { CustomPoliciesPanel } from '@/components/dome/CustomPoliciesPanel';
import { CustomFirewallRulesPanel } from '@/components/shield/CustomFirewallRulesPanel';

export function PolicyManagementView() {
  return (
    <div className="h-full overflow-y-auto bg-[var(--sc-bg-deep)]">
      <div className="mx-auto max-w-7xl space-y-6 p-6">
        <section className="rounded-2xl border border-[var(--sc-border)] bg-[var(--sc-bg-surface)]/70 p-6">
          <div className="text-[11px] uppercase tracking-[0.2em] text-[var(--sc-cyan)]">Protection / Policies</div>
          <h2 className="mt-3 text-3xl font-semibold text-[var(--sc-text-primary)]">Policy management</h2>
          <p className="mt-2 max-w-3xl text-sm text-[var(--sc-text-secondary)]">
            Keep operator-tuned controls in one place. Firewall rules and Iron Dome policies should not be buried inside larger screens when they directly shape blocking, quarantine, and approval behavior.
          </p>
        </section>

        <div className="grid gap-6 xl:grid-cols-2">
          <CustomFirewallRulesPanel />
          <CustomPoliciesPanel />
        </div>
      </div>
    </div>
  );
}
