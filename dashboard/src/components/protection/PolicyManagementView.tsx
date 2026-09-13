'use client';

import { useState } from 'react';
import { TabBar } from '@/components/ds/TabBar';
import { CustomPatternsPanel } from '@/components/dome/CustomPatternsPanel';
import { CustomPoliciesPanel } from '@/components/dome/CustomPoliciesPanel';
import { CustomFirewallRulesPanel } from '@/components/shield/CustomFirewallRulesPanel';

type PolicyTab = 'patterns' | 'firewall' | 'dome';

const TABS = [
  { id: 'patterns', label: 'Custom Patterns' },
  { id: 'firewall', label: 'Firewall Rules' },
  { id: 'dome', label: 'Iron Dome Policies' },
];

/** Policies & Rules (brief §8): custom patterns, firewall rules, and Iron
 *  Dome policies in one page with three tabs, on the shared DS TabBar —
 *  replaces the bespoke hero-header two-panel layout, which buried Custom
 *  Patterns back inside the Status tab instead of here. */
export function PolicyManagementView() {
  const [tab, setTab] = useState<PolicyTab>('patterns');

  return (
    <div className="space-y-4">
      <TabBar tabs={TABS} activeTab={tab} onChange={(id) => setTab(id as PolicyTab)} />
      {tab === 'patterns' && <CustomPatternsPanel />}
      {tab === 'firewall' && <CustomFirewallRulesPanel />}
      {tab === 'dome' && <CustomPoliciesPanel />}
    </div>
  );
}
