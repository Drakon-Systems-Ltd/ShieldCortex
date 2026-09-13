'use client';

/**
 * Debug Panel Component
 *
 * Collapsible bottom panel with tabbed interface for debug tools:
 * - Memory Detail (enhanced)
 * - Query Tester
 * - Activity Log
 * - Relationship Graph
 * - SQL Console
 */

import { useState } from 'react';
import { QueryTester } from './QueryTester';
import { ActivityLog } from './ActivityLog';
import { RelationshipGraph } from './RelationshipGraph';
import { SqlConsole } from './SqlConsole';

type TabId = 'detail' | 'query' | 'activity' | 'graph' | 'sql';

interface Tab {
  id: TabId;
  label: string;
  icon: string;
}

const TABS: Tab[] = [
  { id: 'query', label: 'Query', icon: '🔍' },
  { id: 'activity', label: 'Activity', icon: '📋' },
  { id: 'graph', label: 'Graph', icon: '🕸' },
  { id: 'sql', label: 'SQL', icon: '💾' },
];

interface DebugPanelProps {
  onCollapse?: () => void;
}

export function DebugPanel({ onCollapse }: DebugPanelProps) {
  const [activeTab, setActiveTab] = useState<TabId>('query');
  const [isCollapsed, setIsCollapsed] = useState(false);

  const handleCollapse = () => {
    setIsCollapsed(!isCollapsed);
    onCollapse?.();
  };

  if (isCollapsed) {
    return (
      <div className="h-10 border-t border-[var(--sc-border)] bg-[var(--sc-bg-surface)] flex items-center px-4">
        <button
          onClick={handleCollapse}
          className="flex items-center gap-2 text-sm text-[var(--sc-text-secondary)] hover:text-[var(--sc-text-primary)]"
        >
          <span>▲</span>
          <span>Debug Panel</span>
        </button>
      </div>
    );
  }

  return (
    <div className="h-96 border-t border-[var(--sc-border)] bg-[var(--sc-bg-surface)] flex flex-col">
      {/* Tab Bar */}
      <div className="flex items-center border-b border-[var(--sc-border)] px-2">
        {TABS.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`px-4 py-2 text-sm flex items-center gap-1.5 border-b-2 transition-colors ${
              activeTab === tab.id
                ? 'text-[var(--sc-text-primary)] border-blue-500'
                : 'text-[var(--sc-text-secondary)] border-transparent hover:text-[var(--sc-text-primary)] hover:border-[var(--sc-border)]'
            }`}
          >
            <span>{tab.icon}</span>
            <span>{tab.label}</span>
          </button>
        ))}

        <div className="flex-1" />

        <button
          onClick={handleCollapse}
          className="p-2 text-[var(--sc-text-secondary)] hover:text-[var(--sc-text-primary)]"
          title="Collapse panel"
        >
          ▼
        </button>
      </div>

      {/* Tab Content */}
      <div className="flex-1 overflow-hidden min-h-0">
        {activeTab === 'query' && <QueryTester />}
        {activeTab === 'activity' && <ActivityLog />}
        {activeTab === 'graph' && <RelationshipGraph />}
        {activeTab === 'sql' && <SqlConsole />}
      </div>
    </div>
  );
}
