'use client';

import { useState } from 'react';
import { Shield, Plus, Trash2, ToggleLeft, ToggleRight } from 'lucide-react';
import { useFirewallRules, useCreateFirewallRule, useUpdateFirewallRule, useDeleteFirewallRule } from '@/hooks/useFirewallRules';
import { PREVIEW_FIREWALL_RULES } from '@/lib/pro-previews';
import { CardError } from '@/components/ds/CardError';

function RulesTable() {
  const { data, isLoading, isError, isLocked, refetch } = useFirewallRules();
  const createRule = useCreateFirewallRule();
  const updateRule = useUpdateFirewallRule();
  const deleteRule = useDeleteFirewallRule();
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState<{ name: string; priority: number; condition_type: string; condition_value: string; action: 'block' | 'allow' | 'quarantine' }>({ name: '', priority: 100, condition_type: 'regex', condition_value: '', action: 'block' });

  const rules = data?.rules ?? [];

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    createRule.mutate(form, {
      onSuccess: () => {
        setShowForm(false);
        setForm({ name: '', priority: 100, condition_type: 'regex', condition_value: '', action: 'block' });
      },
    });
  };

  if (isLocked) return <PreviewContent />;

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Shield size={16} className="text-[var(--sc-cyan)]" />
          <h3 className="text-sm font-medium text-[var(--sc-text-primary)]">Custom Firewall Rules</h3>
          <span className="text-xs text-[var(--sc-text-muted)]">{rules.length}/25</span>
        </div>
        <button
          onClick={() => setShowForm(!showForm)}
          className="flex items-center gap-1 px-2 py-1 text-xs bg-[var(--sc-cyan)]/20 text-[var(--sc-cyan)] rounded hover:bg-[var(--sc-cyan)]/30 transition-colors"
        >
          <Plus size={12} /> Add Rule
        </button>
      </div>

      {showForm && (
        <form onSubmit={handleSubmit} className="p-3 bg-[var(--sc-bg-elevated)]/50 rounded-lg space-y-2">
          <div className="grid grid-cols-2 gap-2">
            <input value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} placeholder="Rule name" required className="px-2 py-1.5 text-xs bg-[var(--sc-bg-surface)] border border-[var(--sc-border)] rounded text-[var(--sc-text-primary)] placeholder:text-[var(--sc-text-muted)]" />
            <input value={form.priority} onChange={e => setForm(f => ({ ...f, priority: Number(e.target.value) }))} type="number" placeholder="Priority" className="px-2 py-1.5 text-xs bg-[var(--sc-bg-surface)] border border-[var(--sc-border)] rounded text-[var(--sc-text-primary)]" />
          </div>
          <div className="grid grid-cols-3 gap-2">
            <select value={form.condition_type} onChange={e => setForm(f => ({ ...f, condition_type: e.target.value }))} className="px-2 py-1.5 text-xs bg-[var(--sc-bg-surface)] border border-[var(--sc-border)] rounded text-[var(--sc-text-primary)]">
              <option value="regex">Regex</option>
              <option value="source">Source</option>
              <option value="keyword">Keyword</option>
            </select>
            <input value={form.condition_value} onChange={e => setForm(f => ({ ...f, condition_value: e.target.value }))} placeholder="Condition value" required className="px-2 py-1.5 text-xs bg-[var(--sc-bg-surface)] border border-[var(--sc-border)] rounded text-[var(--sc-text-primary)] placeholder:text-[var(--sc-text-muted)]" />
            <select value={form.action} onChange={e => setForm(f => ({ ...f, action: e.target.value as 'block' | 'allow' | 'quarantine' }))} className="px-2 py-1.5 text-xs bg-[var(--sc-bg-surface)] border border-[var(--sc-border)] rounded text-[var(--sc-text-primary)]">
              <option value="block">Block</option>
              <option value="quarantine">Quarantine</option>
              <option value="allow">Allow</option>
            </select>
          </div>
          <div className="flex gap-2">
            <button type="submit" disabled={createRule.isPending} className="px-3 py-1 text-xs bg-[var(--sc-cyan)] text-[var(--sc-text-primary)] rounded hover:bg-[var(--sc-cyan)]/80 disabled:opacity-50">
              {createRule.isPending ? 'Creating...' : 'Create'}
            </button>
            <button type="button" onClick={() => setShowForm(false)} className="px-3 py-1 text-xs text-[var(--sc-text-secondary)] hover:text-[var(--sc-text-primary)]">Cancel</button>
          </div>
          {createRule.error && <p className="text-xs text-[var(--sc-coral)]">{(createRule.error as Error).message}</p>}
        </form>
      )}

      {isError ? (
        <CardError inline className="py-4" message="Couldn't load firewall rules" onRetry={() => refetch()} />
      ) : isLoading ? (
        <div className="text-xs text-[var(--sc-text-muted)] py-4 text-center">Loading rules...</div>
      ) : rules.length === 0 ? (
        <div className="text-xs text-[var(--sc-text-muted)] py-4 text-center">No custom rules yet. Click &quot;Add Rule&quot; to create one.</div>
      ) : (
        <div className="space-y-1">
          {rules.map(rule => (
            <div key={rule.id} className="flex items-center gap-3 px-3 py-2 bg-[var(--sc-bg-elevated)]/30 rounded text-xs">
              <span className="text-[var(--sc-text-secondary)] w-6 text-right">{rule.priority}</span>
              <span className="text-[var(--sc-text-primary)] flex-1">{rule.name}</span>
              <code className="text-[var(--sc-text-muted)] text-[10px] max-w-[120px] truncate">{rule.condition_value}</code>
              <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium ${
                rule.action === 'block' ? 'bg-[var(--sc-coral)]/20 text-[var(--sc-coral)]' :
                rule.action === 'quarantine' ? 'bg-[var(--sc-amber)]/20 text-[var(--sc-amber)]' :
                'bg-[var(--sc-cyan)]/20 text-[var(--sc-cyan)]'
              }`}>{rule.action}</span>
              <button
                onClick={() => updateRule.mutate({ id: rule.id, enabled: rule.enabled ? 0 : 1 })}
                className="text-[var(--sc-text-muted)] hover:text-[var(--sc-text-primary)]"
                title={rule.enabled ? 'Disable' : 'Enable'}
              >
                {rule.enabled ? <ToggleRight size={14} className="text-[var(--sc-cyan)]" /> : <ToggleLeft size={14} />}
              </button>
              <button onClick={() => deleteRule.mutate(rule.id)} className="text-[var(--sc-text-muted)] hover:text-[var(--sc-coral)]">
                <Trash2 size={12} />
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function PreviewContent() {
  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2">
        <Shield size={16} className="text-[var(--sc-cyan)]" />
        <h3 className="text-sm font-medium text-[var(--sc-text-primary)]">Custom Firewall Rules</h3>
        <span className="text-xs text-[var(--sc-text-muted)]">0/25</span>
      </div>
      <div className="space-y-1">
        {PREVIEW_FIREWALL_RULES.map(rule => (
          <div key={rule.id} className="flex items-center gap-3 px-3 py-2 bg-[var(--sc-bg-elevated)]/30 rounded text-xs">
            <span className="text-[var(--sc-text-secondary)] w-6 text-right">{rule.priority}</span>
            <span className="text-[var(--sc-text-primary)] flex-1">{rule.name}</span>
            <code className="text-[var(--sc-text-muted)] text-[10px] max-w-[120px] truncate">{rule.condition_value}</code>
            <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium ${
              rule.action === 'block' ? 'bg-[var(--sc-coral)]/20 text-[var(--sc-coral)]' :
              rule.action === 'quarantine' ? 'bg-[var(--sc-amber)]/20 text-[var(--sc-amber)]' :
              'bg-[var(--sc-cyan)]/20 text-[var(--sc-cyan)]'
            }`}>{rule.action}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

export function CustomFirewallRulesPanel() {
  return (
    <div className="bg-[var(--sc-bg-surface)]/50 border border-[var(--sc-border)] rounded-xl p-4">
      <RulesTable />
    </div>
  );
}
