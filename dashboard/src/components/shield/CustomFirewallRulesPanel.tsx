'use client';

import { useState } from 'react';
import { Shield, Plus, Trash2, ToggleLeft, ToggleRight } from 'lucide-react';
import { ProFeatureGate } from './ProFeatureGate';
import { useFirewallRules, useCreateFirewallRule, useUpdateFirewallRule, useDeleteFirewallRule } from '@/hooks/useFirewallRules';
import { PREVIEW_FIREWALL_RULES } from '@/lib/pro-previews';

function RulesTable() {
  const { data, isLoading, isLocked } = useFirewallRules();
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
          <Shield size={16} className="text-cyan-400" />
          <h3 className="text-sm font-medium text-slate-200">Custom Firewall Rules</h3>
          <span className="text-xs text-slate-500">{rules.length}/25</span>
        </div>
        <button
          onClick={() => setShowForm(!showForm)}
          className="flex items-center gap-1 px-2 py-1 text-xs bg-cyan-600/20 text-cyan-400 rounded hover:bg-cyan-600/30 transition-colors"
        >
          <Plus size={12} /> Add Rule
        </button>
      </div>

      {showForm && (
        <form onSubmit={handleSubmit} className="p-3 bg-slate-800/50 rounded-lg space-y-2">
          <div className="grid grid-cols-2 gap-2">
            <input value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} placeholder="Rule name" required className="px-2 py-1.5 text-xs bg-slate-900 border border-slate-700 rounded text-slate-200 placeholder:text-slate-600" />
            <input value={form.priority} onChange={e => setForm(f => ({ ...f, priority: Number(e.target.value) }))} type="number" placeholder="Priority" className="px-2 py-1.5 text-xs bg-slate-900 border border-slate-700 rounded text-slate-200" />
          </div>
          <div className="grid grid-cols-3 gap-2">
            <select value={form.condition_type} onChange={e => setForm(f => ({ ...f, condition_type: e.target.value }))} className="px-2 py-1.5 text-xs bg-slate-900 border border-slate-700 rounded text-slate-200">
              <option value="regex">Regex</option>
              <option value="source">Source</option>
              <option value="keyword">Keyword</option>
            </select>
            <input value={form.condition_value} onChange={e => setForm(f => ({ ...f, condition_value: e.target.value }))} placeholder="Condition value" required className="px-2 py-1.5 text-xs bg-slate-900 border border-slate-700 rounded text-slate-200 placeholder:text-slate-600" />
            <select value={form.action} onChange={e => setForm(f => ({ ...f, action: e.target.value as 'block' | 'allow' | 'quarantine' }))} className="px-2 py-1.5 text-xs bg-slate-900 border border-slate-700 rounded text-slate-200">
              <option value="block">Block</option>
              <option value="quarantine">Quarantine</option>
              <option value="allow">Allow</option>
            </select>
          </div>
          <div className="flex gap-2">
            <button type="submit" disabled={createRule.isPending} className="px-3 py-1 text-xs bg-cyan-600 text-white rounded hover:bg-cyan-500 disabled:opacity-50">
              {createRule.isPending ? 'Creating...' : 'Create'}
            </button>
            <button type="button" onClick={() => setShowForm(false)} className="px-3 py-1 text-xs text-slate-400 hover:text-slate-200">Cancel</button>
          </div>
          {createRule.error && <p className="text-xs text-red-400">{(createRule.error as Error).message}</p>}
        </form>
      )}

      {isLoading ? (
        <div className="text-xs text-slate-500 py-4 text-center">Loading rules...</div>
      ) : rules.length === 0 ? (
        <div className="text-xs text-slate-500 py-4 text-center">No custom rules yet. Click "Add Rule" to create one.</div>
      ) : (
        <div className="space-y-1">
          {rules.map(rule => (
            <div key={rule.id} className="flex items-center gap-3 px-3 py-2 bg-slate-800/30 rounded text-xs">
              <span className="text-slate-400 w-6 text-right">{rule.priority}</span>
              <span className="text-slate-200 flex-1">{rule.name}</span>
              <code className="text-slate-500 text-[10px] max-w-[120px] truncate">{rule.condition_value}</code>
              <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium ${
                rule.action === 'block' ? 'bg-red-500/20 text-red-400' :
                rule.action === 'quarantine' ? 'bg-yellow-500/20 text-yellow-400' :
                'bg-green-500/20 text-green-400'
              }`}>{rule.action}</span>
              <button
                onClick={() => updateRule.mutate({ id: rule.id, enabled: rule.enabled ? 0 : 1 })}
                className="text-slate-500 hover:text-slate-300"
                title={rule.enabled ? 'Disable' : 'Enable'}
              >
                {rule.enabled ? <ToggleRight size={14} className="text-cyan-400" /> : <ToggleLeft size={14} />}
              </button>
              <button onClick={() => deleteRule.mutate(rule.id)} className="text-slate-500 hover:text-red-400">
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
        <Shield size={16} className="text-cyan-400" />
        <h3 className="text-sm font-medium text-slate-200">Custom Firewall Rules</h3>
        <span className="text-xs text-slate-500">0/25</span>
      </div>
      <div className="space-y-1">
        {PREVIEW_FIREWALL_RULES.map(rule => (
          <div key={rule.id} className="flex items-center gap-3 px-3 py-2 bg-slate-800/30 rounded text-xs">
            <span className="text-slate-400 w-6 text-right">{rule.priority}</span>
            <span className="text-slate-200 flex-1">{rule.name}</span>
            <code className="text-slate-500 text-[10px] max-w-[120px] truncate">{rule.condition_value}</code>
            <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium ${
              rule.action === 'block' ? 'bg-red-500/20 text-red-400' :
              rule.action === 'quarantine' ? 'bg-yellow-500/20 text-yellow-400' :
              'bg-green-500/20 text-green-400'
            }`}>{rule.action}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

export function CustomFirewallRulesPanel() {
  return (
    <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-4">
      <ProFeatureGate feature="custom_firewall_rules" label="Add custom rules to control what gets blocked, allowed, or quarantined.">
        <RulesTable />
      </ProFeatureGate>
    </div>
  );
}
