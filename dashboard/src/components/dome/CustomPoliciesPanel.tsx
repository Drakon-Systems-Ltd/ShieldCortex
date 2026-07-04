'use client';

import { useState } from 'react';
import { Shield, Plus, Trash2, Check } from 'lucide-react';
import { useCustomPolicies, useCreatePolicy, useDeletePolicy, useActivatePolicy } from '@/hooks/useCustomPolicies';
import { PREVIEW_POLICIES } from '@/lib/pro-previews';

function PoliciesTable() {
  const { data, isLoading, isLocked } = useCustomPolicies();
  const createPolicy = useCreatePolicy();
  const deletePolicy = useDeletePolicy();
  const activatePolicy = useActivatePolicy();
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState({ name: '', description: '' });

  const policies = data?.policies ?? [];

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    createPolicy.mutate({ name: form.name, description: form.description, config: {} }, {
      onSuccess: () => {
        setShowForm(false);
        setForm({ name: '', description: '' });
      },
    });
  };

  if (isLocked) return <PreviewContent />;

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Shield size={16} className="text-[var(--sc-coral)]" />
          <h3 className="text-sm font-medium text-[var(--sc-text-primary)]">Custom Iron Dome Policies</h3>
          <span className="text-xs text-[var(--sc-text-muted)]">{policies.length}/10</span>
        </div>
        <button onClick={() => setShowForm(!showForm)} className="flex items-center gap-1 px-2 py-1 text-xs bg-[var(--sc-coral)]/20 text-[var(--sc-coral)] rounded hover:bg-[var(--sc-coral)]/30 transition-colors">
          <Plus size={12} /> Create Policy
        </button>
      </div>

      {showForm && (
        <form onSubmit={handleSubmit} className="p-3 bg-[var(--sc-bg-elevated)]/50 rounded-lg space-y-2">
          <input value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} placeholder="Policy name" required className="w-full px-2 py-1.5 text-xs bg-[var(--sc-bg-surface)] border border-[var(--sc-border)] rounded text-[var(--sc-text-primary)] placeholder:text-[var(--sc-text-muted)]" />
          <textarea value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))} placeholder="Description" rows={2} className="w-full px-2 py-1.5 text-xs bg-[var(--sc-bg-surface)] border border-[var(--sc-border)] rounded text-[var(--sc-text-primary)] placeholder:text-[var(--sc-text-muted)] resize-none" />
          <div className="flex gap-2">
            <button type="submit" disabled={createPolicy.isPending} className="px-3 py-1 text-xs bg-[var(--sc-coral)] text-[var(--sc-text-primary)] rounded hover:bg-[var(--sc-coral)] disabled:opacity-50">
              {createPolicy.isPending ? 'Creating...' : 'Create'}
            </button>
            <button type="button" onClick={() => setShowForm(false)} className="px-3 py-1 text-xs text-[var(--sc-text-secondary)] hover:text-[var(--sc-text-primary)]">Cancel</button>
          </div>
          {createPolicy.error && <p className="text-xs text-[var(--sc-coral)]">{(createPolicy.error as Error).message}</p>}
        </form>
      )}

      {isLoading ? (
        <div className="text-xs text-[var(--sc-text-muted)] py-4 text-center">Loading policies...</div>
      ) : policies.length === 0 ? (
        <div className="text-xs text-[var(--sc-text-muted)] py-4 text-center">No custom policies yet. Click &quot;Create Policy&quot; to get started.</div>
      ) : (
        <div className="space-y-1">
          {policies.map(policy => (
            <div key={policy.id} className="flex items-center gap-3 px-3 py-2 bg-[var(--sc-bg-elevated)]/30 rounded text-xs">
              <div className="flex-1">
                <div className="flex items-center gap-2">
                  <span className="text-[var(--sc-text-primary)] font-medium">{policy.name}</span>
                  {policy.is_active === 1 && (
                    <span className="px-1.5 py-0.5 rounded bg-[var(--sc-cyan)]/20 text-[var(--sc-cyan)] text-[10px] font-medium">Active</span>
                  )}
                </div>
                {policy.description && <p className="text-[var(--sc-text-muted)] text-[10px] mt-0.5">{policy.description}</p>}
              </div>
              {!policy.is_active && (
                <button
                  onClick={() => activatePolicy.mutate(policy.id)}
                  className="flex items-center gap-1 px-2 py-1 text-[10px] bg-[var(--sc-cyan)]/20 text-[var(--sc-cyan)] rounded hover:bg-[var(--sc-cyan)]/30"
                  title="Set active"
                >
                  <Check size={10} /> Activate
                </button>
              )}
              <button onClick={() => deletePolicy.mutate(policy.id)} className="text-[var(--sc-text-muted)] hover:text-[var(--sc-coral)]">
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
        <Shield size={16} className="text-[var(--sc-coral)]" />
        <h3 className="text-sm font-medium text-[var(--sc-text-primary)]">Custom Iron Dome Policies</h3>
        <span className="text-xs text-[var(--sc-text-muted)]">0/10</span>
      </div>
      <div className="space-y-1">
        {PREVIEW_POLICIES.map(policy => (
          <div key={policy.id} className="flex items-center gap-3 px-3 py-2 bg-[var(--sc-bg-elevated)]/30 rounded text-xs">
            <div className="flex-1">
              <div className="flex items-center gap-2">
                <span className="text-[var(--sc-text-primary)] font-medium">{policy.name}</span>
                {policy.is_active && (
                  <span className="px-1.5 py-0.5 rounded bg-[var(--sc-cyan)]/20 text-[var(--sc-cyan)] text-[10px] font-medium">Active</span>
                )}
              </div>
              <p className="text-[var(--sc-text-muted)] text-[10px] mt-0.5">{policy.description}</p>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

export function CustomPoliciesPanel() {
  return (
    <div className="bg-[var(--sc-bg-surface)]/50 border border-[var(--sc-border)] rounded-xl p-4">
      <PoliciesTable />
    </div>
  );
}
