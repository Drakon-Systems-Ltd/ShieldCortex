'use client';

import { useState } from 'react';
import { Zap, Plus, Trash2, Play } from 'lucide-react';
import { ProFeatureGate } from '../shield/ProFeatureGate';
import { useCustomPatterns, useCreatePattern, useDeletePattern, useTestPattern } from '@/hooks/useCustomPatterns';
import { PREVIEW_PATTERNS } from '@/lib/pro-previews';

function PatternsTable() {
  const { data, isLoading, isLocked } = useCustomPatterns();
  const createPattern = useCreatePattern();
  const deletePattern = useDeletePattern();
  const testPattern = useTestPattern();
  const [showForm, setShowForm] = useState(false);
  const [testInput, setTestInput] = useState<{ id: number; text: string } | null>(null);
  const [form, setForm] = useState<{ name: string; category: string; severity: 'critical' | 'high' | 'medium' | 'low'; regex: string; description: string }>({ name: '', category: 'custom', severity: 'medium', regex: '', description: '' });

  const patterns = data?.patterns ?? [];

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    createPattern.mutate(form, {
      onSuccess: () => {
        setShowForm(false);
        setForm({ name: '', category: 'custom', severity: 'medium', regex: '', description: '' });
      },
    });
  };

  // Validate regex in real-time
  let regexValid = true;
  let regexError = '';
  if (form.regex) {
    try { new RegExp(form.regex); } catch (e) { regexValid = false; regexError = (e as Error).message; }
  }

  if (isLocked) return <PreviewContent />;

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Zap size={16} className="text-[var(--sc-coral)]" />
          <h3 className="text-sm font-medium text-[var(--sc-text-primary)]">Custom Injection Patterns</h3>
          <span className="text-xs text-[var(--sc-text-muted)]">{patterns.length}/50</span>
        </div>
        <button onClick={() => setShowForm(!showForm)} className="flex items-center gap-1 px-2 py-1 text-xs bg-[var(--sc-coral)]/20 text-[var(--sc-coral)] rounded hover:bg-[var(--sc-coral)]/30 transition-colors">
          <Plus size={12} /> Add Pattern
        </button>
      </div>

      {showForm && (
        <form onSubmit={handleSubmit} className="p-3 bg-[var(--sc-bg-elevated)] rounded-lg space-y-2">
          <div className="grid grid-cols-2 gap-2">
            <input value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} placeholder="Pattern name" required className="px-2 py-1.5 text-xs bg-[var(--sc-bg-surface)] border border-[var(--sc-border)] rounded text-[var(--sc-text-primary)] placeholder:text-[var(--sc-text-muted)]" />
            <select value={form.severity} onChange={e => setForm(f => ({ ...f, severity: e.target.value as 'critical' | 'high' | 'medium' | 'low' }))} className="px-2 py-1.5 text-xs bg-[var(--sc-bg-surface)] border border-[var(--sc-border)] rounded text-[var(--sc-text-primary)]">
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>
          <div className="relative">
            <input value={form.regex} onChange={e => setForm(f => ({ ...f, regex: e.target.value }))} placeholder="Regex pattern" required className={`w-full px-2 py-1.5 text-xs bg-[var(--sc-bg-surface)] border rounded text-[var(--sc-text-primary)] font-mono placeholder:text-[var(--sc-text-muted)] ${regexValid ? 'border-[var(--sc-border)]' : 'border-[var(--sc-coral)]'}`} />
            {!regexValid && <p className="text-[10px] text-[var(--sc-coral)] mt-0.5">{regexError}</p>}
          </div>
          <input value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))} placeholder="Description (optional)" className="w-full px-2 py-1.5 text-xs bg-[var(--sc-bg-surface)] border border-[var(--sc-border)] rounded text-[var(--sc-text-primary)] placeholder:text-[var(--sc-text-muted)]" />
          <div className="flex gap-2">
            <button type="submit" disabled={createPattern.isPending || !regexValid} className="px-3 py-1 text-xs bg-[var(--sc-coral)] text-[var(--sc-text-primary)] rounded hover:bg-[var(--sc-coral)] disabled:opacity-50">
              {createPattern.isPending ? 'Creating...' : 'Create'}
            </button>
            <button type="button" onClick={() => setShowForm(false)} className="px-3 py-1 text-xs text-[var(--sc-text-secondary)] hover:text-[var(--sc-text-primary)]">Cancel</button>
          </div>
          {createPattern.error && <p className="text-xs text-[var(--sc-coral)]">{(createPattern.error as Error).message}</p>}
        </form>
      )}

      {isLoading ? (
        <div className="text-xs text-[var(--sc-text-muted)] py-4 text-center">Loading patterns...</div>
      ) : patterns.length === 0 ? (
        <div className="text-xs text-[var(--sc-text-muted)] py-4 text-center">No custom patterns yet. Click &quot;Add Pattern&quot; to create one.</div>
      ) : (
        <div className="space-y-1">
          {patterns.map(pattern => (
            <div key={pattern.id} className="px-3 py-2 bg-[var(--sc-bg-elevated)] rounded text-xs space-y-1">
              <div className="flex items-center gap-2">
                <span className="text-[var(--sc-text-primary)] flex-1 font-medium">{pattern.name}</span>
                <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium ${
                  pattern.severity === 'critical' ? 'bg-[var(--sc-coral)]/20 text-[var(--sc-coral)]' :
                  pattern.severity === 'high' ? 'bg-[var(--sc-coral)]/20 text-[var(--sc-coral)]' :
                  pattern.severity === 'medium' ? 'bg-[var(--sc-amber)]/20 text-[var(--sc-amber)]' :
                  'bg-[var(--sc-bg-elevated)]/20 text-[var(--sc-text-secondary)]'
                }`}>{pattern.severity}</span>
                <button
                  onClick={() => setTestInput(testInput?.id === pattern.id ? null : { id: pattern.id, text: '' })}
                  className="text-[var(--sc-text-muted)] hover:text-[var(--sc-cyan)]" title="Test pattern"
                >
                  <Play size={12} />
                </button>
                <button onClick={() => deletePattern.mutate(pattern.id)} className="text-[var(--sc-text-muted)] hover:text-[var(--sc-coral)]">
                  <Trash2 size={12} />
                </button>
              </div>
              <code className="text-[var(--sc-text-muted)] text-[10px] block truncate">{pattern.regex}</code>
              {testInput?.id === pattern.id && (
                <div className="flex gap-2 mt-1">
                  <input
                    value={testInput.text}
                    onChange={e => setTestInput({ id: pattern.id, text: e.target.value })}
                    placeholder="Test text..."
                    className="flex-1 px-2 py-1 text-[10px] bg-[var(--sc-bg-surface)] border border-[var(--sc-border)] rounded text-[var(--sc-text-primary)] placeholder:text-[var(--sc-text-muted)]"
                  />
                  <button
                    onClick={() => testPattern.mutate({ id: pattern.id, text: testInput.text })}
                    disabled={!testInput.text}
                    className="px-2 py-1 text-[10px] bg-[var(--sc-cyan)]/20 text-[var(--sc-cyan)] rounded hover:bg-[var(--sc-cyan)]/30 disabled:opacity-50"
                  >
                    Test
                  </button>
                  {testPattern.data && <span className="text-[10px] text-[var(--sc-text-secondary)] self-center">{testPattern.data.count} matches</span>}
                </div>
              )}
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
        <Zap size={16} className="text-[var(--sc-coral)]" />
        <h3 className="text-sm font-medium text-[var(--sc-text-primary)]">Custom Injection Patterns</h3>
        <span className="text-xs text-[var(--sc-text-muted)]">0/50</span>
      </div>
      <div className="space-y-1">
        {PREVIEW_PATTERNS.map(pattern => (
          <div key={pattern.id} className="px-3 py-2 bg-[var(--sc-bg-elevated)] rounded text-xs space-y-1">
            <div className="flex items-center gap-2">
              <span className="text-[var(--sc-text-primary)] flex-1 font-medium">{pattern.name}</span>
              <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium ${
                pattern.severity === 'critical' ? 'bg-[var(--sc-coral)]/20 text-[var(--sc-coral)]' :
                pattern.severity === 'high' ? 'bg-[var(--sc-coral)]/20 text-[var(--sc-coral)]' :
                'bg-[var(--sc-amber)]/20 text-[var(--sc-amber)]'
              }`}>{pattern.severity}</span>
            </div>
            <code className="text-[var(--sc-text-muted)] text-[10px] block truncate">{pattern.regex}</code>
          </div>
        ))}
      </div>
    </div>
  );
}

export function CustomPatternsPanel() {
  return (
    <div className="bg-[var(--sc-bg-surface)] border border-[var(--sc-border)] rounded-xl p-4">
      <ProFeatureGate feature="custom_injection_patterns" label="Define up to 50 custom regex patterns for detecting domain-specific threats.">
        <PatternsTable />
      </ProFeatureGate>
    </div>
  );
}
