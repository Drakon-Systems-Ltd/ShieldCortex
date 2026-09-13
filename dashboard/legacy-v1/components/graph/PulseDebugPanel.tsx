'use client';

import { useState } from 'react';
import type { PulseDriver } from './constellation/pulse';

/**
 * Dev-only overlay for poking the PulseDriver by hand. Hidden unless
 * `localStorage.SHIELDCORTEX_DEBUG_PULSE === '1'`. Use it during
 * Living-Constellation development to verify Layer A (created spikes) and
 * Layer B (accessed glows) decay correctly for a known entity id.
 *
 * Hook order is important: useState must run on every render, so the gating
 * early-returns live below it (rules-of-hooks).
 */
export function PulseDebugPanel({ driver }: { driver: PulseDriver | null }) {
  const [id, setId] = useState('');
  if (typeof window === 'undefined') return null;
  if (window.localStorage.getItem('SHIELDCORTEX_DEBUG_PULSE') !== '1') return null;
  if (!driver) return null;
  return (
    <div
      style={{
        position: 'absolute',
        bottom: 8,
        right: 8,
        padding: 8,
        background: '#0a0d14cc',
        color: '#e2e8f0',
        fontSize: 12,
        border: '1px solid #1e293b',
        zIndex: 10,
      }}
    >
      <div style={{ marginBottom: 4, opacity: 0.6 }}>pulse debug</div>
      <input
        value={id}
        onChange={(e) => setId(e.target.value)}
        placeholder="entity id"
        style={{
          width: 140,
          background: '#06070d',
          color: '#e2e8f0',
          border: '1px solid #1e293b',
          padding: '2px 4px',
        }}
      />
      <div style={{ display: 'flex', gap: 4, marginTop: 4 }}>
        <button onClick={() => driver.dispatch({ type: 'memory.created', entityId: id })}>created</button>
        <button onClick={() => driver.dispatch({ type: 'memory.accessed', entityId: id })}>accessed</button>
      </div>
    </div>
  );
}
