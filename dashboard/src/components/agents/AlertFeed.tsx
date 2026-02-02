'use client';

import { useState, useEffect, useRef, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Bell } from 'lucide-react';

interface DefenceAlert {
  id: number;
  source_type: string;
  source_identifier: string;
  firewall_result: string;
  trust_score: number;
  reason: string | null;
  timestamp: string;
}

interface Props {
  agentFilter?: string;
}

const WS_URL = process.env.NEXT_PUBLIC_WS_URL || 'ws://localhost:3001/ws/events';

export function AlertFeed({ agentFilter }: Props) {
  const [alerts, setAlerts] = useState<DefenceAlert[]>([]);
  const idCounter = useRef(0);
  const wsRef = useRef<WebSocket | null>(null);

  const handleMessage = useCallback((event: MessageEvent) => {
    try {
      const msg = JSON.parse(event.data);
      if (msg.type !== 'defence_event') return;

      const data = msg.data as DefenceAlert;
      if (agentFilter && data.source_identifier !== agentFilter) return;

      setAlerts((prev) => [
        { ...data, id: ++idCounter.current },
        ...prev,
      ].slice(0, 50));
    } catch { /* ignore parse errors */ }
  }, [agentFilter]);

  useEffect(() => {
    // Connect to existing WebSocket for defence events
    try {
      const ws = new WebSocket(WS_URL);
      wsRef.current = ws;
      ws.onmessage = handleMessage;
      ws.onerror = () => {}; // Suppress — main WS hook handles reconnection
      return () => {
        ws.close();
        wsRef.current = null;
      };
    } catch {
      return;
    }
  }, [handleMessage]);

  if (alerts.length === 0) {
    return (
      <div className="flex items-center gap-2 text-slate-500 text-xs py-2">
        <Bell size={12} />
        <span>Listening for defence events...</span>
      </div>
    );
  }

  return (
    <div className="space-y-1 max-h-48 overflow-y-auto">
      <AnimatePresence initial={false}>
        {alerts.map((alert) => (
          <motion.div
            key={alert.id}
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0 }}
            className={`px-2 py-1.5 rounded border text-xs ${
              alert.firewall_result === 'BLOCK'
                ? 'bg-red-500/5 border-red-500/20'
                : 'bg-yellow-500/5 border-yellow-500/20'
            }`}
          >
            <div className="flex items-center justify-between">
              <span className={`font-medium ${
                alert.firewall_result === 'BLOCK' ? 'text-red-400' : 'text-yellow-400'
              }`}>
                {alert.firewall_result}
              </span>
              <span className="text-[10px] text-slate-500">
                {new Date(alert.timestamp).toLocaleTimeString()}
              </span>
            </div>
            <p className="text-slate-400 text-[11px] truncate mt-0.5">
              {alert.source_identifier} — {alert.reason ?? 'No reason'}
            </p>
          </motion.div>
        ))}
      </AnimatePresence>
    </div>
  );
}
