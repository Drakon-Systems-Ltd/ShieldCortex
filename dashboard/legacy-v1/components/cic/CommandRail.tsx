'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import { runCommand } from '@/lib/commands/registry';
import { useCommandContext } from './useCommandContext';

interface LogLine {
  kind: 'in' | 'out' | 'err';
  text: string;
}

const LINE_CLASS: Record<LogLine['kind'], string> = {
  in: 'text-[var(--cic-text-dim)]',
  out: 'text-[var(--cic-text)]',
  err: 'text-[var(--cic-coral)]',
};

/**
 * The CIC command rail — a REAL command line. Input → runCommand(registry) →
 * streamed console log. ⌘K focuses it; ↑/↓ walks history; a blinking block
 * cursor anchors the terminal identity. Drives actual API/router actions via
 * {@link useCommandContext}.
 */
export function CommandRail() {
  const ctx = useCommandContext();
  const [input, setInput] = useState('');
  const [log, setLog] = useState<LogLine[]>([]);
  const [history, setHistory] = useState<string[]>([]);
  const [histIdx, setHistIdx] = useState(-1);
  const [running, setRunning] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const logRef = useRef<HTMLDivElement>(null);

  // ⌘K / Ctrl-K focuses the rail from anywhere.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        inputRef.current?.focus();
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  useEffect(() => {
    const el = logRef.current;
    if (el && typeof el.scrollTo === 'function') el.scrollTo({ top: el.scrollHeight });
  }, [log]);

  const submit = useCallback(async () => {
    const cmd = input.trim();
    if (!cmd || running) return;
    setLog((l) => [...l, { kind: 'in', text: cmd }]);
    setHistory((h) => [...h, cmd]);
    setHistIdx(-1);
    setInput('');
    setRunning(true);
    const res = await runCommand(cmd, ctx);
    setLog((l) => [...l, ...res.lines.map((text): LogLine => ({ kind: res.ok ? 'out' : 'err', text }))]);
    setRunning(false);
  }, [input, running, ctx]);

  const onKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      void submit();
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      if (history.length === 0) return;
      const next = histIdx === -1 ? history.length - 1 : Math.max(0, histIdx - 1);
      setHistIdx(next);
      setInput(history[next]);
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      if (histIdx === -1) return;
      const next = histIdx + 1;
      if (next >= history.length) {
        setHistIdx(-1);
        setInput('');
      } else {
        setHistIdx(next);
        setInput(history[next]);
      }
    }
  };

  return (
    <div className="border-t border-[var(--cic-border)] bg-[var(--cic-surface)]/80 font-mono text-sm">
      {log.length > 0 && (
        <div ref={logRef} className="max-h-40 overflow-y-auto px-4 py-2 leading-relaxed">
          {log.map((l, i) => (
            <div key={i} className={`whitespace-pre-wrap ${LINE_CLASS[l.kind]}`}>
              {l.kind === 'in' ? (
                <>
                  <span className="text-[var(--cic-cyan)]">sc ▸ </span>
                  {l.text}
                </>
              ) : (
                l.text
              )}
            </div>
          ))}
        </div>
      )}
      <div className="flex items-center gap-2 px-4 py-2.5">
        <span className="cic-bloom shrink-0 text-[var(--cic-cyan)]">sc&nbsp;▸</span>
        <input
          ref={inputRef}
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={onKeyDown}
          spellCheck={false}
          autoComplete="off"
          aria-label="command line"
          placeholder="recall · scan · forget · consolidate · go · theme · help"
          className="flex-1 bg-transparent text-[var(--cic-text)] outline-none placeholder:text-[var(--cic-text-faint)]"
        />
        {!input && <span className="cli-cursor text-[var(--cic-cyan)]" />}
        <kbd className="shrink-0 rounded border border-[var(--cic-border)] px-1.5 text-xs text-[var(--cic-text-faint)]">
          ⌘K
        </kbd>
      </div>
    </div>
  );
}
