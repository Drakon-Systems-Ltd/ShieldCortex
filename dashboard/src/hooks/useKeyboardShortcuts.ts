'use client';

import { useEffect, useState, useCallback, useRef } from 'react';

interface KeyboardShortcutOptions {
  onFocusSearch: () => void;
  onClosePanel: () => void;
  onNavigate: (view: string) => void;
  onToggleHelp: () => void;
}

/**
 * Global keyboard shortcuts for power-user navigation.
 *
 * Shortcuts:
 *   /         — Focus search input
 *   Escape    — Close detail panels, blur search
 *   g then s  — Go to Shield view
 *   g then m  — Go to Memories view
 *   g then t  — Go to Timeline view
 *   g then g  — Go to Graph view
 *   g then a  — Go to Audit view
 *   g then b  — Go to Brain view
 *   g then d  — Go to Dome view
 *   ?         — Toggle shortcuts help overlay
 */
export function useKeyboardShortcuts(options: KeyboardShortcutOptions): {
  showHelp: boolean;
  setShowHelp: (show: boolean) => void;
} {
  const { onFocusSearch, onClosePanel, onNavigate, onToggleHelp } = options;
  const [showHelp, setShowHelp] = useState(false);

  // Chord state: track last key pressed and its timestamp
  const chordRef = useRef<{ key: string; time: number } | null>(null);

  const handleKeyDown = useCallback(
    (event: KeyboardEvent) => {
      const target = event.target as HTMLElement;
      const tagName = target.tagName.toLowerCase();
      const isEditable =
        tagName === 'input' ||
        tagName === 'textarea' ||
        tagName === 'select' ||
        target.isContentEditable;

      // Escape always works, even in inputs
      if (event.key === 'Escape') {
        if (showHelp) {
          setShowHelp(false);
          return;
        }
        // Blur any focused input first, then close panels
        if (isEditable) {
          (target as HTMLElement).blur();
          return;
        }
        onClosePanel();
        return;
      }

      // All other shortcuts are ignored when typing in an input
      if (isEditable) return;

      // "/" — focus search
      if (event.key === '/') {
        event.preventDefault();
        onFocusSearch();
        return;
      }

      // "?" — toggle help overlay
      if (event.key === '?') {
        event.preventDefault();
        setShowHelp((prev) => !prev);
        onToggleHelp();
        return;
      }

      // Chord detection: g + <key>
      const now = Date.now();
      const chord = chordRef.current;

      if (event.key === 'g') {
        // If we already have a pending 'g', this is "g then g" → Graph
        if (chord && chord.key === 'g' && now - chord.time < 500) {
          chordRef.current = null;
          onNavigate('graph');
          return;
        }
        // Start a new chord
        chordRef.current = { key: 'g', time: now };
        return;
      }

      // Check if this is the second key of a g-chord
      if (chord && chord.key === 'g' && now - chord.time < 500) {
        chordRef.current = null;

        const navMap: Record<string, string> = {
          s: 'shield',
          m: 'memories',
          t: 'timeline',
          a: 'audit',
          b: 'brain',
          d: 'dome',
        };

        const view = navMap[event.key];
        if (view) {
          onNavigate(view);
          return;
        }
      }

      // Any other key clears the chord
      chordRef.current = null;
    },
    [onFocusSearch, onClosePanel, onNavigate, onToggleHelp, showHelp]
  );

  useEffect(() => {
    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [handleKeyDown]);

  return { showHelp, setShowHelp };
}
