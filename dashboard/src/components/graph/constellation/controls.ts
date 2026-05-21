import type { ForceGraphMethods, NodeObject } from 'react-force-graph-2d';

/**
 * Wires drag-to-pin and zoom polish onto a react-force-graph-2d instance.
 *
 * - onNodeDragEnd: sets node.fx/fy = current x/y so the node stays where it
 *   was dropped (drag-to-pin). The legacy graph did not do this — drag-release
 *   let the simulation snap the node back, which the user reported as
 *   "drag fights the simulation."
 * - onShiftClick: releases a user-pinned node (fx = fy = null).
 *   Reading the modifier from the most recent native event is the cleanest
 *   path — react-force-graph passes through the original PointerEvent.
 *
 * Anchor click-to-orbit is handled in ConstellationGraph itself (it owns
 * selection state); this module only handles direct manipulation.
 */
export interface ControlsOpts {
  /**
   * Called when the user shift-clicks a node that is currently user-pinned.
   * Used to clear the pin glyph from React state (controls.ts itself only
   * mutates the runtime force-graph node).
   */
  onUnpin?: (nodeId: string) => void;
}

interface PinnableNode {
  id: string;
  fx?: number | null;
  fy?: number | null;
  x?: number;
  y?: number;
}

const DOUBLE_CLICK_MS = 300;

export function wireControls(
  fgRef: React.MutableRefObject<ForceGraphMethods<NodeObject<PinnableNode>> | undefined>,
  opts: ControlsOpts = {},
) {
  // Per-node last-click timestamps so onNodeClick can synthesise "node double
  // click" (the library doesn't expose onNodeDoubleClick directly).
  const lastClick = new Map<string, number>();

  return {
    handleNodeDragEnd(node: NodeObject<PinnableNode>) {
      if (node.x === undefined || node.y === undefined) return;
      node.fx = node.x;
      node.fy = node.y;
    },

    /**
     * Returns one of:
     *   'unpin'        — caller should NOT also re-anchor
     *   'double-click' — caller should NOT re-anchor; smooth-zoom on the node instead
     *   'single-click' — caller does click-to-orbit + selection
     */
    handleNodeClick(node: NodeObject<PinnableNode>, event: MouseEvent): 'unpin' | 'double-click' | 'single-click' {
      if (event.shiftKey && node.fx !== null && node.fx !== undefined) {
        // d3-force releases a pinned node when fx/fy are null. The library's
        // NodeObject type strips our PinnableNode's `| null`, so cast back.
        (node as PinnableNode).fx = null;
        (node as PinnableNode).fy = null;
        opts.onUnpin?.(String(node.id));
        lastClick.delete(String(node.id));
        return 'unpin';
      }
      const id = String(node.id);
      const now = performance.now();
      const prev = lastClick.get(id) ?? 0;
      lastClick.set(id, now);
      if (now - prev <= DOUBLE_CLICK_MS) {
        // Smooth zoom into the node, per spec §5.5. Does NOT change anchor.
        if (node.x !== undefined && node.y !== undefined) {
          fgRef.current?.centerAt(node.x, node.y, 600);
          fgRef.current?.zoom(2, 600);
        }
        lastClick.delete(id);
        return 'double-click';
      }
      return 'single-click';
    },

    handleBackgroundDoubleClick(reset: () => void) {
      reset();
      fgRef.current?.zoomToFit(600, 80);
    },
  };
}

/**
 * Wheel-debounce note (spec §5.5): react-force-graph-2d's built-in wheel zoom
 * already uses d3-zoom which is frame-throttled and momentum-smoothed — adding
 * a manual 50ms debounce on the wrapping container fights the library's own
 * smoothing. We skip the explicit debounce here and rely on d3-zoom defaults.
 * If users report jumpy zoom in the wild, the next iteration can wrap the
 * canvas in a div that throttles wheel events with `lodash.throttle(50)` —
 * the rest of the control surface does not depend on this.
 */
