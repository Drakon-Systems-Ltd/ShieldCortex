'use client';

/**
 * Memory Links - Neural Synapse Visualization
 * Renders organic, neuron-like connections between related memories
 * with flowing electrical signals and synapse endpoints
 */

import { useMemo, useState, useRef, useCallback } from 'react';
import { useFrame } from '@react-three/fiber';
import { Html, CatmullRomLine } from '@react-three/drei';
import * as THREE from 'three';
import { Memory, MemoryLink } from '@/types/memory';

interface MemoryLinksProps {
  memories: Memory[];
  links: MemoryLink[];
  memoryPositions: Map<number, { x: number; y: number; z: number }>;
  onLinkClick?: (link: MemoryLink) => void;
}

// Relationship colors — always visible (dimmed), brighter on hover
const RELATIONSHIP_STYLES: Record<string, { color: string; label: string }> = {
  references: { color: '#22d3ee', label: 'References' },  // Cyan - information flow
  extends: { color: '#34d399', label: 'Extends' },        // Green - growth
  contradicts: { color: '#f87171', label: 'Contradicts' }, // Red - conflict
  related: { color: '#a78bfa', label: 'Related' },        // Purple - association
};
const DEFAULT_RELATIONSHIP = RELATIONSHIP_STYLES.related;

// Cyan signal color matching the graph particles
const SIGNAL_COLOR = '#22d3ee';

// Bright signal pulse that travels along the neural fiber
function NeuralSignal({
  curve,
  speed = 1,
  delay = 0,
}: {
  curve: THREE.CatmullRomCurve3;
  speed?: number;
  delay?: number;
}) {
  const meshRef = useRef<THREE.Mesh>(null);
  const trailRef = useRef<THREE.Mesh>(null);
  const progressRef = useRef(delay);

  useFrame((_, delta) => {
    if (!meshRef.current) return;

    progressRef.current += delta * speed * 1.2; // Fast darting electrons
    if (progressRef.current > 1) {
      progressRef.current = 0;
    }

    // Get position along curve
    const point = curve.getPoint(progressRef.current);
    meshRef.current.position.copy(point);

    // Bright throughout, slight fade at ends
    const fadeIn = Math.min(progressRef.current * 5, 1);
    const fadeOut = Math.min((1 - progressRef.current) * 5, 1);
    const opacity = fadeIn * fadeOut;
    (meshRef.current.material as THREE.MeshBasicMaterial).opacity = opacity;

    // Halo follows the main signal
    if (trailRef.current) {
      trailRef.current.position.copy(point);
      (trailRef.current.material as THREE.MeshBasicMaterial).opacity = opacity * 0.25;
    }
  });

  return (
    <>
      {/* Tiny electron dot */}
      <mesh ref={meshRef}>
        <sphereGeometry args={[0.04, 8, 8]} />
        <meshBasicMaterial color={SIGNAL_COLOR} transparent opacity={1} />
      </mesh>
      {/* Faint glow around electron */}
      <mesh ref={trailRef}>
        <sphereGeometry args={[0.08, 6, 6]} />
        <meshBasicMaterial color={SIGNAL_COLOR} transparent opacity={0.2} depthWrite={false} />
      </mesh>
    </>
  );
}

// Single neural connection with organic curve
function NeuralConnection({
  link,
  sourcePos,
  targetPos,
  isHovered,
  onHover,
  onUnhover,
}: {
  link: MemoryLink;
  sourcePos: { x: number; y: number; z: number };
  targetPos: { x: number; y: number; z: number };
  isHovered: boolean;
  onHover: () => void;
  onUnhover: () => void;
}) {
  const style = RELATIONSHIP_STYLES[link.relationship] || DEFAULT_RELATIONSHIP;

  // Create organic curved path (like an axon)
  const { curve, points } = useMemo(() => {
    const start = new THREE.Vector3(sourcePos.x, sourcePos.y, sourcePos.z);
    const end = new THREE.Vector3(targetPos.x, targetPos.y, targetPos.z);

    // Calculate control points for organic curve
    const mid = new THREE.Vector3().lerpVectors(start, end, 0.5);
    const direction = new THREE.Vector3().subVectors(end, start);
    const length = direction.length();

    // Add perpendicular offset for curve (organic look)
    const perpendicular = new THREE.Vector3(-direction.y, direction.x, direction.z * 0.5).normalize();
    const curveAmount = length * 0.15 * (link.strength + 0.5);

    // Create control points
    const cp1 = new THREE.Vector3().lerpVectors(start, mid, 0.33);
    cp1.add(perpendicular.clone().multiplyScalar(curveAmount));

    const cp2 = new THREE.Vector3().lerpVectors(start, mid, 0.66);
    cp2.add(perpendicular.clone().multiplyScalar(curveAmount * 0.5));

    const cp3 = new THREE.Vector3().lerpVectors(mid, end, 0.33);
    cp3.add(perpendicular.clone().multiplyScalar(-curveAmount * 0.5));

    const cp4 = new THREE.Vector3().lerpVectors(mid, end, 0.66);
    cp4.add(perpendicular.clone().multiplyScalar(-curveAmount));

    const curvePoints = [start, cp1, cp2, mid, cp3, cp4, end];
    const curve = new THREE.CatmullRomCurve3(curvePoints);
    const points = curve.getPoints(32);

    return { curve, points };
  }, [sourcePos, targetPos, link.strength]);

  // Relationship color always visible — brighter on hover
  const lineColor = style.color;
  const lineWidth = isHovered ? 4 : 1.5 + link.strength * 2;

  return (
    <group>
      {/* Neural fiber — relationship-colored, brighter on hover */}
      <CatmullRomLine
        points={points}
        color={lineColor}
        lineWidth={lineWidth}
        transparent
        opacity={isHovered ? 1 : 0.35}
      />

      {/* Bright white signal pulses traveling along fiber */}
      <NeuralSignal curve={curve} speed={1.2 + link.strength} delay={0} />
      <NeuralSignal curve={curve} speed={1.2 + link.strength} delay={0.5} />
      {link.strength > 0.3 && (
        <NeuralSignal curve={curve} speed={1.5 + link.strength} delay={0.25} />
      )}
      {link.strength > 0.6 && (
        <NeuralSignal curve={curve} speed={1.8 + link.strength} delay={0.75} />
      )}

      {/* Invisible hit area for hover */}
      <mesh
        position={[
          (sourcePos.x + targetPos.x) / 2,
          (sourcePos.y + targetPos.y) / 2,
          (sourcePos.z + targetPos.z) / 2,
        ]}
        onPointerEnter={onHover}
        onPointerLeave={onUnhover}
      >
        <sphereGeometry args={[0.5, 8, 8]} />
        <meshBasicMaterial visible={false} />
      </mesh>

      {/* Hover tooltip */}
      {isHovered && (
        <Html
          position={[
            (sourcePos.x + targetPos.x) / 2,
            (sourcePos.y + targetPos.y) / 2 + 0.5,
            (sourcePos.z + targetPos.z) / 2,
          ]}
          center
          style={{ pointerEvents: 'none' }}
        >
          <div
            className="px-3 py-2 rounded-lg shadow-xl text-xs whitespace-nowrap backdrop-blur-sm"
            style={{
              backgroundColor: 'rgba(15, 23, 42, 0.95)',
              border: `2px solid ${style.color}`,
              color: 'white',
            }}
          >
            <div className="flex items-center gap-2 mb-1">
              <span
                className="w-2 h-2 rounded-full animate-pulse"
                style={{ backgroundColor: style.color }}
              />
              <span className="font-semibold" style={{ color: style.color }}>
                {style.label}
              </span>
            </div>
            <div className="text-[var(--sc-text-primary)] text-[10px] space-y-0.5">
              <div className="truncate max-w-[180px]">
                {link.source_title || `Memory #${link.source_id}`}
              </div>
              <div className="text-[var(--sc-text-muted)]">↓</div>
              <div className="truncate max-w-[180px]">
                {link.target_title || `Memory #${link.target_id}`}
              </div>
              <div className="mt-1 pt-1 border-t border-[var(--sc-border)]">
                Strength: <span style={{ color: style.color }}>{(link.strength * 100).toFixed(0)}%</span>
              </div>
            </div>
          </div>
        </Html>
      )}
    </group>
  );
}

export function MemoryLinks({ memories, links, memoryPositions }: MemoryLinksProps) {
  const [hoveredLink, setHoveredLink] = useState<string | null>(null);

  // Filter to only links where both memories exist and have positions
  const validLinks = useMemo(() => {
    const memoryIds = new Set(memories.map(m => m.id));
    return links.filter(link =>
      memoryIds.has(link.source_id) &&
      memoryIds.has(link.target_id) &&
      memoryPositions.has(link.source_id) &&
      memoryPositions.has(link.target_id)
    );
  }, [memories, links, memoryPositions]);

  const handleHover = useCallback((linkId: string) => {
    setHoveredLink(linkId);
  }, []);

  const handleUnhover = useCallback(() => {
    setHoveredLink(null);
  }, []);

  if (validLinks.length === 0) return null;

  return (
    <group name="neural-connections">
      {validLinks.map((link) => {
        const sourcePos = memoryPositions.get(link.source_id)!;
        const targetPos = memoryPositions.get(link.target_id)!;
        const linkId = `${link.source_id}-${link.target_id}`;

        return (
          <NeuralConnection
            key={linkId}
            link={link}
            sourcePos={sourcePos}
            targetPos={targetPos}
            isHovered={hoveredLink === linkId}
            onHover={() => handleHover(linkId)}
            onUnhover={handleUnhover}
          />
        );
      })}
    </group>
  );
}
