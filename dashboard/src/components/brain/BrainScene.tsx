'use client';

/**
 * Brain Scene
 * Main 3D visualization of the memory brain
 */

import { Suspense, useMemo } from 'react';
import { Canvas } from '@react-three/fiber';
import { OrbitControls, Environment, Stars } from '@react-three/drei';
import { EffectComposer, Bloom } from '@react-three/postprocessing';
import { Memory, MemoryLink } from '@/types/memory';
import { MemoryNode } from './MemoryNode';
import { MemoryLinks } from './MemoryLinks';
import { DataFlowParticles } from './DataFlowParticles';
import { BrainRegions } from './BrainRegions';
import { calculateMemoryPosition } from '@/lib/position-algorithm';

interface BrainSceneProps {
  memories: Memory[];
  links?: MemoryLink[];
  selectedMemory: Memory | null;
  onSelectMemory: (memory: Memory | null) => void;
}

function BrainContent({
  memories,
  links = [],
  selectedMemory,
  onSelectMemory,
}: BrainSceneProps) {
  // Calculate positions for all memories
  const memoryPositions = useMemo(() => {
    return memories.map((memory) => ({
      memory,
      position: calculateMemoryPosition(memory),
    }));
  }, [memories]);

  // Create a map for quick position lookup by memory ID
  const positionMap = useMemo(() => {
    const map = new Map<number, { x: number; y: number; z: number }>();
    memoryPositions.forEach(({ memory, position }) => {
      map.set(memory.id, position);
    });
    return map;
  }, [memoryPositions]);

  return (
    <>
      {/* Ambient lighting */}
      <ambientLight intensity={0.2} />
      <pointLight position={[10, 10, 10]} intensity={0.5} />
      <pointLight position={[-10, -10, -10]} intensity={0.3} color="#4488ff" />

      {/* Brain region indicators */}
      <BrainRegions />

      {/* Data flow particles */}
      <DataFlowParticles count={200} speed={0.4} />

      {/* Memory links (connections between related memories) */}
      {links.length > 0 && (
        <MemoryLinks
          memories={memories}
          links={links}
          memoryPositions={positionMap}
        />
      )}

      {/* Memory nodes */}
      {memoryPositions.map(({ memory, position }) => (
        <MemoryNode
          key={memory.id}
          memory={memory}
          position={[position.x, position.y, position.z]}
          onSelect={onSelectMemory}
          isSelected={selectedMemory?.id === memory.id}
        />
      ))}

      {/* Camera controls */}
      <OrbitControls
        enablePan={true}
        enableZoom={true}
        enableRotate={true}
        minDistance={5}
        maxDistance={25}
        autoRotate={!selectedMemory}
        autoRotateSpeed={0.3}
      />

      {/* Background stars */}
      <Stars
        radius={50}
        depth={50}
        count={1000}
        factor={2}
        saturation={0}
        fade
        speed={0.5}
      />

      {/* Post-processing effects */}
      <EffectComposer>
        <Bloom
          luminanceThreshold={0.2}
          luminanceSmoothing={0.9}
          intensity={0.8}
          radius={0.8}
        />
      </EffectComposer>
    </>
  );
}

export function BrainScene({
  memories,
  links = [],
  selectedMemory,
  onSelectMemory,
}: BrainSceneProps) {
  return (
    <div className="w-full h-full bg-slate-950">
      <Canvas
        camera={{ position: [0, 0, 12], fov: 60 }}
        gl={{ antialias: true, alpha: true }}
        onClick={() => onSelectMemory(null)}
      >
        <Suspense fallback={null}>
          <BrainContent
            memories={memories}
            links={links}
            selectedMemory={selectedMemory}
            onSelectMemory={onSelectMemory}
          />
        </Suspense>
      </Canvas>

      {/* Legend overlay */}
      <div className="absolute bottom-4 left-4 bg-slate-900/90 border border-slate-700 rounded-lg p-3 text-xs backdrop-blur-sm">
        <h4 className="font-semibold text-white mb-2">Memory Regions</h4>
        <div className="space-y-1.5">
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full bg-orange-500" />
            <span className="text-slate-300">Short-Term (Front)</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full bg-purple-500" />
            <span className="text-slate-300">Episodic (Middle)</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full bg-blue-500" />
            <span className="text-slate-300">Long-Term (Back)</span>
          </div>
        </div>
        <div className="mt-3 pt-2 border-t border-slate-700">
          <p className="text-slate-400">
            {memories.length} memories • Click to select
          </p>
        </div>
      </div>
    </div>
  );
}
