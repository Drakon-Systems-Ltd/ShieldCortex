'use client';

/**
 * Core Sphere
 * Glowing central energy core - the "heart" of the AI brain
 *
 * Features:
 * - Bright central sphere with multiple glow layers
 * - Pulsing animation tied to activity level
 * - Color gradient from deep orange (#FF8C00) to bright gold (#FFD700)
 * - Additive blending for realistic glow effect
 */

import { useRef, useMemo, useEffect } from 'react';
import { useFrame } from '@react-three/fiber';
import * as THREE from 'three';

// Shared geometries to prevent memory leaks
const CORE_GEOMETRY = new THREE.SphereGeometry(1, 32, 32);
const GLOW_GEOMETRY = new THREE.SphereGeometry(1, 24, 24);

interface CoreSphereProps {
  /** Activity level 0-1, affects pulse intensity and speed */
  activity?: number;
  /** Base radius of the core sphere */
  radius?: number;
  /** Position of the core */
  position?: [number, number, number];
}

export function CoreSphere({
  activity = 0.5,
  radius = 0.4,
  position = [0, 0, 0],
}: CoreSphereProps) {
  const coreRef = useRef<THREE.Mesh>(null);
  const glow1Ref = useRef<THREE.Mesh>(null);
  const glow2Ref = useRef<THREE.Mesh>(null);
  const glow3Ref = useRef<THREE.Mesh>(null);
  const glow4Ref = useRef<THREE.Mesh>(null);

  // Core material - brightest, deep orange
  const coreMaterial = useMemo(
    () =>
      new THREE.MeshBasicMaterial({
        color: '#FF8C00',
        transparent: true,
        opacity: 0.95,
        depthWrite: false,
      }),
    []
  );

  // Inner glow layer 1 - orange-gold
  const glow1Material = useMemo(
    () =>
      new THREE.MeshBasicMaterial({
        color: '#FFA500',
        transparent: true,
        opacity: 0.15,
        depthWrite: false,
        blending: THREE.AdditiveBlending,
      }),
    []
  );

  // Glow layer 2 - transitioning to gold
  const glow2Material = useMemo(
    () =>
      new THREE.MeshBasicMaterial({
        color: '#FFB700',
        transparent: true,
        opacity: 0.08,
        depthWrite: false,
        blending: THREE.AdditiveBlending,
      }),
    []
  );

  // Glow layer 3 - lighter gold
  const glow3Material = useMemo(
    () =>
      new THREE.MeshBasicMaterial({
        color: '#FFC500',
        transparent: true,
        opacity: 0.04,
        depthWrite: false,
        blending: THREE.AdditiveBlending,
      }),
    []
  );

  // Outer glow layer 4 - brightest gold, most diffuse
  const glow4Material = useMemo(
    () =>
      new THREE.MeshBasicMaterial({
        color: '#FFD700',
        transparent: true,
        opacity: 0.02,
        depthWrite: false,
        blending: THREE.AdditiveBlending,
      }),
    []
  );

  // Cleanup materials on unmount
  useEffect(() => {
    return () => {
      coreMaterial.dispose();
      glow1Material.dispose();
      glow2Material.dispose();
      glow3Material.dispose();
      glow4Material.dispose();
    };
  }, [coreMaterial, glow1Material, glow2Material, glow3Material, glow4Material]);

  // Animation - pulsing "breathing" effect
  useFrame((state) => {
    if (!coreRef.current) return;

    const time = state.clock.elapsedTime;

    // Base pulse speed increases with activity (0.8 to 3.0 Hz)
    const pulseSpeed = 0.8 + activity * 2.2;

    // Primary breathing pulse
    const primaryPulse = Math.sin(time * pulseSpeed) * 0.5 + 0.5;

    // Secondary faster micro-pulse for energy feel
    const microPulse = Math.sin(time * pulseSpeed * 3) * 0.15 + 0.85;

    // Combined pulse with activity influence
    const combinedPulse = primaryPulse * (0.7 + activity * 0.3) * microPulse;

    // Core sphere - subtle scale pulsing
    const coreScale = radius * (1 + combinedPulse * 0.15);
    coreRef.current.scale.setScalar(coreScale);
    coreMaterial.opacity = 0.85 + combinedPulse * 0.1;

    // Glow layer 1 - larger, synced with core
    if (glow1Ref.current) {
      const glow1Scale = radius * 1.6 * (1 + combinedPulse * 0.1);
      glow1Ref.current.scale.setScalar(glow1Scale);
      glow1Material.opacity = (0.1 + combinedPulse * 0.06) * (0.6 + activity * 0.4);
    }

    // Glow layer 2 - slightly phase-shifted for depth
    if (glow2Ref.current) {
      const phase2 = Math.sin(time * pulseSpeed - 0.3) * 0.5 + 0.5;
      const glow2Scale = radius * 2.0 * (1 + phase2 * 0.08);
      glow2Ref.current.scale.setScalar(glow2Scale);
      glow2Material.opacity = (0.05 + phase2 * 0.04) * (0.5 + activity * 0.5);
    }

    // Glow layer 3 - more phase shift, slower feel
    if (glow3Ref.current) {
      const phase3 = Math.sin(time * pulseSpeed * 0.7 - 0.6) * 0.5 + 0.5;
      const glow3Scale = radius * 2.4 * (1 + phase3 * 0.06);
      glow3Ref.current.scale.setScalar(glow3Scale);
      glow3Material.opacity = (0.025 + phase3 * 0.02) * (0.4 + activity * 0.6);
    }

    // Glow layer 4 - outermost, slowest, most ethereal
    if (glow4Ref.current) {
      const phase4 = Math.sin(time * pulseSpeed * 0.5 - 0.9) * 0.5 + 0.5;
      const glow4Scale = radius * 3.0 * (1 + phase4 * 0.05);
      glow4Ref.current.scale.setScalar(glow4Scale);
      glow4Material.opacity = (0.01 + phase4 * 0.015) * (0.3 + activity * 0.7);
    }
  });

  return (
    <group position={position} name="core-sphere">
      {/* Outermost glow layer 4 - brightest gold, most diffuse */}
      <mesh
        ref={glow4Ref}
        geometry={GLOW_GEOMETRY}
        material={glow4Material}
        scale={radius * 3.0}
      />

      {/* Glow layer 3 - lighter gold */}
      <mesh
        ref={glow3Ref}
        geometry={GLOW_GEOMETRY}
        material={glow3Material}
        scale={radius * 2.4}
      />

      {/* Glow layer 2 - transitioning gold */}
      <mesh
        ref={glow2Ref}
        geometry={GLOW_GEOMETRY}
        material={glow2Material}
        scale={radius * 2.0}
      />

      {/* Inner glow layer 1 - orange-gold */}
      <mesh
        ref={glow1Ref}
        geometry={GLOW_GEOMETRY}
        material={glow1Material}
        scale={radius * 1.6}
      />

      {/* Core sphere - brightest, deep orange center */}
      <mesh
        ref={coreRef}
        geometry={CORE_GEOMETRY}
        material={coreMaterial}
        scale={radius}
      />
    </group>
  );
}
