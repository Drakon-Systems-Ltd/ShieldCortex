'use client';

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { authFetch } from '@/lib/auth';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3001';

// ── Types ──

export type IronDomeProfile = 'school' | 'enterprise' | 'personal' | 'paranoid';

export interface IronDomeConfig {
  enabled: boolean;
  trustedChannels: string[];
  killPhrase: string;
  requireApproval: string[];
  autoApprove: string[];
  piiRules: { neverOutput: string[]; aggregatesOnly: string[] };
  subAgentRestrictions: { blockedOperations: string[]; sanitiseContext: boolean };
  profile?: IronDomeProfile;
}

export interface IronDomeStatus {
  enabled: boolean;
  config: IronDomeConfig;
  profile?: IronDomeProfile;
}

export interface InjectionDetection {
  category: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  pattern: string;
  match: string;
  description: string;
}

export interface InjectionScanResult {
  clean: boolean;
  riskLevel: 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  detections: InjectionDetection[];
  textLength: number;
  summary: string;
}

// ── Fetch Functions ──

async function fetchIronDomeStatus(): Promise<IronDomeStatus> {
  const res = await fetch(`${API_BASE}/api/iron-dome/status`);
  if (!res.ok) throw new Error('Failed to fetch Iron Dome status');
  return res.json();
}

async function activateIronDome(profile?: IronDomeProfile): Promise<{ success: boolean; config: IronDomeConfig }> {
  const res = await authFetch(`${API_BASE}/api/iron-dome/activate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ profile }),
  });
  if (!res.ok) throw new Error('Failed to activate Iron Dome');
  return res.json();
}

async function deactivateIronDome(): Promise<{ success: boolean }> {
  const res = await authFetch(`${API_BASE}/api/iron-dome/deactivate`, {
    method: 'POST',
  });
  if (!res.ok) throw new Error('Failed to deactivate Iron Dome');
  return res.json();
}

async function scanForInjection(text: string): Promise<InjectionScanResult> {
  const res = await authFetch(`${API_BASE}/api/iron-dome/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ text }),
  });
  if (!res.ok) throw new Error('Failed to scan text');
  return res.json();
}

async function fetchIronDomeAudit(limit?: number): Promise<{ logs: any[]; total: number }> {
  const params = new URLSearchParams();
  if (limit) params.set('limit', limit.toString());
  const res = await fetch(`${API_BASE}/api/iron-dome/audit?${params}`);
  if (!res.ok) throw new Error('Failed to fetch Iron Dome audit');
  return res.json();
}

// ── Hooks ──

export function useIronDomeStatus() {
  return useQuery<IronDomeStatus>({
    queryKey: ['iron-dome-status'],
    queryFn: fetchIronDomeStatus,
    refetchInterval: 30000,
    retry: 2,
  });
}

export function useActivateIronDome() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (profile?: IronDomeProfile) => activateIronDome(profile),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['iron-dome-status'] });
      queryClient.invalidateQueries({ queryKey: ['iron-dome-audit'] });
    },
  });
}

export function useDeactivateIronDome() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: deactivateIronDome,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['iron-dome-status'] });
    },
  });
}

export function useIronDomeScan() {
  return useMutation({
    mutationFn: scanForInjection,
  });
}

export function useIronDomeAudit(limit?: number) {
  return useQuery({
    queryKey: ['iron-dome-audit', limit],
    queryFn: () => fetchIronDomeAudit(limit),
    refetchInterval: 30000,
    retry: 2,
  });
}
