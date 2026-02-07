'use client';

import { useMutation } from '@tanstack/react-query';
import type { SkillScanAllResponse, SkillScanContentResult } from '@/types/skills';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3001';

async function scanAll(dir?: string): Promise<SkillScanAllResponse> {
  const response = await fetch(`${API_BASE}/api/skills/scan-all`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ dir }),
  });
  if (!response.ok) throw new Error('Failed to scan skills');
  return response.json();
}

async function scanContent(params: {
  content: string;
  format?: string;
  name?: string;
  mode?: string;
}): Promise<SkillScanContentResult> {
  const response = await fetch(`${API_BASE}/api/skills/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(params),
  });
  if (!response.ok) throw new Error('Failed to scan skill content');
  return response.json();
}

export function useSkillScanAll() {
  return useMutation({
    mutationFn: (dir?: string) => scanAll(dir),
  });
}

export function useSkillScanContent() {
  return useMutation({
    mutationFn: scanContent,
  });
}

async function trustSkill(path: string): Promise<{ trusted: boolean; path: string }> {
  const response = await fetch(`${API_BASE}/api/skills/trust`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ path }),
  });
  if (!response.ok) throw new Error('Failed to trust skill');
  return response.json();
}

async function untrustSkill(path: string): Promise<{ trusted: boolean; path: string }> {
  const response = await fetch(`${API_BASE}/api/skills/trust`, {
    method: 'DELETE',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ path }),
  });
  if (!response.ok) throw new Error('Failed to untrust skill');
  return response.json();
}

async function deleteSkillFile(path: string): Promise<{ deleted: boolean; path: string }> {
  const response = await fetch(`${API_BASE}/api/skills/file`, {
    method: 'DELETE',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ path }),
  });
  if (!response.ok) {
    const data = await response.json().catch(() => ({}));
    throw new Error(data.error || 'Failed to delete skill file');
  }
  return response.json();
}

export function useSkillTrust() {
  return useMutation({ mutationFn: trustSkill });
}

export function useSkillUntrust() {
  return useMutation({ mutationFn: untrustSkill });
}

export function useDeleteSkillFile() {
  return useMutation({ mutationFn: deleteSkillFile });
}
