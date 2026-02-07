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
