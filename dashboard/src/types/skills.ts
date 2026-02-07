export type SkillFormat = 'skill-md' | 'hook-md' | 'hook-js' | 'rules' | 'claude-md' | 'copilot-md' | 'aider-yml' | 'continue-json' | 'unknown';
export type RiskLevel = 'safe' | 'low' | 'medium' | 'high' | 'critical';
export type Severity = 'low' | 'medium' | 'high' | 'critical';

export interface SkillThreatFinding {
  pattern: string;
  severity: Severity;
  description: string;
  matchedText?: string;
  line?: number;
}

export interface SkillScanFileResult {
  path: string;
  safe: boolean;
  skillName: string;
  format: SkillFormat;
  riskLevel: RiskLevel;
  summary: string;
  findings: SkillThreatFinding[];
  scanDurationMs: number;
}

export interface SkillScanAllResponse {
  files: SkillScanFileResult[];
  totalScanned: number;
  threatCount: number;
  scannedAt: string;
}

export interface SkillScanContentResult {
  safe: boolean;
  skillName: string;
  format: SkillFormat;
  findings: SkillThreatFinding[];
  riskLevel: RiskLevel;
  summary: string;
  scanDurationMs: number;
}
