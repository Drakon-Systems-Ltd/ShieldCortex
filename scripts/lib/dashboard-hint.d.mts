export const DASHBOARD_URL: 'http://localhost:3030';
export const DASHBOARD_PORT: 3030;
export const DASHBOARD_COMMAND: 'shieldcortex dashboard';
export const ALWAYS_ON_COMMAND: 'shieldcortex service install';
export interface DashboardHint {
  title: string;
  command: string;
  url: string;
  detail: string;
  alwaysOnCommand: string;
  alwaysOnDetail: string;
}
export function isHeadlessSystem(): boolean;
export function isDashboardRunning(timeoutMs?: number): Promise<boolean>;
export function getDashboardHint(): Promise<DashboardHint | null>;
