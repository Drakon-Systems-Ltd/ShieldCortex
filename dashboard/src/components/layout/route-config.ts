import type { LucideIcon } from 'lucide-react';
import {
  Database,
  Home,
  ScanSearch,
  Settings,
  Shield,
} from 'lucide-react';

export interface NavItem {
  href: string;
  label: string;
  icon: LucideIcon;
}

export const NAV_ITEMS: NavItem[] = [
  { href: '/overview', label: 'Overview', icon: Home },
  { href: '/memory', label: 'Memory', icon: Database },
  { href: '/protection', label: 'Protection', icon: Shield },
  { href: '/xray', label: 'X-Ray', icon: ScanSearch },
  { href: '/settings', label: 'Settings', icon: Settings },
];
