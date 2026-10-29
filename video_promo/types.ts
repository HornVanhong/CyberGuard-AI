export interface EngineItem {
  id: string;
  name: string;
  category: string;
  badge: string;
  color: string;
  icon: string;
  description: string;
}

export interface CyberGuardTheme {
  navyDark: string;
  navySurface: string;
  cyanNeon: string;
  emeraldGreen: string;
  alertCrimson: string;
  textLight: string;
  textMuted: string;
  glassBg: string;
  glassBorder: string;
}

export const THEME: CyberGuardTheme = {
  navyDark: '#0a0e17',
  navySurface: '#111827',
  cyanNeon: '#00f0ff',
  emeraldGreen: '#10b981',
  alertCrimson: '#ef4444',
  textLight: '#f3f4f6',
  textMuted: '#9ca3af',
  glassBg: 'rgba(17, 24, 39, 0.75)',
  glassBorder: 'rgba(0, 240, 255, 0.25)',
};
