export interface SceneConfig {
  id: string;
  name: string;
  fromFrame: number;
  durationInFrames: number;
}

export const SCENES: Record<string, SceneConfig> = {
  HOOK: {
    id: 'hook',
    name: 'Scene 1: The Hook',
    fromFrame: 0,
    durationInFrames: 120, // 0 - 4s
  },
  REVEAL: {
    id: 'reveal',
    name: 'Scene 2: Product Reveal',
    fromFrame: 120,
    durationInFrames: 120, // 4 - 8s
  },
  DEMO: {
    id: 'demo',
    name: 'Scene 3: Real Telegram Product Demo',
    fromFrame: 240,
    durationInFrames: 270, // 8 - 17s
  },
  ENGINES: {
    id: 'engines',
    name: 'Scene 4: Security Engine Showcase',
    fromFrame: 510,
    durationInFrames: 180, // 17 - 23s
  },
  CTA: {
    id: 'cta',
    name: 'Scene 5: Call to Action',
    fromFrame: 690,
    durationInFrames: 210, // 23 - 30s
  },
};

export const COLOR_PALETTE = {
  deepNavy: '#0A0E17',
  deepNavyDark: '#060910',
  neonCyan: '#00F0FF',
  emeraldGreen: '#10B981',
  alertCrimson: '#EF4444',
  cleanWhite: '#F4F7FB',
  glassBg: 'rgba(10, 14, 23, 0.78)',
  glassBorder: 'rgba(0, 240, 255, 0.28)',
};

export const VERIFIED_ENGINES = [
  { name: 'ClamAV', role: 'Streaming Antivirus Scanning', roleKhmer: 'ស្កេនមេរោគ Streaming Antivirus', status: 'ACTIVE', color: '#10B981', icon: '🛡️' },
  { name: 'YARA', role: 'Rule-Based Pattern Detection', roleKhmer: 'ផ្ទៀងផ្ទាត់លំនាំកូដ Rule Signatures', status: 'ACTIVE', color: '#00F0FF', icon: '⚡' },
  { name: 'Ghidra SRE', role: 'Passive Binary Decompiler', roleKhmer: 'Decompile កូដ Binary ដោយស្វ័យប្រវត្តិ', status: 'ACTIVE', color: '#38BDF8', icon: '🔬' },
  { name: 'Detect It Easy', role: 'Packer Identification (UPX/Themida)', roleKhmer: 'ពិនិត្យមើល Packer (UPX/Themida)', status: 'ACTIVE', color: '#10B981', icon: '📦' },
  { name: 'oletools', role: 'VBA Macro & Document Analysis', roleKhmer: 'វិភាគកូដ Macro ក្នុងឯកសារ Office', status: 'ACTIVE', color: '#F59E0B', icon: '📑' },
  { name: 'capa', role: 'Binary Capability Detection', roleKhmer: 'វិភាគសមត្ថភាពលាក់កំបាំងរបស់កូដ', status: 'ACTIVE', color: '#10B981', icon: '🔍' },
  { name: 'ExifTool & PDFiD', role: 'Metadata & Document Inspection', roleKhmer: 'ពិនិត្យ Metadata & PDF Streams', status: 'ACTIVE', color: '#00F0FF', icon: '📄' },
  { name: 'Google Gemini AI', role: 'AI-Assisted Threat Analysis', roleKhmer: 'បញ្ញាសិប្បនិម្មិតវិភាគហានិភ័យ', status: 'ACTIVE', color: '#8B5CF6', icon: '✨' },
];
