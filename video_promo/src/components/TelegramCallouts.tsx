import React from 'react';
import { interpolate, spring, useCurrentFrame, useVideoConfig } from 'remotion';

interface TelegramCalloutsProps {
  language?: 'kh' | 'en';
}

export const TelegramCallouts: React.FC<TelegramCalloutsProps> = ({ language = 'kh' }) => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  const isKhmer = language === 'kh';

  // Callout 1: Appears frames 25-95 (Step 1)
  const callout1Spring = spring({
    fps,
    frame: frame - 25,
    config: { damping: 14, mass: 0.6, stiffness: 100 },
  });
  const callout1Opacity = interpolate(frame, [25, 35, 90, 105], [0, 1, 1, 0], {
    extrapolateLeft: 'clamp',
    extrapolateRight: 'clamp',
  });

  // Callout 2: Appears frames 105-180 (Step 2 - Multi-Engine)
  const callout2Spring = spring({
    fps,
    frame: frame - 105,
    config: { damping: 14, mass: 0.6, stiffness: 100 },
  });
  const callout2Opacity = interpolate(frame, [105, 115, 170, 185], [0, 1, 1, 0], {
    extrapolateLeft: 'clamp',
    extrapolateRight: 'clamp',
  });

  // Callout 3: Appears frames 185-265 (Step 3 - AI Analysis & Action)
  const callout3Spring = spring({
    fps,
    frame: frame - 185,
    config: { damping: 14, mass: 0.6, stiffness: 100 },
  });
  const callout3Opacity = interpolate(frame, [185, 195, 255, 270], [0, 1, 1, 0], {
    extrapolateLeft: 'clamp',
    extrapolateRight: 'clamp',
  });

  return (
    <div style={{ position: 'absolute', inset: 0, pointerEvents: 'none', zIndex: 30 }}>
      {/* Callout 1: Top Right HUD Badge */}
      {frame >= 20 && frame <= 110 && (
        <div
          style={{
            position: 'absolute',
            top: 180,
            right: 50,
            transform: `scale(${callout1Spring}) translateY(${interpolate(frame, [25, 95], [10, -5])}px)`,
            opacity: callout1Opacity,
            backgroundColor: 'rgba(10, 14, 23, 0.88)',
            border: '1.5px solid #00F0FF',
            borderRadius: 16,
            padding: '14px 20px',
            boxShadow: '0 0 25px rgba(0, 240, 255, 0.35)',
            maxWidth: 340,
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
            <span style={{ width: 8, height: 8, borderRadius: '50%', backgroundColor: '#00F0FF', boxShadow: '0 0 8px #00F0FF' }} />
            <span style={{ fontSize: 11, color: '#00F0FF', fontWeight: 800, letterSpacing: '1px' }}>
              {isKhmer ? 'ជំហានទី ០១ // ផ្ញើឯកសារ' : 'STEP 01 // TELEGRAM CHAT'}
            </span>
          </div>
          <div style={{ fontSize: 18, fontWeight: 900, color: '#FFFFFF', letterSpacing: '-0.3px' }}>
            {isKhmer ? 'Forward ឯកសារមកកាន់ Bot' : 'Forward Any File'}
          </div>
          <div style={{ fontSize: 12, color: '#94A3B8', marginTop: 3, lineHeight: 1.4 }}>
            {isKhmer
              ? 'ឯកសារ EXE, Word/Excel, PDF, ZIP — មិនបាច់ដំឡើងកម្មវិធីបន្ថែម។'
              : 'Exe, Office Macros, PDFs, ZIPs — zero installation needed.'}
          </div>
        </div>
      )}

      {/* Callout 2: Left Middle HUD Badge */}
      {frame >= 100 && frame <= 190 && (
        <div
          style={{
            position: 'absolute',
            top: 480,
            left: 50,
            transform: `scale(${callout2Spring})`,
            opacity: callout2Opacity,
            backgroundColor: 'rgba(10, 14, 23, 0.92)',
            border: '1.5px solid #EF4444',
            borderRadius: 16,
            padding: '14px 20px',
            boxShadow: '0 0 30px rgba(239, 68, 68, 0.4)',
            maxWidth: 340,
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
            <span style={{ width: 8, height: 8, borderRadius: '50%', backgroundColor: '#EF4444', boxShadow: '0 0 8px #EF4444' }} />
            <span style={{ fontSize: 11, color: '#EF4444', fontWeight: 800, letterSpacing: '1px' }}>
              {isKhmer ? 'ជំហានទី ០២ // វិភាគទិន្នន័យ' : 'STEP 02 // PARALLEL AUDIT'}
            </span>
          </div>
          <div style={{ fontSize: 18, fontWeight: 900, color: '#FFFFFF', letterSpacing: '-0.3px' }}>
            {isKhmer ? 'ដឹងលទ្ធផលមេរោគភ្លាមៗ' : 'Instant Malware Verdict'}
          </div>
          <div style={{ fontSize: 12, color: '#94A3B8', marginTop: 3, lineHeight: 1.4 }}>
            {isKhmer
              ? 'ClamAV + YARA ពិនិត្យរកឃើញមេរោគក្នុងរយៈពេល < ២ វិនាទី។'
              : 'ClamAV TCP + YARA rules detect weaponized payloads in < 2s.'}
          </div>
        </div>
      )}

      {/* Callout 3: Bottom Right HUD Badge */}
      {frame >= 180 && (
        <div
          style={{
            position: 'absolute',
            bottom: 230,
            right: 50,
            transform: `scale(${callout3Spring})`,
            opacity: callout3Opacity,
            backgroundColor: 'rgba(10, 14, 23, 0.92)',
            border: '1.5px solid #8B5CF6',
            borderRadius: 16,
            padding: '14px 20px',
            boxShadow: '0 0 30px rgba(139, 92, 246, 0.4)',
            maxWidth: 350,
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
            <span style={{ width: 8, height: 8, borderRadius: '50%', backgroundColor: '#8B5CF6', boxShadow: '0 0 8px #8B5CF6' }} />
            <span style={{ fontSize: 11, color: '#C084FC', fontWeight: 800, letterSpacing: '1px' }}>
              {isKhmer ? 'ជំហានទី ០៣ // បញ្ញាសិប្បនិម្មិត GEMINI' : 'STEP 03 // GEMINI AI REASONING'}
            </span>
          </div>
          <div style={{ fontSize: 18, fontWeight: 900, color: '#FFFFFF', letterSpacing: '-0.3px' }}>
            {isKhmer ? 'ពន្យល់ពីហានិភ័យយ៉ាងច្បាស់' : 'Plain-Language Intel'}
          </div>
          <div style={{ fontSize: 12, color: '#94A3B8', marginTop: 3, lineHeight: 1.4 }}>
            {isKhmer
              ? 'យល់ដឹងពីគ្រោះថ្នាក់មុនពេលចុចបើក — រួមជាមួយមុខងារ Ghidra Decompile។'
              : 'Understand the exact risk before clicking — plus one-tap Ghidra decompilation.'}
          </div>
        </div>
      )}
    </div>
  );
};