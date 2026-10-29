import React from 'react';
import { AbsoluteFill, interpolate, spring, useCurrentFrame, useVideoConfig } from 'remotion';
import { CyberBackground } from '../components/CyberBackground';
import { EngineGrid } from '../components/EngineGrid';

interface Scene4EnginesProps {
  isVertical?: boolean;
  language?: 'kh' | 'en';
}

export const Scene4Engines: React.FC<Scene4EnginesProps> = ({
  isVertical = true,
  language = 'kh',
}) => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  // Scene fade in / out (total 180 frames)
  const opacity = interpolate(frame, [0, 15, 165, 180], [0, 1, 1, 0], {
    extrapolateLeft: 'clamp',
    extrapolateRight: 'clamp',
  });

  const headerSpring = spring({
    fps,
    frame,
    config: { damping: 14, mass: 0.5, stiffness: 100 },
  });

  const isKhmer = language === 'kh';

  return (
    <AbsoluteFill
      style={{
        opacity,
        overflow: 'hidden',
      }}
    >
      <CyberBackground glowMode="emerald" gridSpeed={1.3} isVertical={isVertical} />

      {/* Main Container */}
      <div
        style={{
          position: 'absolute',
          inset: 0,
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          padding: isVertical ? '80px 32px' : '40px 60px',
          zIndex: 20,
        }}
      >
        {/* Section Header */}
        <div
          style={{
            transform: `scale(${headerSpring})`,
            textAlign: 'center',
            marginBottom: isVertical ? 26 : 24,
          }}
        >
          <div
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: 8,
              padding: '6px 16px',
              backgroundColor: 'rgba(16, 185, 129, 0.14)',
              border: '1.5px solid rgba(16, 185, 129, 0.45)',
              borderRadius: 20,
              fontSize: isKhmer ? 13 : 12,
              fontWeight: 800,
              color: '#10B981',
              letterSpacing: '0.5px',
              marginBottom: 12,
            }}
          >
            <span
              style={{
                width: 7,
                height: 7,
                borderRadius: '50%',
                backgroundColor: '#10B981',
                boxShadow: '0 0 8px #10B981',
              }}
            />
            {isKhmer ? 'ប្រព័ន្ធស្កេនស្របគ្នា ១២ កម្រិត' : 'PARALLEL INSPECTION PIPELINE'}
          </div>

          <div
            style={{
              fontSize: isVertical ? (isKhmer ? 42 : 44) : 52,
              fontWeight: 900,
              color: '#FFFFFF',
              letterSpacing: isKhmer ? '0px' : '-1.5px',
              lineHeight: 1.2,
            }}
          >
            {isKhmer ? 'ម៉ាស៊ីនស្កេនមេរោគ ១២ កម្រិត' : '12 HEAVY-DUTY ENGINES'}
          </div>

          <div
            style={{
              fontSize: isVertical ? (isKhmer ? 17 : 17) : 20,
              color: '#94A3B8',
              marginTop: 6,
              fontWeight: 500,
            }}
          >
            {isKhmer
              ? 'កំចាត់មេរោគ, ផ្ទៀងផ្ទាត់ហត្ថលេខាកូដ, Decompiler និង Gemini AI'
              : 'Antivirus, byte-pattern signatures, binary decompilers, and Gemini AI.'}
          </div>
        </div>

        {/* Engine Cards Grid */}
        <EngineGrid isVertical={isVertical} language={language} />

        {/* Bottom Verification Telemetry */}
        <div
          style={{
            marginTop: isVertical ? 22 : 20,
            display: 'flex',
            alignItems: 'center',
            gap: 12,
            fontSize: isKhmer ? 12 : 12,
            color: '#10B981',
            backgroundColor: 'rgba(15, 23, 42, 0.8)',
            padding: '6px 20px',
            borderRadius: 14,
            border: '1px solid rgba(16, 185, 129, 0.3)',
            fontWeight: 700,
          }}
        >
          {isKhmer ? (
            <>
              <span>ហត្ថលេខាមេរោគ៖ ១,៤២០,០០០+</span>
              <span>•</span>
              <span>រយៈពេលស្កេនជាមធ្យម៖ ១.៨ វិនាទី</span>
            </>
          ) : (
            <>
              <span>ACTIVE SIGNATURES: 1,420,000+</span>
              <span>•</span>
              <span>AVERAGE SCAN TIME: 1.8s</span>
            </>
          )}
        </div>
      </div>
    </AbsoluteFill>
  );
};