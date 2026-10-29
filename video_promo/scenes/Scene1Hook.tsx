import React from 'react';
import { AbsoluteFill, interpolate, spring, useCurrentFrame, useVideoConfig } from 'remotion';
import { CyberBackground } from '../components/CyberBackground';
import { GlitchTitle } from '../components/GlitchTitle';

export const Scene1Hook: React.FC = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  // Scene fade in / out
  const sceneOpacity = interpolate(frame, [0, 15, 135, 150], [0, 1, 1, 0], {
    extrapolateLeft: 'clamp',
    extrapolateRight: 'clamp',
  });

  const cameraScale = interpolate(frame, [0, 150], [0.97, 1.04]);

  // Warning icons spring
  const iconSpring = spring({
    fps,
    frame: frame - 15,
    config: { damping: 15, mass: 0.5, stiffness: 100 },
  });

  // Dynamic threat count
  const threatCount = Math.floor(
    interpolate(frame, [0, 150], [12000, 89450], {
      extrapolateRight: 'clamp',
    })
  );

  return (
    <AbsoluteFill
      style={{
        opacity: sceneOpacity,
        transform: `scale(${cameraScale})`,
      }}
    >
      <CyberBackground glowMode="crimson" gridSpeed={1.8} />

      {/* Top Threat Telemetry Header */}
      <div
        style={{
          position: 'absolute',
          top: 48,
          left: 80,
          right: 80,
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          zIndex: 10,
        }}
      >
        <div
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: 8,
            padding: '6px 14px',
            backgroundColor: 'rgba(239, 68, 68, 0.15)',
            border: '1px solid rgba(239, 68, 68, 0.45)',
            borderRadius: 20,
            fontSize: 12,
            fontWeight: 800,
            color: '#ef4444',
            fontFamily: 'Consolas, monospace',
            letterSpacing: '1.5px',
          }}
        >
          <span style={{ width: 8, height: 8, borderRadius: '50%', backgroundColor: '#ef4444', boxShadow: '0 0 10px #ef4444' }} />
          CRITICAL PERIMETER ALERT
        </div>

        <div style={{ color: '#ef4444', fontFamily: 'Consolas, monospace', fontSize: 13, letterSpacing: '2px' }}>
          MALICIOUS TELEGRAM PAYLOADS: {threatCount.toLocaleString()} / 24H
        </div>
      </div>

      {/* Main Center Content */}
      <div
        style={{
          position: 'absolute',
          inset: 0,
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 10,
          textAlign: 'center',
          padding: '0 60px',
        }}
      >
        {/* Pulsing Warning Hazard Icon */}
        <div
          style={{
            transform: `scale(${iconSpring})`,
            marginBottom: 24,
            width: 84,
            height: 84,
            borderRadius: 20,
            backgroundColor: 'rgba(239, 68, 68, 0.15)',
            border: '2px solid #ef4444',
            boxShadow: '0 0 30px rgba(239, 68, 68, 0.4)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            fontSize: 42,
          }}
        >
          ⚠️
        </div>

        {/* Glitch Animated Headline */}
        <GlitchTitle
          text="Every day, thousands of suspicious files enter your chat."
          fontSize={48}
          color="#ffffff"
          glowColor="#ef4444"
          delay={10}
        />

        {/* Subtitle Warning */}
        <div
          style={{
            marginTop: 20,
            fontSize: 18,
            color: '#fca5a5',
            fontFamily: 'Consolas, monospace',
            letterSpacing: '2px',
            textTransform: 'uppercase',
            opacity: interpolate(frame, [40, 60], [0, 1], { extrapolateRight: 'clamp' }),
          }}
        >
          Zero-Day Droppers • Weaponized PDFs • Trojanized Office Macros
        </div>

        {/* Floating Danger Badges */}
        <div
          style={{
            display: 'flex',
            gap: 16,
            marginTop: 32,
            opacity: interpolate(frame, [60, 80], [0, 1], { extrapolateRight: 'clamp' }),
          }}
        >
          <div style={{ background: 'rgba(239, 68, 68, 0.1)', border: '1px solid #ef4444', padding: '8px 16px', borderRadius: 8, color: '#f87171', fontSize: 13, fontFamily: 'Consolas, monospace' }}>
            🔴 invoice_urgent.pdf.exe
          </div>
          <div style={{ background: 'rgba(239, 68, 68, 0.1)', border: '1px solid #ef4444', padding: '8px 16px', borderRadius: 8, color: '#f87171', fontSize: 13, fontFamily: 'Consolas, monospace' }}>
            🔴 document_macro.docm
          </div>
          <div style={{ background: 'rgba(239, 68, 68, 0.1)', border: '1px solid #ef4444', padding: '8px 16px', borderRadius: 8, color: '#f87171', fontSize: 13, fontFamily: 'Consolas, monospace' }}>
            🔴 zip_bomb_42gb.zip
          </div>
        </div>
      </div>
    </AbsoluteFill>
  );
};
