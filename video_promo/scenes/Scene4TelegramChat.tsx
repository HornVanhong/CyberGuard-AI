import React from 'react';
import { AbsoluteFill, interpolate, spring, useCurrentFrame, useVideoConfig } from 'remotion';
import { CyberBackground } from '../components/CyberBackground';
import { TelegramChatMockup } from '../components/TelegramChatMockup';

export const Scene4TelegramChat: React.FC = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  // Scene transition
  const sceneOpacity = interpolate(frame, [0, 15, 165, 180], [0, 1, 1, 0], {
    extrapolateLeft: 'clamp',
    extrapolateRight: 'clamp',
  });

  const chatSpring = spring({
    fps,
    frame,
    config: { damping: 15, mass: 0.5, stiffness: 100 },
  });

  return (
    <AbsoluteFill
      style={{
        opacity: sceneOpacity,
      }}
    >
      <CyberBackground glowMode="cyan" />

      {/* Top Header */}
      <div
        style={{
          position: 'absolute',
          top: 40,
          left: 80,
          right: 80,
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          zIndex: 10,
        }}
      >
        <div style={{ display: 'flex', gap: 14 }}>
          <div
            style={{
              padding: '6px 16px',
              backgroundColor: 'rgba(0, 240, 255, 0.15)',
              border: '1px solid rgba(0, 240, 255, 0.45)',
              borderRadius: 20,
              fontSize: 12,
              fontWeight: 800,
              color: '#00f0ff',
              fontFamily: 'Consolas, monospace',
            }}
          >
            ● TELEGRAM ZERO-TRUST INTERFACE
          </div>
          <div
            style={{
              padding: '6px 16px',
              backgroundColor: 'rgba(139, 92, 246, 0.15)',
              border: '1px solid rgba(139, 92, 246, 0.45)',
              borderRadius: 20,
              fontSize: 12,
              fontWeight: 800,
              color: '#c4b5fd',
              fontFamily: 'Consolas, monospace',
            }}
          >
            AI ASSISTANT: GOOGLE GEMINI
          </div>
        </div>

        <div style={{ color: '#00f0ff', fontFamily: 'Consolas, monospace', fontSize: 13 }}>
          CLIENT: TELEGRAM DESKTOP & MOBILE // SERVERLESS EDGE
        </div>
      </div>

      {/* Section Headline */}
      <div
        style={{
          position: 'absolute',
          top: 96,
          left: 0,
          right: 0,
          textAlign: 'center',
          zIndex: 10,
        }}
      >
        <div
          style={{
            fontSize: 40,
            fontWeight: 900,
            color: '#ffffff',
            letterSpacing: '0.5px',
            fontFamily: '"Montserrat", "Inter", sans-serif',
            textShadow: '0 0 25px rgba(0, 240, 255, 0.4)',
          }}
        >
          Instant Telegram File Inspection
        </div>
        <div style={{ fontSize: 15, color: '#9ca3af', marginTop: 4, fontFamily: 'Consolas, monospace' }}>
          Drop any suspicious file. Get instant multi-engine verdicts and plain-language AI explanations.
        </div>
      </div>

      {/* Center Animated Telegram Chat Mockup */}
      <div
        style={{
          position: 'absolute',
          top: 195,
          left: 0,
          right: 0,
          display: 'flex',
          justifyContent: 'center',
          zIndex: 10,
          transform: `scale(${chatSpring})`,
        }}
      >
        <TelegramChatMockup />
      </div>
    </AbsoluteFill>
  );
};
